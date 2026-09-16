package e2e

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"

	"github.com/nothingdns/nothingdns/internal/protocol"
	dnsquic "github.com/nothingdns/nothingdns/internal/quic"
	"github.com/nothingdns/nothingdns/internal/server"
)

// doqTestAdapter adapts a server.Handler into a quic.DoQHandler for the
// e2e tests, mirroring the production adapter in cmd/nothingdns/adapters.go
// without importing the cmd package.
type doqTestAdapter struct {
	handler server.Handler
}

func (a *doqTestAdapter) ServeDoQ(stream *dnsquic.Stream, queryData []byte) {
	msg, err := protocol.UnpackMessage(queryData)
	if err != nil {
		return
	}
	defer msg.Release()
	if len(msg.Questions) == 0 {
		return
	}
	rw := &doqTestResponseWriter{stream: stream, query: msg}
	a.handler.ServeDNS(rw, msg)
}

// doqTestResponseWriter implements server.ResponseWriter over a DoQ stream,
// writing the RFC 9250 §4.2 2-octet length prefix before the DNS message.
type doqTestResponseWriter struct {
	stream *dnsquic.Stream
	query  *protocol.Message
}

func (w *doqTestResponseWriter) Write(msg *protocol.Message) (int, error) {
	msg.Header.ID = w.query.Header.ID
	msg.Header.Flags.QR = true

	buf := make([]byte, msg.WireLength()+2)
	n, err := msg.Pack(buf[2:])
	if err != nil {
		return 0, err
	}
	binary.BigEndian.PutUint16(buf[0:2], uint16(n))

	written := 0
	for written < n+2 {
		nn, err := w.stream.Write(buf[written : n+2])
		if err != nil {
			return written, err
		}
		written += nn
	}
	return written, nil
}

func (w *doqTestResponseWriter) ClientInfo() *server.ClientInfo {
	addr := w.stream.RemoteAddr()
	if addr == nil {
		addr = &net.UDPAddr{}
	}
	return &server.ClientInfo{Addr: addr, Protocol: "quic"}
}

func (w *doqTestResponseWriter) MaxSize() int {
	return dnsquic.DoQMaxMessageSize
}

// startDoQTestServer starts a real DoQServer on 127.0.0.1:0 backed by the
// given DNS handler and returns its UDP address. Cleanup is registered on t.
func startDoQTestServer(t *testing.T, handler server.Handler) *net.UDPAddr {
	t.Helper()

	tlsConfig := generateSelfSignedCert(t)
	tlsConfig.NextProtos = []string{"doq"}

	srv := dnsquic.NewDoQServer("127.0.0.1:0", &doqTestAdapter{handler: handler}, tlsConfig)
	if err := srv.Listen(); err != nil {
		t.Fatalf("DoQ Listen: %v", err)
	}
	go func() {
		_ = srv.Serve()
	}()
	t.Cleanup(func() {
		_ = srv.Stop()
	})

	time.Sleep(10 * time.Millisecond)

	udpAddr, ok := srv.Addr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("Expected *net.UDPAddr, got %T", srv.Addr())
	}
	return udpAddr
}

// dialDoQ opens a QUIC connection to the DoQ server with the RFC 9250 "doq" ALPN.
func dialDoQ(t *testing.T, addr *net.UDPAddr) *quicgo.Conn {
	t.Helper()

	localConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP for QUIC client: %v", err)
	}
	t.Cleanup(func() { _ = localConn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"doq"},
	}

	conn, err := quicgo.Dial(ctx, localConn, addr, clientTLS, &quicgo.Config{MaxIncomingStreams: 10})
	if err != nil {
		t.Fatalf("quic.Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
	return conn
}

// doqRoundTrip sends a single DNS query on its own QUIC stream (RFC 9250
// §4.2: one query per stream, 2-octet length prefix) and returns the response.
func doqRoundTrip(t *testing.T, conn *quicgo.Conn, query *protocol.Message) *protocol.Message {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("OpenStreamSync: %v", err)
	}

	buf := make([]byte, query.WireLength()+2)
	n, err := query.Pack(buf[2:])
	if err != nil {
		t.Fatalf("Pack query: %v", err)
	}
	binary.BigEndian.PutUint16(buf[0:2], uint16(n))

	if _, err := stream.Write(buf[:n+2]); err != nil {
		t.Fatalf("stream.Write: %v", err)
	}
	// Half-close: client is done sending (RFC 9250 §4.2).
	if err := stream.Close(); err != nil {
		t.Fatalf("stream.Close: %v", err)
	}

	if err := stream.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		t.Fatalf("read response length prefix: %v", err)
	}
	msgLen := binary.BigEndian.Uint16(lenBuf[:])
	if msgLen == 0 {
		t.Fatal("zero-length DoQ response")
	}
	respBuf := make([]byte, msgLen)
	if _, err := io.ReadFull(stream, respBuf); err != nil {
		t.Fatalf("read response body: %v", err)
	}

	resp, err := protocol.UnpackMessage(respBuf)
	if err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	return resp
}

// TestDoQEndToEnd exercises a real DoQ server (RFC 9250) with a real quic-go
// client: TLS handshake with the "doq" ALPN, 2-octet length-prefixed query on
// a bidirectional stream, and a validated DNS response.
func TestDoQEndToEnd(t *testing.T) {
	handler := server.HandlerFunc(func(w server.ResponseWriter, req *protocol.Message) {
		resp := &protocol.Message{
			Header:    protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Questions: req.Questions,
		}
		if len(req.Questions) > 0 && req.Questions[0].QType == protocol.TypeA {
			resp.AddAnswer(&protocol.ResourceRecord{
				Name:  req.Questions[0].Name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{10, 20, 30, 40}},
			})
		}
		w.Write(resp)
	})

	addr := startDoQTestServer(t, handler)
	conn := dialDoQ(t, addr)

	// RFC 9250 §4.2.1: DoQ clients MUST use a Message ID of 0.
	query, err := protocol.NewQuery(0, "doq.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("NewQuery: %v", err)
	}

	resp := doqRoundTrip(t, conn, query)

	if resp.Header.ID != 0 {
		t.Errorf("response ID = %d, want 0", resp.Header.ID)
	}
	if !resp.Header.Flags.QR {
		t.Error("expected QR flag set in response")
	}
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("RCODE = %d, want NOERROR", resp.Header.Flags.RCODE)
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answers))
	}
	a, ok := resp.Answers[0].Data.(*protocol.RDataA)
	if !ok {
		t.Fatalf("expected RDataA, got %T", resp.Answers[0].Data)
	}
	if a.Address != [4]byte{10, 20, 30, 40} {
		t.Errorf("A record = %v, want 10.20.30.40", a.Address)
	}
}

// TestDoQMultipleStreams verifies that multiple DNS queries can be carried on
// separate streams of a single QUIC connection (RFC 9250 §4.2: one query per
// stream) and each receives its own response.
func TestDoQMultipleStreams(t *testing.T) {
	handler := server.HandlerFunc(func(w server.ResponseWriter, req *protocol.Message) {
		resp := &protocol.Message{
			Header:    protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Questions: req.Questions,
		}
		if len(req.Questions) > 0 {
			// Echo the first label length into the last address octet so each
			// query gets a distinguishable answer.
			name := req.Questions[0].Name.String()
			resp.AddAnswer(&protocol.ResourceRecord{
				Name:  req.Questions[0].Name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   60,
				Data:  &protocol.RDataA{Address: [4]byte{127, 0, 0, byte(len(name))}},
			})
		}
		w.Write(resp)
	})

	addr := startDoQTestServer(t, handler)
	conn := dialDoQ(t, addr)

	domains := []string{"a.example.com.", "bb.example.com.", "ccc.example.com."}
	for _, domain := range domains {
		query, err := protocol.NewQuery(0, domain, protocol.TypeA)
		if err != nil {
			t.Fatalf("NewQuery(%q): %v", domain, err)
		}
		resp := doqRoundTrip(t, conn, query)

		if len(resp.Answers) != 1 {
			t.Fatalf("%s: expected 1 answer, got %d", domain, len(resp.Answers))
		}
		a, ok := resp.Answers[0].Data.(*protocol.RDataA)
		if !ok {
			t.Fatalf("%s: expected RDataA, got %T", domain, resp.Answers[0].Data)
		}
		if want := byte(len(domain)); a.Address[3] != want {
			t.Errorf("%s: answer octet = %d, want %d", domain, a.Address[3], want)
		}
		if len(resp.Questions) != 1 || resp.Questions[0].Name.String() != domain {
			t.Errorf("%s: question section not echoed correctly: %+v", domain, resp.Questions)
		}
	}
}
