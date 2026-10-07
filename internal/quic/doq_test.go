package quic

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// generateTestTLS creates a self-signed TLS cert for testing.
func generateTestTLS(t *testing.T) *tls.Config {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}))
	if err != nil {
		t.Fatalf("tls.X509KeyPair: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"doq"},
	}
}

// =================== Constructor Tests ===================

func TestNewDoQServer(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, &tls.Config{NextProtos: []string{"doq"}})

	if srv == nil {
		t.Fatal("NewDoQServer returned nil")
	}
	if srv.addr != "127.0.0.1:0" {
		t.Errorf("addr = %q, want %q", srv.addr, "127.0.0.1:0")
	}
	if srv.handler == nil {
		t.Error("handler should not be nil")
	}
	if srv.tlsConfig == nil {
		t.Error("tlsConfig should not be nil")
	}
	if srv.config == nil {
		t.Error("config should not be nil (default should be applied)")
	}
	if srv.ctx == nil {
		t.Error("ctx should not be nil")
	}
	if srv.cancel == nil {
		t.Error("cancel should not be nil")
	}
}

func TestNewDoQServerWithConfig(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	cfg := &quic.Config{
		MaxIncomingStreams: 50,
	}

	srv := NewDoQServerWithConfig("127.0.0.1:8853", handler, &tls.Config{NextProtos: []string{"doq"}}, cfg)

	if srv == nil {
		t.Fatal("NewDoQServerWithConfig returned nil")
	}
	if srv.config != cfg {
		t.Error("custom config was not applied")
	}
	if srv.config.MaxIncomingStreams != 50 {
		t.Errorf("MaxIncomingStreams = %d, want 50", srv.config.MaxIncomingStreams)
	}
}

func TestNewDoQServerWithNilConfig(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServerWithConfig("127.0.0.1:0", handler, &tls.Config{NextProtos: []string{"doq"}}, nil)

	if srv == nil {
		t.Fatal("NewDoQServerWithConfig returned nil with nil config")
	}
	if srv.config == nil {
		t.Fatal("nil config should be replaced with defaults")
	}
	if srv.config.MaxIncomingStreams != DoQMaxStreamsPerConnection {
		t.Errorf("MaxIncomingStreams = %d, want %d (default)", srv.config.MaxIncomingStreams, DoQMaxStreamsPerConnection)
	}
}

// =================== Listen / Stop Tests ===================

func TestDoQServerListenAndStop(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, generateTestTLS(t))

	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	addr := srv.Addr()
	if addr == nil {
		t.Fatal("Addr() returned nil after Listen")
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("Addr() is %T, want *net.UDPAddr", addr)
	}
	if udpAddr.Port == 0 {
		t.Error("expected a non-zero port after binding to :0")
	}

	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestDoQServerListenWithConn(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, generateTestTLS(t))

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	srv.ListenWithConn(conn)

	addr := srv.Addr()
	if addr == nil {
		t.Fatal("Addr() returned nil after ListenWithConn")
	}
}

func TestDoQServerStopIdempotent(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, generateTestTLS(t))

	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	// First stop should succeed.
	if err := srv.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}

	// Second stop should not panic.
	srv.Stop()
}

func TestDoQServerStopWithoutListen(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, generateTestTLS(t))

	// Stop without Listen — conn is nil, should return nil.
	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop without Listen: %v", err)
	}
}

func TestDoQServerListenInvalidAddr(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("not-valid-address-!!!", handler, &tls.Config{NextProtos: []string{"doq"}})

	if err := srv.Listen(); err == nil {
		t.Error("expected error for invalid address")
		srv.Stop()
	}
}

func TestDoQServerAddrBeforeListen(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, &tls.Config{NextProtos: []string{"doq"}})

	if addr := srv.Addr(); addr != nil {
		t.Errorf("Addr() before Listen should be nil, got %v", addr)
	}
}

// =================== Metrics / Stats Tests ===================

func TestDoQServerStatsInitial(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, &tls.Config{NextProtos: []string{"doq"}})

	stats := srv.Stats()

	if stats.ConnectionsAccepted != 0 {
		t.Errorf("ConnectionsAccepted = %d, want 0", stats.ConnectionsAccepted)
	}
	if stats.ConnectionsClosed != 0 {
		t.Errorf("ConnectionsClosed = %d, want 0", stats.ConnectionsClosed)
	}
	if stats.QueriesReceived != 0 {
		t.Errorf("QueriesReceived = %d, want 0", stats.QueriesReceived)
	}
	if stats.QueriesResponded != 0 {
		t.Errorf("QueriesResponded = %d, want 0", stats.QueriesResponded)
	}
	if stats.Errors != 0 {
		t.Errorf("Errors = %d, want 0", stats.Errors)
	}
	if stats.ActiveConnections != 0 {
		t.Errorf("ActiveConnections = %d, want 0", stats.ActiveConnections)
	}
}

func TestDoQServerStatsZeroValue(t *testing.T) {
	var stats DoQServerStats

	if stats.ConnectionsAccepted != 0 ||
		stats.ConnectionsClosed != 0 ||
		stats.QueriesReceived != 0 ||
		stats.QueriesResponded != 0 ||
		stats.Errors != 0 ||
		stats.ActiveConnections != 0 {
		t.Error("zero-value DoQServerStats should have all zeros")
	}
}

// =================== Serve Without Listen Tests ===================

func TestDoQServerServeWithoutListen(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, &tls.Config{NextProtos: []string{"doq"}})

	// Serve without a prior Listen should return an error immediately.
	err := srv.Serve()
	if err == nil {
		t.Error("expected error from Serve() without Listen()")
	}
}

// =================== Serve Lifecycle Tests ===================

func TestDoQServerServeAndStop(t *testing.T) {
	handler := DoQHandlerFunc(func(s *Stream, q []byte) {})
	srv := NewDoQServer("127.0.0.1:0", handler, generateTestTLS(t))

	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- srv.Serve()
	}()

	// Give the goroutines a moment to start.
	time.Sleep(50 * time.Millisecond)

	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Stop")
	}
}

// =================== DoQ Constants Tests ===================

func TestDoQConstants(t *testing.T) {
	if DefaultDoQPort != 853 {
		t.Errorf("DefaultDoQPort = %d, want 853", DefaultDoQPort)
	}
	if DoQMaxMessageSize != 65535 {
		t.Errorf("DoQMaxMessageSize = %d, want 65535", DoQMaxMessageSize)
	}
	if DoQStreamIdleTimeout != 30*time.Second {
		t.Errorf("DoQStreamIdleTimeout = %v, want 30s", DoQStreamIdleTimeout)
	}
	if DoQConnectionIdleTimeout != 60*time.Second {
		t.Errorf("DoQConnectionIdleTimeout = %v, want 60s", DoQConnectionIdleTimeout)
	}
	if DoQMaxConnections != 500 {
		t.Errorf("DoQMaxConnections = %d, want 500", DoQMaxConnections)
	}
	if DoQMaxStreamsPerConnection != 100 {
		t.Errorf("DoQMaxStreamsPerConnection = %d, want 100", DoQMaxStreamsPerConnection)
	}
}

type stringAddr string

func (a stringAddr) Network() string { return "test" }
func (a stringAddr) String() string  { return string(a) }

func TestDoQRemoteIP(t *testing.T) {
	tests := []struct {
		name string
		addr net.Addr
		want string
	}{
		{name: "nil", addr: nil, want: "unknown"},
		{name: "udp", addr: &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 853}, want: "192.0.2.10"},
		{name: "tcp hostport", addr: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 853}, want: "2001:db8::1"},
		{name: "custom hostport", addr: stringAddr("198.51.100.20:853"), want: "198.51.100.20"},
		{name: "custom opaque", addr: stringAddr("opaque-peer"), want: "opaque-peer"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := doqRemoteIP(tt.addr); got != tt.want {
				t.Fatalf("doqRemoteIP(%v) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

// =================== Handler Adapter Tests ===================

func TestDoQHandlerFunc(t *testing.T) {
	var called bool
	var receivedQuery []byte
	var receivedStream *Stream

	fn := DoQHandlerFunc(func(s *Stream, q []byte) {
		called = true
		receivedStream = s
		receivedQuery = q
	})

	stream := &Stream{}
	query := []byte{0x01, 0x02, 0x03}
	fn.ServeDoQ(stream, query)

	if !called {
		t.Error("handler function was not called")
	}
	if receivedStream != stream {
		t.Error("handler received wrong stream")
	}
	if len(receivedQuery) != 3 || receivedQuery[0] != 0x01 {
		t.Errorf("handler received wrong query: %v", receivedQuery)
	}
}

// =================== End-to-End Integration Test ===================

func TestDoQServerEndToEnd(t *testing.T) {
	var receivedQuery []byte
	var queryCh = make(chan []byte, 1)

	handler := DoQHandlerFunc(func(s *Stream, q []byte) {
		receivedQuery = make([]byte, len(q))
		copy(receivedQuery, q)
		queryCh <- q

		// Exercise uncovered Stream wrapper methods
		_ = s.RemoteAddr()
		_ = s.StreamID()
		_ = s.SetReadDeadline(time.Time{})
		_ = s.SetWriteDeadline(time.Time{})
		_ = s.SetDeadline(time.Time{})
		_ = s.Context()
		s.CancelRead(0)
		s.CancelWrite(0)

		// Read the wrapper — post-echo the stream is half-closed
		// (client closed its write side), so Read returns io.EOF
		// without blocking. s.Read goes through the wrapper, not
		// the raw quic-go stream.
		buf := make([]byte, 1)
		_, _ = s.Read(buf)

		// Echo back the query as response
		_, _ = s.Write(q)
		_ = s.Close()
	})

	tlsConfig := generateTestTLS(t)
	srv := NewDoQServer("127.0.0.1:0", handler, tlsConfig)

	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	go func() {
		_ = srv.Serve()
	}()
	defer srv.Stop()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Connect as a QUIC client
	udpAddr, err := net.ResolveUDPAddr("udp", srv.Addr().String())
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}

	conn, err := quic.Dial(
		context.Background(),
		&net.UDPConn{},
		udpAddr,
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"doq"}},
		&quic.Config{MaxIncomingStreams: 10},
	)
	if err != nil {
		// Try with a real UDP conn
		localConn, dialErr := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if dialErr != nil {
			t.Fatalf("quic.Dial failed and fallback ListenUDP failed: %v / %v", err, dialErr)
		}
		defer localConn.Close()

		conn, err = quic.Dial(
			context.Background(),
			localConn,
			udpAddr,
			&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"doq"}},
			&quic.Config{MaxIncomingStreams: 10},
		)
		if err != nil {
			t.Fatalf("quic.Dial: %v", err)
		}
	}
	defer conn.CloseWithError(0, "")

	// Open a stream and send a DNS query
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("OpenStreamSync: %v", err)
	}
	defer stream.Close()

	// RFC 9250 §4.2: each DNS message is prefixed by a 2-octet length field.
	dnsQuery := []byte{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
		0x00, 0x01, 0x00, 0x01}
	framed := make([]byte, 2+len(dnsQuery))
	framed[0] = byte(len(dnsQuery) >> 8)
	framed[1] = byte(len(dnsQuery))
	copy(framed[2:], dnsQuery)

	_, err = stream.Write(framed)
	if err != nil {
		t.Fatalf("stream.Write: %v", err)
	}
	stream.Close()

	// Wait for server to receive the query
	select {
	case q := <-queryCh:
		if string(q) != string(dnsQuery) {
			t.Errorf("received query mismatch: got %v, want %v", q, dnsQuery)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not receive query within timeout")
	}

	// Verify stats
	stats := srv.Stats()
	if stats.QueriesReceived != 1 {
		t.Errorf("QueriesReceived = %d, want 1", stats.QueriesReceived)
	}
}

// =================== Shutdown / Error-Code Regression Tests ===================

func dialDoQTest(t *testing.T, addr string) *quic.Conn {
	t.Helper()
	c, err := quic.DialAddr(context.Background(), addr,
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"doq"}},
		&quic.Config{MaxIdleTimeout: 20 * time.Second})
	if err != nil {
		t.Fatalf("DialAddr: %v", err)
	}
	t.Cleanup(func() { _ = c.CloseWithError(0, "") })
	return c
}

// waitAppClose waits (bounded) for the client connection to be closed by the
// peer and returns the DoQ application error code it carried.
func waitAppClose(t *testing.T, c *quic.Conn) quic.ApplicationErrorCode {
	t.Helper()
	select {
	case <-c.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("client connection was not closed by the server")
	}
	var ae *quic.ApplicationError
	if !errors.As(context.Cause(c.Context()), &ae) {
		t.Fatalf("close cause = %v, want *quic.ApplicationError", context.Cause(c.Context()))
	}
	return ae.ErrorCode
}

// F52: Stop must send CONNECTION_CLOSE (DOQ_NO_ERROR) on established
// connections before closing the UDP socket; otherwise clients hang until
// their idle timeout.
func TestDoQServerStopClosesClientConnections(t *testing.T) {
	handled := make(chan struct{}, 1)
	srv := NewDoQServer("127.0.0.1:0", DoQHandlerFunc(func(s *Stream, q []byte) {
		handled <- struct{}{}
	}), generateTestTLS(t))
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve() }()

	c := dialDoQTest(t, srv.Addr().String())
	st, err := c.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("OpenStreamSync: %v", err)
	}
	if _, err := st.Write([]byte{0, 1, 0}); err != nil {
		t.Fatalf("stream write: %v", err)
	}
	_ = st.Close()
	<-handled // gate: the connection is registered server-side

	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if code := waitAppClose(t, c); code != 0 {
		t.Fatalf("close code = %#x, want DOQ_NO_ERROR", code)
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if got := srv.Stats().ActiveConnections; got != 0 {
		t.Fatalf("ActiveConnections after Stop = %d, want 0", got)
	}
}

// F53: Serve after Stop is a clean shutdown, not "server not listening".
func TestDoQServerServeAfterStopReturnsNil(t *testing.T) {
	srv := NewDoQServer("127.0.0.1:0", DoQHandlerFunc(func(s *Stream, q []byte) {}),
		&tls.Config{NextProtos: []string{"doq"}})
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := srv.Serve(); err != nil {
		t.Fatalf("Serve after Stop = %v, want nil", err)
	}
}

// F54: connections refused by the connection limits carry
// DOQ_EXCESSIVE_LOAD (0x4), not DOQ_UNSPECIFIED_ERROR (0x5).
func TestDoQServerConnLimitUsesExcessiveLoad(t *testing.T) {
	srv := NewDoQServer("127.0.0.1:0", DoQHandlerFunc(func(s *Stream, q []byte) {}), generateTestTLS(t))
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go func() { _ = srv.Serve() }()
	defer srv.Stop()

	addr := srv.Addr().String()
	for i := 0; i < DoQMaxConnectionsPerIP; i++ {
		dialDoQTest(t, addr)
	}
	if code := waitAppClose(t, dialDoQTest(t, addr)); code != 0x4 {
		t.Fatalf("over-limit close code = %#x, want 0x4 (DOQ_EXCESSIVE_LOAD)", code)
	}
}
