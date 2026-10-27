package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// A padded query gets a padded answer over DoT and DoQ too (RFC 7830 §4,
// RFC 9250 §5.4), not only over DoH; an unpadded one does not (F735).

func paddingTestQuery(t *testing.T, pad bool) []byte {
	t.Helper()
	q, err := protocol.NewQuery(0, "www.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	q.SetEDNS0(1232, false)
	if pad {
		q.GetOPT().Data.(*protocol.RDataOPT).AddOption(protocol.OptionCodePadding, make([]byte, 100))
	}
	buf := make([]byte, 512)
	n, err := q.Pack(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

// paddingOptions returns how many Padding options the answer carries.
func paddingOptions(t *testing.T, wire []byte) int {
	t.Helper()
	m, err := protocol.UnpackMessage(wire)
	if err != nil {
		t.Fatalf("unpack answer: %v", err)
	}
	if len(m.Answers) != 1 {
		t.Fatalf("answer has %d records, want 1 (rcode %d)", len(m.Answers), m.Header.Flags.RCODE)
	}
	count := 0
	if opt := m.GetOPT(); opt != nil {
		for _, o := range opt.Data.(*protocol.RDataOPT).Options {
			if o.Code == protocol.OptionCodePadding {
				count++
			}
		}
	}
	return count
}

func TestEncryptedTransportsPadAnswers(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "example.com.", Type: "SOA", TTL: 300, RData: "ns1.example.com. admin.example.com. 1 3600 600 604800 300"},
		{Name: "www.example.com.", Type: "A", TTL: 300, RData: "192.0.2.1"},
	})
	padded, plain := paddingTestQuery(t, true), paddingTestQuery(t, false)

	t.Run("DoQ", func(t *testing.T) {
		ask := func(query []byte) []byte {
			msg, err := protocol.UnpackMessage(query)
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			rw := &doqResponseWriter{stream: &out, remoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, query: msg}
			h.ServeDNS(rw, msg)
			return out.Bytes()[2:]
		}
		// Asked twice: the cached answer must not collect a second option.
		for i := 0; i < 2; i++ {
			if got := paddingOptions(t, ask(padded)); got != 1 {
				t.Fatalf("padded query, answer %d: %d padding options, want 1", i, got)
			}
		}
		if got := paddingOptions(t, ask(plain)); got != 0 {
			t.Fatalf("unpadded query: %d padding options, want 0", got)
		}
	})

	t.Run("DoT", func(t *testing.T) {
		certPEM, keyPEM := tlsReloadGenCert(t, "127.0.0.1")
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		srv := server.NewTLSServer("127.0.0.1:0", h, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := srv.Listen(); err != nil {
			t.Fatal(err)
		}
		defer srv.Stop()
		go srv.Serve()
		conn, err := tls.Dial("tcp", srv.Addr().String(), &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		ask := func(query []byte) []byte {
			frame := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
			if _, err := conn.Write(append(frame, query...)); err != nil {
				t.Fatal(err)
			}
			var lb [2]byte
			if _, err := io.ReadFull(conn, lb[:]); err != nil {
				t.Fatal(err)
			}
			answer := make([]byte, binary.BigEndian.Uint16(lb[:]))
			if _, err := io.ReadFull(conn, answer); err != nil {
				t.Fatal(err)
			}
			return answer
		}
		for i := 0; i < 2; i++ {
			if got := paddingOptions(t, ask(padded)); got != 1 {
				t.Fatalf("padded query, answer %d: %d padding options, want 1", i, got)
			}
		}
		if got := paddingOptions(t, ask(plain)); got != 0 {
			t.Fatalf("unpadded query: %d padding options, want 0", got)
		}
	})
}
