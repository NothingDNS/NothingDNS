package quic

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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

	// RFC 9250: DNS messages over QUIC are NOT length-prefixed
	dnsQuery := []byte{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
		0x00, 0x01, 0x00, 0x01}

	_, err = stream.Write(dnsQuery)
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
