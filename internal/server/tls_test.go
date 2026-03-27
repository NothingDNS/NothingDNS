package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func generateTestTLSCert(t *testing.T) tls.Certificate {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("Failed to load certificate: %v", err)
	}

	return cert
}

func TestNewTLSServer(t *testing.T) {
	cert := generateTestTLSCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	server := NewTLSServer("127.0.0.1:0", nil, tlsConfig)
	if server == nil {
		t.Fatal("NewTLSServer returned nil")
	}
	if server.workers == 0 {
		t.Error("Workers should be > 0")
	}
}

func TestNewTLSServerWithWorkers(t *testing.T) {
	cert := generateTestTLSCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	tests := []struct {
		name    string
		workers int
		wantMin int
	}{
		{"default workers", 0, 1},
		{"negative workers", -5, 1},
		{"single worker", 1, 1},
		{"multiple workers", 4, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewTLSServerWithWorkers("127.0.0.1:0", nil, tlsConfig, tt.workers)
			if server == nil {
				t.Fatal("Server should not be nil")
			}
			if server.workers < tt.wantMin {
				t.Errorf("Workers = %d, want >= %d", server.workers, tt.wantMin)
			}
		})
	}
}

func TestTLSServerServeWithoutListen(t *testing.T) {
	cert := generateTestTLSCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	server := NewTLSServer("127.0.0.1:0", nil, tlsConfig)
	err := server.Serve()
	if err == nil {
		t.Error("Serve should return error when not listening")
	}
}

func TestTLSServerAddrNil(t *testing.T) {
	cert := generateTestTLSCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	server := NewTLSServer("127.0.0.1:0", nil, tlsConfig)
	if server.Addr() != nil {
		t.Error("Addr should return nil when listener is nil")
	}
}

func TestTLSServerStopNilListener(t *testing.T) {
	cert := generateTestTLSCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	server := NewTLSServer("127.0.0.1:0", nil, tlsConfig)
	err := server.Stop()
	if err != nil {
		t.Errorf("Stop should not return error: %v", err)
	}
}

func TestTLSServerStats(t *testing.T) {
	cert := generateTestTLSCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	server := NewTLSServer("127.0.0.1:0", nil, tlsConfig)
	stats := server.Stats()

	if stats.Workers == 0 {
		t.Error("Workers should be > 0")
	}
}

func TestTLSServerListenAndAddr(t *testing.T) {
	cert := generateTestTLSCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		w.Write(&protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
		})
	})

	server := NewTLSServer("127.0.0.1:0", handler, tlsConfig)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	if server.Addr() == nil {
		t.Error("Addr should not be nil after Listen")
	}
}

func TestTLSResponseWriterDoubleWrite(t *testing.T) {
	// Test double write error
	w := &tlsResponseWriter{
		written: true,
	}

	_, err := w.Write(&protocol.Message{})
	if err == nil {
		t.Error("Write should fail when already written")
	}
}

func TestTLSServerListenWithListener(t *testing.T) {
	cert := generateTestTLSCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	server := NewTLSServer("127.0.0.1:0", nil, tlsConfig)

	// Create a mock listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer ln.Close()

	server.ListenWithListener(ln)

	if server.listener == nil {
		t.Error("Listener should be set")
	}
}

func TestTLSServerServeAndQuery(t *testing.T) {
	cert := generateTestTLSCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		w.Write(&protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
		})
	})

	server := NewTLSServer("127.0.0.1:0", handler, tlsConfig)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(50 * time.Millisecond)

	// Connect with TLS client
	tlsClientConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", server.Addr().String(), tlsClientConfig)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Create a query
	query, _ := protocol.NewQuery(0x1234, "test.com.", protocol.TypeA)
	buf := make([]byte, 512)
	n, _ := query.Pack(buf[2:])
	binary.BigEndian.PutUint16(buf[0:], uint16(n))
	conn.Write(buf[:n+2])

	// Read response
	var lengthBuf [2]byte
	io.ReadFull(conn, lengthBuf[:])
	respLen := binary.BigEndian.Uint16(lengthBuf[:])
	respBuf := make([]byte, respLen)
	io.ReadFull(conn, respBuf)

	if respLen == 0 {
		t.Error("Expected non-empty response")
	}
}

func TestTLSResponseWriterMaxSize(t *testing.T) {
	w := &tlsResponseWriter{
		maxSize: 512,
	}

	if w.MaxSize() != 512 {
		t.Errorf("MaxSize() = %d, want 512", w.MaxSize())
	}
}

func TestTLSResponseWriterClientInfo(t *testing.T) {
	client := &ClientInfo{
		Protocol: "dot",
	}
	w := &tlsResponseWriter{
		client: client,
	}

	if w.ClientInfo() != client {
		t.Error("ClientInfo should return the client info")
	}
}

func TestTLSServerConstants(t *testing.T) {
	if TLSMaxMessageSize != 65535 {
		t.Errorf("TLSMaxMessageSize = %d, want 65535", TLSMaxMessageSize)
	}
	if DefaultTLSPort != 853 {
		t.Errorf("DefaultTLSPort = %d, want 853", DefaultTLSPort)
	}
}

func TestTLSServerServe_Stop(t *testing.T) {
	cert := generateTestTLSCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		w.Write(&protocol.Message{})
	})

	server := NewTLSServer("127.0.0.1:0", handler, tlsConfig)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	// Start server in goroutine
	go server.Serve()
	time.Sleep(50 * time.Millisecond)

	// Stop the server
	err := server.Stop()
	if err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestTLSServerServe_AcceptError(t *testing.T) {
	cert := generateTestTLSCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		w.Write(&protocol.Message{})
	})

	server := NewTLSServer("127.0.0.1:0", handler, tlsConfig)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	// Start server
	go server.Serve()
	time.Sleep(20 * time.Millisecond)

	// Close listener to cause Accept error
	server.listener.Close()

	// Cancel context to stop the server properly
	server.cancel()
	time.Sleep(50 * time.Millisecond)
}

func TestTLSServerStats_Initial(t *testing.T) {
	cert := generateTestTLSCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	server := NewTLSServer("127.0.0.1:0", nil, tlsConfig)

	stats := server.Stats()
	if stats.ConnectionsAccepted != 0 {
		t.Errorf("ConnectionsAccepted = %d, want 0", stats.ConnectionsAccepted)
	}
	if stats.ConnectionsClosed != 0 {
		t.Errorf("ConnectionsClosed = %d, want 0", stats.ConnectionsClosed)
	}
	if stats.MessagesReceived != 0 {
		t.Errorf("MessagesReceived = %d, want 0", stats.MessagesReceived)
	}
	if stats.Errors != 0 {
		t.Errorf("Errors = %d, want 0", stats.Errors)
	}
}
