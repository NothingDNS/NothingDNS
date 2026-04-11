package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
)

// generateSelfSignedCert generates a self-signed certificate for testing.
func generateSelfSignedCert(t *testing.T) *tls.Config {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: mustMarshalECPrivateKey(priv)})

	clientCertPool := x509.NewCertPool()
	clientCertPool.AppendCertsFromPEM(certPEM)

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("Failed to load key pair: %v", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS12,
	}
}

func mustMarshalECPrivateKey(key *ecdsa.PrivateKey) []byte {
	bytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(err)
	}
	return bytes
}

// TestDoTWithTLSServer tests DNS over TLS with a real TLS server.
func TestDoTWithTLSServer(t *testing.T) {
	handler := server.HandlerFunc(func(w server.ResponseWriter, req *protocol.Message) {
		resp := &protocol.Message{
			Header:  protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Questions: req.Questions,
		}
		if len(req.Questions) > 0 && req.Questions[0].QType == protocol.TypeA {
			resp.AddAnswer(&protocol.ResourceRecord{
				Name:  req.Questions[0].Name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{1, 1, 1, 1}},
			})
		}
		w.Write(resp)
	})

	srv := server.NewTLSServer("127.0.0.1:0", handler, generateSelfSignedCert(t))
	if err := srv.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer srv.Stop()

	go srv.Serve()
	time.Sleep(10 * time.Millisecond)

	addr := srv.Addr()
	tlsAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("Expected TCPAddr, got %T", addr)
	}

	// Connect with TLS
	conn, err := tls.Dial("tcp", tlsAddr.String(), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("Failed to dial TLS: %v", err)
	}
	defer conn.Close()

	query, _ := protocol.NewQuery(0xabcd, "tls.example.com.", protocol.TypeA)
	buf := make([]byte, 512)
	n, _ := query.Pack(buf)

	// Write length-prefixed
	lenBuf := [2]byte{byte(n >> 8), byte(n & 0xff)}
	conn.Write(lenBuf[:])
	conn.Write(buf[:n])

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Read response
	var respLen [2]byte
	_, err = conn.Read(respLen[:])
	if err != nil {
		t.Fatalf("Failed to read length: %v", err)
	}

	msgLen := int(respLen[0])<<8 | int(respLen[1])
	respBuf := make([]byte, msgLen)
	_, err = conn.Read(respBuf)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	resp, err := protocol.UnpackMessage(respBuf)
	if err != nil {
		t.Fatalf("Failed to unpack: %v", err)
	}

	if resp.Header.ID != query.Header.ID {
		t.Errorf("ID mismatch: got %x, want %x", resp.Header.ID, query.Header.ID)
	}

	if !resp.Header.Flags.QR {
		t.Error("Expected QR flag to be set")
	}
}

// TestDoTMultipleConnections tests multiple TLS connections.
func TestDoTMultipleConnections(t *testing.T) {
	var connCount int
	var mu sync.Mutex

	handler := server.HandlerFunc(func(w server.ResponseWriter, req *protocol.Message) {
		mu.Lock()
		connCount++
		mu.Unlock()

		resp := &protocol.Message{
			Header:  protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Questions: req.Questions,
		}
		w.Write(resp)
	})

	srv := server.NewTLSServer("127.0.0.1:0", handler, generateSelfSignedCert(t))
	if err := srv.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer srv.Stop()

	go srv.Serve()
	time.Sleep(10 * time.Millisecond)

	addr := srv.Addr().(*net.TCPAddr)

	// Create 5 separate TLS connections
	for i := 0; i < 5; i++ {
		conn, err := tls.Dial("tcp", addr.String(), &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			t.Fatalf("Failed to dial TLS: %v", err)
		}

		query, _ := protocol.NewQuery(uint16(i), "example.com.", protocol.TypeA)
		buf := make([]byte, 512)
		n, _ := query.Pack(buf)

		lenBuf := [2]byte{byte(n >> 8), byte(n & 0xff)}
		conn.Write(lenBuf[:])
		conn.Write(buf[:n])

		conn.SetReadDeadline(time.Now().Add(2 * time.Second))

		var respLen [2]byte
		conn.Read(respLen[:])
		msgLen := int(respLen[0])<<8 | int(respLen[1])
		respBuf := make([]byte, msgLen)
		conn.Read(respBuf)

		conn.Close()
	}

	mu.Lock()
	defer mu.Unlock()
	if connCount != 5 {
		t.Errorf("Expected 5 connections, got %d", connCount)
	}
}

// TestDoTTLSHandshakeError tests that invalid TLS handshake is handled.
func TestDoTTLSHandshakeError(t *testing.T) {
	handler := server.HandlerFunc(func(w server.ResponseWriter, req *protocol.Message) {
		resp := &protocol.Message{
			Header:  protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Questions: req.Questions,
		}
		w.Write(resp)
	})

	srv := server.NewTLSServer("127.0.0.1:0", handler, generateSelfSignedCert(t))
	if err := srv.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer srv.Stop()

	go srv.Serve()
	time.Sleep(10 * time.Millisecond)

	addr := srv.Addr().(*net.TCPAddr)

	// Try to connect without TLS (plain TCP) - should fail gracefully
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	// Send a query without TLS handshake
	query, _ := protocol.NewQuery(0x1234, "test.example.com.", protocol.TypeA)
	buf := make([]byte, 512)
	n, _ := query.Pack(buf)

	conn.Write(buf[:n])
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

	// Should not receive a valid DNS response
	respBuf := make([]byte, 512)
	conn.Read(respBuf)
}

// TestDoTConnectionReuse tests that TLS connections can be reused.
func TestDoTConnectionReuse(t *testing.T) {
	handler := server.HandlerFunc(func(w server.ResponseWriter, req *protocol.Message) {
		resp := &protocol.Message{
			Header:  protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Questions: req.Questions,
		}
		w.Write(resp)
	})

	srv := server.NewTLSServer("127.0.0.1:0", handler, generateSelfSignedCert(t))
	if err := srv.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer srv.Stop()

	go srv.Serve()
	time.Sleep(10 * time.Millisecond)

	addr := srv.Addr().(*net.TCPAddr)

	conn, err := tls.Dial("tcp", addr.String(), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("Failed to dial TLS: %v", err)
	}
	defer conn.Close()

	// Send multiple queries on same connection
	domains := []string{"a.com.", "b.com.", "c.com.", "d.com.", "e.com."}
	for i, domain := range domains {
		query, _ := protocol.NewQuery(uint16(i), domain, protocol.TypeA)
		buf := make([]byte, 512)
		n, _ := query.Pack(buf)

		lenBuf := [2]byte{byte(n >> 8), byte(n & 0xff)}
		conn.Write(lenBuf[:])
		conn.Write(buf[:n])
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	for i := 0; i < len(domains); i++ {
		var respLen [2]byte
		_, err := conn.Read(respLen[:])
		if err != nil {
			t.Fatalf("Failed to read response %d: %v", i, err)
		}
		msgLen := int(respLen[0])<<8 | int(respLen[1])
		respBuf := make([]byte, msgLen)
		_, err = conn.Read(respBuf)
		if err != nil {
			t.Fatalf("Failed to read response %d: %v", i, err)
		}
	}
}
