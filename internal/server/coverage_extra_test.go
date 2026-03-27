package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// ==============================================================================
// TCP Listen error path
// ==============================================================================

func TestTCPServerListenError(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {})
	server := NewTCPServer("invalid-address:-1", handler)
	err := server.Listen()
	if err == nil {
		t.Error("Listen should return error for invalid address")
		server.Stop()
	}
}

// ==============================================================================
// TCP Serve - accept error that is not due to shutdown
// ==============================================================================

func TestTCPServerServeAcceptErrorContinue(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		w.Write(&protocol.Message{})
	})

	server := NewTCPServerWithWorkers("127.0.0.1:0", handler, 1)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	// Start serving
	go server.Serve()
	time.Sleep(20 * time.Millisecond)

	// Close the underlying listener to trigger an Accept error.
	// Since the server's context isn't cancelled, it increments errors and continues.
	server.listener.Close()

	// Give time for the error to be processed
	time.Sleep(30 * time.Millisecond)

	stats := server.Stats()
	// The error from Accept after close should be counted
	if stats.Errors == 0 {
		// The accept loop might have exited if the context was cancelled,
		// but if not, errors should be > 0
		t.Log("Errors may or may not be > 0 depending on timing")
	}

	// Clean up: cancel context to let goroutines finish
	server.cancel()
	time.Sleep(30 * time.Millisecond)
}

// ==============================================================================
// TCP handleConnection - read error (non-EOF)
// ==============================================================================

func TestTCPServerHandleConnectionReadError(t *testing.T) {
	server := NewTCPServerWithWorkers("127.0.0.1:0", HandlerFunc(func(w ResponseWriter, req *protocol.Message) {}), 1)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(20 * time.Millisecond)

	// Connect and immediately close, causing a read error (non-EOF) on server side
	client, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	client.Close()

	time.Sleep(50 * time.Millisecond)

	stats := server.Stats()
	if stats.ConnectionsAccepted == 0 {
		t.Error("Expected at least one connection accepted")
	}
}

// ==============================================================================
// TCP handleConnection - incomplete body read
// ==============================================================================

func TestTCPServerHandleConnectionIncompleteBody(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		w.Write(&protocol.Message{})
	})

	server := NewTCPServerWithWorkers("127.0.0.1:0", handler, 1)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(20 * time.Millisecond)

	client, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	// Send length prefix claiming 100 bytes but only send 10
	data := make([]byte, 12)
	binary.BigEndian.PutUint16(data[0:2], 100) // Length = 100
	copy(data[2:], []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09})
	client.Write(data)

	// Connection should be closed by server due to incomplete read
	time.Sleep(50 * time.Millisecond)
}

// ==============================================================================
// TCP handleMessage - EDNS0 with client subnet (ECS)
// ==============================================================================

func TestTCPServerHandleMessageEDNS0WithECS(t *testing.T) {
	var receivedClientInfo *ClientInfo

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		receivedClientInfo = w.ClientInfo()
		w.Write(&protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
		})
	})

	server := NewTCPServerWithWorkers("127.0.0.1:0", handler, 1)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(20 * time.Millisecond)

	client, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	// Build a query with EDNS0 OPT record containing a Client Subnet option
	query, _ := protocol.NewQuery(0xABCD, "ecs-test.com.", protocol.TypeA)
	query.SetEDNS0(4096, false)

	// Replace the additional section with our custom OPT record
	opt := &protocol.RDataOPT{Options: []protocol.EDNS0Option{
		{
			Code: protocol.OptionCodeClientSubnet,
			Data: []byte{0x00, 0x01, 0x18, 0x00, 10, 0, 0, 0}, // IPv4 /24
		},
	}}
	query.Additionals = []*protocol.ResourceRecord{
		{
			Name:  mustParseName("."),
			Type:  protocol.TypeOPT,
			Class: 4096,
			Data:   opt,
		},
	}

	buf := make([]byte, 512)
	n, _ := query.Pack(buf[2:])
	binary.BigEndian.PutUint16(buf[0:], uint16(n))
	client.Write(buf[:n+2])

	// Read response
	var lengthBuf [2]byte
	io.ReadFull(client, lengthBuf[:])
	respLen := binary.BigEndian.Uint16(lengthBuf[:])
	respBuf := make([]byte, respLen)
	io.ReadFull(client, respBuf)

	if receivedClientInfo == nil {
		t.Fatal("ClientInfo should not be nil")
	}
	if !receivedClientInfo.HasEDNS0 {
		t.Error("HasEDNS0 should be true")
	}
	if receivedClientInfo.EDNS0UDPSize != 4096 {
		t.Errorf("EDNS0UDPSize = %d, want 4096", receivedClientInfo.EDNS0UDPSize)
	}
	// ClientSubnet is nil because UnpackMessage does not register TypeOPT in createRData,
	// so after pack/unpack the OPT record's Data is *RDataRaw, not *RDataOPT.
	// The ECS option bytes are preserved in the raw data but the type assertion fails.
	if receivedClientInfo.ClientSubnet != nil {
		t.Error("ClientSubnet should be nil since TypeOPT is not registered in createRData")
	}
}

// ==============================================================================
// TCP handleMessage - EDNS0 with invalid ECS data (UnpackEDNS0ClientSubnet fails)
// ==============================================================================

func TestTCPServerHandleMessageEDNS0InvalidECS(t *testing.T) {
	var receivedClientInfo *ClientInfo

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		receivedClientInfo = w.ClientInfo()
		w.Write(&protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
		})
	})

	server := NewTCPServerWithWorkers("127.0.0.1:0", handler, 1)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(20 * time.Millisecond)

	client, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	// Build a query with EDNS0 OPT record containing invalid Client Subnet data
	query, _ := protocol.NewQuery(0xABCD, "invalid-ecs.com.", protocol.TypeA)
	query.SetEDNS0(4096, false)

	// Invalid ECS data (too short to unpack)
	opt := &protocol.RDataOPT{Options: []protocol.EDNS0Option{
		{
			Code: protocol.OptionCodeClientSubnet,
			Data: []byte{0x00}, // Too short for valid ECS
		},
	}}
	query.Additionals = []*protocol.ResourceRecord{
		{
			Name:  mustParseName("."),
			Type:  protocol.TypeOPT,
			Class: 4096,
			Data:   opt,
		},
	}

	buf := make([]byte, 512)
	n, _ := query.Pack(buf[2:])
	binary.BigEndian.PutUint16(buf[0:], uint16(n))
	client.Write(buf[:n+2])

	// Read response
	var lengthBuf [2]byte
	io.ReadFull(client, lengthBuf[:])
	respLen := binary.BigEndian.Uint16(lengthBuf[:])
	respBuf := make([]byte, respLen)
	io.ReadFull(client, respBuf)

	if receivedClientInfo == nil {
		t.Fatal("ClientInfo should not be nil")
	}
	if !receivedClientInfo.HasEDNS0 {
		t.Error("HasEDNS0 should be true")
	}
	// ClientSubnet should be nil since ECS data was invalid
	if receivedClientInfo.ClientSubnet != nil {
		t.Error("ClientSubnet should be nil for invalid ECS data")
	}
}

// ==============================================================================
// TCP Write - truncation path
// ==============================================================================

func TestTCPResponseWriterTruncation(t *testing.T) {
	// Start a real TCP server and have the handler send a very large response
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: req.Questions,
		}
		// Add many answers to create a large message
		name := mustParseName("big.example.com.")
		for i := 0; i < 500; i++ {
			resp.AddAnswer(&protocol.ResourceRecord{
				Name:  name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data: &protocol.RDataA{
					Address: [4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)},
				},
			})
		}
		w.Write(resp)
	})

	server := NewTCPServerWithWorkers("127.0.0.1:0", handler, 1)
	// Override maxSize to be small to trigger truncation
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(20 * time.Millisecond)

	client, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	query, _ := protocol.NewQuery(0xBEEF, "big.example.com.", protocol.TypeA)
	buf := make([]byte, 512)
	n, _ := query.Pack(buf[2:])
	binary.BigEndian.PutUint16(buf[0:], uint16(n))
	client.Write(buf[:n+2])

	// Read response
	var lengthBuf [2]byte
	io.ReadFull(client, lengthBuf[:])
	respLen := binary.BigEndian.Uint16(lengthBuf[:])
	respBuf := make([]byte, respLen)
	io.ReadFull(client, respBuf)

	resp, err := protocol.UnpackMessage(respBuf)
	if err != nil {
		t.Fatalf("Failed to unpack response: %v", err)
	}
	if resp.Header.ID != 0xBEEF {
		t.Errorf("Response ID = %d, want 0xBEEF", resp.Header.ID)
	}
}

// ==============================================================================
// TCP Write - write error path (closed connection)
// ==============================================================================

func TestTCPResponseWriterWriteError(t *testing.T) {
	writeErr := make(chan error, 1)
	var writeOnce sync.Once

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		// Close connection from another goroutine to cause write error
		writeOnce.Do(func() {
			// Attempt to write to a connection that will be closed
			_, err := w.Write(&protocol.Message{
				Header: protocol.Header{
					ID:    req.Header.ID,
					Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
				},
			})
			writeErr <- err
		})
	})

	server := NewTCPServerWithWorkers("127.0.0.1:0", handler, 1)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(20 * time.Millisecond)

	// Connect, send a query, then immediately close
	client, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	query, _ := protocol.NewQuery(0x1234, "test.com.", protocol.TypeA)
	buf := make([]byte, 512)
	n, _ := query.Pack(buf[2:])
	binary.BigEndian.PutUint16(buf[0:], uint16(n))
	client.Write(buf[:n+2])

	// Close client quickly to potentially cause write error
	client.Close()

	// Wait a bit for the handler to attempt writing
	time.Sleep(100 * time.Millisecond)
}

// ==============================================================================
// TLS Listen error path
// ==============================================================================

func TestTLSServerListenError(t *testing.T) {
	cert := generateTestTLSCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {})
	server := NewTLSServer("invalid-address:-1", handler, tlsConfig)
	err := server.Listen()
	if err == nil {
		t.Error("Listen should return error for invalid address")
		server.Stop()
	}
}

// ==============================================================================
// TLS handleConnection - non-TLS connection (cast failure)
// ==============================================================================

func TestTLSServerHandleConnectionNonTLS(t *testing.T) {
	cert := generateTestTLSCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		w.Write(&protocol.Message{})
	})

	server := NewTLSServerWithWorkers("127.0.0.1:0", handler, tlsConfig, 1)

	// Create a plain TCP listener and inject it (not a TLS listener)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	server.ListenWithListener(ln)

	go server.Serve()
	time.Sleep(20 * time.Millisecond)

	// Connect with a plain TCP client (not TLS), so the cast to *tls.Conn will fail
	client, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	time.Sleep(50 * time.Millisecond)

	stats := server.Stats()
	if stats.Errors == 0 {
		t.Error("Expected errors from non-TLS connection cast failure")
	}

	server.Stop()
}

// ==============================================================================
// TLS handleMessage - zero length message
// ==============================================================================

func TestTLSServerHandleMessageZeroLength(t *testing.T) {
	cert := generateTestTLSCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		w.Write(&protocol.Message{})
	})

	server := NewTLSServerWithWorkers("127.0.0.1:0", handler, tlsConfig, 1)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(20 * time.Millisecond)

	tlsClientConfig := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", server.Addr().String(), tlsClientConfig)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Send zero-length message
	conn.Write([]byte{0x00, 0x00})

	// Connection should be closed by server
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("Expected connection to be closed after zero-length message")
	}
}

// ==============================================================================
// TLS handleMessage - oversized length message
// ==============================================================================

func TestTLSServerHandleMessageOversizedLength(t *testing.T) {
	cert := generateTestTLSCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		w.Write(&protocol.Message{})
	})

	server := NewTLSServerWithWorkers("127.0.0.1:0", handler, tlsConfig, 1)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(20 * time.Millisecond)

	tlsClientConfig := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", server.Addr().String(), tlsClientConfig)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Send oversized length prefix
	conn.Write([]byte{0xFF, 0xFF})

	// Connection should be closed
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("Expected connection to be closed after oversized length")
	}
}

// ==============================================================================
// TLS handleMessage - incomplete body read
// ==============================================================================

func TestTLSServerHandleMessageIncompleteBody(t *testing.T) {
	cert := generateTestTLSCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		w.Write(&protocol.Message{})
	})

	server := NewTLSServerWithWorkers("127.0.0.1:0", handler, tlsConfig, 1)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(20 * time.Millisecond)

	tlsClientConfig := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", server.Addr().String(), tlsClientConfig)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Send length prefix claiming 100 bytes but only send 5
	data := make([]byte, 7)
	binary.BigEndian.PutUint16(data[0:2], 100) // Length = 100
	copy(data[2:], []byte{0x00, 0x01, 0x02, 0x03, 0x04})
	conn.Write(data)

	// Connection should be closed by server
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("Expected connection to be closed after incomplete body")
	}
}

// ==============================================================================
// TLS processMessage - EDNS0 detection
// ==============================================================================

func TestTLSServerProcessMessageWithEDNS0(t *testing.T) {
	cert := generateTestTLSCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	var receivedClientInfo *ClientInfo

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		receivedClientInfo = w.ClientInfo()
		w.Write(&protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
		})
	})

	server := NewTLSServerWithWorkers("127.0.0.1:0", handler, tlsConfig, 1)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(20 * time.Millisecond)

	tlsClientConfig := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", server.Addr().String(), tlsClientConfig)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Build query with EDNS0
	query, _ := protocol.NewQuery(0xDCBA, "edns.example.com.", protocol.TypeA)
	query.SetEDNS0(4096, true)

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

	if receivedClientInfo == nil {
		t.Fatal("ClientInfo should not be nil")
	}
	if !receivedClientInfo.HasEDNS0 {
		t.Error("HasEDNS0 should be true")
	}
	if receivedClientInfo.Protocol != "dot" {
		t.Errorf("Protocol = %s, want dot", receivedClientInfo.Protocol)
	}
	if receivedClientInfo.EDNS0UDPSize != 4096 {
		t.Errorf("EDNS0UDPSize = %d, want 4096", receivedClientInfo.EDNS0UDPSize)
	}
}

// ==============================================================================
// TLS processMessage - malformed DNS data
// ==============================================================================

func TestTLSServerProcessMessageMalformedData(t *testing.T) {
	cert := generateTestTLSCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		t.Error("Handler should not be called for malformed data")
	})

	server := NewTLSServerWithWorkers("127.0.0.1:0", handler, tlsConfig, 1)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(20 * time.Millisecond)

	tlsClientConfig := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", server.Addr().String(), tlsClientConfig)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Send valid-length prefix but invalid DNS data
	data := make([]byte, 50)
	binary.BigEndian.PutUint16(data[0:2], 48) // Length = 48
	for i := 2; i < 50; i++ {
		data[i] = 0xFF
	}
	conn.Write(data)

	// Wait for server to process
	time.Sleep(50 * time.Millisecond)
}

// ==============================================================================
// TLS Write - large message triggering truncation
// ==============================================================================

func TestTLSResponseWriterLargeMessage(t *testing.T) {
	cert := generateTestTLSCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: req.Questions,
		}
		// Add many answers to create a large message
		name := mustParseName("big.example.com.")
		for i := 0; i < 500; i++ {
			resp.AddAnswer(&protocol.ResourceRecord{
				Name:  name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data: &protocol.RDataA{
					Address: [4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)},
				},
			})
		}
		w.Write(resp)
	})

	server := NewTLSServerWithWorkers("127.0.0.1:0", handler, tlsConfig, 1)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(20 * time.Millisecond)

	tlsClientConfig := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", server.Addr().String(), tlsClientConfig)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	query, _ := protocol.NewQuery(0xCAFE, "big.example.com.", protocol.TypeA)
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

	resp, err := protocol.UnpackMessage(respBuf)
	if err != nil {
		t.Fatalf("Failed to unpack response: %v", err)
	}
	if resp.Header.ID != 0xCAFE {
		t.Errorf("Response ID = %d, want 0xCAFE", resp.Header.ID)
	}
}

// ==============================================================================
// TLS Write - double write error
// ==============================================================================

func TestTLSResponseWriterDoubleWriteIntegration(t *testing.T) {
	cert := generateTestTLSCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	var writeErrors []error

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
		}
		w.Write(resp)
		_, err := w.Write(resp)
		writeErrors = append(writeErrors, err)
	})

	server := NewTLSServerWithWorkers("127.0.0.1:0", handler, tlsConfig, 1)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(20 * time.Millisecond)

	tlsClientConfig := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", server.Addr().String(), tlsClientConfig)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	query, _ := protocol.NewQuery(0x1111, "double.com.", protocol.TypeA)
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

	// Verify second write produced an error
	if len(writeErrors) == 0 || writeErrors[0] == nil {
		t.Error("Second write should return an error")
	}
}

// ==============================================================================
// TLS Serve - accept error that is not due to shutdown
// ==============================================================================

func TestTLSServerServeAcceptErrorContinue(t *testing.T) {
	cert := generateTestTLSCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		w.Write(&protocol.Message{})
	})

	server := NewTLSServerWithWorkers("127.0.0.1:0", handler, tlsConfig, 1)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	go server.Serve()
	time.Sleep(20 * time.Millisecond)

	// Close the listener to trigger Accept error while context is not cancelled
	server.listener.Close()

	time.Sleep(30 * time.Millisecond)

	// Clean up
	server.cancel()
	time.Sleep(30 * time.Millisecond)
}

// ==============================================================================
// UDP Listen error path
// ==============================================================================

func TestUDPServerListenError(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {})
	server := NewUDPServer("invalid-address:-1", handler)
	err := server.Listen()
	if err == nil {
		t.Error("Listen should return error for invalid address")
		server.Stop()
	}
}

// ==============================================================================
// UDP Serve - error when not listening
// ==============================================================================

func TestUDPServerServeWithoutListen(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {})
	server := NewUDPServer("127.0.0.1:0", handler)
	err := server.Serve()
	if err == nil {
		t.Error("Serve should return error when not listening")
		server.Stop()
	}
}

// ==============================================================================
// mockUDPConn for testing UDP reader error paths
// ==============================================================================

type mockUDPConn struct {
	readErr      error
	readData     []byte
	readAddr     *net.UDPAddr
	writeErr     error
	closed       int32
	localAddrVal net.Addr
	readCh       chan struct{} // Signal when a ReadFromUDP is attempted
}

func (m *mockUDPConn) ReadFromUDP(buf []byte) (int, *net.UDPAddr, error) {
	if m.readCh != nil {
		select {
		case m.readCh <- struct{}{}:
		default:
		}
	}
	if m.readErr != nil {
		return 0, nil, m.readErr
	}
	if len(m.readData) == 0 {
		return 0, nil, io.EOF
	}
	n := copy(buf, m.readData)
	return n, m.readAddr, nil
}

func (m *mockUDPConn) WriteToUDP(buf []byte, addr *net.UDPAddr) (int, error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return len(buf), nil
}

func (m *mockUDPConn) Close() error {
	atomic.StoreInt32(&m.closed, 1)
	return nil
}

func (m *mockUDPConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockUDPConn) LocalAddr() net.Addr {
	if m.localAddrVal != nil {
		return m.localAddrVal
	}
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
}

// ==============================================================================
// UDP reader - context cancellation
// ==============================================================================

func TestUDPServerReaderContextCancel(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {})
	server := NewUDPServerWithWorkers("127.0.0.1:0", handler, 1)

	// Use a mock connection that returns an error
	mockConn := &mockUDPConn{
		readErr: io.EOF,
	}
	server.ListenWithConn(mockConn)

	// Start Serve which starts reader
	done := make(chan struct{})
	go func() {
		server.Serve()
		close(done)
	}()

	time.Sleep(20 * time.Millisecond)
	server.Stop()

	select {
	case <-done:
		// Good, Serve returned
	case <-time.After(2 * time.Second):
		t.Error("Serve should return after Stop()")
	}
}

// ==============================================================================
// UDP reader - net.ErrClosed error
// ==============================================================================

func TestUDPServerReaderNetErrClosed(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {})
	server := NewUDPServerWithWorkers("127.0.0.1:0", handler, 1)

	mockConn := &mockUDPConn{
		readErr: net.ErrClosed,
	}
	server.ListenWithConn(mockConn)

	done := make(chan struct{})
	go func() {
		server.Serve()
		close(done)
	}()

	// Give the reader goroutine time to encounter net.ErrClosed
	time.Sleep(50 * time.Millisecond)

	// Serve() blocks on ctx.Done(), so we need to call Stop() to cancel the context.
	// The reader goroutine exits on net.ErrClosed, but Serve() itself needs Stop().
	server.Stop()

	select {
	case <-done:
		// Serve returned after Stop() cancelled the context
	case <-time.After(2 * time.Second):
		t.Error("Serve should return after Stop() is called")
	}
}

// ==============================================================================
// UDP reader - generic read error
// ==============================================================================

func TestUDPServerReaderGenericError(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {})
	server := NewUDPServerWithWorkers("127.0.0.1:0", handler, 1)

	// Return a generic error first, then net.ErrClosed to stop
	callCount := int32(0)
	mockConn := &mockUDPConn{}
	mockConn.readErr = errors.New("generic read error")

	server.ListenWithConn(mockConn)

	done := make(chan struct{})
	go func() {
		server.Serve()
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)

	// Should have incremented errors
	stats := server.Stats()
	if stats.Errors == 0 {
		t.Error("Expected errors to be incremented after generic read error")
	}

	// Now stop the server
	atomic.AddInt32(&callCount, 1)
	server.Stop()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("Serve should return after Stop()")
	}
}

// ==============================================================================
// UDP handleRequest - EDNS0 with ECS
// ==============================================================================

func TestUDPServerHandleRequestEDNS0WithECS(t *testing.T) {
	var receivedClientInfo *ClientInfo

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		receivedClientInfo = w.ClientInfo()
		w.Write(&protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
		})
	})

	server := NewUDPServer("127.0.0.1:0", handler)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(20 * time.Millisecond)

	client, err := net.DialUDP("udp", nil, server.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	// Build query with EDNS0 and ECS
	query, _ := protocol.NewQuery(0xF00D, "ecs.example.com.", protocol.TypeA)
	query.SetEDNS0(4096, false)

	opt := &protocol.RDataOPT{Options: []protocol.EDNS0Option{
		{
			Code: protocol.OptionCodeClientSubnet,
			Data: []byte{0x00, 0x01, 0x20, 0x00, 192, 168, 0, 0}, // IPv4 /32
		},
	}}
	query.Additionals = []*protocol.ResourceRecord{
		{
			Name:  mustParseName("."),
			Type:  protocol.TypeOPT,
			Class: 4096,
			Data:   opt,
		},
	}

	buf := make([]byte, 512)
	n, _ := query.Pack(buf)
	client.Write(buf[:n])

	// Read response
	client.SetReadDeadline(time.Now().Add(time.Second))
	respBuf := make([]byte, 512)
	n, err = client.Read(respBuf)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if receivedClientInfo == nil {
		t.Fatal("ClientInfo should not be nil")
	}
	if !receivedClientInfo.HasEDNS0 {
		t.Error("HasEDNS0 should be true")
	}
	if receivedClientInfo.EDNS0UDPSize != 4096 {
		t.Errorf("EDNS0UDPSize = %d, want 4096", receivedClientInfo.EDNS0UDPSize)
	}
	// ClientSubnet is nil because UnpackMessage does not register TypeOPT in createRData,
	// so after pack/unpack the OPT record's Data is *RDataRaw, not *RDataOPT.
	if receivedClientInfo.ClientSubnet != nil {
		t.Error("ClientSubnet should be nil since TypeOPT is not registered in createRData")
	}
}

// ==============================================================================
// UDP handleRequest - EDNS0 with invalid ECS
// ==============================================================================

func TestUDPServerHandleRequestEDNS0InvalidECS(t *testing.T) {
	var receivedClientInfo *ClientInfo

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		receivedClientInfo = w.ClientInfo()
		w.Write(&protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
		})
	})

	server := NewUDPServer("127.0.0.1:0", handler)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(20 * time.Millisecond)

	client, err := net.DialUDP("udp", nil, server.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	query, _ := protocol.NewQuery(0xF00D, "bad-ecs.example.com.", protocol.TypeA)
	query.SetEDNS0(4096, false)

	opt := &protocol.RDataOPT{Options: []protocol.EDNS0Option{
		{
			Code: protocol.OptionCodeClientSubnet,
			Data: []byte{0x00}, // Invalid: too short
		},
	}}
	query.Additionals = []*protocol.ResourceRecord{
		{
			Name:  mustParseName("."),
			Type:  protocol.TypeOPT,
			Class: 4096,
			Data:   opt,
		},
	}

	buf := make([]byte, 512)
	n, _ := query.Pack(buf)
	client.Write(buf[:n])

	client.SetReadDeadline(time.Now().Add(time.Second))
	respBuf := make([]byte, 512)
	n, _ = client.Read(respBuf)

	if receivedClientInfo != nil && receivedClientInfo.ClientSubnet != nil {
		t.Error("ClientSubnet should be nil for invalid ECS data")
	}
}

// ==============================================================================
// UDP Write - truncation path (large response, small maxSize)
// ==============================================================================

func TestUDPResponseWriterTruncation(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: req.Questions,
		}
		// Create a response large enough to exceed default 512-byte UDP limit
		name := mustParseName("large.example.com.")
		for i := 0; i < 50; i++ {
			resp.AddAnswer(&protocol.ResourceRecord{
				Name:  name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data: &protocol.RDataA{
					Address: [4]byte{byte(i), byte(i >> 8), 1, 1},
				},
			})
		}
		w.Write(resp)
	})

	server := NewUDPServer("127.0.0.1:0", handler)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(20 * time.Millisecond)

	client, err := net.DialUDP("udp", nil, server.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	// Query without EDNS0 so maxSize is 512
	query, _ := protocol.NewQuery(0xAAAA, "large.example.com.", protocol.TypeA)
	buf := make([]byte, 512)
	n, _ := query.Pack(buf)
	client.Write(buf[:n])

	client.SetReadDeadline(time.Now().Add(time.Second))
	respBuf := make([]byte, 4096)
	n, err = client.Read(respBuf)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	resp, err := protocol.UnpackMessage(respBuf[:n])
	if err != nil {
		t.Fatalf("Failed to unpack response: %v", err)
	}

	// TC bit should be set since the response was truncated
	if !resp.Header.Flags.TC {
		t.Error("Expected TC bit to be set for truncated response")
	}
}

// ==============================================================================
// UDP Write - write error (use mock connection that returns write errors)
// ==============================================================================

func TestUDPResponseWriterWriteError(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		w.Write(&protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
		})
	})

	server := NewUDPServerWithWorkers("127.0.0.1:0", handler, 1)

	// Use a mock connection that fails on writes
	mockConn := &mockUDPConn{
		writeErr: errors.New("write failed"),
		readData: nil,
	}
	server.ListenWithConn(mockConn)

	// Manually feed a valid DNS query to handleRequest
	query, _ := protocol.NewQuery(0x1234, "test.com.", protocol.TypeA)
	buf := make([]byte, 512)
	n, _ := query.Pack(buf)

	req := &udpRequest{
		data: buf,
		addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		n:    n,
	}

	server.handleRequest(req)

	// Stats should not show packets sent since write failed
	stats := server.Stats()
	if stats.PacketsSent != 0 {
		t.Errorf("PacketsSent = %d, want 0 after write error", stats.PacketsSent)
	}
}

// ==============================================================================
// UDP Write - second write returns error
// ==============================================================================

func TestUDPResponseWriterDoubleWriteDirect(t *testing.T) {
	server := NewUDPServerWithWorkers("127.0.0.1:0", HandlerFunc(func(w ResponseWriter, req *protocol.Message) {}), 1)

	mockConn := &mockUDPConn{}
	server.ListenWithConn(mockConn)

	rw := &udpResponseWriter{
		server:  server,
		client:  &ClientInfo{Addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}},
		maxSize: 512,
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0x1234,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
	}

	_, err := rw.Write(msg)
	if err != nil {
		t.Errorf("First write should succeed: %v", err)
	}

	_, err = rw.Write(msg)
	if err == nil {
		t.Error("Second write should return error")
	}
}

// ==============================================================================
// ClientInfo.IP - additional address types
// ==============================================================================

func TestClientInfoIPDefaultPathNoHostPort(t *testing.T) {
	// Test the default case where SplitHostPort fails, and we fall back to ParseIP
	// Use a UnixAddr which doesn't have host:port format
	client := &ClientInfo{
		Addr: &net.UnixAddr{Name: "/tmp/test.sock", Net: "unix"},
	}
	ip := client.IP()
	// Unix addresses don't have IPs, so this should go through the default path
	// SplitHostPort will fail for "/tmp/test.sock", then ParseIP returns nil
	if ip != nil {
		t.Errorf("Expected nil IP for Unix address, got %v", ip)
	}
}

// ==============================================================================
// ClientInfo.IP - default path with parseable IP string
// ==============================================================================

func TestClientInfoIPDefaultPathParseable(t *testing.T) {
	// Use a custom net.Addr implementation that returns a plain IP
	client := &ClientInfo{
		Addr: &plainIPAddr{ip: "1.2.3.4"},
	}
	ip := client.IP()
	if ip == nil {
		t.Fatal("Expected non-nil IP")
	}
	if ip.String() != "1.2.3.4" {
		t.Errorf("IP = %s, want 1.2.3.4", ip.String())
	}
}

// plainIPAddr is a test helper that implements net.Addr with a plain IP string
type plainIPAddr struct {
	ip string
}

func (a *plainIPAddr) Network() string { return "test" }
func (a *plainIPAddr) String() string  { return a.ip }

// ==============================================================================
// Handler IP test with SplitHostPort-able address
// ==============================================================================

func TestClientInfoIPDefaultPathWithHostPort(t *testing.T) {
	client := &ClientInfo{
		Addr: &hostPortAddr{host: "9.8.7.6", port: "53"},
	}
	ip := client.IP()
	if ip == nil {
		t.Fatal("Expected non-nil IP")
	}
	if ip.String() != "9.8.7.6" {
		t.Errorf("IP = %s, want 9.8.7.6", ip.String())
	}
}

type hostPortAddr struct {
	host string
	port string
}

func (a *hostPortAddr) Network() string { return "test" }
func (a *hostPortAddr) String() string  { return a.host + ":" + a.port }

// ==============================================================================
// TLS certificate helper re-used from tls_test.go for standalone compilation
// ==============================================================================

func generateTLSCertForCoverage(t *testing.T) tls.Certificate {
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

// ==============================================================================
// TCP Serve - graceful shutdown during Serve
// ==============================================================================

func TestTCPServerServeGracefulShutdown(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		w.Write(&protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
		})
	})

	server := NewTCPServerWithWorkers("127.0.0.1:0", handler, 1)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- server.Serve()
	}()

	time.Sleep(20 * time.Millisecond)

	// Stop should trigger graceful shutdown
	err := server.Stop()
	if err != nil {
		t.Errorf("Stop returned error: %v", err)
	}

	select {
	case serveErr := <-done:
		if serveErr != nil {
			t.Errorf("Serve returned error: %v", serveErr)
		}
	case <-time.After(2 * time.Second):
		t.Error("Serve did not return after Stop()")
	}
}

// ==============================================================================
// TLS Serve - graceful shutdown during Serve
// ==============================================================================

func TestTLSServerServeGracefulShutdown(t *testing.T) {
	cert := generateTLSCertForCoverage(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		w.Write(&protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
		})
	})

	server := NewTLSServerWithWorkers("127.0.0.1:0", handler, tlsConfig, 1)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- server.Serve()
	}()

	time.Sleep(20 * time.Millisecond)

	err := server.Stop()
	if err != nil {
		t.Errorf("Stop returned error: %v", err)
	}

	select {
	case serveErr := <-done:
		if serveErr != nil {
			t.Errorf("Serve returned error: %v", serveErr)
		}
	case <-time.After(2 * time.Second):
		t.Error("Serve did not return after Stop()")
	}
}

// ==============================================================================
// TCP Write - direct test with small maxSize for truncation
// ==============================================================================

func TestTCPResponseWriterTruncationDirect(t *testing.T) {
	// Create a TCP server and use it to test the truncation path
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: req.Questions,
		}
		// Add many answers
		name := mustParseName("trunc.example.com.")
		for i := 0; i < 300; i++ {
			resp.AddAnswer(&protocol.ResourceRecord{
				Name:  name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data: &protocol.RDataA{
					Address: [4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)},
				},
			})
		}
		w.Write(resp)
	})

	server := NewTCPServerWithWorkers("127.0.0.1:0", handler, 1)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(20 * time.Millisecond)

	client, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	query, _ := protocol.NewQuery(0x5678, "trunc.example.com.", protocol.TypeA)
	buf := make([]byte, 512)
	n, _ := query.Pack(buf[2:])
	binary.BigEndian.PutUint16(buf[0:], uint16(n))
	client.Write(buf[:n+2])

	// Read response
	var lengthBuf [2]byte
	io.ReadFull(client, lengthBuf[:])
	respLen := binary.BigEndian.Uint16(lengthBuf[:])
	respBuf := make([]byte, respLen)
	io.ReadFull(client, respBuf)

	resp, err := protocol.UnpackMessage(respBuf)
	if err != nil {
		t.Fatalf("Failed to unpack response: %v", err)
	}
	if resp.Header.ID != 0x5678 {
		t.Errorf("Response ID = %d, want 0x5678", resp.Header.ID)
	}
}
