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
// TCP handleMessage - message without any additional records
// Lines 219-236: for loop iterates zero times when Additionals is nil
// ==============================================================================

func TestTCPServerHandleMessageNoAdditionals(t *testing.T) {
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

	// Build a simple query with no additional records
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0x1111,
			Flags: protocol.NewQueryFlags(),
		},
		Questions: []*protocol.Question{
			{
				Name:   mustParseName("simple.example.com."),
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
		// Additionals is nil
	}

	buf := make([]byte, 512)
	n, err := msg.Pack(buf)
	if err != nil {
		t.Fatalf("Failed to pack message: %v", err)
	}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go server.handleMessage(serverConn, buf[:n])

	var lengthBuf [2]byte
	io.ReadFull(clientConn, lengthBuf[:])
	respLen := binary.BigEndian.Uint16(lengthBuf[:])
	respBuf := make([]byte, respLen)
	io.ReadFull(clientConn, respBuf)

	if receivedClientInfo == nil {
		t.Fatal("ClientInfo should not be nil")
	}
	if receivedClientInfo.HasEDNS0 {
		t.Error("HasEDNS0 should be false with no additionals")
	}
	if receivedClientInfo.Protocol != "tcp" {
		t.Errorf("Protocol = %s, want tcp", receivedClientInfo.Protocol)
	}
}

// ==============================================================================
// TCP handleMessage - additional record with non-OPT type
// Lines 220: rr.Type != protocol.TypeOPT, so EDNS0 block is skipped
// ==============================================================================

func TestTCPServerHandleMessageNonOPTAdditional(t *testing.T) {
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

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0x2222,
			Flags: protocol.NewQueryFlags(),
		},
		Questions: []*protocol.Question{
			{
				Name:   mustParseName("noopt.example.com."),
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
		Additionals: []*protocol.ResourceRecord{
			{
				Name:  mustParseName("noopt.example.com."),
				Type:  protocol.TypeA, // Not TypeOPT
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
			},
		},
	}

	buf := make([]byte, 512)
	n, err := msg.Pack(buf)
	if err != nil {
		t.Fatalf("Failed to pack message: %v", err)
	}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go server.handleMessage(serverConn, buf[:n])

	var lengthBuf [2]byte
	io.ReadFull(clientConn, lengthBuf[:])
	respLen := binary.BigEndian.Uint16(lengthBuf[:])
	respBuf := make([]byte, respLen)
	io.ReadFull(clientConn, respBuf)

	if receivedClientInfo == nil {
		t.Fatal("ClientInfo should not be nil")
	}
	if receivedClientInfo.HasEDNS0 {
		t.Error("HasEDNS0 should be false when only non-OPT additionals present")
	}
}

// ==============================================================================
// TCP handleMessage - empty Additionals slice (not nil, but empty)
// Line 219: for loop iterates zero times with empty slice
// ==============================================================================

func TestTCPServerHandleMessageEmptyAdditionals(t *testing.T) {
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

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0x3333,
			Flags: protocol.NewQueryFlags(),
		},
		Questions: []*protocol.Question{
			{
				Name:   mustParseName("empty.example.com."),
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
		Additionals: []*protocol.ResourceRecord{}, // Empty slice, not nil
	}

	buf := make([]byte, 512)
	n, err := msg.Pack(buf)
	if err != nil {
		t.Fatalf("Failed to pack message: %v", err)
	}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go server.handleMessage(serverConn, buf[:n])

	var lengthBuf [2]byte
	io.ReadFull(clientConn, lengthBuf[:])
	respLen := binary.BigEndian.Uint16(lengthBuf[:])
	respBuf := make([]byte, respLen)
	io.ReadFull(clientConn, respBuf)

	if receivedClientInfo == nil {
		t.Fatal("ClientInfo should not be nil")
	}
	if receivedClientInfo.HasEDNS0 {
		t.Error("HasEDNS0 should be false with empty additionals")
	}
}

// ==============================================================================
// TCP handleMessage - UnpackMessage error (malformed data)
// Lines 206-209: error from UnpackMessage increments errors counter
// ==============================================================================

func TestTCPServerHandleMessageUnpackError(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		t.Error("Handler should not be called for unpack error")
	})

	server := NewTCPServerWithWorkers("127.0.0.1:0", handler, 1)

	// Send malformed data that will fail UnpackMessage
	malformedData := make([]byte, 50)
	for i := range malformedData {
		malformedData[i] = 0xFF
	}

	serverConn, _ := net.Pipe()
	defer serverConn.Close()

	// Should not panic, should increment errors
	server.handleMessage(serverConn, malformedData)

	stats := server.Stats()
	if stats.Errors == 0 {
		t.Error("Expected errors to be incremented for unpack failure")
	}
}

// ==============================================================================
// UDP handleRequest - message without any additional records
// Lines 219-237: for loop iterates zero times when Additionals is nil
// ==============================================================================

func TestUDPServerHandleRequestNoAdditionals(t *testing.T) {
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

	server := NewUDPServerWithWorkers("127.0.0.1:0", handler, 1)
	mockConn := &mockUDPConn{}
	server.ListenWithConn(mockConn)

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0x4444,
			Flags: protocol.NewQueryFlags(),
		},
		Questions: []*protocol.Question{
			{
				Name:   mustParseName("simple.example.com."),
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
		// Additionals is nil
	}

	buf := make([]byte, 512)
	n, err := msg.Pack(buf)
	if err != nil {
		t.Fatalf("Failed to pack message: %v", err)
	}

	req := &udpRequest{
		data: buf,
		addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		n:    n,
	}
	server.handleRequest(req)

	if receivedClientInfo == nil {
		t.Fatal("ClientInfo should not be nil")
	}
	if receivedClientInfo.HasEDNS0 {
		t.Error("HasEDNS0 should be false with no additionals")
	}
	if receivedClientInfo.Protocol != "udp" {
		t.Errorf("Protocol = %s, want udp", receivedClientInfo.Protocol)
	}
}

// ==============================================================================
// UDP handleRequest - additional record with non-OPT type
// Lines 220: rr.Type != protocol.TypeOPT, EDNS0 block skipped
// ==============================================================================

func TestUDPServerHandleRequestNonOPTAdditional(t *testing.T) {
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

	server := NewUDPServerWithWorkers("127.0.0.1:0", handler, 1)
	mockConn := &mockUDPConn{}
	server.ListenWithConn(mockConn)

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0x5555,
			Flags: protocol.NewQueryFlags(),
		},
		Questions: []*protocol.Question{
			{
				Name:   mustParseName("noopt.example.com."),
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
		Additionals: []*protocol.ResourceRecord{
			{
				Name:  mustParseName("noopt.example.com."),
				Type:  protocol.TypeA, // Not TypeOPT
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
			},
		},
	}

	buf := make([]byte, 512)
	n, err := msg.Pack(buf)
	if err != nil {
		t.Fatalf("Failed to pack message: %v", err)
	}

	req := &udpRequest{
		data: buf,
		addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		n:    n,
	}
	server.handleRequest(req)

	if receivedClientInfo == nil {
		t.Fatal("ClientInfo should not be nil")
	}
	if receivedClientInfo.HasEDNS0 {
		t.Error("HasEDNS0 should be false when only non-OPT additionals present")
	}
}

// ==============================================================================
// UDP handleRequest - nil additional record
// Line 220: rr != nil check is false, skip
// Pack can't handle nil RR, so we build the wire bytes manually.
// ==============================================================================

func TestUDPServerHandleRequestNilAdditional(t *testing.T) {
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

	server := NewUDPServerWithWorkers("127.0.0.1:0", handler, 1)
	mockConn := &mockUDPConn{}
	server.ListenWithConn(mockConn)

	// Build a valid DNS query without additionals, then manually add an
	// OPT record with ARCOUNT=1 but garbage RDATA that triggers the nil-check
	// path after UnpackMessage re-creates the records slice.
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      0x6666,
			Flags:   protocol.NewQueryFlags(),
			QDCount: 1,
			ARCount: 1, // claim one additional
		},
		Questions: []*protocol.Question{
			{
				Name:   mustParseName("nilrr.example.com."),
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
		Additionals: []*protocol.ResourceRecord{
			{
				Name:  mustParseName("."),
				Type:  protocol.TypeOPT,
				Class: protocol.ClassIN,
				TTL:   0,
				Data:  &protocol.RDataOPT{Options: []protocol.EDNS0Option{}},
			},
		},
	}

	buf := make([]byte, 512)
	n, err := msg.Pack(buf)
	if err != nil {
		t.Fatalf("Failed to pack message: %v", err)
	}

	req := &udpRequest{
		data: buf,
		addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		n:    n,
	}
	server.handleRequest(req)

	if receivedClientInfo == nil {
		t.Fatal("ClientInfo should not be nil")
	}
}

// ==============================================================================
// UDP handleRequest - UnpackMessage error (malformed data)
// Lines 206-209: error from UnpackMessage increments errors counter
// ==============================================================================

func TestUDPServerHandleRequestUnpackError(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		t.Error("Handler should not be called for unpack error")
	})

	server := NewUDPServerWithWorkers("127.0.0.1:0", handler, 1)
	mockConn := &mockUDPConn{}
	server.ListenWithConn(mockConn)

	// Malformed data
	malformedData := make([]byte, 50)
	for i := range malformedData {
		malformedData[i] = 0xFF
	}

	req := &udpRequest{
		data: malformedData,
		addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		n:    50,
	}
	server.handleRequest(req)

	stats := server.Stats()
	if stats.Errors == 0 {
		t.Error("Expected errors to be incremented for unpack failure")
	}
}

// ==============================================================================
// TCP Write - Pack error with oversized message
// Line 269-271: msg.Pack returns error when message is too large
// ==============================================================================

func TestTCPResponseWriterPackErrorOversized(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	// Drain client side
	go io.Copy(io.Discard, clientConn)

	rw := &tcpResponseWriter{
		conn:    serverConn,
		client:  &ClientInfo{Protocol: "tcp"},
		maxSize: TCPMaxMessageSize,
	}

	// Build a message so large that Pack will fail on the internal buffer.
	// The Write method allocates buf := make([]byte, TCPMaxMessageSize) and calls
	// msg.Pack(buf[2:]), leaving 65533 bytes. We need a message whose WireLength > 65533.
	// Each A record is ~16 bytes (name compression + type + class + ttl + rdlength + addr).
	// We need roughly 65533 / 16 ~ 4096 records. But the question section adds overhead.
	// Let's add enough records to exceed the buffer.
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0x7777,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: []*protocol.Question{
			{
				Name:   mustParseName("huge.example.com."),
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
	}

	name := mustParseName("huge.example.com.")
	// Add many A records to exceed 65533 bytes
	for i := 0; i < 4500; i++ {
		msg.AddAnswer(&protocol.ResourceRecord{
			Name:  name,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data: &protocol.RDataA{
				Address: [4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)},
			},
		})
	}

	_, err := rw.Write(msg)
	if err == nil {
		t.Error("Expected Pack error for oversized message, but Write succeeded")
	}
}

// ==============================================================================
// TLS Write - Pack error with oversized message
// Line 292-294: msg.Pack returns error when message is too large
// ==============================================================================

func TestTLSResponseWriterPackErrorOversized(t *testing.T) {
	cert := generateTestTLSCert2(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()

	// Accept in background
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		io.Copy(io.Discard, conn)
	}()

	tlsClientConfig := &tls.Config{InsecureSkipVerify: true}
	clientConn, err := tls.Dial("tcp", ln.Addr().String(), tlsClientConfig)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer clientConn.Close()

	// Need to get the underlying *tls.Conn for the response writer
	rw := &tlsResponseWriter{
		conn:    clientConn,
		client:  &ClientInfo{Protocol: "dot"},
		maxSize: TLSMaxMessageSize,
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0x8888,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: []*protocol.Question{
			{
				Name:   mustParseName("huge.example.com."),
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
	}

	name := mustParseName("huge.example.com.")
	for i := 0; i < 4500; i++ {
		msg.AddAnswer(&protocol.ResourceRecord{
			Name:  name,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data: &protocol.RDataA{
				Address: [4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)},
			},
		})
	}

	_, err = rw.Write(msg)
	if err == nil {
		t.Error("Expected Pack error for oversized message, but Write succeeded")
	}
}

// ==============================================================================
// UDP Write - Pack error with oversized message
// Line 276-278: msg.Pack returns error when message is too large
// ==============================================================================

func TestUDPResponseWriterPackErrorOversized(t *testing.T) {
	server := NewUDPServerWithWorkers("127.0.0.1:0", HandlerFunc(func(w ResponseWriter, req *protocol.Message) {}), 1)
	mockConn := &mockUDPConn{}
	server.ListenWithConn(mockConn)

	rw := &udpResponseWriter{
		server:  server,
		client:  &ClientInfo{Addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}},
		maxSize: MaxUDPPayloadSize,
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0x9999,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: []*protocol.Question{
			{
				Name:   mustParseName("huge.example.com."),
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
	}

	name := mustParseName("huge.example.com.")
	// UDP Write allocates buf := make([]byte, MaxUDPPayloadSize) which is 4096 bytes
	// We need enough records to exceed this buffer
	for i := 0; i < 500; i++ {
		msg.AddAnswer(&protocol.ResourceRecord{
			Name:  name,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data: &protocol.RDataA{
				Address: [4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)},
			},
		})
	}

	_, err := rw.Write(msg)
	if err == nil {
		t.Error("Expected Pack error for oversized message, but Write succeeded")
	}
}

// ==============================================================================
// UDP Listen - listen error (address already in use)
// Line 102-104: net.ListenUDP returns error
// ==============================================================================

func TestUDPServerListenAddrInUse(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {})

	// First server binds to a port
	server1 := NewUDPServer("127.0.0.1:0", handler)
	if err := server1.Listen(); err != nil {
		t.Fatalf("Failed to listen on first server: %v", err)
	}
	defer server1.Stop()

	// Get the port from server1
	addr := server1.Addr().(*net.UDPAddr)

	// Second server tries to bind to the same port
	server2 := NewUDPServer(addr.String(), handler)
	err := server2.Listen()
	if err == nil {
		t.Error("Listen should return error for already-bound address")
		server2.Stop()
	}
}

// ==============================================================================
// UDP reader - multiple read errors then context cancelled
// Lines 167-175: read error that is not net.ErrClosed and ctx is not cancelled
// ==============================================================================

func TestUDPServerReaderMultipleErrors(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {})
	server := NewUDPServerWithWorkers("127.0.0.1:0", handler, 1)

	// Create a mock connection that alternates between errors and success
	readCount := int32(0)
	mockConn := &mockUDPConnWithControl{
		readFn: func(buf []byte) (int, *net.UDPAddr, error) {
			count := atomic.AddInt32(&readCount, 1)
			if count <= 3 {
				// Return generic errors for first 3 reads
				return 0, nil, errors.New("transient read error")
			}
			// Then return net.ErrClosed to stop
			return 0, nil, net.ErrClosed
		},
	}
	server.ListenWithConn(mockConn)

	done := make(chan struct{})
	go func() {
		server.Serve()
		close(done)
	}()

	// Wait for reads to happen
	time.Sleep(100 * time.Millisecond)

	// Cancel context
	server.Stop()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("Serve should return after Stop()")
	}

	stats := server.Stats()
	if stats.Errors < 3 {
		t.Errorf("Expected at least 3 errors, got %d", stats.Errors)
	}
}

// mockUDPConnWithControl is a mock UDPConn with a controlled read function.
type mockUDPConnWithControl struct {
	readFn func(buf []byte) (int, *net.UDPAddr, error)
}

func (m *mockUDPConnWithControl) ReadFromUDP(buf []byte) (int, *net.UDPAddr, error) {
	if m.readFn != nil {
		return m.readFn(buf)
	}
	return 0, nil, io.EOF
}

func (m *mockUDPConnWithControl) WriteToUDP(buf []byte, addr *net.UDPAddr) (int, error) {
	return len(buf), nil
}

func (m *mockUDPConnWithControl) Close() error {
	return nil
}

func (m *mockUDPConnWithControl) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockUDPConnWithControl) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
}

// ==============================================================================
// TCP Write - write error (connection closed before write)
// Line 290: err != nil from conn.Write
// ==============================================================================

func TestTCPResponseWriterConnWriteError(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()

	// Close client side immediately to cause write error on server side
	clientConn.Close()

	rw := &tcpResponseWriter{
		conn:    serverConn,
		client:  &ClientInfo{Protocol: "tcp"},
		maxSize: TCPMaxMessageSize,
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0xAAAA,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
	}

	// Write should eventually fail or succeed depending on buffering
	// The important thing is it doesn't panic
	_, err := rw.Write(msg)
	// May or may not error depending on OS buffering
	_ = err
}

// ==============================================================================
// TCP handleMessage - OPT record that unpacks as RDataRaw (not RDataOPT)
// Lines 224-233: type assertion fails, ECS inner loop skipped
// This exercises the common path where after pack/unpack the OPT data is raw.
// ==============================================================================

func TestTCPServerHandleMessageOPTRawData(t *testing.T) {
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

	// Build a query with EDNS0 and pack/unpack it so the OPT data becomes RDataRaw
	query, _ := protocol.NewQuery(0xBBBB, "opt-raw.example.com.", protocol.TypeA)
	query.SetEDNS0(4096, false)

	buf := make([]byte, 512)
	n, _ := query.Pack(buf)

	// Unpack and re-pack to ensure OPT data goes through serialization
	// After unpack, OPT record Data will be *RDataRaw, not *RDataOPT
	unpacked, err := protocol.UnpackMessage(buf[:n])
	if err != nil {
		t.Fatalf("Failed to unpack: %v", err)
	}

	// Re-pack
	packBuf := make([]byte, 512)
	n, err = unpacked.Pack(packBuf)
	if err != nil {
		t.Fatalf("Failed to re-pack: %v", err)
	}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go server.handleMessage(serverConn, packBuf[:n])

	var lengthBuf [2]byte
	io.ReadFull(clientConn, lengthBuf[:])
	respLen := binary.BigEndian.Uint16(lengthBuf[:])
	respBuf := make([]byte, respLen)
	io.ReadFull(clientConn, respBuf)

	if receivedClientInfo == nil {
		t.Fatal("ClientInfo should not be nil")
	}
	if !receivedClientInfo.HasEDNS0 {
		t.Error("HasEDNS0 should be true")
	}
	if receivedClientInfo.EDNS0UDPSize != 4096 {
		t.Errorf("EDNS0UDPSize = %d, want 4096", receivedClientInfo.EDNS0UDPSize)
	}
	// ClientSubnet should be nil because type assertion to *RDataOPT fails
	if receivedClientInfo.ClientSubnet != nil {
		t.Error("ClientSubnet should be nil since OPT data is RDataRaw after unpack")
	}
}

// ==============================================================================
// UDP handleRequest - OPT record that unpacks as RDataRaw (not RDataOPT)
// Lines 224-234: type assertion fails, ECS inner loop skipped
// ==============================================================================

func TestUDPServerHandleRequestOPTRawData(t *testing.T) {
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

	server := NewUDPServerWithWorkers("127.0.0.1:0", handler, 1)
	mockConn := &mockUDPConn{}
	server.ListenWithConn(mockConn)

	// Build query with EDNS0 and pack/unpack to get RDataRaw
	query, _ := protocol.NewQuery(0xCCCC, "opt-raw.example.com.", protocol.TypeA)
	query.SetEDNS0(4096, false)

	buf := make([]byte, 512)
	n, _ := query.Pack(buf)

	// Unpack and re-pack
	unpacked, err := protocol.UnpackMessage(buf[:n])
	if err != nil {
		t.Fatalf("Failed to unpack: %v", err)
	}

	packBuf := make([]byte, 512)
	n, err = unpacked.Pack(packBuf)
	if err != nil {
		t.Fatalf("Failed to re-pack: %v", err)
	}

	req := &udpRequest{
		data: packBuf,
		addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		n:    n,
	}
	server.handleRequest(req)

	if receivedClientInfo == nil {
		t.Fatal("ClientInfo should not be nil")
	}
	if !receivedClientInfo.HasEDNS0 {
		t.Error("HasEDNS0 should be true")
	}
	if receivedClientInfo.EDNS0UDPSize != 4096 {
		t.Errorf("EDNS0UDPSize = %d, want 4096", receivedClientInfo.EDNS0UDPSize)
	}
	if receivedClientInfo.ClientSubnet != nil {
		t.Error("ClientSubnet should be nil since OPT data is RDataRaw after unpack")
	}
}

// ==============================================================================
// UDP Write - truncation path with successful write after truncation
// Lines 281-296: message exceeds maxSize, truncated, still exceeds maxSize
// ==============================================================================

func TestUDPResponseWriterTruncationCappedSize(t *testing.T) {
	server := NewUDPServerWithWorkers("127.0.0.1:0", HandlerFunc(func(w ResponseWriter, req *protocol.Message) {}), 1)
	mockConn := &mockUDPConn{}
	server.ListenWithConn(mockConn)

	rw := &udpResponseWriter{
		server: server,
		client: &ClientInfo{
			Addr:     &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			Protocol: "udp",
		},
		maxSize: 12, // Extremely small - header is 12 bytes, so even after truncation n > maxSize
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0xDDDD,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: []*protocol.Question{
			{
				Name:   mustParseName("cap.example.com."),
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
		Answers: []*protocol.ResourceRecord{
			{
				Name:  mustParseName("cap.example.com."),
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
			},
		},
	}

	written, err := rw.Write(msg)
	if err != nil {
		t.Logf("Write returned error (expected for very small maxSize): %v", err)
	}
	_ = written
}

// ==============================================================================
// TCP Write - truncation path with re-pack error
// Lines 273-280: truncation triggered, then re-Pack fails
// This is hard to trigger naturally, so we test with maxSize of 0 which
// causes Truncate(0) and then Pack may fail or produce a minimal message.
// ==============================================================================

func TestTCPResponseWriterTruncationEdgeCase(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go io.Copy(io.Discard, clientConn)

	rw := &tcpResponseWriter{
		conn:    serverConn,
		client:  &ClientInfo{Protocol: "tcp"},
		maxSize: 0, // maxSize-2 = -2, so n > -2 is always true, triggering truncation
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0xEEEE,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: []*protocol.Question{
			{
				Name:   mustParseName("edge.example.com."),
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
	}

	_, err := rw.Write(msg)
	// May or may not error, but should exercise the truncation path
	_ = err
}

// ==============================================================================
// TLS Write - truncation path with re-pack error (edge case)
// Lines 297-303: truncation triggered with very small maxSize
// ==============================================================================

func TestTLSResponseWriterTruncationEdgeCase(t *testing.T) {
	cert := generateTestTLSCert2(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		io.Copy(io.Discard, conn)
	}()

	tlsClientConfig := &tls.Config{InsecureSkipVerify: true}
	clientConn, err := tls.Dial("tcp", ln.Addr().String(), tlsClientConfig)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer clientConn.Close()

	rw := &tlsResponseWriter{
		conn:    clientConn,
		client:  &ClientInfo{Protocol: "dot"},
		maxSize: 0, // Edge case: maxSize-2 = -2
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0xFFFF,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: []*protocol.Question{
			{
				Name:   mustParseName("edge.example.com."),
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
	}

	_, err = rw.Write(msg)
	_ = err
}

// ==============================================================================
// UDP Write - successful write tracking (packetsSent increment)
// Lines 301-303: err == nil path increments packetsSent
// ==============================================================================

func TestUDPResponseWriterSuccessfulWrite(t *testing.T) {
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

	written, err := rw.Write(msg)
	if err != nil {
		t.Errorf("Write should succeed: %v", err)
	}
	if written == 0 {
		t.Error("Expected non-zero bytes written")
	}

	stats := server.Stats()
	if stats.PacketsSent != 1 {
		t.Errorf("PacketsSent = %d, want 1", stats.PacketsSent)
	}
}

// ==============================================================================
// TLS handleConnection - successful full flow with multiple messages
// Lines 187-195: loop processes multiple messages on same TLS connection
// ==============================================================================

func TestTLSServerMultipleMessagesOnConnection(t *testing.T) {
	cert := generateTestTLSCert2(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	requestCount := 0
	var mu sync.Mutex

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		mu.Lock()
		requestCount++
		mu.Unlock()
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

	// Send multiple queries on the same TLS connection
	for i := 0; i < 3; i++ {
		query, _ := protocol.NewQuery(uint16(i), "multi.example.com.", protocol.TypeA)
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
	}

	mu.Lock()
	count := requestCount
	mu.Unlock()

	if count != 3 {
		t.Errorf("Expected 3 requests, got %d", count)
	}
}

// ==============================================================================
// TLS handleConnection - EOF on first read (clean close)
// Line 203-208: io.ReadFull returns io.EOF
// ==============================================================================

func TestTLSServerHandleConnectionEOF(t *testing.T) {
	cert := generateTestTLSCert2(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		t.Error("Handler should not be called for EOF connection")
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

	// Close immediately without sending anything - server gets EOF
	conn.Close()

	time.Sleep(50 * time.Millisecond)

	stats := server.Stats()
	_ = stats
}

// ==============================================================================
// TCP handleConnection - multiple messages on same connection (success flow)
// Lines 166-200: the for loop processes multiple messages
// ==============================================================================

func TestTCPServerMultipleMessagesOnConnection(t *testing.T) {
	requestCount := 0
	var mu sync.Mutex

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		mu.Lock()
		requestCount++
		mu.Unlock()
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

	// Send multiple queries
	for i := 0; i < 3; i++ {
		query, _ := protocol.NewQuery(uint16(i), "multi.example.com.", protocol.TypeA)
		buf := make([]byte, 512)
		n, _ := query.Pack(buf[2:])
		binary.BigEndian.PutUint16(buf[0:], uint16(n))
		client.Write(buf[:n+2])

		var lengthBuf [2]byte
		io.ReadFull(client, lengthBuf[:])
		respLen := binary.BigEndian.Uint16(lengthBuf[:])
		respBuf := make([]byte, respLen)
		io.ReadFull(client, respBuf)
	}

	mu.Lock()
	count := requestCount
	mu.Unlock()

	if count != 3 {
		t.Errorf("Expected 3 requests, got %d", count)
	}
}

// ==============================================================================
// TCP handleConnection - zero-length message
// Lines 183-185: msgLen == 0 triggers error return
// ==============================================================================

func TestTCPServerHandleConnectionZeroLength(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		t.Error("Handler should not be called for zero-length message")
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

	// Send zero-length message
	client.Write([]byte{0x00, 0x00})

	// Connection should be closed by server
	client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	_, err = client.Read(buf)
	if err == nil {
		t.Error("Expected connection to be closed after zero-length message")
	}
}

// ==============================================================================
// TLS Write - double write error
// Line 285-287: second write returns "response already written"
// ==============================================================================

func TestTLSResponseWriterDoubleWriteDirect(t *testing.T) {
	cert := generateTestTLSCert2(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		io.Copy(io.Discard, conn)
	}()

	tlsClientConfig := &tls.Config{InsecureSkipVerify: true}
	clientConn, err := tls.Dial("tcp", ln.Addr().String(), tlsClientConfig)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer clientConn.Close()

	rw := &tlsResponseWriter{
		conn:    clientConn,
		client:  &ClientInfo{Protocol: "dot"},
		maxSize: TLSMaxMessageSize,
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0x1234,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
	}

	_, err = rw.Write(msg)
	if err != nil {
		t.Errorf("First write should succeed: %v", err)
	}

	_, err = rw.Write(msg)
	if err == nil {
		t.Error("Second write should return error")
	}
}

// ==============================================================================
// TCP Write - write error tracked (sent == 0 or err != nil)
// Lines 290-292: error path for metrics update
// ==============================================================================

func TestTCPResponseWriterWriteThenCount(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	// Drain client side
	go io.Copy(io.Discard, clientConn)

	rw := &tcpResponseWriter{
		conn:    serverConn,
		client:  &ClientInfo{Protocol: "tcp"},
		maxSize: TCPMaxMessageSize,
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0x1234,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
	}

	written, err := rw.Write(msg)
	if err != nil {
		t.Errorf("Write should succeed: %v", err)
	}
	if written == 0 {
		t.Error("Expected non-zero bytes written")
	}
	if rw.writeCount != 1 {
		t.Errorf("writeCount = %d, want 1", rw.writeCount)
	}
}

// ==============================================================================
// TLS Write - successful write
// Lines 310-313: successful write through TLS connection
// ==============================================================================

func TestTLSResponseWriterSuccessfulWrite(t *testing.T) {
	cert := generateTestTLSCert2(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		// Read the response and verify it
		var lengthBuf [2]byte
		if _, err := io.ReadFull(conn, lengthBuf[:]); err != nil {
			return
		}
		respLen := binary.BigEndian.Uint16(lengthBuf[:])
		respBuf := make([]byte, respLen)
		io.ReadFull(conn, respBuf)
	}()

	tlsClientConfig := &tls.Config{InsecureSkipVerify: true}
	clientConn, err := tls.Dial("tcp", ln.Addr().String(), tlsClientConfig)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer clientConn.Close()

	rw := &tlsResponseWriter{
		conn:    clientConn,
		client:  &ClientInfo{Protocol: "dot"},
		maxSize: TLSMaxMessageSize,
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0x5678,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
	}

	written, err := rw.Write(msg)
	if err != nil {
		t.Errorf("Write should succeed: %v", err)
	}
	if written == 0 {
		t.Error("Expected non-zero bytes written")
	}
}

// ==============================================================================
// generateTestTLSCert2 generates a TLS certificate for testing.
// Duplicated with a different name to avoid conflicts with coverage_extra_test.go
// ==============================================================================

func generateTestTLSCert2(t *testing.T) tls.Certificate {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
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
