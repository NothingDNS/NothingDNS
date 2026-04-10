package server

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// mustParseName is a helper that panics on parse failure.
func mustParseName(s string) *protocol.Name {
	n, err := protocol.ParseName(s)
	if err != nil {
		panic(err)
	}
	return n
}

// TestNewTCPServerWithWorkers tests TCP server creation with different worker counts.
func TestNewTCPServerWithWorkers(t *testing.T) {
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
			server := NewTCPServerWithWorkers("127.0.0.1:0", nil, tt.workers)
			if server == nil {
				t.Fatal("Server should not be nil")
			}
			if server.workers < tt.wantMin {
				t.Errorf("Workers = %d, want >= %d", server.workers, tt.wantMin)
			}
		})
	}
}

// TestTCPServerServeWithoutListen tests Serve error when not listening.
func TestTCPServerServeWithoutListen(t *testing.T) {
	server := NewTCPServer("127.0.0.1:0", nil)
	err := server.Serve()
	if err == nil {
		t.Error("Serve should return error when not listening")
	}
}

// TestTCPServerAddrNil tests Addr when listener is nil.
func TestTCPServerAddrNil(t *testing.T) {
	server := NewTCPServer("127.0.0.1:0", nil)
	if server.Addr() != nil {
		t.Error("Addr should return nil when listener is nil")
	}
}

// TestTCPServerStopNilListener tests Stop when listener is nil.
func TestTCPServerStopNilListener(t *testing.T) {
	server := NewTCPServer("127.0.0.1:0", nil)
	err := server.Stop()
	if err != nil {
		t.Errorf("Stop should not return error: %v", err)
	}
}

// TestTCPServerEDNS0ClientSubnet tests EDNS0 client subnet handling in TCP.
func TestTCPServerEDNS0ClientSubnet(t *testing.T) {
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

	server := NewTCPServer("127.0.0.1:0", handler)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(10 * time.Millisecond)

	client, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	// Create query with EDNS0 client subnet
	query, _ := protocol.NewQuery(0x1234, "test.com.", protocol.TypeA)
	query.SetEDNS0(4096, false)

	// Add ECS option
	opt := &protocol.RDataOPT{Options: []protocol.EDNS0Option{
		{
			Code: protocol.OptionCodeClientSubnet,
			Data: []byte{0x00, 0x01, 0x18, 0x00, 192, 168, 1, 0}, // /24 subnet
		},
	}}
	query.Additionals = []*protocol.ResourceRecord{
		{
			Name:  mustParseName("."),
			Type:  protocol.TypeOPT,
			Class: 4096,
			Data:  opt,
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

	// Verify ClientInfo
	if receivedClientInfo == nil {
		t.Fatal("ClientInfo should not be nil")
	}
	if !receivedClientInfo.HasEDNS0 {
		t.Error("HasEDNS0 should be true")
	}
}

// TestTCPServerLargeMessage tests handling of large messages.
func TestTCPServerLargeMessage(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: req.Questions,
		}
		w.Write(resp)
	})

	server := NewTCPServer("127.0.0.1:0", handler)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(10 * time.Millisecond)

	client, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	// Create a query
	query, _ := protocol.NewQuery(0x1234, "example.com.", protocol.TypeA)
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

	// Verify
	if respLen == 0 {
		t.Error("Response should have content")
	}
}

// TestTCPServerMalformedMessage tests handling of malformed DNS messages.
func TestTCPServerMalformedMessage(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		t.Error("Handler should not be called for malformed message")
	})

	server := NewTCPServer("127.0.0.1:0", handler)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(10 * time.Millisecond)

	client, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	// Send malformed message (valid length, invalid DNS)
	data := make([]byte, 50)
	binary.BigEndian.PutUint16(data[0:2], 48) // Length = 48
	for i := 2; i < 50; i++ {
		data[i] = 0xFF // Invalid data
	}
	client.Write(data)

	// Connection should be closed
	time.Sleep(50 * time.Millisecond)
}

// TestTCPServerOversizedLength tests handling of oversized length prefix.
func TestTCPServerOversizedLength(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		w.Write(&protocol.Message{})
	})

	server := NewTCPServer("127.0.0.1:0", handler)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(10 * time.Millisecond)

	client, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	// Send max length (will timeout waiting for data)
	data := []byte{0xFF, 0xFF} // Length = 65535
	client.Write(data)

	// Connection should be closed
	client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1)
	_, err = client.Read(buf)
	if err == nil {
		t.Error("Expected connection to be closed")
	}
}

// TestUDPServerAddr tests UDP server address.
func TestUDPServerAddr(t *testing.T) {
	server := NewUDPServer("127.0.0.1:0", nil)
	if server.Addr() != nil {
		t.Error("Addr should be nil before Listen")
	}

	if err := server.Listen(); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer server.Stop()

	if server.Addr() == nil {
		t.Error("Addr should not be nil after Listen")
	}
}

// TestUDPServerStopWithoutListen tests UDP server stop without listen.
func TestUDPServerStopWithoutListen(t *testing.T) {
	server := NewUDPServer("127.0.0.1:0", nil)
	// Stop should not panic
	server.Stop()
}

// TestUDPServerListenWithConn tests ListenWithConn.
func TestUDPServerListenWithConn(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		w.Write(&protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
		})
	})

	server := NewUDPServer("127.0.0.1:0", handler)

	// Create a mock connection
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("Failed to create UDP connection: %v", err)
	}
	defer conn.Close()

	server.ListenWithConn(conn)

	if server.conn == nil {
		t.Error("Connection should be set")
	}
}

// TestUDPResponseWriterMaxSize tests MaxSize for UDP.
func TestUDPResponseWriterMaxSize(t *testing.T) {
	rw := &udpResponseWriter{
		maxSize: 512,
	}

	if rw.MaxSize() != 512 {
		t.Errorf("MaxSize() = %d, want 512", rw.MaxSize())
	}
}

// TestUDPResponseWriterClientInfo tests ClientInfo for UDP.
func TestUDPResponseWriterClientInfo(t *testing.T) {
	client := &ClientInfo{
		Protocol: "udp",
	}
	rw := &udpResponseWriter{
		client: client,
	}

	if rw.ClientInfo() != client {
		t.Error("ClientInfo should return the client info")
	}
}

// TestUDPServerConstants tests UDP server constants.
func TestUDPServerConstants(t *testing.T) {
	if DefaultUDPPayloadSize != 512 {
		t.Errorf("DefaultUDPPayloadSize = %d, want 512", DefaultUDPPayloadSize)
	}
	if MaxUDPPayloadSize != 4096 {
		t.Errorf("MaxUDPPayloadSize = %d, want 4096", MaxUDPPayloadSize)
	}
	if UDPReadBufferSize != 4096 {
		t.Errorf("UDPReadBufferSize = %d, want 4096", UDPReadBufferSize)
	}
}

// TestTCPResponseWriterMaxSize tests MaxSize for TCP.
func TestTCPResponseWriterMaxSize(t *testing.T) {
	rw := &tcpResponseWriter{
		maxSize: 65535,
	}

	if rw.MaxSize() != 65535 {
		t.Errorf("MaxSize() = %d, want 65535", rw.MaxSize())
	}
}

// TestTCPResponseWriterClientInfo tests ClientInfo for TCP.
func TestTCPResponseWriterClientInfo(t *testing.T) {
	client := &ClientInfo{
		Protocol: "tcp",
	}
	rw := &tcpResponseWriter{
		client: client,
	}

	if rw.ClientInfo() != client {
		t.Error("ClientInfo should return the client info")
	}
}

// TestTCPListenWithListener tests ListenWithListener for TCP.
func TestTCPListenWithListener(t *testing.T) {
	server := NewTCPServer("127.0.0.1:0", nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer ln.Close()

	server.ListenWithListener(ln)

	if server.Listener() == nil {
		t.Error("Listener should be set")
	}
}
