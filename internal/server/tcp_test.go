package server

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ecostack/nothingdns/internal/protocol"
)

// TestTCPServerBasicQuery tests basic TCP query handling.
func TestTCPServerBasicQuery(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: req.Questions,
		}

		if len(req.Questions) > 0 && req.Questions[0].QType == protocol.TypeA {
			resp.AddAnswer(&protocol.ResourceRecord{
				Name:  req.Questions[0].Name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data: &protocol.RDataA{
					Address: [4]byte{127, 0, 0, 1},
				},
			})
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

	// Create query
	query, err := protocol.NewQuery(0x1234, "example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Failed to create query: %v", err)
	}

	// Pack query
	buf := make([]byte, 512)
	n, err := query.Pack(buf[2:])
	if err != nil {
		t.Fatalf("Failed to pack query: %v", err)
	}
	binary.BigEndian.PutUint16(buf[0:], uint16(n))

	// Send query
	_, err = client.Write(buf[:n+2])
	if err != nil {
		t.Fatalf("Failed to send query: %v", err)
	}

	// Read length prefix
	var lengthBuf [2]byte
	_, err = io.ReadFull(client, lengthBuf[:])
	if err != nil {
		t.Fatalf("Failed to read length: %v", err)
	}
	respLen := binary.BigEndian.Uint16(lengthBuf[:])

	// Read response
	respBuf := make([]byte, respLen)
	_, err = io.ReadFull(client, respBuf)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	// Parse response
	resp, err := protocol.UnpackMessage(respBuf)
	if err != nil {
		t.Fatalf("Failed to unpack response: %v", err)
	}

	if resp.Header.ID != query.Header.ID {
		t.Errorf("Response ID mismatch: got %d, want %d", resp.Header.ID, query.Header.ID)
	}

	if !resp.Header.Flags.QR {
		t.Error("Response should have QR=1")
	}

	if len(resp.Answers) != 1 {
		t.Errorf("Expected 1 answer, got %d", len(resp.Answers))
	}
}

// TestTCPServerMultipleQueries tests multiple queries on same connection.
func TestTCPServerMultipleQueries(t *testing.T) {
	requestCount := 0

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		requestCount++
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

	// Send multiple queries
	for i := 0; i < 5; i++ {
		query, _ := protocol.NewQuery(uint16(i), "example.com.", protocol.TypeA)
		buf := make([]byte, 512)
		n, _ := query.Pack(buf[2:])
		binary.BigEndian.PutUint16(buf[0:], uint16(n))
		client.Write(buf[:n+2])
	}

	// Read all responses
	for i := 0; i < 5; i++ {
		var lengthBuf [2]byte
		_, err := io.ReadFull(client, lengthBuf[:])
		if err != nil {
			t.Fatalf("Failed to read length %d: %v", i, err)
		}
		respLen := binary.BigEndian.Uint16(lengthBuf[:])

		respBuf := make([]byte, respLen)
		_, err = io.ReadFull(client, respBuf)
		if err != nil {
			t.Fatalf("Failed to read response %d: %v", i, err)
		}
	}

	if requestCount != 5 {
		t.Errorf("Expected 5 requests, got %d", requestCount)
	}
}

// TestTCPServerInvalidLength tests handling of invalid length prefix.
func TestTCPServerInvalidLength(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
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

	// Send length prefix for zero-length message
	client.Write([]byte{0x00, 0x00})

	// Connection should be closed by server
	client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	_, err = client.Read(buf)
	if err == nil {
		t.Error("Expected connection to be closed after invalid message")
	}
}

// TestTCPServerConnectionLimit tests connection limiting.
func TestTCPServerConnectionLimit(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		time.Sleep(100 * time.Millisecond) // Slow handler
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

	// Create many connections
	connections := make([]net.Conn, 0, 20)
	for i := 0; i < 20; i++ {
		client, err := net.Dial("tcp", server.Addr().String())
		if err != nil {
			// Expected to fail after connection limit
			break
		}
		connections = append(connections, client)
	}

	// Close all connections
	for _, c := range connections {
		c.Close()
	}

	// Verify server is still running
	client, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Errorf("Server should still accept connections: %v", err)
	} else {
		client.Close()
	}
}

// TestTCPServerStats tests server statistics.
func TestTCPServerStats(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
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

	// Send a query
	client, _ := net.Dial("tcp", server.Addr().String())
	query, _ := protocol.NewQuery(0x1234, "test.com.", protocol.TypeA)
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
	client.Close()

	// Check stats
	stats := server.Stats()
	if stats.MessagesReceived != 1 {
		t.Errorf("Expected 1 message received, got %d", stats.MessagesReceived)
	}
	if stats.ConnectionsAccepted != 1 {
		t.Errorf("Expected 1 connection accepted, got %d", stats.ConnectionsAccepted)
	}
	if stats.Workers == 0 {
		t.Error("Workers should be > 0")
	}
}

// TestTCPServerClientInfo tests ClientInfo is populated correctly.
func TestTCPServerClientInfo(t *testing.T) {
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

	client, _ := net.Dial("tcp", server.Addr().String())
	query, _ := protocol.NewQuery(0x1234, "test.com.", protocol.TypeA)
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
	client.Close()

	// Verify ClientInfo
	if receivedClientInfo == nil {
		t.Fatal("ClientInfo should not be nil")
	}

	if receivedClientInfo.Protocol != "tcp" {
		t.Errorf("Protocol should be tcp, got %s", receivedClientInfo.Protocol)
	}

	if receivedClientInfo.Addr == nil {
		t.Error("Addr should not be nil")
	}
}
