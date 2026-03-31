package server

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// TestUDPServerBasicQuery tests basic UDP query handling.
func TestUDPServerBasicQuery(t *testing.T) {
	// Create a simple handler that returns a canned response
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		// Create response
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: req.Questions,
		}

		// Add an answer for A queries
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

	// Create and start server
	server := NewUDPServer("127.0.0.1:0", handler)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	// Start serving in background
	go server.Serve()

	// Wait for server to be ready
	time.Sleep(10 * time.Millisecond)

	// Get server address
	addr := server.Addr()
	if addr == nil {
		t.Fatal("Server address is nil")
	}

	// Create a UDP client
	client, err := net.DialUDP("udp", nil, addr.(*net.UDPAddr))
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	// Create a query
	query, err := protocol.NewQuery(0x1234, "example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Failed to create query: %v", err)
	}

	// Pack the query
	buf := make([]byte, 512)
	n, err := query.Pack(buf)
	if err != nil {
		t.Fatalf("Failed to pack query: %v", err)
	}

	// Send query
	_, err = client.Write(buf[:n])
	if err != nil {
		t.Fatalf("Failed to send query: %v", err)
	}

	// Read response
	client.SetReadDeadline(time.Now().Add(time.Second))
	respBuf := make([]byte, 512)
	n, err = client.Read(respBuf)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	// Parse response
	resp, err := protocol.UnpackMessage(respBuf[:n])
	if err != nil {
		t.Fatalf("Failed to unpack response: %v", err)
	}

	// Verify response
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

// TestUDPServerWithEDNS0 tests UDP with EDNS0 OPT record.
func TestUDPServerWithEDNS0(t *testing.T) {
	infoCh := make(chan *ClientInfo, 1)

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		infoCh <- w.ClientInfo()

		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: req.Questions,
		}

		w.Write(resp)
	})

	server := NewUDPServer("127.0.0.1:0", handler)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(10 * time.Millisecond)

	client, err := net.DialUDP("udp", nil, server.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	// Create query with EDNS0
	query, err := protocol.NewQuery(0x5678, "test.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Failed to create query: %v", err)
	}
	query.SetEDNS0(4096, true)

	// Pack and send
	buf := make([]byte, 512)
	n, err := query.Pack(buf)
	if err != nil {
		t.Fatalf("Failed to pack query: %v", err)
	}

	_, err = client.Write(buf[:n])
	if err != nil {
		t.Fatalf("Failed to send query: %v", err)
	}

	// Read response
	client.SetReadDeadline(time.Now().Add(time.Second))
	respBuf := make([]byte, 512)
	n, err = client.Read(respBuf)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	// Verify EDNS0 was detected
	var receivedClientInfo *ClientInfo
	select {
	case receivedClientInfo = <-infoCh:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for handler")
	}

	if receivedClientInfo == nil {
		t.Fatal("ClientInfo should not be nil")
	}

	if !receivedClientInfo.HasEDNS0 {
		t.Error("HasEDNS0 should be true")
	}

	if receivedClientInfo.EDNS0UDPSize != 4096 {
		t.Errorf("EDNS0UDPSize should be 4096, got %d", receivedClientInfo.EDNS0UDPSize)
	}

	// Parse and verify response
	resp, err := protocol.UnpackMessage(respBuf[:n])
	if err != nil {
		t.Fatalf("Failed to unpack response: %v", err)
	}

	if resp.Header.ID != 0x5678 {
		t.Errorf("Response ID mismatch: got %d, want %d", resp.Header.ID, 0x5678)
	}
}

// TestUDPServerInvalidMessage tests that invalid messages don't crash the server.
func TestUDPServerInvalidMessage(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		// Should not be called for invalid messages
		t.Error("Handler should not be called for invalid message")
	})

	server := NewUDPServer("127.0.0.1:0", handler)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(10 * time.Millisecond)

	client, err := net.DialUDP("udp", nil, server.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	// Send garbage data
	_, err = client.Write([]byte{0x00, 0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("Failed to send garbage: %v", err)
	}

	// Wait a bit and check that server is still running (didn't crash)
	time.Sleep(50 * time.Millisecond)

	// Check stats - should have received packet but not sent response
	stats := server.Stats()
	if stats.PacketsReceived != 1 {
		t.Errorf("Expected 1 packet received, got %d", stats.PacketsReceived)
	}
}

// TestUDPServerMultipleQueries tests multiple sequential queries.
func TestUDPServerMultipleQueries(t *testing.T) {
	var requestCount atomic.Int32

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		requestCount.Add(1)
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: req.Questions,
		}
		w.Write(resp)
	})

	server := NewUDPServer("127.0.0.1:0", handler)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(10 * time.Millisecond)

	client, err := net.DialUDP("udp", nil, server.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	// Send multiple queries
	for i := 0; i < 10; i++ {
		query, _ := protocol.NewQuery(uint16(i), "example.com.", protocol.TypeA)
		buf := make([]byte, 512)
		n, _ := query.Pack(buf)
		client.Write(buf[:n])
	}

	// Read all responses
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	for i := 0; i < 10; i++ {
		respBuf := make([]byte, 512)
		_, err := client.Read(respBuf)
		if err != nil {
			t.Fatalf("Failed to read response %d: %v", i, err)
		}
	}

	if requestCount.Load() != 10 {
		t.Errorf("Expected 10 requests, got %d", requestCount.Load())
	}
}

// TestResponseSizeLimit tests the response size limit calculation.
func TestResponseSizeLimit(t *testing.T) {
	tests := []struct {
		name     string
		client   *ClientInfo
		expected int
	}{
		{
			name:     "nil client",
			client:   nil,
			expected: 512,
		},
		{
			name: "TCP client",
			client: &ClientInfo{
				Protocol: "tcp",
				HasEDNS0: true,
				EDNS0UDPSize: 8192,
			},
			expected: 65535,
		},
		{
			name: "UDP without EDNS0",
			client: &ClientInfo{
				Protocol: "udp",
				HasEDNS0: false,
			},
			expected: 512,
		},
		{
			name: "UDP with EDNS0 small",
			client: &ClientInfo{
				Protocol:     "udp",
				HasEDNS0:     true,
				EDNS0UDPSize: 1024,
			},
			expected: 1024,
		},
		{
			name: "UDP with EDNS0 large (capped)",
			client: &ClientInfo{
				Protocol:     "udp",
				HasEDNS0:     true,
				EDNS0UDPSize: 8192,
			},
			expected: 4096, // Should be capped
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ResponseSizeLimit(tt.client)
			if result != tt.expected {
				t.Errorf("ResponseSizeLimit() = %d, want %d", result, tt.expected)
			}
		})
	}
}

// TestClientInfoIP tests the ClientInfo.IP() method.
func TestClientInfoIP(t *testing.T) {
	tests := []struct {
		name     string
		client   *ClientInfo
		expected string
	}{
		{
			name:     "nil client",
			client:   nil,
			expected: "",
		},
		{
			name:     "nil addr",
			client:   &ClientInfo{},
			expected: "",
		},
		{
			name: "UDP addr",
			client: &ClientInfo{
				Addr: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 53},
			},
			expected: "192.168.1.1",
		},
		{
			name: "TCP addr",
			client: &ClientInfo{
				Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 53},
			},
			expected: "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.client.IP()
			var resultStr string
			if result != nil {
				resultStr = result.String()
			}
			if resultStr != tt.expected {
				t.Errorf("IP() = %s, want %s", resultStr, tt.expected)
			}
		})
	}
}

// TestTruncateRRSet tests the truncateRRSet function.
func TestTruncateRRSet(t *testing.T) {
	name, _ := protocol.ParseName("example.com.")

	tests := []struct {
		name     string
		answers  []*protocol.ResourceRecord
		maxSize  int
		expected int // expected number of records
	}{
		{
			name:     "empty answers",
			answers:  nil,
			maxSize:  512,
			expected: 0,
		},
		{
			name:     "zero max size",
			answers:  []*protocol.ResourceRecord{{Name: name, Type: protocol.TypeA, Data: &protocol.RDataA{}}},
			maxSize:  0,
			expected: 0,
		},
		{
			name:     "negative max size",
			answers:  []*protocol.ResourceRecord{{Name: name, Type: protocol.TypeA, Data: &protocol.RDataA{}}},
			maxSize:  -1,
			expected: 0,
		},
		{
			name: "nil data in answer",
			answers: []*protocol.ResourceRecord{
				{Name: name, Type: protocol.TypeA, Data: nil},
			},
			maxSize:  512,
			expected: 0,
		},
		{
			name: "single small record",
			answers: []*protocol.ResourceRecord{
				{Name: name, Type: protocol.TypeA, Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}},
			},
			maxSize:  512,
			expected: 1,
		},
		{
			name: "multiple records small max",
			answers: []*protocol.ResourceRecord{
				{Name: name, Type: protocol.TypeA, Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}},
				{Name: name, Type: protocol.TypeA, Data: &protocol.RDataA{Address: [4]byte{5, 6, 7, 8}}},
			},
			maxSize:  30, // Small enough to only fit one
			expected: 1,
		},
		{
			name: "multiple records fit all",
			answers: []*protocol.ResourceRecord{
				{Name: name, Type: protocol.TypeA, Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}},
				{Name: name, Type: protocol.TypeA, Data: &protocol.RDataA{Address: [4]byte{5, 6, 7, 8}}},
			},
			maxSize:  512,
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateRRSet(tt.answers, tt.maxSize)
			if len(result) != tt.expected {
				t.Errorf("truncateRRSet() returned %d records, want %d", len(result), tt.expected)
			}
		})
	}
}

// TestUDPResponseWriterDoubleWrite tests that writing twice returns an error.
func TestUDPResponseWriterDoubleWrite(t *testing.T) {
	var called atomic.Int32
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
		}

		// First write should succeed
		_, err := w.Write(resp)
		if err != nil {
			t.Errorf("First write failed: %v", err)
		}

		// Second write should fail
		_, err = w.Write(resp)
		if err == nil {
			t.Error("Second write should return error")
		}
		called.Add(1)
	})

	server := NewUDPServer("127.0.0.1:0", handler)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(10 * time.Millisecond)

	addr := server.Addr()
	client, err := net.DialUDP("udp", nil, addr.(*net.UDPAddr))
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	query, _ := protocol.NewQuery(0x1234, "example.com.", protocol.TypeA)
	buf := make([]byte, 512)
	n, _ := query.Pack(buf)
	client.Write(buf[:n])

	client.SetReadDeadline(time.Now().Add(time.Second))
	respBuf := make([]byte, 512)
	client.Read(respBuf)

	if called.Load() != 1 {
		t.Errorf("Handler called %d times, want 1", called.Load())
	}
}

// TestUDPServerStats tests the Stats method.
func TestUDPServerStats(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
		}
		w.Write(resp)
	})

	server := NewUDPServer("127.0.0.1:0", handler)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	// Check initial stats
	stats := server.Stats()
	if stats.Workers <= 0 {
		t.Errorf("Initial workers = %d, want > 0", stats.Workers)
	}

	go server.Serve()
	time.Sleep(10 * time.Millisecond)

	// Get server address and query it
	addr := server.Addr()
	client, err := net.DialUDP("udp", nil, addr.(*net.UDPAddr))
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	query, _ := protocol.NewQuery(0x1234, "example.com.", protocol.TypeA)
	buf := make([]byte, 512)
	n, _ := query.Pack(buf)
	client.Write(buf[:n])

	client.SetReadDeadline(time.Now().Add(time.Second))
	respBuf := make([]byte, 512)
	client.Read(respBuf)

	// Check stats after query
	stats = server.Stats()
	if stats.PacketsReceived < 1 {
		t.Errorf("PacketsReceived = %d, want at least 1", stats.PacketsReceived)
	}
	if stats.PacketsSent < 1 {
		t.Errorf("PacketsSent = %d, want at least 1", stats.PacketsSent)
	}
}