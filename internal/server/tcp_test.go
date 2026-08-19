package server

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
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

	if got := requestCount.Load(); got != 5 {
		t.Errorf("Expected 5 requests, got %d", got)
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

func TestTCPServerDecrementIPConnDeletesZeroCount(t *testing.T) {
	server := NewTCPServer("127.0.0.1:0", nil)
	const ip = "192.0.2.1"

	server.ipConnCount[ip] = 2
	server.decrementIPConn(ip)
	if got := server.ipConnCount[ip]; got != 1 {
		t.Fatalf("count after first decrement = %d, want 1", got)
	}

	server.decrementIPConn(ip)
	if _, ok := server.ipConnCount[ip]; ok {
		t.Fatal("expected per-IP connection counter entry to be deleted at zero")
	}

	server.decrementIPConn(ip)
	if _, ok := server.ipConnCount[ip]; ok {
		t.Fatal("unexpected counter entry after decrementing absent IP")
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

// newLargeTestResponse builds a response whose wire form exceeds the pooled
// frame buffer (defaultFrameBufSize / MaxUDPPayloadSize), to exercise the
// rare buffer-too-small fallback in the response write paths.
func newLargeTestResponse(t *testing.T, answers int) *protocol.Message {
	t.Helper()

	q, err := protocol.NewQuestion("oversized.example.com.", protocol.TypeA, protocol.ClassIN)
	if err != nil {
		t.Fatalf("NewQuestion failed: %v", err)
	}
	resp := &protocol.Message{
		Header:    protocol.Header{ID: 0xFA11, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Questions: []*protocol.Question{q},
	}
	name := mustParseName("oversized.example.com.")
	for i := 0; i < answers; i++ {
		resp.AddAnswer(&protocol.ResourceRecord{
			Name:  name,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, byte(i)}},
		})
	}
	return resp
}

// TestPackFramedDNSPayloadFallbackLargerThanFrameBuf exercises the rare
// path: the response does not fit the supplied (pool-sized) frame buffer,
// so packFramedDNSPayload must detect ErrBufferTooSmall, allocate an
// exact-size frame, and pack the full message into it untruncated.
func TestPackFramedDNSPayloadFallbackLargerThanFrameBuf(t *testing.T) {
	msg := newLargeTestResponse(t, 300)
	if msg.WireLength() <= defaultFrameBufSize {
		t.Fatalf("test response wire length = %d, want > %d", msg.WireLength(), defaultFrameBufSize)
	}

	frameBuf := make([]byte, defaultFrameBufSize)
	frame, n, err := packFramedDNSPayload(msg, frameBuf, TCPMaxMessageSize, "TCP")
	if err != nil {
		t.Fatalf("packFramedDNSPayload failed: %v", err)
	}
	if n <= len(frameBuf)-2 {
		t.Fatalf("payload length %d fits the original buffer; fallback not exercised", n)
	}
	if &frame[0] == &frameBuf[0] {
		t.Fatal("expected a fallback-allocated frame, got the original buffer")
	}
	if len(frame) < n+2 {
		t.Fatalf("returned frame too short for payload+prefix: len=%d, need %d", len(frame), n+2)
	}

	got, err := protocol.UnpackMessage(frame[2 : 2+n])
	if err != nil {
		t.Fatalf("fallback-packed response unpack failed: %v", err)
	}
	if got.Header.Flags.TC {
		t.Fatal("response within maxSize must not be truncated")
	}
	if len(got.Answers) != 300 {
		t.Fatalf("answer count = %d, want 300", len(got.Answers))
	}
}

// TestPackFramedDNSPayloadNoTCForAdditionalOnly verifies RFC 2181 §9:
// dropping only Additional-section records (OPT, glue) must NOT set the TC
// bit. Regression: packFramedDNSPayload pre-set msg.Header.Flags.TC = true
// before calling Truncate, so any TCP response that needed only its
// Additional section trimmed went out with TC=1 even though no required
// data was omitted — inconsistent with the UDP writer, which relies on
// Truncate's own RFC 2181 logic.
func TestPackFramedDNSPayloadNoTCForAdditionalOnly(t *testing.T) {
	msg := newLargeTestResponse(t, 3)
	// Add a large Additional record so the message exceeds maxSize only
	// once the Additional section is included; the question + 3 answers
	// must fit on their own.
	bigName := mustParseName("additional.example.com.")
	// TXT rdata strings are capped at 255 bytes each and labels at 63;
	// build a record that is large on the wire but valid.
	var bigStrings []string
	for i := 0; i < 12; i++ {
		bigStrings = append(bigStrings, strings.Repeat("x", 63))
	}
	msg.AddAdditional(&protocol.ResourceRecord{
		Name:  bigName,
		Type:  protocol.TypeTXT,
		Class: protocol.ClassIN,
		TTL:   60,
		Data:  &protocol.RDataTXT{Strings: bigStrings},
	})

	frameBuf := make([]byte, defaultFrameBufSize)
	// maxSize large enough for question + answers but not + additional.
	maxSize := msg.WireLength() - 500
	frame, n, err := packFramedDNSPayload(msg, frameBuf, maxSize, "TCP")
	if err != nil {
		t.Fatalf("packFramedDNSPayload failed: %v", err)
	}
	if n > maxSize {
		t.Fatalf("payload length %d exceeds maxSize %d", n, maxSize)
	}

	got, err := protocol.UnpackMessage(frame[2 : 2+n])
	if err != nil {
		t.Fatalf("packed response unpack failed: %v", err)
	}
	if got.Header.Flags.TC {
		t.Fatal("TC bit set after dropping only Additional records (RFC 2181 §9)")
	}
	if len(got.Answers) != 3 {
		t.Fatalf("answer count = %d, want 3 (answers must survive)", len(got.Answers))
	}
}

// TestPackFramedDNSPayloadFallbackThenTruncate verifies that when the
// response both exceeds the frame buffer and the transport maxSize, the
// fallback frame is used and record-boundary truncation still applies.
func TestPackFramedDNSPayloadFallbackThenTruncate(t *testing.T) {
	msg := newLargeTestResponse(t, 300)
	frameBuf := make([]byte, defaultFrameBufSize)

	const maxSize = 2000
	frame, n, err := packFramedDNSPayload(msg, frameBuf, maxSize, "TCP")
	if err != nil {
		t.Fatalf("packFramedDNSPayload failed: %v", err)
	}
	if n > maxSize {
		t.Fatalf("payload length %d exceeds maxSize %d after truncation", n, maxSize)
	}

	got, err := protocol.UnpackMessage(frame[2 : 2+n])
	if err != nil {
		t.Fatalf("truncated response unpack failed: %v", err)
	}
	if !got.Header.Flags.TC {
		t.Fatal("expected TC bit on truncated response")
	}
	if len(got.Answers) == 0 || len(got.Answers) >= 300 {
		t.Fatalf("answer count after truncation = %d, want record-boundary reduction", len(got.Answers))
	}
}

// TestTCPServerLargeResponseExceedsPooledBuffer runs the fallback end to
// end: the handler writes a response larger than the pooled frame buffer
// and the client must receive it whole over the framed TCP stream.
func TestTCPServerLargeResponseExceedsPooledBuffer(t *testing.T) {
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		resp := newLargeTestResponse(t, 300)
		resp.Header.ID = req.Header.ID
		if _, err := w.Write(resp); err != nil {
			t.Errorf("Write failed: %v", err)
		}
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

	query, err := protocol.NewQuery(0x4242, "oversized.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Failed to create query: %v", err)
	}
	buf := make([]byte, 512)
	n, err := query.Pack(buf[2:])
	if err != nil {
		t.Fatalf("Failed to pack query: %v", err)
	}
	binary.BigEndian.PutUint16(buf[0:], uint16(n))
	if _, err := client.Write(buf[:n+2]); err != nil {
		t.Fatalf("Failed to send query: %v", err)
	}

	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	var lengthBuf [2]byte
	if _, err := io.ReadFull(client, lengthBuf[:]); err != nil {
		t.Fatalf("Failed to read length: %v", err)
	}
	respLen := binary.BigEndian.Uint16(lengthBuf[:])
	if int(respLen) <= defaultFrameBufSize-2 {
		t.Fatalf("response length %d fits the pooled buffer; fallback not exercised", respLen)
	}
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(client, respBuf); err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	resp, err := protocol.UnpackMessage(respBuf)
	if err != nil {
		t.Fatalf("Failed to unpack response: %v", err)
	}
	if resp.Header.Flags.TC {
		t.Fatal("large TCP response must not be truncated below TCPMaxMessageSize")
	}
	if len(resp.Answers) != 300 {
		t.Fatalf("answer count = %d, want 300", len(resp.Answers))
	}
}
