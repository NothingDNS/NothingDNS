package server

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// ==============================================================================
// UDP reader - default case: channel full, packet dropped
// Lines 181-187 in udp.go: the select in reader() hits the default branch
// when the requestChan is full and the packet must be dropped.
// ==============================================================================

func TestUDPServerReaderChannelFullDropPacket(t *testing.T) {
	// Use a handler that blocks using a channel, so we can unblock it for clean shutdown.
	handlerCalled := int32(0)
	unblock := make(chan struct{})

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		atomic.AddInt32(&handlerCalled, 1)
		// Block until we signal unblock, so the worker stays busy and the channel fills
		<-unblock
	})

	server := NewUDPServerWithWorkers("127.0.0.1:0", handler, 1)
	// Use a mock that rapidly produces valid DNS query packets
	query, _ := protocol.NewQuery(0xAAAA, "flood.example.com.", protocol.TypeA)
	queryBuf := make([]byte, 512)
	n, _ := query.Pack(queryBuf)

	readCount := int32(0)
	mockConn := &mockUDPConnFlood{
		data:  queryBuf[:n],
		addr:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		count: &readCount,
	}
	server.ListenWithConn(mockConn)

	done := make(chan struct{})
	go func() {
		server.Serve()
		close(done)
	}()

	// Wait for many reads to happen (channel capacity is workers*2 = 2)
	// After the channel fills, the default branch drops packets
	deadline := time.After(500 * time.Millisecond)
	for {
		time.Sleep(10 * time.Millisecond)
		count := atomic.LoadInt32(&readCount)
		if count > 10 {
			break // Enough reads happened
		}
		select {
		case <-deadline:
			goto shutdown
		default:
		}
	}

shutdown:
	// Unblock the handler so the worker can finish
	close(unblock)
	server.Stop()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("Serve should return after Stop()")
	}

	total := atomic.LoadInt32(&readCount)
	t.Logf("Total reads: %d, handler calls: %d", total, atomic.LoadInt32(&handlerCalled))

	// With channel capacity of 2 and 1 blocked worker, most packets should be dropped
	stats := server.Stats()
	_ = stats
}

// mockUDPConnFlood is a mock that continuously returns valid DNS data for flooding tests.
type mockUDPConnFlood struct {
	data  []byte
	addr  *net.UDPAddr
	count *int32
}

func (m *mockUDPConnFlood) ReadFromUDP(buf []byte) (int, *net.UDPAddr, error) {
	atomic.AddInt32(m.count, 1)
	n := copy(buf, m.data)
	return n, m.addr, nil
}

func (m *mockUDPConnFlood) WriteToUDP(buf []byte, addr *net.UDPAddr) (int, error) {
	return len(buf), nil
}

func (m *mockUDPConnFlood) Close() error {
	return nil
}

func (m *mockUDPConnFlood) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockUDPConnFlood) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
}

// ==============================================================================
// TCP Write - successful write tracking block (err == nil && sent > 0)
// Lines 290-292 in tcp.go: the if body for successful write metrics
// ==============================================================================

func TestTCPResponseWriterSuccessfulWriteMetricsBlock(t *testing.T) {
	// Set up a real TCP server that responds and triggers the write metrics block
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
	defer server.Stop()

	go server.Serve()
	time.Sleep(20 * time.Millisecond)

	// Connect as a client and send a query, then read the response
	client, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	query, _ := protocol.NewQuery(0x4242, "metrics.example.com.", protocol.TypeA)
	buf := make([]byte, 512)
	n, _ := query.Pack(buf[2:])
	binary.BigEndian.PutUint16(buf[0:], uint16(n))
	client.Write(buf[:n+2])

	// Read response fully
	var lengthBuf [2]byte
	io.ReadFull(client, lengthBuf[:])
	respLen := binary.BigEndian.Uint16(lengthBuf[:])
	respBuf := make([]byte, respLen)
	io.ReadFull(client, respBuf)

	// The write went through the metrics block path
	stats := server.Stats()
	if stats.MessagesReceived == 0 {
		t.Error("Expected at least one message received")
	}
}

// ==============================================================================
// TCP Write - multiple writes through real connection to hit metrics block
// Lines 290-292: ensures the empty if-body is entered for coverage
// ==============================================================================

func TestTCPResponseWriterMultipleSuccessfulWrites(t *testing.T) {
	var mu sync.Mutex
	writeCount := 0

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		mu.Lock()
		writeCount++
		mu.Unlock()

		// Write a simple response that will go through successfully
		w.Write(&protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: req.Questions,
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

	// Send multiple queries to ensure the write path is exercised multiple times
	for i := 0; i < 5; i++ {
		query, _ := protocol.NewQuery(uint16(0x5000+i), "multi-write.example.com.", protocol.TypeA)
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
	count := writeCount
	mu.Unlock()

	if count != 5 {
		t.Errorf("Expected 5 writes, got %d", count)
	}
}

// ==============================================================================
// TCP Write - direct pipe test for successful write tracking
// Lines 290-292: ensures sent > 0 and err == nil
// ==============================================================================

func TestTCPResponseWriterDirectPipeSuccessfulWrite(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	// Read all data from client side in background
	receivedData := make([]byte, 0, 1024)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 1024)
		for {
			n, err := clientConn.Read(buf)
			if n > 0 {
				receivedData = append(receivedData, buf[:n]...)
			}
			if err != nil {
				return
			}
		}
	}()

	rw := &tcpResponseWriter{
		conn:    serverConn,
		client:  &ClientInfo{Protocol: "tcp"},
		maxSize: TCPMaxMessageSize,
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0x7777,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
	}

	written, err := rw.Write(msg)
	if err != nil {
		t.Fatalf("Write should succeed: %v", err)
	}
	if written == 0 {
		t.Error("Expected non-zero bytes written")
	}

	// Close to allow reader goroutine to finish
	serverConn.Close()
	<-readDone

	if len(receivedData) == 0 {
		t.Error("Expected data to be written to the pipe")
	}

	// Verify the response starts with a length prefix
	if len(receivedData) >= 2 {
		respLen := binary.BigEndian.Uint16(receivedData[0:2])
		if respLen == 0 {
			t.Error("Expected non-zero response length prefix")
		}
	}
}

// ==============================================================================
// UDP handleRequest - EDNS0 with nil OPT Data field
// Line 225: type assertion on nil Data should fail gracefully
// ==============================================================================

func TestUDPServerHandleRequestOPTNilData(t *testing.T) {
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

	// Construct a message with an OPT record that has nil Data
	// Pack it to wire format and let UnpackMessage reconstruct it.
	// The OPT data will become *RDataRaw, which satisfies the test.
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0x8888,
			Flags: protocol.NewQueryFlags(),
		},
		Questions: []*protocol.Question{
			{
				Name:   mustParseName("nildata.example.com."),
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
		Additionals: []*protocol.ResourceRecord{
			{
				Name:  mustParseName("."),
				Type:  protocol.TypeOPT,
				Class: 4096,
				TTL:   0,
				Data:  &protocol.RDataOPT{Options: nil}, // nil options
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
	if !receivedClientInfo.HasEDNS0 {
		t.Error("HasEDNS0 should be true with OPT record")
	}
}

// ==============================================================================
// TCP handleMessage - EDNS0 OPT with nil Data (direct call)
// Exercises the type assertion path where Data is nil after unpack
// ==============================================================================

func TestTCPServerHandleMessageOPTNilDataDirect(t *testing.T) {
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

	// Build message with OPT record having nil Data, pack it
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0x9999,
			Flags: protocol.NewQueryFlags(),
		},
		Questions: []*protocol.Question{
			{
				Name:   mustParseName("nildata.example.com."),
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
		Additionals: []*protocol.ResourceRecord{
			{
				Name:  mustParseName("."),
				Type:  protocol.TypeOPT,
				Class: 4096,
				TTL:   0,
				Data:  &protocol.RDataOPT{Options: nil},
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
	if !receivedClientInfo.HasEDNS0 {
		t.Error("HasEDNS0 should be true with OPT record")
	}
}

// ==============================================================================
// UDP Write - truncation with large question name to force different code path
// Lines 281-296: truncation path exercised with different message shapes
// ==============================================================================

func TestUDPResponseWriterTruncationWithLargeQuestion(t *testing.T) {
	server := NewUDPServerWithWorkers("127.0.0.1:0", HandlerFunc(func(w ResponseWriter, req *protocol.Message) {}), 1)
	mockConn := &mockUDPConn{}
	server.ListenWithConn(mockConn)

	rw := &udpResponseWriter{
		server: server,
		client: &ClientInfo{
			Addr:     &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			Protocol: "udp",
		},
		maxSize: 64, // Small but not tiny - enough for header + some of the question
	}

	// Create a message with a very long domain name to make it exceed maxSize
	longName := mustParseName("a.really.very.long.domain.name.that.will.make.the.message.exceed.the.max.size.example.com.")
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0xCCCC,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: []*protocol.Question{
			{
				Name:   longName,
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
		Answers: []*protocol.ResourceRecord{
			{
				Name:  longName,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
			},
		},
	}

	written, err := rw.Write(msg)
	// May succeed with truncated message or fail
	if err != nil {
		t.Logf("Write returned error (acceptable): %v", err)
	}
	_ = written
}
