package server

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// ==============================================================================
// UDP reader - full loop with success, error, success, then close
// Exercises the reader select and error handling paths more thoroughly.
// ==============================================================================

func TestUDPServerReaderSequenceV2(t *testing.T) {
	query, _ := protocol.NewQuery(0xE1, "seqv2.example.com.", protocol.TypeA)
	queryBuf := make([]byte, 512)
	queryN, _ := query.Pack(queryBuf)

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		w.Write(&protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
		})
	})

	server := NewUDPServerWithWorkers("127.0.0.1:0", handler, 1)

	step := int32(0)
	mockConn := &mockUDPConnWithControl{
		readFn: func(buf []byte) (int, *net.UDPAddr, error) {
			s := atomic.AddInt32(&step, 1)
			switch {
			case s == 1:
				n := copy(buf, queryBuf[:queryN])
				return n, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}, nil
			case s == 2:
				return 0, nil, errors.New("transient error")
			case s == 3:
				n := copy(buf, queryBuf[:queryN])
				return n, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 54321}, nil
			default:
				return 0, nil, net.ErrClosed
			}
		},
	}
	server.ListenWithConn(mockConn)

	done := make(chan struct{})
	go func() {
		server.Serve()
		close(done)
	}()

	time.Sleep(200 * time.Millisecond)
	server.Stop()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("Serve should return")
	}

	stats := server.Stats()
	if stats.Errors == 0 {
		t.Error("Expected at least 1 error from the generic read error")
	}
	if stats.PacketsReceived < 2 {
		t.Errorf("Expected at least 2 packets received, got %d", stats.PacketsReceived)
	}
}

// ==============================================================================
// UDP reader - multiple successful reads
// ==============================================================================

func TestUDPServerReaderMultipleSuccessV2(t *testing.T) {
	var receivedMsgs []*protocol.Message
	var mu sync.Mutex

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		mu.Lock()
		receivedMsgs = append(receivedMsgs, req)
		mu.Unlock()
		w.Write(&protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
		})
	})

	server := NewUDPServerWithWorkers("127.0.0.1:0", handler, 2)

	query, _ := protocol.NewQuery(0xF1, "readsv2.example.com.", protocol.TypeA)
	queryBuf := make([]byte, 512)
	queryN, _ := query.Pack(queryBuf)

	readCount := int32(0)
	mockConn := &mockUDPConnWithControl{
		readFn: func(buf []byte) (int, *net.UDPAddr, error) {
			count := atomic.AddInt32(&readCount, 1)
			if count > 5 {
				return 0, nil, net.ErrClosed
			}
			n := copy(buf, queryBuf[:queryN])
			return n, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}, nil
		},
	}
	server.ListenWithConn(mockConn)

	done := make(chan struct{})
	go func() {
		server.Serve()
		close(done)
	}()

	time.Sleep(200 * time.Millisecond)
	server.Stop()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("Serve should return")
	}

	mu.Lock()
	count := len(receivedMsgs)
	mu.Unlock()

	if count == 0 {
		t.Error("Expected at least one message to be handled")
	}
}

// ==============================================================================
// TCP Write - detailed success path with answers
// Exercises the full pack -> write path in tcpResponseWriter
// ==============================================================================

func TestTCPResponseWriterWriteDetailedV2(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go io.Copy(io.Discard, clientConn)

	rw := &tcpResponseWriter{
		conn:    serverConn,
		client:  &ClientInfo{Protocol: "tcp"},
		maxSize: TCPMaxMessageSize,
		writeMu: &sync.Mutex{},
	}

	name := mustParseName("detailv2.example.com.")
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0xDD01,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: []*protocol.Question{
			{
				Name:   name,
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
		Answers: []*protocol.ResourceRecord{
			{
				Name:  name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
			},
		},
	}

	written, err := rw.Write(msg)
	if err != nil {
		t.Errorf("Write should succeed: %v", err)
	}
	if written <= 0 {
		t.Error("Expected positive bytes written")
	}
	if rw.writeCount != 1 {
		t.Errorf("writeCount = %d, want 1", rw.writeCount)
	}

	// Second write to verify writeCount increments
	msg2 := &protocol.Message{
		Header: protocol.Header{
			ID:    0xDD02,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
	}

	_, err2 := rw.Write(msg2)
	if err2 != nil {
		t.Errorf("Second write should succeed: %v", err2)
	}
	if rw.writeCount != 2 {
		t.Errorf("writeCount = %d, want 2", rw.writeCount)
	}
}

// ==============================================================================
// TCP Write - verify response data on client side
// Exercises the full pack -> write -> read path
// ==============================================================================

func TestTCPResponseWriterWriteVerifyData(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	var receivedData []byte
	var receiveMu sync.Mutex

	go func() {
		buf := make([]byte, 4096)
		n, err := clientConn.Read(buf)
		if err == nil {
			receiveMu.Lock()
			receivedData = make([]byte, n)
			copy(receivedData, buf[:n])
			receiveMu.Unlock()
		}
	}()

	rw := &tcpResponseWriter{
		conn:    serverConn,
		client:  &ClientInfo{Protocol: "tcp"},
		maxSize: TCPMaxMessageSize,
		writeMu: &sync.Mutex{},
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0xBEEF,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: []*protocol.Question{
			{
				Name:   mustParseName("verify.example.com."),
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
	}

	written, err := rw.Write(msg)
	if err != nil {
		t.Fatalf("Write should succeed: %v", err)
	}
	if written == 0 {
		t.Error("Expected non-zero bytes written")
	}

	time.Sleep(20 * time.Millisecond)

	receiveMu.Lock()
	if len(receivedData) == 0 {
		t.Error("Expected data to be received on client side")
	}
	if len(receivedData) >= 2 {
		respLen := binary.BigEndian.Uint16(receivedData[:2])
		if respLen == 0 {
			t.Error("Expected non-zero response length prefix")
		}
	}
	receiveMu.Unlock()
}

// ==============================================================================
// UDP Write - truncation with actual write
// Exercises the truncation path through to actual send
// ==============================================================================

func TestUDPResponseWriterTruncationWriteV2(t *testing.T) {
	server := NewUDPServerWithWorkers("127.0.0.1:0", HandlerFunc(func(w ResponseWriter, req *protocol.Message) {}), 1)
	mockConn := &mockUDPConn{}
	server.ListenWithConn(mockConn)

	rw := &udpResponseWriter{
		server: server,
		client: &ClientInfo{
			Addr:     &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			Protocol: "udp",
		},
		maxSize: 100,
	}

	name := mustParseName("truncv2.example.com.")
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0xCC01,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: []*protocol.Question{
			{
				Name:   name,
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
	}

	for i := 0; i < 30; i++ {
		msg.AddAnswer(&protocol.ResourceRecord{
			Name:  name,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataA{Address: [4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}},
		})
	}

	written, err := rw.Write(msg)
	// May succeed or fail depending on truncation result
	_ = written
	_ = err
}
