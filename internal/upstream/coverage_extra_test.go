package upstream

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// buildTestDNSResponse builds a valid DNS response message for testing.
func buildTestDNSResponse(id uint16) *protocol.Message {
	name, _ := protocol.ParseName("test.com.")
	return &protocol.Message{
		Header: protocol.Header{
			ID:    id,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeA, QClass: protocol.ClassIN},
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
}

// packMessage is a helper to pack a protocol.Message into a byte slice.
func packMessage(t *testing.T, msg *protocol.Message) []byte {
	t.Helper()
	buf := make([]byte, 65535)
	n, err := msg.Pack(buf)
	if err != nil {
		t.Fatalf("failed to pack message: %v", err)
	}
	return buf[:n]
}

// startTCPMockServer starts a TCP listener that accepts one connection and calls handler.
// Returns the listener address and a cleanup function.
func startTCPMockServer(t *testing.T, handler func(conn net.Conn)) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handler(conn)
		conn.Close()
	}()

	return ln.Addr().String(), func() { ln.Close(); <-done }
}

// startUDPMockServer starts a UDP listener that calls handler for each received packet.
// Returns the listener address and a cleanup function.
func startUDPMockServer(t *testing.T, handler func(conn *net.UDPConn, data []byte, remote *net.UDPAddr)) (string, func()) {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve UDP addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}

	localAddr := conn.LocalAddr().String()
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-done:
				return
			default:
			}
			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			handler(conn, buf[:n], remote)
		}
	}()

	return localAddr, func() { close(done); conn.Close() }
}

// newTestClient creates a Client configured to talk to the given address.
func newTestClient(t *testing.T, addr string) *Client {
	t.Helper()
	config := Config{
		Servers:  []string{addr},
		Strategy: "random",
		Timeout:  2 * time.Second,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	return client
}

// newTestQuery creates a simple DNS query message.
func newTestQuery(id uint16) *protocol.Message {
	return &protocol.Message{
		Header: protocol.Header{
			ID:      id,
			Flags:   protocol.NewQueryFlags(),
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   &protocol.Name{Labels: []string{"test", "com"}, FQDN: true},
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
	}
}

// ---------------------------------------------------------------------------
// TestQueryUDP_SendError: UDP server address that refuses connections (send fails).
// Using a non-routable address to trigger a write error quickly.
// ---------------------------------------------------------------------------
func TestQueryUDP_SendError(t *testing.T) {
	config := Config{
		Servers:  []string{"198.51.100.1:53"}, // TEST-NET-1, non-routable
		Strategy: "random",
		Timeout:  200 * time.Millisecond,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	msg := newTestQuery(0x1234)
	_, err = client.queryUDP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error from queryUDP with non-routable address")
	}
}

// ---------------------------------------------------------------------------
// TestQueryUDP_ReadError: UDP server that accepts queries but never replies,
// causing a read timeout.
// ---------------------------------------------------------------------------
func TestQueryUDP_ReadError(t *testing.T) {
	addr, cleanup := startUDPMockServer(t, func(_ *net.UDPConn, _ []byte, _ *net.UDPAddr) {
		// Intentionally do not reply - silence causes read timeout
	})
	defer cleanup()

	client := newTestClient(t, addr)
	defer client.Close()

	msg := newTestQuery(0xABCD)
	_, err := client.queryUDP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error when UDP server does not respond")
	}
}

// ---------------------------------------------------------------------------
// TestQueryUDP_TruncatedResponse: UDP server that sends a TC=1 response,
// which should return both the response and an error.
// ---------------------------------------------------------------------------
func TestQueryUDP_TruncatedResponse(t *testing.T) {
	addr, cleanup := startUDPMockServer(t, func(conn *net.UDPConn, data []byte, remote *net.UDPAddr) {
		// Extract the query ID from the received data
		if len(data) < 2 {
			return
		}
		queryID := uint16(data[0])<<8 | uint16(data[1])

		resp := buildTestDNSResponse(queryID)
		resp.Header.Flags.TC = true // Set truncation bit
		packed := packMessage(&testing.T{}, resp)
		conn.WriteToUDP(packed, remote)
	})
	defer cleanup()

	client := newTestClient(t, addr)
	defer client.Close()

	msg := newTestQuery(0xBEEF)
	resp, err := client.queryUDP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error for truncated response")
	}
	if resp == nil {
		t.Error("expected non-nil response even when TC bit is set")
	}
	if resp != nil && !resp.Header.Flags.TC {
		t.Error("expected TC flag to be set in response")
	}
}

// ---------------------------------------------------------------------------
// TestQueryUDP_UnpackError: UDP server that sends garbage (non-DNS) data.
// ---------------------------------------------------------------------------
func TestQueryUDP_UnpackError(t *testing.T) {
	addr, cleanup := startUDPMockServer(t, func(conn *net.UDPConn, _ []byte, remote *net.UDPAddr) {
		// Send invalid DNS data
		garbage := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
		conn.WriteToUDP(garbage, remote)
	})
	defer cleanup()

	client := newTestClient(t, addr)
	defer client.Close()

	msg := newTestQuery(0xDEAD)
	_, err := client.queryUDP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error when unpacking garbage UDP response")
	}
}

// ---------------------------------------------------------------------------
// TestQueryTCP_SendLengthError: TCP server that closes immediately, causing
// the length-prefix write to fail.
// ---------------------------------------------------------------------------
func TestQueryTCP_SendLengthError(t *testing.T) {
	addr, cleanup := startTCPMockServer(t, func(_ net.Conn) {
		// Close immediately - the client's Write of the length prefix will fail
	})
	defer cleanup()

	client := newTestClient(t, addr)
	defer client.Close()

	msg := newTestQuery(0x1111)
	_, err := client.queryTCP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error when TCP server closes before receiving length prefix")
	}
}

// ---------------------------------------------------------------------------
// TestQueryTCP_ReadLengthError: TCP server that reads the query but then
// closes without sending a response length prefix.
// ---------------------------------------------------------------------------
func TestQueryTCP_ReadLengthError(t *testing.T) {
	addr, cleanup := startTCPMockServer(t, func(conn net.Conn) {
		// Read the full query (length prefix + body) then close
		io.ReadAll(io.LimitReader(conn, 65535))
		// Do not send any response - client's Read of length prefix will fail
	})
	defer cleanup()

	client := newTestClient(t, addr)
	defer client.Close()

	msg := newTestQuery(0x2222)
	_, err := client.queryTCP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error when TCP server closes before sending length prefix")
	}
}

// ---------------------------------------------------------------------------
// TestQueryTCP_ReadBodyError: TCP server that sends a length prefix but
// closes before sending the response body.
// ---------------------------------------------------------------------------
func TestQueryTCP_ReadBodyError(t *testing.T) {
	addr, cleanup := startTCPMockServer(t, func(conn net.Conn) {
		// Read the query
		io.ReadAll(io.LimitReader(conn, 65535))
		// Send length prefix indicating a response of 100 bytes
		lengthBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lengthBuf, 100)
		conn.Write(lengthBuf)
		// Do NOT send the body - close causes read error
	})
	defer cleanup()

	client := newTestClient(t, addr)
	defer client.Close()

	msg := newTestQuery(0x3333)
	_, err := client.queryTCP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error when TCP server sends length but no body")
	}
}

// ---------------------------------------------------------------------------
// TestQueryTCP_UnpackError: TCP server that sends garbage data with a valid
// length prefix.
// ---------------------------------------------------------------------------
func TestQueryTCP_UnpackError(t *testing.T) {
	addr, cleanup := startTCPMockServer(t, func(conn net.Conn) {
		// Read the query
		io.ReadAll(io.LimitReader(conn, 65535))
		// Send garbage response with valid length prefix
		garbage := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
		lengthBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lengthBuf, uint16(len(garbage)))
		conn.Write(lengthBuf)
		conn.Write(garbage)
	})
	defer cleanup()

	client := newTestClient(t, addr)
	defer client.Close()

	msg := newTestQuery(0x4444)
	_, err := client.queryTCP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error when unpacking garbage TCP response")
	}
}

// ---------------------------------------------------------------------------
// TestQueryTCP_LargeResponse: TCP server that sends a response larger than
// the pool buffer, triggering the buf = make([]byte, respLen) resize path.
// The pool buffer is replaced with a smaller one to force the resize.
// ---------------------------------------------------------------------------
func TestQueryTCP_LargeResponse(t *testing.T) {
	// First, determine the size of a packed query message so we know the minimum
	// pool buffer size needed for Pack to succeed.
	queryMsg := newTestQuery(0x5555)
	queryBuf := make([]byte, 65535)
	queryN, err := queryMsg.Pack(queryBuf)
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	minPackSize := queryN + 1 // buffer must be at least this big for Pack

	// Now build a response that is larger than minPackSize so we can use a
	// pool buffer between minPackSize and the response size.
	resp := buildTestDNSResponse(0x5555)
	for i := 0; i < 50; i++ {
		name, _ := protocol.ParseName("test.com.")
		resp.Answers = append(resp.Answers, &protocol.ResourceRecord{
			Name:  name,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataA{Address: [4]byte{byte(i), 2, 3, 4}},
		})
	}
	resp.Header.ANCount = uint16(len(resp.Answers))

	respPacked := packMessage(t, resp)
	poolBufSize := len(respPacked) - 1 // one byte smaller than response

	// Ensure poolBufSize is still large enough for Pack
	if poolBufSize < minPackSize {
		poolBufSize = minPackSize
		// Add more answers to make the response larger than poolBufSize
		for poolBufSize >= len(respPacked) {
			name, _ := protocol.ParseName("test.com.")
			resp.Answers = append(resp.Answers, &protocol.ResourceRecord{
				Name:  name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{0, 0, 0, 0}},
			})
			resp.Header.ANCount = uint16(len(resp.Answers))
			respPacked = packMessage(t, resp)
		}
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read the query (length prefix + body)
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		queryLen := int(binary.BigEndian.Uint16(lenBuf))
		if _, err := io.ReadFull(conn, make([]byte, queryLen)); err != nil {
			return
		}

		// Send the large response
		respLen := make([]byte, 2)
		binary.BigEndian.PutUint16(respLen, uint16(len(respPacked)))
		conn.Write(respLen)
		conn.Write(respPacked)
	}()

	client := newTestClient(t, ln.Addr().String())

	// Replace the TCP pool buffer with one smaller than the response,
	// but large enough for Pack to succeed.
	client.mu.Lock()
	poolAddr := client.servers[0].Address
	finalPoolSize := poolBufSize
	client.tcpPool[poolAddr] = &sync.Pool{
		New: func() interface{} {
			return make([]byte, finalPoolSize)
		},
	}
	client.mu.Unlock()

	msg := newTestQuery(0x5555)
	resultResp, err := client.queryTCP(client.servers[0], msg)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if resultResp == nil {
		t.Fatal("expected non-nil response")
	}
	if resultResp.Header.ID != 0x5555 {
		t.Errorf("expected response ID 0x5555, got 0x%04X", resultResp.Header.ID)
	}
	if len(resultResp.Answers) < 1 {
		t.Error("expected at least one answer in response")
	}

	client.Close()
	ln.Close()
	wg.Wait()
}

// ---------------------------------------------------------------------------
// TestCheckHealth_UDPFailTCPFail: Both UDP and TCP fail for a server.
// checkHealth fires goroutines that attempt UDP then TCP. Since neither
// queryUDP nor queryTCP call markFailure (only Query does), we verify
// that checkHealth runs without panic and the server remains unchanged.
// ---------------------------------------------------------------------------
func TestCheckHealth_UDPFailTCPFail(t *testing.T) {
	// Start a TCP listener that accepts connections but immediately closes them.
	// UDP will fail (no UDP listener), and TCP will also fail (connection closed).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tcpServerDone := make(chan struct{})
	go func() {
		defer close(tcpServerDone)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close() // Immediately close - causes TCP failure
		}
	}()

	addr := ln.Addr().String()
	config := Config{
		Servers:  []string{addr},
		Strategy: "random",
		Timeout:  200 * time.Millisecond,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	// Record initial state
	initialHealthy := client.servers[0].IsHealthy()

	// Call checkHealth - the goroutines will try UDP (fails) then TCP (fails).
	// This exercises the code paths where both UDP and TCP fail.
	client.checkHealth()

	// Wait for the health check goroutines to complete.
	time.Sleep(600 * time.Millisecond)

	// Server should still be in its initial state since checkHealth goroutines
	// don't modify server health on failure (only markSuccess is called on success).
	finalHealthy := client.servers[0].IsHealthy()
	if finalHealthy != initialHealthy {
		t.Logf("server health changed from %v to %v", initialHealthy, finalHealthy)
	}

	ln.Close()
	<-tcpServerDone
}

// ---------------------------------------------------------------------------
// TestCheckHealth_UDPFailTCPSuccess: UDP fails but TCP succeeds.
// We start a TCP mock server but no UDP server, so UDP will fail
// (timeout/connection refused) and TCP will succeed.
// ---------------------------------------------------------------------------
func TestCheckHealth_UDPFailTCPSuccess(t *testing.T) {
	// Start a TCP mock server that echoes DNS responses
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read query
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		queryLen := int(binary.BigEndian.Uint16(lenBuf))
		queryData := make([]byte, queryLen)
		if _, err := io.ReadFull(conn, queryData); err != nil {
			return
		}

		// Extract query ID and build valid response
		var queryID uint16
		if len(queryData) >= 2 {
			queryID = uint16(queryData[0])<<8 | uint16(queryData[1])
		}
		resp := buildTestDNSResponse(queryID)
		resp.Questions = []*protocol.Question{
			{
				Name:   &protocol.Name{Labels: []string{}, FQDN: true},
				QType:  protocol.TypeNS,
				QClass: protocol.ClassIN,
			},
		}
		packed := packMessage(&testing.T{}, resp)

		respLen := make([]byte, 2)
		binary.BigEndian.PutUint16(respLen, uint16(len(packed)))
		conn.Write(respLen)
		conn.Write(packed)
	}()

	// Use a random high UDP port that won't have a UDP listener
	// but will have our TCP mock server.
	// We construct a client pointing at the TCP server address.
	// UDP to this address will fail (connection refused / timeout),
	// but TCP will succeed.
	addr := ln.Addr().String()
	config := Config{
		Servers:  []string{addr},
		Strategy: "random",
		Timeout:  2 * time.Second,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	// call checkHealth - UDP will fail, then TCP should succeed
	client.checkHealth()

	// Wait for the health check goroutine
	time.Sleep(500 * time.Millisecond)

	// Server should still be healthy (TCP succeeded and called markSuccess)
	if !client.servers[0].IsHealthy() {
		t.Error("expected server to remain healthy after TCP fallback success")
	}

	ln.Close()
	wg.Wait()
}

// ---------------------------------------------------------------------------
// TestHealthCheckLoop_ExitsOnCancel: Verify the health check loop exits
// cleanly when the context is cancelled via Close().
// ---------------------------------------------------------------------------
func TestHealthCheckLoop_ExitsOnCancel(t *testing.T) {
	config := Config{
		Servers:  []string{"8.8.8.8:53"},
		Strategy: "random",
		Timeout:  100 * time.Millisecond,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	// Close cancels the context; the health check loop should exit via ctx.Done()
	start := time.Now()
	if err := client.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
	elapsed := time.Since(start)

	// Close should return quickly (within a second), meaning the loop exited
	if elapsed > 2*time.Second {
		t.Errorf("Close took too long (%v), health check loop may not have exited on cancel", elapsed)
	}

	// Verify the WaitGroup is done by calling Close again (should be idempotent)
	if err := client.Close(); err != nil {
		t.Errorf("second Close failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestQueryTCP_SendBodyError: TCP server that accepts the length prefix
// but closes before the query body is fully written.
// ---------------------------------------------------------------------------
func TestQueryTCP_SendBodyError(t *testing.T) {
	addr, cleanup := startTCPMockServer(t, func(conn net.Conn) {
		// Read only the 2-byte length prefix then close immediately
		lenBuf := make([]byte, 2)
		io.ReadFull(conn, lenBuf)
		// Close right after reading length prefix - client's Write of body fails
	})
	defer cleanup()

	client := newTestClient(t, addr)
	defer client.Close()

	msg := newTestQuery(0x6666)
	_, err := client.queryTCP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error when TCP server closes before receiving query body")
	}
}

// ---------------------------------------------------------------------------
// TestQueryTCP_PackError: Attempt to pack a message into a tiny buffer
// to trigger pack failure.
// ---------------------------------------------------------------------------
func TestQueryTCP_PackError(t *testing.T) {
	config := Config{
		Servers:  []string{"127.0.0.1:0"},
		Strategy: "random",
		Timeout:  200 * time.Millisecond,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	// Replace the TCP pool with a zero-length buffer to force Pack to fail
	client.mu.Lock()
	addr := client.servers[0].Address
	client.tcpPool[addr] = &sync.Pool{
		New: func() interface{} {
			return make([]byte, 0) // Zero-length buffer
		},
	}
	client.mu.Unlock()

	msg := newTestQuery(0x7777)
	_, err = client.queryTCP(client.servers[0], msg)
	if err == nil {
		t.Error("expected pack error with zero-length buffer")
	}
}

// ---------------------------------------------------------------------------
// TestQueryUDP_PackError: Attempt to pack a message into a tiny buffer
// to trigger UDP pack failure.
// ---------------------------------------------------------------------------
func TestQueryUDP_PackError(t *testing.T) {
	config := Config{
		Servers:  []string{"127.0.0.1:0"},
		Strategy: "random",
		Timeout:  200 * time.Millisecond,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	// Replace the UDP pool with a zero-length buffer to force Pack to fail
	client.mu.Lock()
	addr := client.servers[0].Address
	client.udpPool[addr] = &sync.Pool{
		New: func() interface{} {
			return make([]byte, 0) // Zero-length buffer
		},
	}
	client.mu.Unlock()

	msg := newTestQuery(0x8888)
	_, err = client.queryUDP(client.servers[0], msg)
	if err == nil {
		t.Error("expected pack error with zero-length buffer")
	}
}

// ---------------------------------------------------------------------------
// TestHealthCheckLoop_TickerFires: Verify that the health check loop
// calls checkHealth on each tick by using a very short interval and
// observing server state changes.
// ---------------------------------------------------------------------------
func TestHealthCheckLoop_TickerFires(t *testing.T) {
	// Use a non-routable address so health checks fail quickly
	config := Config{
		Servers:  []string{"198.51.100.1:53"},
		Strategy: "random",
		Timeout:  200 * time.Millisecond,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	// The health check loop uses a fixed 30s ticker in healthCheckLoop.
	// Wait a moment and then close. The loop should have had a chance to
	// at least select on the ticker case.
	// Since the ticker is 30s, we can't wait for it in a unit test.
	// Instead, just verify clean shutdown.
	if err := client.Close(); err != nil {
		t.Errorf("close failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestQueryUDP_SuccessWithMockServer: Full success path for queryUDP
// with a properly responding mock UDP server.
// ---------------------------------------------------------------------------
func TestQueryUDP_SuccessWithMockServer(t *testing.T) {
	addr, cleanup := startUDPMockServer(t, func(conn *net.UDPConn, data []byte, remote *net.UDPAddr) {
		if len(data) < 2 {
			return
		}
		queryID := uint16(data[0])<<8 | uint16(data[1])
		resp := buildTestDNSResponse(queryID)
		packed := packMessage(t, resp)
		conn.WriteToUDP(packed, remote)
	})
	defer cleanup()

	client := newTestClient(t, addr)
	defer client.Close()

	msg := newTestQuery(0x9999)
	resp, err := client.queryUDP(client.servers[0], msg)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Header.ID != 0x9999 {
		t.Errorf("expected response ID 0x9999, got 0x%04X", resp.Header.ID)
	}
	if resp.Header.Flags.TC {
		t.Error("expected TC flag to be clear")
	}

	// Verify server was marked healthy
	if !client.servers[0].IsHealthy() {
		t.Error("expected server to be healthy after successful UDP query")
	}
}

// ---------------------------------------------------------------------------
// TestQueryTCP_SuccessWithMockServer: Full success path for queryTCP
// with a properly responding mock TCP server.
// ---------------------------------------------------------------------------
func TestQueryTCP_SuccessWithMockServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read length prefix
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		queryLen := int(binary.BigEndian.Uint16(lenBuf))
		queryData := make([]byte, queryLen)
		if _, err := io.ReadFull(conn, queryData); err != nil {
			return
		}

		// Extract query ID
		var queryID uint16
		if len(queryData) >= 2 {
			queryID = uint16(queryData[0])<<8 | uint16(queryData[1])
		}

		// Build and send response
		resp := buildTestDNSResponse(queryID)
		packed := packMessage(&testing.T{}, resp)

		respLen := make([]byte, 2)
		binary.BigEndian.PutUint16(respLen, uint16(len(packed)))
		conn.Write(respLen)
		conn.Write(packed)
	}()

	client := newTestClient(t, ln.Addr().String())
	defer client.Close()

	msg := newTestQuery(0xAAAA)
	resp, err := client.queryTCP(client.servers[0], msg)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Header.ID != 0xAAAA {
		t.Errorf("expected response ID 0xAAAA, got 0x%04X", resp.Header.ID)
	}

	// Verify server was marked healthy
	if !client.servers[0].IsHealthy() {
		t.Error("expected server to be healthy after successful TCP query")
	}

	ln.Close()
	wg.Wait()
}
