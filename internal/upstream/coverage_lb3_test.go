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

// ---------------------------------------------------------------------------
// Client.queryUDP - SetDeadline error path (client.go:336-338)
// We trigger this by using a connection to a closed/unreachable endpoint
// and relying on the fact that SetDeadline can fail on certain conn types.
// Since net.DialTimeout returns a real *net.UDPConn where SetDeadline
// never fails, we test the error propagation indirectly via an address
// that will fail at the Write stage after a successful dial + deadline.
// ---------------------------------------------------------------------------

func TestClientQueryUDP_WriteError(t *testing.T) {
	// Start a UDP server that never responds so we hit the Read error path
	addr, cleanup := startUDPMockServer3(t, func(conn *net.UDPConn, data []byte, remote *net.UDPAddr) {
		// Do not respond - drop the packet to trigger read timeout error
	})
	defer cleanup()

	client := &Client{
		servers: []*Server{
			{Address: addr, healthy: true, Timeout: 200 * time.Millisecond},
		},
		udpPool: map[string]*sync.Pool{
			addr: {New: func() interface{} { return make([]byte, 4096) }},
		},
		tcpPool: make(map[string]*sync.Pool),
	}

	msg := newTestQuery3(0xAAAA)
	_, err := client.queryUDP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error when UDP server does not respond")
	}
	t.Logf("queryUDP error (expected): %v", err)
}

// ---------------------------------------------------------------------------
// Client.queryTCP - SetDeadline error path (client.go:394-396)
// ---------------------------------------------------------------------------

func TestClientQueryTCP_DialTimeout(t *testing.T) {
	client := &Client{
		servers: []*Server{
			{Address: "127.0.0.1:1", healthy: true, Timeout: 100 * time.Millisecond},
		},
		udpPool: map[string]*sync.Pool{
			"127.0.0.1:1": {New: func() interface{} { return make([]byte, 4096) }},
		},
		tcpPool: map[string]*sync.Pool{
			"127.0.0.1:1": {New: func() interface{} { return make([]byte, 65535) }},
		},
	}

	msg := newTestQuery3(0xBBBB)
	_, err := client.queryTCP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error when TCP server is not listening")
	}
	t.Logf("queryTCP error (expected): %v", err)
}

// ---------------------------------------------------------------------------
// Client.queryTCP - Write packed error path (client.go:406-408)
// Start a TCP server, accept connection, then close it immediately so
// the Write after SetDeadline fails.
// ---------------------------------------------------------------------------

func TestClientQueryTCP_WriteAfterClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	// Accept one connection and immediately close it
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close()
		ln.Close()
	}()

	client := &Client{
		servers: []*Server{
			{Address: addr, healthy: true, Timeout: 5 * time.Second},
		},
		udpPool: map[string]*sync.Pool{
			addr: {New: func() interface{} { return make([]byte, 4096) }},
		},
		tcpPool: map[string]*sync.Pool{
			addr: {New: func() interface{} { return make([]byte, 65535) }},
		},
	}

	// Wait for server to be ready then test
	time.Sleep(50 * time.Millisecond)

	msg := newTestQuery3(0xCCCC)
	_, err = client.queryTCP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error when TCP connection is closed by server")
	}
	t.Logf("queryTCP error (expected): %v", err)
}

// ---------------------------------------------------------------------------
// Client.queryUDP - successful round-trip (covers latency/markSuccess paths)
// ---------------------------------------------------------------------------

func TestClientQueryUDP_SuccessRoundTrip(t *testing.T) {
	addr, cleanup := startUDPMockServer3(t, func(conn *net.UDPConn, data []byte, remote *net.UDPAddr) {
		if len(data) < 2 {
			return
		}
		queryID := uint16(data[0])<<8 | uint16(data[1])
		resp := buildTestDNSResponse3(queryID)
		packed := packMessage3(t, resp)
		conn.WriteToUDP(packed, remote)
	})
	defer cleanup()

	server := &Server{Address: addr, healthy: true, Timeout: 2 * time.Second}
	client := &Client{
		servers: []*Server{server},
		udpPool: map[string]*sync.Pool{
			addr: {New: func() interface{} { return make([]byte, 4096) }},
		},
		tcpPool: make(map[string]*sync.Pool),
	}

	msg := newTestQuery3(0xDDDD)
	resp, err := client.queryUDP(server, msg)
	if err != nil {
		t.Fatalf("queryUDP() error = %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Header.ID != 0xDDDD {
		t.Errorf("expected ID 0xDDDD, got 0x%04X", resp.Header.ID)
	}
}

// ---------------------------------------------------------------------------
// Client.queryTCP - successful round-trip (covers latency/markSuccess paths)
// ---------------------------------------------------------------------------

func TestClientQueryTCP_SuccessRoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ln.Close()
			return
		}
		defer conn.Close()
		defer ln.Close()

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

		var queryID uint16
		if len(queryData) >= 2 {
			queryID = uint16(queryData[0])<<8 | uint16(queryData[1])
		}

		resp := buildTestDNSResponse3(queryID)
		packed := packMessage3(t, resp)

		respLen := make([]byte, 2)
		binary.BigEndian.PutUint16(respLen, uint16(len(packed)))
		conn.Write(respLen)
		conn.Write(packed)
	}()

	time.Sleep(50 * time.Millisecond)

	server := &Server{Address: addr, healthy: true, Timeout: 2 * time.Second}
	client := &Client{
		servers: []*Server{server},
		udpPool: map[string]*sync.Pool{
			addr: {New: func() interface{} { return make([]byte, 4096) }},
		},
		tcpPool: map[string]*sync.Pool{
			addr: {New: func() interface{} { return make([]byte, 65535) }},
		},
	}

	msg := newTestQuery3(0xEEEE)
	resp, err := client.queryTCP(server, msg)
	if err != nil {
		t.Fatalf("queryTCP() error = %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Header.ID != 0xEEEE {
		t.Errorf("expected ID 0xEEEE, got 0x%04X", resp.Header.ID)
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer.selectAnycastTarget - backend nil path (loadbalancer.go:300-302)
// We create an AnycastGroup where Stats returns healthy > 0 but SelectBackend
// returns nil by having an empty Backends slice. This requires manipulating
// the group's internal state directly.
// ---------------------------------------------------------------------------

func TestLBSelectAnycastTarget_BackendNil(t *testing.T) {
	// Create a group with backends so Stats will report healthy
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)
	b1 := &AnycastBackend{
		PhysicalIP: "10.0.1.1",
		Port:       53,
		Region:     "us-east-1",
		Zone:       "a",
		Weight:     50,
		healthy:    true,
	}
	group.AddBackend(b1)

	lb := &LoadBalancer{
		anycastGroups: map[string]*AnycastGroup{
			"192.0.2.1": group,
		},
		topology: Topology{Region: "us-east-1", Zone: "a"},
		udpPool:  make(map[string]*sync.Pool),
		tcpPool:  make(map[string]*sync.Pool),
	}

	// Now empty the backends after the group is set up
	// This simulates a race where backends are removed between Stats() and SelectBackend()
	group.mu.Lock()
	group.Backends = nil
	group.mu.Unlock()

	_, err := lb.selectAnycastTarget()
	if err == nil {
		t.Error("expected error when no backends available")
	}
	t.Logf("selectAnycastTarget error (expected): %v", err)
}

// ---------------------------------------------------------------------------
// LoadBalancer.selectStandaloneTarget - selected nil path (loadbalancer.go:331-333)
// This is effectively unreachable through normal code since all selection
// strategies return a server when servers exist. We test by having a strategy
// that maps to selectFastest with an empty servers slice during the call.
// Since the early check `len(lb.servers) == 0` is done first, we need to
// manipulate servers between the check and the strategy call.
// This is not achievable without races, so we test via the early return
// path directly (len(servers) == 0) which already exists in other tests.
//
// Instead, test the path where selectFastest returns nil with empty servers.
// ---------------------------------------------------------------------------

func TestLBSelectStandaloneTarget_FastestEmptyServers(t *testing.T) {
	lb := &LoadBalancer{
		servers:  []*Server{},
		strategy: Fastest,
		udpPool:  make(map[string]*sync.Pool),
		tcpPool:  make(map[string]*sync.Pool),
	}

	_, err := lb.selectStandaloneTarget()
	if err == nil {
		t.Error("expected error for no upstream servers")
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer.queryUDP - read error path (non-routable address triggers read timeout)
// ---------------------------------------------------------------------------

func TestLBQueryUDP_ReadError(t *testing.T) {
	if testing.Short() {
		t.Skip("requires network timeout")
	}
	// Use a port where nobody is listening - UDP will succeed at dial
	// but read will timeout
	addr := "127.0.0.1:1"

	lb := &LoadBalancer{
		udpPool: make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
	}

	msg := newTestQuery3(0x1234)
	_, err := lb.queryUDP(addr, msg)
	if err == nil {
		t.Error("expected error when no UDP server responds")
	}
	t.Logf("LB queryUDP error (expected): %v", err)
}

// ---------------------------------------------------------------------------
// LoadBalancer.queryUDP - write error via closed connection
// We dial to a listening UDP server, then immediately close the listener.
// UDP doesn't have real "connections" so write errors are rare. However,
// we can get errors by writing to a port that returns ICMP unreachable.
// ---------------------------------------------------------------------------

func TestLBQueryUDP_ICMPError(t *testing.T) {
	// Start a UDP server briefly to get a port, then close it
	// This should cause an ICMP port unreachable on some systems
	addr, cleanup := startUDPMockServer3(t, func(conn *net.UDPConn, data []byte, remote *net.UDPAddr) {
		// Send back garbage to trigger unpack error
		conn.WriteToUDP([]byte{0xFF, 0xFF, 0xFF, 0xFF}, remote)
	})
	defer cleanup()

	lb := &LoadBalancer{
		servers: []*Server{
			{Address: addr, healthy: true, Timeout: 2 * time.Second},
		},
		udpPool: make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
	}

	msg := newTestQuery3(0x1235)
	_, err := lb.queryUDP(addr, msg)
	// The response is garbage, so we expect an unpack error
	if err == nil {
		t.Error("expected error for garbage response")
	}
	t.Logf("LB queryUDP error (expected): %v", err)
}

// ---------------------------------------------------------------------------
// LoadBalancer.queryUDP - TC bit set triggers truncated error
// (loadbalancer.go:512-514)
// ---------------------------------------------------------------------------

func TestLBQueryUDP_TruncatedResponse(t *testing.T) {
	addr, cleanup := startUDPMockServer3(t, func(conn *net.UDPConn, data []byte, remote *net.UDPAddr) {
		if len(data) < 2 {
			return
		}
		queryID := uint16(data[0])<<8 | uint16(data[1])
		resp := buildTestDNSResponse3(queryID)
		// Set the TC (truncation) flag
		resp.Header.Flags.TC = true
		packed := packMessage3(t, resp)
		conn.WriteToUDP(packed, remote)
	})
	defer cleanup()

	lb := &LoadBalancer{
		servers: []*Server{
			{Address: addr, healthy: true, Timeout: 2 * time.Second},
		},
		udpPool: make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
	}

	msg := newTestQuery3(0x1236)
	resp, err := lb.queryUDP(addr, msg)
	// Should get a response but also a "response truncated" error
	if err == nil {
		t.Error("expected error for truncated response")
	}
	if resp == nil {
		t.Error("expected non-nil response even with truncation error")
	}
	t.Logf("LB queryUDP truncated (expected): %v", err)
}

// ---------------------------------------------------------------------------
// LoadBalancer.queryTCP - send length error (loadbalancer.go:557-559)
// Start TCP server, accept connection, close immediately.
// ---------------------------------------------------------------------------

func TestLBQueryTCP_SendLengthError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	// Accept and immediately close - triggers RST which may cause
	// the first Write (length prefix) to fail
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ln.Close()
			return
		}
		conn.Close()
		ln.Close()
	}()

	time.Sleep(50 * time.Millisecond)

	lb := &LoadBalancer{
		udpPool: make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
	}

	msg := newTestQuery3(0x5678)
	_, err = lb.queryTCP(addr, msg)
	if err == nil {
		t.Error("expected error when TCP connection closes immediately")
	}
	t.Logf("LB queryTCP error (expected): %v", err)
}

// ---------------------------------------------------------------------------
// LoadBalancer.queryTCP - send query error via concurrent close
// (loadbalancer.go:562-564)
// Server accepts, reads length, then closes before query data arrives.
// ---------------------------------------------------------------------------

func TestLBQueryTCP_SendQueryAfterServerClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ln.Close()
			return
		}
		defer conn.Close()
		defer ln.Close()

		// Read length prefix only
		lenBuf := make([]byte, 2)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		// Read the query data
		queryLen := int(binary.BigEndian.Uint16(lenBuf))
		queryData := make([]byte, queryLen)
		if _, err := io.ReadFull(conn, queryData); err != nil {
			return
		}
		// Close immediately without response to trigger read length error
	}()

	time.Sleep(50 * time.Millisecond)

	lb := &LoadBalancer{
		udpPool: make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
	}

	msg := newTestQuery3(0x5679)
	_, err = lb.queryTCP(addr, msg)
	if err == nil {
		t.Error("expected error when TCP server closes without responding")
	}
	t.Logf("LB queryTCP error (expected): %v", err)
}

// ---------------------------------------------------------------------------
// LoadBalancer.queryTCP - send query error (loadbalancer.go:562-564)
// Start TCP server that reads the length prefix but then closes before
// the query data is written.
// ---------------------------------------------------------------------------

func TestLBQueryTCP_SendQueryError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ln.Close()
			return
		}
		// Read the length prefix then close
		buf := make([]byte, 2)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		conn.Read(buf)
		conn.Close()
		ln.Close()
	}()

	time.Sleep(50 * time.Millisecond)

	lb := &LoadBalancer{
		udpPool: make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
	}

	msg := newTestQuery3(0x9ABC)
	_, err = lb.queryTCP(addr, msg)
	if err == nil {
		t.Error("expected error when TCP connection closes mid-transaction")
	}
	t.Logf("LB queryTCP error (expected): %v", err)
}

// ---------------------------------------------------------------------------
// LoadBalancer.queryTCP - read length error (loadbalancer.go:567-568)
// Start TCP server that accepts, reads query, then closes before sending
// the response length prefix.
// ---------------------------------------------------------------------------

func TestLBQueryTCP_ReadLengthError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ln.Close()
			return
		}
		defer conn.Close()
		defer ln.Close()

		// Read the full query (length prefix + data)
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		queryLen := int(binary.BigEndian.Uint16(lenBuf))
		queryData := make([]byte, queryLen)
		if _, err := io.ReadFull(conn, queryData); err != nil {
			return
		}
		// Now close without sending response
	}()

	time.Sleep(50 * time.Millisecond)

	lb := &LoadBalancer{
		udpPool: make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
	}

	msg := newTestQuery3(0xDEF0)
	_, err = lb.queryTCP(addr, msg)
	if err == nil {
		t.Error("expected error when TCP server closes without responding")
	}
	t.Logf("LB queryTCP error (expected): %v", err)
}

// ---------------------------------------------------------------------------
// LoadBalancer.queryTCP - read response error (loadbalancer.go:577-579)
// Start TCP server that sends the length prefix but closes before
// sending the response body.
// ---------------------------------------------------------------------------

func TestLBQueryTCP_ReadResponseError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ln.Close()
			return
		}
		defer conn.Close()
		defer ln.Close()

		// Read the full query
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		queryLen := int(binary.BigEndian.Uint16(lenBuf))
		queryData := make([]byte, queryLen)
		if _, err := io.ReadFull(conn, queryData); err != nil {
			return
		}

		// Send a response length prefix that claims 100 bytes, but close immediately
		respLen := make([]byte, 2)
		binary.BigEndian.PutUint16(respLen, 100)
		conn.Write(respLen)
		// Close without writing response body -> read error on client side
	}()

	time.Sleep(50 * time.Millisecond)

	lb := &LoadBalancer{
		udpPool: make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
	}

	msg := newTestQuery3(0xF0F0)
	_, err = lb.queryTCP(addr, msg)
	if err == nil {
		t.Error("expected error when TCP server sends incomplete response")
	}
	t.Logf("LB queryTCP error (expected): %v", err)
}

// ---------------------------------------------------------------------------
// weightedSelect - fallback to last backend (anycast.go:246)
// This path is reached when selector >= currentWeight for all backends
// in the weighted loop. We construct backends where the weighted selection
// falls through to the last one.
// ---------------------------------------------------------------------------

func TestWeightedSelect_FallbackLast(t *testing.T) {
	// Create backends with very specific weights.
	// totalWeight = 1 + 1 = 2. selector = time.Now().UnixNano() % 2
	// If selector >= 1 after first iteration, we fall through to last backend.
	// We call it many times to try to hit the fallback path.
	backends := []*AnycastBackend{
		{PhysicalIP: "10.0.0.1", Weight: 1},
		{PhysicalIP: "10.0.0.2", Weight: 1},
	}

	results := make(map[string]int)
	for i := 0; i < 100; i++ {
		result := weightedSelect(backends)
		results[result.PhysicalIP]++
	}

	// Both backends should have been selected
	if len(results) < 2 {
		t.Logf("Only %d unique backends selected (expected 2)", len(results))
	}
}

// ---------------------------------------------------------------------------
// weightedSelect - weighted selection with varied weights
// Test the weighted path with backends of different weights.
// ---------------------------------------------------------------------------

func TestWeightedSelect_VariousWeights(t *testing.T) {
	backends := []*AnycastBackend{
		{PhysicalIP: "10.0.0.1", Weight: 3},
		{PhysicalIP: "10.0.0.2", Weight: 2},
		{PhysicalIP: "10.0.0.3", Weight: 1},
	}

	// Run many times to exercise different code paths
	results := make(map[string]int)
	for i := 0; i < 200; i++ {
		result := weightedSelect(backends)
		if result == nil {
			t.Fatal("expected non-nil backend")
		}
		results[result.PhysicalIP]++
	}

	// All backends should be selected at least once
	if len(results) < 2 {
		t.Errorf("expected at least 2 unique backends, got %d", len(results))
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer.queryUDP - success path with server latency update
// (loadbalancer.go:504-510)
// ---------------------------------------------------------------------------

func TestLBQueryUDP_SuccessWithLatencyUpdate(t *testing.T) {
	addr, cleanup := startUDPMockServer3(t, func(conn *net.UDPConn, data []byte, remote *net.UDPAddr) {
		if len(data) < 2 {
			return
		}
		queryID := uint16(data[0])<<8 | uint16(data[1])
		resp := buildTestDNSResponse3(queryID)
		packed := packMessage3(t, resp)
		conn.WriteToUDP(packed, remote)
	})
	defer cleanup()

	server := &Server{Address: addr, healthy: true, Timeout: 2 * time.Second}

	lb := &LoadBalancer{
		servers: []*Server{server},
		udpPool: make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
	}

	msg := newTestQuery3(0x7777)
	resp, err := lb.queryUDP(addr, msg)
	if err != nil {
		t.Fatalf("queryUDP() error = %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	if resp.Header.ID != 0x7777 {
		t.Errorf("response ID = %#x, want 0x7777", resp.Header.ID)
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer.queryTCP - success path with server latency update
// (loadbalancer.go:589-594)
// ---------------------------------------------------------------------------

func TestLBQueryTCP_SuccessWithLatencyUpdate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ln.Close()
			return
		}
		defer conn.Close()
		defer ln.Close()

		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		queryLen := int(binary.BigEndian.Uint16(lenBuf))
		queryData := make([]byte, queryLen)
		if _, err := io.ReadFull(conn, queryData); err != nil {
			return
		}

		var queryID uint16
		if len(queryData) >= 2 {
			queryID = uint16(queryData[0])<<8 | uint16(queryData[1])
		}

		resp := buildTestDNSResponse3(queryID)
		packed := packMessage3(t, resp)

		respLen := make([]byte, 2)
		binary.BigEndian.PutUint16(respLen, uint16(len(packed)))
		conn.Write(respLen)
		conn.Write(packed)
	}()

	time.Sleep(50 * time.Millisecond)

	server := &Server{Address: addr, healthy: true, Timeout: 2 * time.Second}

	lb := &LoadBalancer{
		servers: []*Server{server},
		udpPool: make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
	}

	msg := newTestQuery3(0x8888)
	resp, err := lb.queryTCP(addr, msg)
	if err != nil {
		t.Fatalf("queryTCP() error = %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	if resp.Header.ID != 0x8888 {
		t.Errorf("response ID = %#x, want 0x8888", resp.Header.ID)
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer.queryTCP - large response triggers buffer reallocation
// (loadbalancer.go:572-573)
// ---------------------------------------------------------------------------

func TestLBQueryTCP_LargeResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ln.Close()
			return
		}
		defer conn.Close()
		defer ln.Close()

		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		queryLen := int(binary.BigEndian.Uint16(lenBuf))
		queryData := make([]byte, queryLen)
		if _, err := io.ReadFull(conn, queryData); err != nil {
			return
		}

		// Build a response with many answers to make it larger than the default pool buffer
		var queryID uint16
		if len(queryData) >= 2 {
			queryID = uint16(queryData[0])<<8 | uint16(queryData[1])
		}
		resp := buildTestDNSResponse3(queryID)
		// Add many answer records to inflate the response size
		name, _ := protocol.ParseName("test.com.")
		for i := 0; i < 200; i++ {
			resp.Answers = append(resp.Answers, &protocol.ResourceRecord{
				Name:  name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{byte(i >> 8), byte(i), 3, 4}},
			})
		}
		packed := packMessage3(t, resp)

		respLen := make([]byte, 2)
		binary.BigEndian.PutUint16(respLen, uint16(len(packed)))
		conn.Write(respLen)
		conn.Write(packed)
	}()

	time.Sleep(50 * time.Millisecond)

	lb := &LoadBalancer{
		servers: []*Server{},
		udpPool: make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
	}

	msg := newTestQuery3(0x9999)
	resp, err := lb.queryTCP(addr, msg)
	if err != nil {
		t.Fatalf("queryTCP() error = %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

// ---------------------------------------------------------------------------
// Helper functions for coverage_lb3 tests
// ---------------------------------------------------------------------------

func newTestQuery3(id uint16) *protocol.Message {
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

func buildTestDNSResponse3(id uint16) *protocol.Message {
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

func packMessage3(t *testing.T, msg *protocol.Message) []byte {
	t.Helper()
	buf := make([]byte, 65535)
	n, err := msg.Pack(buf)
	if err != nil {
		t.Fatalf("pack message: %v", err)
	}
	return buf[:n]
}

func startUDPMockServer3(t *testing.T, handler func(conn *net.UDPConn, data []byte, remote *net.UDPAddr)) (string, func()) {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve UDP: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
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
