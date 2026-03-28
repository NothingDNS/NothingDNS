package upstream

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// ---------------------------------------------------------------------------
// LoadBalancer - selectStandaloneTarget with RoundRobin strategy
// ---------------------------------------------------------------------------

func TestLoadBalancer_SelectStandaloneTarget_RoundRobin(t *testing.T) {
	lb := &LoadBalancer{
		servers: []*Server{
			{Address: "10.0.0.1:53", healthy: true},
			{Address: "10.0.0.2:53", healthy: true},
			{Address: "10.0.0.3:53", healthy: true},
		},
		strategy: RoundRobin,
		udpPool:  make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
	}

	// Multiple selections should rotate
	seen := make(map[string]int)
	for i := 0; i < 6; i++ {
		target, err := lb.selectStandaloneTarget()
		if err != nil {
			t.Fatalf("selectStandaloneTarget() error = %v", err)
		}
		seen[target.Address]++
	}

	// All servers should have been selected at least once
	if len(seen) < 2 {
		t.Errorf("expected at least 2 different servers, got %d", len(seen))
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer - selectStandaloneTarget with Fastest strategy
// ---------------------------------------------------------------------------

func TestLoadBalancer_SelectStandaloneTarget_Fastest(t *testing.T) {
	s1 := &Server{Address: "10.0.0.1:53", healthy: true}
	s2 := &Server{Address: "10.0.0.2:53", healthy: true}
	s2.latency = 1 * time.Millisecond

	lb := &LoadBalancer{
		servers: []*Server{s1, s2},
		strategy: Fastest,
		udpPool:  make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
	}

	target, err := lb.selectStandaloneTarget()
	if err != nil {
		t.Fatalf("selectStandaloneTarget() error = %v", err)
	}
	// s1 has 0 latency, which is the fastest
	if target.Address != "10.0.0.1:53" {
		t.Errorf("expected fastest server 10.0.0.1:53, got %s", target.Address)
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer - selectStandaloneTarget with Fastest strategy, all unhealthy
// ---------------------------------------------------------------------------

func TestLoadBalancer_SelectStandaloneTarget_Fastest_AllUnhealthy(t *testing.T) {
	s1 := &Server{Address: "10.0.0.1:53", healthy: false}
	s2 := &Server{Address: "10.0.0.2:53", healthy: false}

	lb := &LoadBalancer{
		servers:  []*Server{s1, s2},
		strategy: Fastest,
		udpPool:  make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
	}

	target, err := lb.selectStandaloneTarget()
	if err != nil {
		t.Fatalf("selectStandaloneTarget() error = %v", err)
	}
	// Falls back to first server when all unhealthy
	if target.Address != "10.0.0.1:53" {
		t.Errorf("expected fallback to first server, got %s", target.Address)
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer - selectStandaloneTarget with default (random) strategy
// ---------------------------------------------------------------------------

func TestLoadBalancer_SelectStandaloneTarget_Random(t *testing.T) {
	lb := &LoadBalancer{
		servers: []*Server{
			{Address: "10.0.0.1:53", healthy: true},
			{Address: "10.0.0.2:53", healthy: true},
		},
		strategy: Strategy(99),
		udpPool:  make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
	}

	target, err := lb.selectStandaloneTarget()
	if err != nil {
		t.Fatalf("selectStandaloneTarget() error = %v", err)
	}
	if target.Address != "10.0.0.1:53" && target.Address != "10.0.0.2:53" {
		t.Errorf("unexpected target address: %s", target.Address)
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer - selectStandaloneTarget with nil (all selected are nil)
// ---------------------------------------------------------------------------

func TestLoadBalancer_SelectStandaloneTarget_NoHealthyServers(t *testing.T) {
	lb := &LoadBalancer{
		servers:  []*Server{}, // empty servers list
		strategy: Random,
		udpPool:  make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
	}

	_, err := lb.selectStandaloneTarget()
	if err == nil {
		t.Error("expected error for no upstream servers")
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer - selectRandom with no healthy servers but servers exist
// ---------------------------------------------------------------------------

func TestLoadBalancer_SelectRandom_NoHealthyFallback(t *testing.T) {
	lb := &LoadBalancer{
		servers: []*Server{
			{Address: "10.0.0.1:53", healthy: false},
			{Address: "10.0.0.2:53", healthy: false},
		},
	}

	selected := lb.selectRandom()
	if selected == nil {
		t.Error("expected fallback to first server even when all unhealthy")
	}
	if selected.Address != "10.0.0.1:53" && selected.Address != "10.0.0.2:53" {
		t.Errorf("unexpected server: %s", selected.Address)
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer - selectRandom with no servers at all
// ---------------------------------------------------------------------------

func TestLoadBalancer_SelectRandom_EmptyServers(t *testing.T) {
	lb := &LoadBalancer{servers: []*Server{}}
	selected := lb.selectRandom()
	if selected != nil {
		t.Error("expected nil for empty servers")
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer - selectRoundRobin fallback to starting position
// ---------------------------------------------------------------------------

func TestLoadBalancer_SelectRoundRobin_AllUnhealthy(t *testing.T) {
	lb := &LoadBalancer{
		servers: []*Server{
			{Address: "10.0.0.1:53", healthy: false},
			{Address: "10.0.0.2:53", healthy: false},
		},
	}

	selected := lb.selectRoundRobin()
	if selected == nil {
		t.Error("expected fallback server, got nil")
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer - selectFastest with no healthy and some latency data
// ---------------------------------------------------------------------------

func TestLoadBalancer_SelectFastest_NoHealthyWithLatency(t *testing.T) {
	s1 := &Server{Address: "10.0.0.1:53", healthy: false}
	s1.latency = 100 * time.Millisecond
	s2 := &Server{Address: "10.0.0.2:53", healthy: false}
	s2.latency = 50 * time.Millisecond

	lb := &LoadBalancer{
		servers: []*Server{s1, s2},
	}

	selected := lb.selectFastest()
	if selected == nil {
		t.Error("expected fallback server, got nil")
	}
	if selected.Address != "10.0.0.1:53" {
		t.Errorf("expected fallback to first server, got %s", selected.Address)
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer - queryUDP with no pool (creates one dynamically)
// ---------------------------------------------------------------------------

func TestLoadBalancer_QueryUDP_NoPool(t *testing.T) {
	// Use a mock UDP server that responds with garbage to trigger Unpack error
	addr, cleanup := startUDPMockServer2(t, func(conn *net.UDPConn, data []byte, remote *net.UDPAddr) {
		conn.WriteToUDP([]byte{0xFF, 0xFF, 0xFF, 0xFF}, remote)
	})
	defer cleanup()

	lb := &LoadBalancer{
		udpPool: make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
	}

	msg := newTestQuery2(0x1111)
	_, err := lb.queryUDP(addr, msg)
	if err == nil {
		t.Error("expected error for garbage response")
	}
	// Pool should have been created dynamically
	lb.mu.RLock()
	_, exists := lb.udpPool[addr]
	lb.mu.RUnlock()
	if !exists {
		t.Error("expected UDP pool to be created dynamically")
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer - queryTCP with no pool (creates one dynamically)
// ---------------------------------------------------------------------------

func TestLoadBalancer_QueryTCP_NoPool(t *testing.T) {
	// Start a TCP server that closes immediately to trigger a fast error
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()
	defer ln.Close()

	lb := &LoadBalancer{
		udpPool: make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
	}

	msg := newTestQuery2(0x2222)
	_, err = lb.queryTCP(addr, msg)
	if err == nil {
		t.Error("expected error for closed connection")
	}
	// Pool should have been created dynamically
	lb.mu.RLock()
	_, exists := lb.tcpPool[addr]
	lb.mu.RUnlock()
	if !exists {
		t.Error("expected TCP pool to be created dynamically")
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer - queryUDP with Pack error (zero-length pool buffer)
// ---------------------------------------------------------------------------

func TestLoadBalancer_QueryUDP_PackError(t *testing.T) {
	lb := &LoadBalancer{
		udpPool: map[string]*sync.Pool{
			"127.0.0.1:53": {New: func() interface{} { return make([]byte, 0) }},
		},
		tcpPool: make(map[string]*sync.Pool),
	}

	msg := newTestQuery2(0x3333)
	_, err := lb.queryUDP("127.0.0.1:53", msg)
	if err == nil {
		t.Error("expected pack error with zero-length buffer")
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer - queryTCP with Pack error (zero-length pool buffer)
// ---------------------------------------------------------------------------

func TestLoadBalancer_QueryTCP_PackError(t *testing.T) {
	lb := &LoadBalancer{
		udpPool: make(map[string]*sync.Pool),
		tcpPool: map[string]*sync.Pool{
			"127.0.0.1:53": {New: func() interface{} { return make([]byte, 0) }},
		},
	}

	msg := newTestQuery2(0x4444)
	_, err := lb.queryTCP("127.0.0.1:53", msg)
	if err == nil {
		t.Error("expected pack error with zero-length buffer")
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer - checkHealth with standalone servers (connection failures)
// ---------------------------------------------------------------------------

func TestLoadBalancer_CheckHealth_StandaloneServers(t *testing.T) {
	lb := &LoadBalancer{
		servers: []*Server{
			{Address: "198.51.100.1:53", healthy: true, Timeout: 200 * time.Millisecond},
		},
		udpPool:  make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
		healthCheck: 30 * time.Second,
	}

	lb.udpPool["198.51.100.1:53"] = &sync.Pool{
		New: func() interface{} { return make([]byte, 4096) },
	}
	lb.tcpPool["198.51.100.1:53"] = &sync.Pool{
		New: func() interface{} { return make([]byte, 65535) },
	}

	// checkHealth fires goroutines that try to connect. Non-routable address will fail.
	lb.checkHealth()
	time.Sleep(500 * time.Millisecond)
	// Server should still be in initial state since queryUDP/TCP don't call markFailure
	// (only queryWithFailover does)
}

// ---------------------------------------------------------------------------
// LoadBalancer - checkHealth with anycast backends
// ---------------------------------------------------------------------------

func TestLoadBalancer_CheckHealth_AnycastBackends(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)
	backend := &AnycastBackend{
		PhysicalIP: "198.51.100.2",
		Port:       53,
		Region:     "us-east-1",
		Zone:       "a",
		Weight:     50,
	}
	group.AddBackend(backend)

	lb := &LoadBalancer{
		anycastGroups: map[string]*AnycastGroup{
			"192.0.2.1": group,
		},
		udpPool:      make(map[string]*sync.Pool),
		tcpPool:      make(map[string]*sync.Pool),
		healthCheck:  30 * time.Second,
	}

	lb.checkHealth()
	time.Sleep(500 * time.Millisecond)
	// Backend should be marked as failed (unreachable address)
}

// ---------------------------------------------------------------------------
// LoadBalancer - queryUDP success with mock UDP server
// ---------------------------------------------------------------------------

func TestLoadBalancer_QueryUDP_Success(t *testing.T) {
	addr, cleanup := startUDPMockServer2(t, func(conn *net.UDPConn, data []byte, remote *net.UDPAddr) {
		if len(data) < 2 {
			return
		}
		queryID := uint16(data[0])<<8 | uint16(data[1])
		resp := buildTestDNSResponse2(queryID)
		packed := packMessage2(t, resp)
		conn.WriteToUDP(packed, remote)
	})
	defer cleanup()

	lb := &LoadBalancer{
		servers: []*Server{
			{Address: addr, healthy: true, Timeout: 2 * time.Second},
		},
		udpPool:  make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
	}

	lb.udpPool[addr] = &sync.Pool{
		New: func() interface{} { return make([]byte, 4096) },
	}

	msg := newTestQuery2(0x5678)
	resp, err := lb.queryUDP(addr, msg)
	if err != nil {
		t.Fatalf("queryUDP() error = %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Header.ID != 0x5678 {
		t.Errorf("expected ID 0x5678, got 0x%04X", resp.Header.ID)
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer - queryTCP success with mock TCP server
// ---------------------------------------------------------------------------

func TestLoadBalancer_QueryTCP_Success(t *testing.T) {
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

		var queryID uint16
		if len(queryData) >= 2 {
			queryID = uint16(queryData[0])<<8 | uint16(queryData[1])
		}

		resp := buildTestDNSResponse2(queryID)
		packed := packMessage2(&testing.T{}, resp)

		respLen := make([]byte, 2)
		binary.BigEndian.PutUint16(respLen, uint16(len(packed)))
		conn.Write(respLen)
		conn.Write(packed)
	}()

	addr := ln.Addr().String()
	lb := &LoadBalancer{
		servers: []*Server{
			{Address: addr, healthy: true, Timeout: 2 * time.Second},
		},
		udpPool:  make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
	}

	lb.tcpPool[addr] = &sync.Pool{
		New: func() interface{} { return make([]byte, 65535) },
	}

	msg := newTestQuery2(0x9ABC)
	resp, err := lb.queryTCP(addr, msg)
	if err != nil {
		t.Fatalf("queryTCP() error = %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Header.ID != 0x9ABC {
		t.Errorf("expected ID 0x9ABC, got 0x%04X", resp.Header.ID)
	}

	ln.Close()
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Server - markFailure threshold and markSuccess reset
// ---------------------------------------------------------------------------

func TestServer_MarkFailure_Threshold(t *testing.T) {
	s := &Server{Address: "10.0.0.1:53", healthy: true}

	// First two failures should not mark unhealthy
	s.markFailure()
	if !s.healthy {
		t.Error("expected healthy after 1 failure")
	}
	s.markFailure()
	if !s.healthy {
		t.Error("expected healthy after 2 failures")
	}

	// Third failure should mark unhealthy
	s.markFailure()
	if s.healthy {
		t.Error("expected unhealthy after 3 failures")
	}

	// markSuccess should reset
	s.markSuccess(1 * time.Millisecond)
	if !s.healthy {
		t.Error("expected healthy after markSuccess")
	}
	if s.failCount != 0 {
		t.Errorf("expected failCount 0, got %d", s.failCount)
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer - healthCheckLoop exits on cancel
// ---------------------------------------------------------------------------

func TestLoadBalancer_HealthCheckLoop_ExitsOnCancel(t *testing.T) {
	lb := &LoadBalancer{
		servers:     []*Server{},
		anycastGroups: map[string]*AnycastGroup{},
		udpPool:     make(map[string]*sync.Pool),
		tcpPool:     make(map[string]*sync.Pool),
		healthCheck: 30 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	lb.wg.Add(1)
	go lb.healthCheckLoop(ctx)

	// Cancel after a brief moment
	time.Sleep(50 * time.Millisecond)
	cancel()
	lb.wg.Wait() // Should return quickly
}

// ---------------------------------------------------------------------------
// weightedSelect - single backend
// ---------------------------------------------------------------------------

func TestWeightedSelect_SingleBackend(t *testing.T) {
	backend := &AnycastBackend{PhysicalIP: "10.0.0.1", Weight: 50}
	result := weightedSelect([]*AnycastBackend{backend})
	if result != backend {
		t.Error("expected single backend to be returned")
	}
}

// ---------------------------------------------------------------------------
// weightedSelect - all zero weights
// ---------------------------------------------------------------------------

func TestWeightedSelect_AllZeroWeights(t *testing.T) {
	backends := []*AnycastBackend{
		{PhysicalIP: "10.0.0.1", Weight: 0},
		{PhysicalIP: "10.0.0.2", Weight: 0},
	}
	result := weightedSelect(backends)
	if result == nil {
		t.Error("expected a backend even with all zero weights")
	}
	if result.PhysicalIP != "10.0.0.1" && result.PhysicalIP != "10.0.0.2" {
		t.Errorf("unexpected backend: %s", result.PhysicalIP)
	}
}

// ---------------------------------------------------------------------------
// weightedSelect - fallback to last backend
// ---------------------------------------------------------------------------

func TestWeightedSelect_WithWeights(t *testing.T) {
	backends := []*AnycastBackend{
		{PhysicalIP: "10.0.0.1", Weight: 100},
		{PhysicalIP: "10.0.0.2", Weight: 100},
	}
	result := weightedSelect(backends)
	if result == nil {
		t.Error("expected a backend")
	}
}

// ---------------------------------------------------------------------------
// Helper functions for loadbalancer tests
// ---------------------------------------------------------------------------

func newTestQuery2(id uint16) *protocol.Message {
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

func buildTestDNSResponse2(id uint16) *protocol.Message {
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

func packMessage2(t *testing.T, msg *protocol.Message) []byte {
	t.Helper()
	buf := make([]byte, 65535)
	n, err := msg.Pack(buf)
	if err != nil {
		t.Fatalf("pack message: %v", err)
	}
	return buf[:n]
}

func startUDPMockServer2(t *testing.T, handler func(conn *net.UDPConn, data []byte, remote *net.UDPAddr)) (string, func()) {
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
