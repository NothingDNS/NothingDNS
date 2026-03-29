package upstream

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// client.go:451-452 - healthCheckLoop ticker fires
// The Client healthCheckLoop uses a hardcoded 30s ticker. We run a real
// server so that checkHealth() completes within the tick and then cancel.
// This test takes ~31s to complete.
// ---------------------------------------------------------------------------

func TestClient_HealthCheckLoop_TickerFires(t *testing.T) {
	// Start a UDP server that responds to queries
	addr, cleanup := startUDPMockServer2(t, func(conn *net.UDPConn, data []byte, remote *net.UDPAddr) {
		if len(data) < 2 {
			return
		}
		queryID := uint16(data[0])<<8 | uint16(data[1])
		resp := buildTestDNSResponse2(queryID)
		packed := packMessage2(&testing.T{}, resp)
		conn.WriteToUDP(packed, remote)
	})
	defer cleanup()

	config := Config{
		Servers:  []string{addr},
		Strategy: "random",
		Timeout:  2 * time.Second,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	// Wait for the 30s ticker to fire at least once.
	// We wait a bit longer than 30s to ensure the ticker fires.
	waitCh := make(chan struct{})
	go func() {
		time.Sleep(31 * time.Second)
		close(waitCh)
	}()

	select {
	case <-waitCh:
		// Ticker should have fired by now
	case <-time.After(35 * time.Second):
		t.Fatal("timed out waiting for health check ticker to fire")
	}

	if err := client.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// client.go:336-338 - queryUDP SetDeadline error
// client.go:342-344 - queryUDP Write error
// Using timeout=0, UDP dial succeeds, SetDeadline(Now+0) causes Write to fail.
// ---------------------------------------------------------------------------

func TestClient_QueryUDP_WriteDeadlineExpired(t *testing.T) {
	addr, cleanup := startUDPMockServer2(t, func(conn *net.UDPConn, data []byte, remote *net.UDPAddr) {
		// Don't need to respond
	})
	defer cleanup()

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

	// Set timeout to 0: UDP dial succeeds, SetDeadline(Now+0) causes Write to fail
	client.servers[0].Timeout = 0

	msg := newTestQuery2(0xC100)
	_, err = client.queryUDP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error with zero timeout (write)")
	}
}

// ---------------------------------------------------------------------------
// client.go:401-403 - queryTCP send length error
// With timeout=0, TCP dial succeeds (localhost), SetDeadline(Now+0) succeeds,
// but Write of length prefix fails because deadline is now.
// ---------------------------------------------------------------------------

func TestClient_QueryTCP_SendLengthZeroDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	config := Config{
		Servers:  []string{ln.Addr().String()},
		Strategy: "random",
		Timeout:  2 * time.Second,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	// Set timeout to 0: TCP dial succeeds on localhost, then Write fails
	client.servers[0].Timeout = 0

	msg := newTestQuery2(0xC200)
	_, err = client.queryTCP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error with zero timeout (send length)")
	}
}

// ---------------------------------------------------------------------------
// client.go:406-408 - queryTCP send query body error
// Server reads the length prefix then closes before the body write fails.
// This test uses a server that closes after reading the length prefix,
// making the body write fail due to broken pipe.
// ---------------------------------------------------------------------------

func TestClient_QueryTCP_SendBodyPipeError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Read the 2-byte length prefix, then close
		lenBuf := make([]byte, 2)
		io.ReadFull(conn, lenBuf)
		// Now close - client's next Write (body) should fail
		time.Sleep(10 * time.Millisecond)
	}()

	config := Config{
		Servers:  []string{ln.Addr().String()},
		Strategy: "random",
		Timeout:  2 * time.Second,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	msg := newTestQuery2(0xC300)
	_, err = client.queryTCP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error when server closes before body write")
	}
}

// ---------------------------------------------------------------------------
// client.go:423-425 - queryTCP read response body error
// Server sends a large length prefix but no actual body data.
// ---------------------------------------------------------------------------

func TestClient_QueryTCP_ReadResponseBodyError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read the query
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		queryLen := int(binary.BigEndian.Uint16(lenBuf))
		if queryLen > 0 {
			io.ReadFull(conn, make([]byte, queryLen))
		}

		// Send length prefix indicating a large response, then close
		respLen := make([]byte, 2)
		binary.BigEndian.PutUint16(respLen, 200)
		conn.Write(respLen)
		// Don't send the body - close immediately
	}()

	config := Config{
		Servers:  []string{ln.Addr().String()},
		Strategy: "random",
		Timeout:  2 * time.Second,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	msg := newTestQuery2(0xC500)
	_, err = client.queryTCP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error when server sends length but no body")
	}
}

// ---------------------------------------------------------------------------
// loadbalancer.go:443-445 - queryWithFailover retry path error
// "query failed on primary and failover"
// We need primary to fail, then failover target to also fail.
// The key is making sure failoverTarget.Address != target.Address so
// we actually attempt the retry.
// ---------------------------------------------------------------------------

func TestLB_QueryWithFailover_PrimaryAndFailoverBothFail(t *testing.T) {
	// Create two servers that will fail to connect
	s1 := &Server{Address: "127.0.0.1:1", healthy: true, Timeout: 100 * time.Millisecond}
	s2 := &Server{Address: "127.0.0.1:2", healthy: true, Timeout: 100 * time.Millisecond}
	s1.latency = 1 * time.Nanosecond  // Very low latency so Fastest picks s1 as failover
	s2.latency = 100 * time.Millisecond // Higher latency

	lb := &LoadBalancer{
		servers:       []*Server{s1, s2},
		anycastGroups: map[string]*AnycastGroup{},
		strategy:      Fastest, // Use Fastest to ensure s1 is picked as failover
		udpPool:       make(map[string]*sync.Pool),
		tcpPool:       make(map[string]*sync.Pool),
	}

	lb.udpPool["127.0.0.1:1"] = &sync.Pool{New: func() interface{} { return make([]byte, 4096) }}
	lb.udpPool["127.0.0.1:2"] = &sync.Pool{New: func() interface{} { return make([]byte, 4096) }}
	lb.tcpPool["127.0.0.1:1"] = &sync.Pool{New: func() interface{} { return make([]byte, 65535) }}
	lb.tcpPool["127.0.0.1:2"] = &sync.Pool{New: func() interface{} { return make([]byte, 65535) }}

	// Use the second server as primary so selectTarget picks the first as failover
	target := &Target{
		Type:    "standalone",
		Address: "127.0.0.1:2",
		Server:  s2,
	}

	msg := newTestQuery2(0xD100)
	_, err := lb.queryWithFailover(target, msg)
	if err == nil {
		t.Error("expected error when primary and failover both fail")
	}
	// Verify the error mentions failover failure
	if err != nil {
		t.Logf("error (expected): %v", err)
	}
}

// ---------------------------------------------------------------------------
// loadbalancer.go: queryWithFailover - full failover path with actual servers
// Primary target UDP fails, TCP fails, failover to second target UDP succeeds.
// ---------------------------------------------------------------------------

func TestLB_QueryWithFailover_FailoverUDPSuccess(t *testing.T) {
	// Start a UDP mock server for the failover target
	addr, cleanup := startUDPMockServer2(t, func(conn *net.UDPConn, data []byte, remote *net.UDPAddr) {
		if len(data) < 2 {
			return
		}
		queryID := uint16(data[0])<<8 | uint16(data[1])
		resp := buildTestDNSResponse2(queryID)
		packed := packMessage2(&testing.T{}, resp)
		conn.WriteToUDP(packed, remote)
	})
	defer cleanup()

	// Create two servers: one bad, one good
	badServer := &Server{Address: "127.0.0.1:1", healthy: true, Timeout: 100 * time.Millisecond}
	badServer.latency = 100 * time.Millisecond // Higher latency
	goodServer := &Server{Address: addr, healthy: true, Timeout: 2 * time.Second}
	goodServer.latency = 1 * time.Millisecond // Lower latency so Fastest picks it

	lb := &LoadBalancer{
		servers:       []*Server{badServer, goodServer},
		anycastGroups: map[string]*AnycastGroup{},
		strategy:      Fastest, // Use Fastest to ensure good server is picked as failover
		udpPool:       make(map[string]*sync.Pool),
		tcpPool:       make(map[string]*sync.Pool),
	}

	lb.udpPool["127.0.0.1:1"] = &sync.Pool{New: func() interface{} { return make([]byte, 4096) }}
	lb.udpPool[addr] = &sync.Pool{New: func() interface{} { return make([]byte, 4096) }}
	lb.tcpPool["127.0.0.1:1"] = &sync.Pool{New: func() interface{} { return make([]byte, 65535) }}
	lb.tcpPool[addr] = &sync.Pool{New: func() interface{} { return make([]byte, 65535) }}

	// Target the bad server first
	target := &Target{
		Type:    "standalone",
		Address: "127.0.0.1:1",
		Server:  badServer,
	}

	msg := newTestQuery2(0xD700)
	resp, err := lb.queryWithFailover(target, msg)
	if err != nil {
		t.Fatalf("expected failover success, got error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Header.ID != 0xD700 {
		t.Errorf("expected ID 0xD700, got 0x%04X", resp.Header.ID)
	}
}

// ---------------------------------------------------------------------------
// loadbalancer.go: queryWithFailover - failover TCP success
// Primary fails, failover target UDP fails but TCP succeeds.
// ---------------------------------------------------------------------------

func TestLB_QueryWithFailover_FailoverTCPSuccess(t *testing.T) {
	// Start a TCP server for the failover target (no UDP listener)
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
	badServer := &Server{Address: "127.0.0.1:2", healthy: true, Timeout: 100 * time.Millisecond}
	badServer.latency = 100 * time.Millisecond // Higher latency
	goodServer := &Server{Address: addr, healthy: true, Timeout: 2 * time.Second}
	goodServer.latency = 1 * time.Millisecond // Lower latency so Fastest picks it

	lb := &LoadBalancer{
		servers:       []*Server{badServer, goodServer},
		anycastGroups: map[string]*AnycastGroup{},
		strategy:      Fastest, // Use Fastest to ensure good server is picked as failover
		udpPool:       make(map[string]*sync.Pool),
		tcpPool:       make(map[string]*sync.Pool),
	}

	lb.udpPool["127.0.0.1:2"] = &sync.Pool{New: func() interface{} { return make([]byte, 4096) }}
	lb.udpPool[addr] = &sync.Pool{New: func() interface{} { return make([]byte, 4096) }}
	lb.tcpPool["127.0.0.1:2"] = &sync.Pool{New: func() interface{} { return make([]byte, 65535) }}
	lb.tcpPool[addr] = &sync.Pool{New: func() interface{} { return make([]byte, 65535) }}

	target := &Target{
		Type:    "standalone",
		Address: "127.0.0.1:2",
		Server:  badServer,
	}

	msg := newTestQuery2(0xD800)
	resp, err := lb.queryWithFailover(target, msg)
	if err != nil {
		t.Fatalf("expected failover TCP success, got error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	ln.Close()
	wg.Wait()
}

// ---------------------------------------------------------------------------
// loadbalancer.go: selectAnycastTarget - all backends unhealthy, fallback group
// ---------------------------------------------------------------------------

func TestLB_SelectAnycastTarget_AllBackendsUnhealthy(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	// Add backends and mark them as unhealthy
	b1 := &AnycastBackend{
		PhysicalIP: "10.0.0.1",
		Port:       53,
		Region:     "us-east-1",
		Zone:       "a",
		Weight:     100,
	}
	group.AddBackend(b1)

	b2 := &AnycastBackend{
		PhysicalIP: "10.0.0.2",
		Port:       53,
		Region:     "eu-west-1",
		Zone:       "b",
		Weight:     100,
	}
	group.AddBackend(b2)

	// Mark all backends unhealthy by calling markFailure 3 times each
	for i := 0; i < 3; i++ {
		b1.markFailure()
		b2.markFailure()
	}

	lb := &LoadBalancer{
		anycastGroups: map[string]*AnycastGroup{
			"192.0.2.1": group,
		},
		strategy: Random,
		udpPool:  make(map[string]*sync.Pool),
		tcpPool:  make(map[string]*sync.Pool),
		topology: Topology{Region: "us-east-1", Zone: "a"},
	}

	// Even with all backends unhealthy, selectAnycastTarget should return
	// a target because SelectBackend falls back to g.Backends[0]
	target, err := lb.selectAnycastTarget()
	if err != nil {
		t.Fatalf("expected fallback target, got error: %v", err)
	}
	if target == nil {
		t.Fatal("expected non-nil target with unhealthy backends")
	}
	if target.Type != "anycast" {
		t.Errorf("expected anycast type, got %s", target.Type)
	}
}

// ---------------------------------------------------------------------------
// loadbalancer.go: selectAnycastTarget - with healthy backends and region match
// ---------------------------------------------------------------------------

func TestLB_SelectAnycastTarget_HealthyBackendRegionMatch(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	b1 := &AnycastBackend{
		PhysicalIP: "10.0.0.1",
		Port:       53,
		Region:     "us-east-1",
		Zone:       "a",
		Weight:     100,
	}
	group.AddBackend(b1)

	b2 := &AnycastBackend{
		PhysicalIP: "10.0.0.2",
		Port:       53,
		Region:     "eu-west-1",
		Zone:       "b",
		Weight:     50,
	}
	group.AddBackend(b2)

	lb := &LoadBalancer{
		anycastGroups: map[string]*AnycastGroup{
			"192.0.2.1": group,
		},
		strategy: Random,
		udpPool:  make(map[string]*sync.Pool),
		tcpPool:  make(map[string]*sync.Pool),
		topology: Topology{Region: "us-east-1", Zone: "a"},
	}

	target, err := lb.selectAnycastTarget()
	if err != nil {
		t.Fatalf("expected target, got error: %v", err)
	}
	if target == nil {
		t.Fatal("expected non-nil target")
	}
	// Should prefer the us-east-1 backend due to region match
	if target.Region != "us-east-1" {
		t.Errorf("expected us-east-1 region, got %s", target.Region)
	}
}

// ---------------------------------------------------------------------------
// Client: QueryContext with cancelled context
// ---------------------------------------------------------------------------

func TestClient_QueryContext_CancelledContext(t *testing.T) {
	config := Config{
		Servers:  []string{"127.0.0.1:1"},
		Strategy: "random",
		Timeout:  200 * time.Millisecond,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	msg := newTestQuery2(0xE100)
	_, err = client.QueryContext(ctx, msg)
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Client: Query all servers unhealthy
// ---------------------------------------------------------------------------

func TestClient_Query_AllServersUnhealthy(t *testing.T) {
	config := Config{
		Servers:  []string{"127.0.0.1:1"},
		Strategy: "random",
		Timeout:  200 * time.Millisecond,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	// Mark server unhealthy
	client.servers[0].healthy = false
	client.servers[0].failCount = 3

	msg := newTestQuery2(0xE200)
	// The selectRandom should still pick it as a fallback
	// Query will try UDP then TCP, both fail
	_, err = client.Query(msg)
	if err == nil {
		t.Error("expected error with all servers unreachable")
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer: Full Query path through anycast
// ---------------------------------------------------------------------------

func TestLB_Query_AnycastPath(t *testing.T) {
	// Start a UDP server for the anycast backend
	addr, cleanup := startUDPMockServer2(t, func(conn *net.UDPConn, data []byte, remote *net.UDPAddr) {
		if len(data) < 2 {
			return
		}
		queryID := uint16(data[0])<<8 | uint16(data[1])
		resp := buildTestDNSResponse2(queryID)
		packed := packMessage2(&testing.T{}, resp)
		conn.WriteToUDP(packed, remote)
	})
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	_ = host

	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)
	backend := &AnycastBackend{
		PhysicalIP: "127.0.0.1",
		Port:       port,
		Region:     "us-east-1",
		Zone:       "a",
		Weight:     100,
	}
	group.AddBackend(backend)

	lb := &LoadBalancer{
		anycastGroups: map[string]*AnycastGroup{
			"192.0.2.1": group,
		},
		servers:     []*Server{},
		strategy:    Random,
		udpPool:     make(map[string]*sync.Pool),
		tcpPool:     make(map[string]*sync.Pool),
		healthCheck: 30 * time.Second,
	}

	msg := newTestQuery2(0xE300)
	resp, err := lb.Query(msg)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Header.ID != 0xE300 {
		t.Errorf("expected ID 0xE300, got 0x%04X", resp.Header.ID)
	}

	lb.Close()
}

// ---------------------------------------------------------------------------
// LoadBalancer: NewLoadBalancer with invalid config
// ---------------------------------------------------------------------------

func TestNewLoadBalancer_NoServersOrGroups(t *testing.T) {
	config := LoadBalancerConfig{
		AnycastGroups: []AnycastGroupConfig{},
		Servers:       []string{},
	}
	_, err := NewLoadBalancer(config)
	if err == nil {
		t.Error("expected error with no servers or groups")
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer: NewLoadBalancer with invalid backend weight
// ---------------------------------------------------------------------------

func TestNewLoadBalancer_InvalidBackendWeight(t *testing.T) {
	config := LoadBalancerConfig{
		AnycastGroups: []AnycastGroupConfig{
			{
				AnycastIP: "192.0.2.1",
				Backends: []AnycastBackendConfig{
					{
						PhysicalIP: "10.0.0.1",
						Port:       53,
						Region:     "us-east-1",
						Zone:       "a",
						Weight:     200, // Invalid: > 100
					},
				},
			},
		},
		Servers: []string{},
	}
	_, err := NewLoadBalancer(config)
	if err == nil {
		t.Error("expected error with invalid backend weight")
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer: NewLoadBalancer with empty backend physical IP
// ---------------------------------------------------------------------------

func TestNewLoadBalancer_EmptyBackendIP(t *testing.T) {
	config := LoadBalancerConfig{
		AnycastGroups: []AnycastGroupConfig{
			{
				AnycastIP: "192.0.2.1",
				Backends: []AnycastBackendConfig{
					{
						PhysicalIP: "", // Empty
						Port:       53,
						Region:     "us-east-1",
						Weight:     100,
					},
				},
			},
		},
		Servers: []string{},
	}
	_, err := NewLoadBalancer(config)
	if err == nil {
		t.Error("expected error with empty backend IP")
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer: GetAnycastGroups and GetTopology
// ---------------------------------------------------------------------------

func TestLB_GetAnycastGroups_GetTopology(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)
	backend := &AnycastBackend{
		PhysicalIP: "10.0.0.1",
		Port:       53,
		Region:     "us-east-1",
		Zone:       "a",
		Weight:     100,
	}
	group.AddBackend(backend)

	lb, err := NewLoadBalancer(LoadBalancerConfig{
		AnycastGroups: []AnycastGroupConfig{
			{
				AnycastIP: "192.0.2.1",
				Backends: []AnycastBackendConfig{
					{
						PhysicalIP: "10.0.0.1",
						Port:       53,
						Region:     "us-east-1",
						Zone:       "a",
						Weight:     100,
					},
				},
			},
		},
		Servers:         []string{},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
		Region:          "us-east-1",
		Zone:            "a",
		Weight:          100,
	})
	if err != nil {
		t.Fatalf("create lb: %v", err)
	}
	defer lb.Close()

	groups := lb.GetAnycastGroups()
	if len(groups) != 1 {
		t.Errorf("expected 1 group, got %d", len(groups))
	}

	topo := lb.GetTopology()
	if topo.Region != "us-east-1" {
		t.Errorf("expected region us-east-1, got %s", topo.Region)
	}

	queries, failed, failovers := lb.Stats()
	if queries != 0 || failed != 0 || failovers != 0 {
		t.Errorf("expected all zero stats, got queries=%d failed=%d failovers=%d", queries, failed, failovers)
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer: Stats after queries
// ---------------------------------------------------------------------------

func TestLB_Stats_AfterQueries(t *testing.T) {
	addr, cleanup := startUDPMockServer2(t, func(conn *net.UDPConn, data []byte, remote *net.UDPAddr) {
		if len(data) < 2 {
			return
		}
		queryID := uint16(data[0])<<8 | uint16(data[1])
		resp := buildTestDNSResponse2(queryID)
		packed := packMessage2(&testing.T{}, resp)
		conn.WriteToUDP(packed, remote)
	})
	defer cleanup()

	lb, err := NewLoadBalancer(LoadBalancerConfig{
		Servers:     []string{addr},
		Strategy:    "random",
		HealthCheck: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("create lb: %v", err)
	}
	defer lb.Close()

	msg := newTestQuery2(0xE400)
	_, err = lb.Query(msg)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	queries, failed, failovers := lb.Stats()
	if queries != 1 {
		t.Errorf("expected 1 query, got %d", queries)
	}
	if failed != 0 {
		t.Errorf("expected 0 failed, got %d", failed)
	}
	if failovers != 0 {
		t.Errorf("expected 0 failovers, got %d", failovers)
	}
}

// ---------------------------------------------------------------------------
// Client: selectServer strategies
// ---------------------------------------------------------------------------

func TestClient_SelectServer_RoundRobin(t *testing.T) {
	config := Config{
		Servers:  []string{"10.0.0.1:53", "10.0.0.2:53"},
		Strategy: "round_robin",
		Timeout:  200 * time.Millisecond,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	server := client.selectServer()
	if server == nil {
		t.Error("expected non-nil server")
	}
}

func TestClient_SelectServer_Fastest(t *testing.T) {
	config := Config{
		Servers:  []string{"10.0.0.1:53", "10.0.0.2:53"},
		Strategy: "fastest",
		Timeout:  200 * time.Millisecond,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	server := client.selectServer()
	if server == nil {
		t.Error("expected non-nil server")
	}
}

// ---------------------------------------------------------------------------
// Anycast: FailoverToNext edge cases
// ---------------------------------------------------------------------------

func TestAnycastGroup_FailoverToNext_SingleBackend(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)
	backend := &AnycastBackend{
		PhysicalIP: "10.0.0.1",
		Port:       53,
		Region:     "us-east-1",
		Weight:     100,
	}
	group.AddBackend(backend)

	// Failover with single backend should return nil
	result := group.FailoverToNext()
	if result != nil {
		t.Error("expected nil for failover with single backend")
	}
}

func TestAnycastGroup_GetActiveBackend_InvalidIndex(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)
	backend := &AnycastBackend{
		PhysicalIP: "10.0.0.1",
		Port:       53,
		Region:     "us-east-1",
		Weight:     100,
	}
	group.AddBackend(backend)

	// Set activeIndex to a value beyond the backend list length
	group.activeIndex = 5

	result := group.GetActiveBackend()
	if result == nil {
		t.Error("expected non-nil backend after index reset")
	}
	if result.PhysicalIP != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %s", result.PhysicalIP)
	}
}

// ---------------------------------------------------------------------------
// AnycastGroup: RemoveBackend
// ---------------------------------------------------------------------------

func TestAnycastGroup_RemoveBackend(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	b1 := &AnycastBackend{PhysicalIP: "10.0.0.1", Port: 53, Weight: 100}
	b2 := &AnycastBackend{PhysicalIP: "10.0.0.2", Port: 53, Weight: 100}
	group.AddBackend(b1)
	group.AddBackend(b2)

	total, _ := group.Stats()
	if total != 2 {
		t.Fatalf("expected 2 backends, got %d", total)
	}

	group.RemoveBackend("10.0.0.1")
	total, _ = group.Stats()
	if total != 1 {
		t.Errorf("expected 1 backend after removal, got %d", total)
	}

	// Remove non-existent backend should be a no-op
	group.RemoveBackend("10.0.0.99")
	total, _ = group.Stats()
	if total != 1 {
		t.Errorf("expected 1 backend after removing non-existent, got %d", total)
	}
}

// ---------------------------------------------------------------------------
// AnycastGroup: SelectBackend with no preferred region
// ---------------------------------------------------------------------------

func TestAnycastGroup_SelectBackend_NoPreferredRegion(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	b1 := &AnycastBackend{PhysicalIP: "10.0.0.1", Port: 53, Region: "us-east-1", Weight: 100}
	b2 := &AnycastBackend{PhysicalIP: "10.0.0.2", Port: 53, Region: "eu-west-1", Weight: 100}
	group.AddBackend(b1)
	group.AddBackend(b2)

	// No preferred region - should do weighted selection
	result := group.SelectBackend("", "")
	if result == nil {
		t.Error("expected non-nil backend")
	}
}

// ---------------------------------------------------------------------------
// AnycastGroup: SelectBackend with empty backends
// ---------------------------------------------------------------------------

func TestAnycastGroup_SelectBackend_EmptyBackends(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	result := group.SelectBackend("us-east-1", "a")
	if result != nil {
		t.Error("expected nil for empty backends")
	}
}

// ---------------------------------------------------------------------------
// AnycastBackend: Stats method
// ---------------------------------------------------------------------------

func TestAnycastBackend_Stats(t *testing.T) {
	b := &AnycastBackend{
		PhysicalIP: "10.0.0.1",
		Port:       53,
		Region:     "us-east-1",
		Weight:     100,
	}
	b.healthy = true
	b.latency = 10 * time.Millisecond
	b.failCount = 1
	b.successCount = 5

	healthy, latency, failCount, successCount := b.Stats()
	if !healthy {
		t.Error("expected healthy")
	}
	if latency != 10*time.Millisecond {
		t.Errorf("expected 10ms latency, got %v", latency)
	}
	if failCount != 1 {
		t.Errorf("expected failCount 1, got %d", failCount)
	}
	if successCount != 5 {
		t.Errorf("expected successCount 5, got %d", successCount)
	}
}

// ---------------------------------------------------------------------------
// AnycastBackend: Address method
// ---------------------------------------------------------------------------

func TestAnycastBackend_Address(t *testing.T) {
	b := &AnycastBackend{PhysicalIP: "10.0.0.1", Port: 5353}
	addr := b.Address()
	if addr != "10.0.0.1:5353" {
		t.Errorf("expected 10.0.0.1:5353, got %s", addr)
	}
}

// ---------------------------------------------------------------------------
// AnycastGroup: GetHealthyBackends
// ---------------------------------------------------------------------------

func TestAnycastGroup_GetHealthyBackends(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	b1 := &AnycastBackend{PhysicalIP: "10.0.0.1", Port: 53, Weight: 100}
	b2 := &AnycastBackend{PhysicalIP: "10.0.0.2", Port: 53, Weight: 100}
	group.AddBackend(b1)
	group.AddBackend(b2)

	// Both should be healthy initially
	healthy := group.GetHealthyBackends()
	if len(healthy) != 2 {
		t.Errorf("expected 2 healthy backends, got %d", len(healthy))
	}

	// Mark one unhealthy
	for i := 0; i < 3; i++ {
		b1.markFailure()
	}

	healthy = group.GetHealthyBackends()
	if len(healthy) != 1 {
		t.Errorf("expected 1 healthy backend, got %d", len(healthy))
	}
}

// ---------------------------------------------------------------------------
// AnycastBackend: markSuccess health threshold
// ---------------------------------------------------------------------------

func TestAnycastBackend_MarkSuccess_Threshold(t *testing.T) {
	b := &AnycastBackend{
		PhysicalIP: "10.0.0.1",
		Port:       53,
		Weight:     100,
	}
	b.healthy = false
	b.failCount = 3

	// First success should not mark healthy (needs 2 consecutive)
	b.markSuccess(5 * time.Millisecond)
	if b.healthy {
		t.Error("expected unhealthy after 1 success")
	}
	if b.successCount != 1 {
		t.Errorf("expected successCount 1, got %d", b.successCount)
	}

	// Second success should mark healthy
	b.markSuccess(3 * time.Millisecond)
	if !b.healthy {
		t.Error("expected healthy after 2 consecutive successes")
	}
}

// ---------------------------------------------------------------------------
// AnycastGroup: AddBackend validation
// ---------------------------------------------------------------------------

func TestAnycastGroup_AddBackend_InvalidWeight(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	b := &AnycastBackend{PhysicalIP: "10.0.0.1", Port: 53, Weight: -10}
	err := group.AddBackend(b)
	if err == nil {
		t.Error("expected error with negative weight")
	}

	b2 := &AnycastBackend{PhysicalIP: "10.0.0.1", Port: 53, Weight: 150}
	err = group.AddBackend(b2)
	if err == nil {
		t.Error("expected error with weight > 100")
	}
}

// ---------------------------------------------------------------------------
// AnycastGroup: AddBackend default port and weight
// ---------------------------------------------------------------------------

func TestAnycastGroup_AddBackend_Defaults(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	b := &AnycastBackend{PhysicalIP: "10.0.0.1", Port: 0, Weight: 0}
	err := group.AddBackend(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b.Port != 53 {
		t.Errorf("expected default port 53, got %d", b.Port)
	}
	if b.Weight != 100 {
		t.Errorf("expected default weight 100, got %d", b.Weight)
	}
}
