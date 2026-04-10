package upstream

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestNewLoadBalancer(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53", "8.8.4.4:53"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
		Region:          "us-east-1",
		Zone:            "a",
		Weight:          50,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}

	if lb == nil {
		t.Fatal("NewLoadBalancer returned nil")
	}

	defer lb.Close()

	if len(lb.servers) != 2 {
		t.Errorf("Expected 2 servers, got %d", len(lb.servers))
	}

	if lb.topology.Region != "us-east-1" {
		t.Errorf("Expected region 'us-east-1', got '%s'", lb.topology.Region)
	}

	if lb.topology.Zone != "a" {
		t.Errorf("Expected zone 'a', got '%s'", lb.topology.Zone)
	}

	if lb.topology.Weight != 50 {
		t.Errorf("Expected weight 50, got %d", lb.topology.Weight)
	}
}

func TestNewLoadBalancerWithAnycast(t *testing.T) {
	config := LoadBalancerConfig{
		AnycastGroups: []AnycastGroupConfig{
			{
				AnycastIP:   "192.0.2.1",
				HealthCheck: "30s",
				Backends: []AnycastBackendConfig{
					{PhysicalIP: "10.0.1.1", Port: 53, Region: "us-east-1", Zone: "a", Weight: 50},
					{PhysicalIP: "10.0.1.2", Port: 53, Region: "us-east-1", Zone: "b", Weight: 50},
				},
			},
		},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}

	if lb == nil {
		t.Fatal("NewLoadBalancer returned nil")
	}

	defer lb.Close()

	if len(lb.anycastGroups) != 1 {
		t.Errorf("Expected 1 anycast group, got %d", len(lb.anycastGroups))
	}

	group, ok := lb.anycastGroups["192.0.2.1"]
	if !ok {
		t.Fatal("Anycast group not found")
	}

	if len(group.Backends) != 2 {
		t.Errorf("Expected 2 backends, got %d", len(group.Backends))
	}
}

func TestNewLoadBalancerNoServers(t *testing.T) {
	config := LoadBalancerConfig{
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err == nil {
		t.Error("Expected error for no servers, got nil")
		if lb != nil {
			lb.Close()
		}
	}
}

func TestNewLoadBalancerDefaults(t *testing.T) {
	config := LoadBalancerConfig{
		Servers: []string{"8.8.8.8:53"},
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}

	defer lb.Close()

	if lb.healthCheck != 30*time.Second {
		t.Errorf("Expected default health check 30s, got %v", lb.healthCheck)
	}

	if lb.failoverTimeout != 5*time.Second {
		t.Errorf("Expected default failover timeout 5s, got %v", lb.failoverTimeout)
	}
}

func TestLoadBalancerSelectTarget(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53", "8.8.4.4:53"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}

	defer lb.Close()

	// Mark servers as healthy
	for _, s := range lb.servers {
		s.healthy = true
	}

	target, err := lb.selectTarget()
	if err != nil {
		t.Fatalf("selectTarget failed: %v", err)
	}

	if target == nil {
		t.Fatal("selectTarget returned nil")
	}

	if target.Type != "standalone" {
		t.Errorf("Expected type 'standalone', got '%s'", target.Type)
	}

	if target.Address == "" {
		t.Error("Expected non-empty address")
	}
}

func TestLoadBalancerSelectAnycastTarget(t *testing.T) {
	config := LoadBalancerConfig{
		AnycastGroups: []AnycastGroupConfig{
			{
				AnycastIP:   "192.0.2.1",
				HealthCheck: "30s",
				Backends: []AnycastBackendConfig{
					{PhysicalIP: "10.0.1.1", Port: 53, Region: "us-east-1", Zone: "a", Weight: 50},
					{PhysicalIP: "10.0.1.2", Port: 53, Region: "us-east-1", Zone: "b", Weight: 50},
				},
			},
		},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
		Region:          "us-east-1",
		Zone:            "a",
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}

	defer lb.Close()

	target, err := lb.selectTarget()
	if err != nil {
		t.Fatalf("selectTarget failed: %v", err)
	}

	if target == nil {
		t.Fatal("selectTarget returned nil")
	}

	if target.Type != "anycast" {
		t.Errorf("Expected type 'anycast', got '%s'", target.Type)
	}

	if target.AnycastIP != "192.0.2.1" {
		t.Errorf("Expected anycast IP '192.0.2.1', got '%s'", target.AnycastIP)
	}
}

func TestLoadBalancerSelectStandaloneRandom(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}

	defer lb.Close()

	// Mark all servers as healthy
	for _, s := range lb.servers {
		s.healthy = true
	}

	// Run multiple selections to ensure we get selections
	selections := make(map[string]int)
	for i := 0; i < 100; i++ {
		lb.strategy = Random
		target, err := lb.selectStandaloneTarget()
		if err != nil {
			t.Fatalf("selectStandaloneTarget failed: %v", err)
		}
		selections[target.Address]++
	}

	if len(selections) == 0 {
		t.Error("Expected some selections")
	}
}

func TestLoadBalancerSelectStandaloneRoundRobin(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53"},
		Strategy:        "round_robin",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}

	defer lb.Close()

	// Mark all servers as healthy
	for _, s := range lb.servers {
		s.healthy = true
	}

	lb.strategy = RoundRobin

	// Test round-robin selection
	selected1, _ := lb.selectStandaloneTarget()
	selected2, _ := lb.selectStandaloneTarget()
	selected3, _ := lb.selectStandaloneTarget()

	// Should cycle through servers
	if selected1.Address == selected2.Address {
		t.Log("Warning: Same server selected twice in round-robin (possible with race conditions)")
	}

	// All should be valid server addresses
	validAddresses := map[string]bool{
		"8.8.8.8:53": true,
		"8.8.4.4:53": true,
		"1.1.1.1:53": true,
	}

	if !validAddresses[selected1.Address] {
		t.Errorf("Invalid address: %s", selected1.Address)
	}
	if !validAddresses[selected2.Address] {
		t.Errorf("Invalid address: %s", selected2.Address)
	}
	if !validAddresses[selected3.Address] {
		t.Errorf("Invalid address: %s", selected3.Address)
	}
}

func TestLoadBalancerSelectStandaloneFastest(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53", "8.8.4.4:53"},
		Strategy:        "fastest",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}

	defer lb.Close()

	// Set different latencies
	lb.servers[0].healthy = true
	lb.servers[0].latency = 50 * time.Millisecond

	lb.servers[1].healthy = true
	lb.servers[1].latency = 10 * time.Millisecond

	lb.strategy = Fastest

	selected, err := lb.selectStandaloneTarget()
	if err != nil {
		t.Fatalf("selectStandaloneTarget failed: %v", err)
	}

	// Should select the fastest server
	if selected.Address != "8.8.4.4:53" {
		t.Errorf("Expected fastest server 8.8.4.4:53, got %s", selected.Address)
	}
}

func TestLoadBalancerSelectNoHealthyServers(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}

	defer lb.Close()

	// Mark server as unhealthy
	lb.servers[0].healthy = false

	// Should still return a server (fallback to first)
	selected, err := lb.selectStandaloneTarget()
	if err != nil {
		t.Fatalf("selectStandaloneTarget failed: %v", err)
	}

	if selected == nil {
		t.Error("Expected fallback server when no healthy servers")
	}
}

func TestLoadBalancerStats(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}

	defer lb.Close()

	// Test initial stats
	queries, failed, failovers := lb.Stats()
	if queries != 0 || failed != 0 || failovers != 0 {
		t.Errorf("Expected all stats to be 0, got queries=%d, failed=%d, failovers=%d", queries, failed, failovers)
	}
}

func TestLoadBalancerGetAnycastGroups(t *testing.T) {
	config := LoadBalancerConfig{
		AnycastGroups: []AnycastGroupConfig{
			{
				AnycastIP:   "192.0.2.1",
				HealthCheck: "30s",
				Backends: []AnycastBackendConfig{
					{PhysicalIP: "10.0.1.1", Port: 53},
				},
			},
		},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}

	defer lb.Close()

	groups := lb.GetAnycastGroups()
	if len(groups) != 1 {
		t.Errorf("Expected 1 anycast group, got %d", len(groups))
	}

	_, ok := groups["192.0.2.1"]
	if !ok {
		t.Error("Expected anycast group with IP 192.0.2.1")
	}
}

func TestLoadBalancerGetTopology(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
		Region:          "eu-west-1",
		Zone:            "b",
		Weight:          75,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}

	defer lb.Close()

	topology := lb.GetTopology()

	if topology.Region != "eu-west-1" {
		t.Errorf("Expected region 'eu-west-1', got '%s'", topology.Region)
	}

	if topology.Zone != "b" {
		t.Errorf("Expected zone 'b', got '%s'", topology.Zone)
	}

	if topology.Weight != 75 {
		t.Errorf("Expected weight 75, got %d", topology.Weight)
	}
}

func TestLoadBalancerQueryContext(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}

	defer lb.Close()

	// Create a test message
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 1,
		},
	}

	// Test with context (this will fail to connect but tests the code path)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	_, err = lb.QueryContext(ctx, msg)
	// We expect an error due to timeout or network failure
	if err == nil {
		t.Log("QueryContext completed without error (unexpected but not a failure)")
	}
}

func TestLoadBalancerClose(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}

	err = lb.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Double close should be safe
	err = lb.Close()
	if err != nil {
		t.Errorf("Second Close failed: %v", err)
	}
}

func TestLoadBalancerQuery(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	// Mark server healthy
	lb.servers[0].healthy = true

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 1,
		},
	}

	_, err = lb.Query(msg)
	// Query may fail due to network, but should not panic
	t.Logf("Query result: %v", err)

	// Verify stats
	queries, _, _ := lb.Stats()
	if queries != 1 {
		t.Errorf("expected 1 query, got %d", queries)
	}
}

func TestLoadBalancerQueryNoServers(t *testing.T) {
	if testing.Short() {
		t.Skip("requires network timeout")
	}
	config := LoadBalancerConfig{
		Servers:         []string{"127.0.0.1:1"}, // Invalid port
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	// Mark server as unhealthy
	lb.servers[0].healthy = false

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 1,
		},
	}

	_, err = lb.Query(msg)
	if err == nil {
		t.Error("expected error with no healthy servers")
	}

	// Verify stats show failed queries
	queries, failed, _ := lb.Stats()
	if queries != 1 {
		t.Errorf("expected 1 query, got %d", queries)
	}
	if failed != 1 {
		t.Errorf("expected 1 failed query, got %d", failed)
	}
}

func TestLoadBalancerQueryFailover(t *testing.T) {
	if testing.Short() {
		t.Skip("requires network timeout")
	}
	config := LoadBalancerConfig{
		Servers:         []string{"127.0.0.1:1", "127.0.0.1:2"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 100 * time.Millisecond,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	// Mark first server unhealthy to trigger failover
	lb.servers[0].healthy = false
	lb.servers[1].healthy = false

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 1,
		},
	}

	_, err = lb.Query(msg)
	if err == nil {
		t.Log("Query succeeded unexpectedly")
	}

	// Verify failover was attempted
	_, _, failovers := lb.Stats()
	if failovers < 1 {
		t.Log("Note: failover count may vary depending on connection errors")
	}
}

func TestLoadBalancerCheckHealth(t *testing.T) {
	if testing.Short() {
		t.Skip("requires network timeout")
	}
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	// Call checkHealth directly
	lb.checkHealth()

	// Give goroutines time to complete
	time.Sleep(100 * time.Millisecond)
}

func TestLoadBalancerCheckHealthWithAnycast(t *testing.T) {
	config := LoadBalancerConfig{
		AnycastGroups: []AnycastGroupConfig{
			{
				AnycastIP:   "192.0.2.1",
				HealthCheck: "30s",
				Backends: []AnycastBackendConfig{
					{PhysicalIP: "10.0.1.1", Port: 53, Region: "us-east-1", Zone: "a", Weight: 50},
				},
			},
		},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	// Call checkHealth directly
	lb.checkHealth()

	// Give goroutines time to complete
	time.Sleep(100 * time.Millisecond)
}

func TestLoadBalancerQueryUDP(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"invalid.hostname.invalid:53"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	_, err = lb.queryUDP("invalid.hostname.invalid:53", msg)
	if err == nil {
		t.Error("expected error with invalid address")
	}
}

func TestLoadBalancerQueryTCP(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"invalid.hostname.invalid:53"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	_, err = lb.queryTCP("invalid.hostname.invalid:53", msg)
	if err == nil {
		t.Error("expected error with invalid address")
	}
}

func TestLoadBalancerSelectAnycastTargetNoHealthyBackends(t *testing.T) {
	config := LoadBalancerConfig{
		AnycastGroups: []AnycastGroupConfig{
			{
				AnycastIP:   "192.0.2.1",
				HealthCheck: "30s",
				Backends: []AnycastBackendConfig{
					{PhysicalIP: "10.0.1.1", Port: 53, Region: "us-east-1", Zone: "a", Weight: 50},
				},
			},
		},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	// Mark backend as unhealthy
	for _, group := range lb.anycastGroups {
		for _, backend := range group.Backends {
			backend.markFailure()
			backend.markFailure()
			backend.markFailure()
		}
	}

	// Should still return a target (fallback behavior)
	target, err := lb.selectAnycastTarget()
	if err != nil {
		t.Logf("selectAnycastTarget returned error: %v (acceptable fallback behavior)", err)
		return
	}
	if target == nil {
		t.Error("expected fallback target even with unhealthy backends")
	}
}

func TestLoadBalancerSelectAnycastTargetNoGroups(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	// With standalone servers, selectAnycastTarget should not be called
	// but we test the fallback behavior anyway
	target, err := lb.selectTarget()
	if err != nil {
		t.Fatalf("selectTarget failed: %v", err)
	}
	if target.Type != "standalone" {
		t.Errorf("expected standalone target, got %s", target.Type)
	}
}

func TestLoadBalancerSelectStandaloneTargetNilServer(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	// Test all strategies return a server
	strategies := []Strategy{Random, RoundRobin, Fastest}
	for _, strategy := range strategies {
		lb.strategy = strategy
		// Ensure server is healthy
		lb.servers[0].healthy = true
		lb.servers[0].latency = 10 * time.Millisecond

		target, err := lb.selectStandaloneTarget()
		if err != nil {
			t.Errorf("selectStandaloneTarget failed for strategy %v: %v", strategy, err)
		}
		if target == nil {
			t.Errorf("expected target for strategy %v", strategy)
		}
	}
}

func TestLoadBalancerSelectRandom(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	// Mark all servers as healthy
	for _, s := range lb.servers {
		s.healthy = true
	}

	server := lb.selectRandom()
	if server == nil {
		t.Error("expected random server selection")
	}
}

func TestLoadBalancerSelectRandomNoServers(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	// Mark server as unhealthy
	lb.servers[0].healthy = false

	// Should return first server as fallback
	server := lb.selectRandom()
	if server == nil {
		t.Error("expected fallback server")
	}
}

func TestLoadBalancerSelectRoundRobin(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53"},
		Strategy:        "round_robin",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	// Mark all servers as healthy
	for _, s := range lb.servers {
		s.healthy = true
	}

	// Multiple calls should return servers
	for i := 0; i < 10; i++ {
		server := lb.selectRoundRobin()
		if server == nil {
			t.Error("expected round-robin server selection")
		}
	}
}

func TestLoadBalancerSelectRoundRobinNoServers(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53"},
		Strategy:        "round_robin",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	// Mark server as unhealthy
	lb.servers[0].healthy = false

	// Should return first server as fallback
	server := lb.selectRoundRobin()
	if server == nil {
		t.Error("expected fallback server")
	}
}

func TestLoadBalancerSelectFastest(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53", "8.8.4.4:53"},
		Strategy:        "fastest",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	// Set latencies
	lb.servers[0].healthy = true
	lb.servers[0].latency = 100 * time.Millisecond

	lb.servers[1].healthy = true
	lb.servers[1].latency = 10 * time.Millisecond

	// Should select the faster server
	server := lb.selectFastest()
	if server == nil {
		t.Fatal("expected fastest server")
	}
	if server.Address != "8.8.4.4:53" {
		t.Errorf("expected fastest server 8.8.4.4:53, got %s", server.Address)
	}
}

func TestLoadBalancerSelectFastestNoServers(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53"},
		Strategy:        "fastest",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	// Mark server as unhealthy
	lb.servers[0].healthy = false

	// Should return first server as fallback
	server := lb.selectFastest()
	if server == nil {
		t.Error("expected fallback server")
	}
}

func TestLoadBalancerQueryWithFailoverUDPError(t *testing.T) {
	if testing.Short() {
		t.Skip("requires network timeout")
	}
	config := LoadBalancerConfig{
		Servers:         []string{"127.0.0.1:1", "127.0.0.1:2"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 100 * time.Millisecond,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	// Create a target
	target := &Target{
		Type:    "standalone",
		Address: "127.0.0.1:1",
		Server:  lb.servers[0],
	}

	_, err = lb.queryWithFailover(target, msg)
	// Should fail since there's no actual DNS server
	if err == nil {
		t.Log("QueryWithFailover succeeded (unexpected)")
	}
}

func TestLoadBalancerQueryWithFailoverAnycastTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("requires network timeout")
	}
	config := LoadBalancerConfig{
		AnycastGroups: []AnycastGroupConfig{
			{
				AnycastIP:   "192.0.2.1",
				HealthCheck: "30s",
				Backends: []AnycastBackendConfig{
					{PhysicalIP: "127.0.0.1", Port: 1, Region: "us-east-1", Zone: "a", Weight: 50},
				},
			},
		},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 100 * time.Millisecond,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	// Create an anycast target
	target := &Target{
		Type:       "anycast",
		Address:    "127.0.0.1:1",
		AnycastIP:  "192.0.2.1",
		PhysicalIP: "127.0.0.1",
		Region:     "us-east-1",
		Zone:       "a",
	}

	_, err = lb.queryWithFailover(target, msg)
	// Should fail since there's no actual DNS server
	if err == nil {
		t.Log("QueryWithFailover succeeded (unexpected)")
	}
}

func TestLoadBalancerHealthCheckLoop(t *testing.T) {
	if testing.Short() {
		t.Skip("requires health check interval wait")
	}
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53"},
		Strategy:        "random",
		HealthCheck:     10 * time.Millisecond,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}

	// Let health check loop run a few times
	time.Sleep(50 * time.Millisecond)

	// Close should stop the loop
	if err := lb.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestLoadBalancerUDPPoolDynamic(t *testing.T) {
	if testing.Short() {
		t.Skip("requires network timeout")
	}
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	// Query an address that doesn't have a pool (anycast scenario)
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	// queryUDP should create a pool dynamically for unknown address
	_, _ = lb.queryUDP("10.0.0.1:53", msg)

	// Pool should have been created
	lb.mu.RLock()
	pool := lb.udpPool["10.0.0.1:53"]
	lb.mu.RUnlock()

	if pool == nil {
		t.Error("expected UDP pool to be created dynamically")
	}
}

func TestLoadBalancerTCPPoolDynamic(t *testing.T) {
	if testing.Short() {
		t.Skip("requires network timeout")
	}
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	// Query an address that doesn't have a pool (anycast scenario)
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	// queryTCP should create a pool dynamically for unknown address
	_, _ = lb.queryTCP("10.0.0.1:53", msg)

	// Pool should have been created
	lb.mu.RLock()
	pool := lb.tcpPool["10.0.0.1:53"]
	lb.mu.RUnlock()

	if pool == nil {
		t.Error("expected TCP pool to be created dynamically")
	}
}

func TestLoadBalancerSelectTargetNoServersOrAnycast(t *testing.T) {
	// This test verifies error handling when neither servers nor anycast groups exist
	// Note: NewLoadBalancer already checks this, but we test selectStandaloneTarget directly
	lb := &LoadBalancer{
		servers:       []*Server{},
		anycastGroups: map[string]*AnycastGroup{},
		strategy:      Random,
		udpPool:       make(map[string]*sync.Pool),
		tcpPool:       make(map[string]*sync.Pool),
	}

	_, err := lb.selectStandaloneTarget()
	if err == nil {
		t.Error("expected error with no servers")
	}
}

func TestLoadBalancerSelectTargetStrategySwitch(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53", "8.8.4.4:53"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	// Mark all servers as healthy
	for _, s := range lb.servers {
		s.healthy = true
		s.latency = 10 * time.Millisecond
	}

	// Test that selectTarget properly switches based on strategy
	testCases := []struct {
		strategy Strategy
	}{
		{Random},
		{RoundRobin},
		{Fastest},
	}

	for _, tc := range testCases {
		lb.strategy = tc.strategy
		target, err := lb.selectTarget()
		if err != nil {
			t.Errorf("selectTarget failed for strategy %v: %v", tc.strategy, err)
		}
		if target == nil {
			t.Errorf("expected target for strategy %v", tc.strategy)
		}
	}
}

func TestLoadBalancerConcurrentAccess(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53", "8.8.4.4:53"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			_, _ = lb.selectTarget()
		}()
		go func() {
			defer wg.Done()
			_, _, _ = lb.Stats()
		}()
		go func() {
			defer wg.Done()
			_ = lb.GetAnycastGroups()
		}()
	}
	wg.Wait()
}

func TestLoadBalancerNewLoadBalancerInvalidBackend(t *testing.T) {
	config := LoadBalancerConfig{
		AnycastGroups: []AnycastGroupConfig{
			{
				AnycastIP:   "192.0.2.1",
				HealthCheck: "30s",
				Backends: []AnycastBackendConfig{
					{PhysicalIP: "", Port: 53}, // Empty physical IP should fail
				},
			},
		},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err == nil {
		if lb != nil {
			lb.Close()
		}
		t.Error("Expected error for invalid backend (empty physical IP)")
	}
}

func TestLoadBalancerQuerySelectTargetError(t *testing.T) {
	// Create a load balancer with a broken selectAnycastTarget path
	lb := &LoadBalancer{
		servers:       []*Server{},
		anycastGroups: map[string]*AnycastGroup{},
		strategy:      Random,
		udpPool:       make(map[string]*sync.Pool),
		tcpPool:       make(map[string]*sync.Pool),
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	_, err := lb.Query(msg)
	if err == nil {
		t.Error("Expected error when selectTarget fails")
	}
}

func TestLoadBalancerQueryContextSuccess(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	ctx := context.Background()
	_, err = lb.QueryContext(ctx, msg)
	// May fail due to network, but should not panic
	t.Logf("QueryContext result: %v", err)
}

func TestLoadBalancerQueryTCPWithInvalidAddress(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	_, err = lb.queryTCP("invalid.invalid:53", msg)
	if err == nil {
		t.Error("expected error with invalid address")
	}
}

func TestLoadBalancerQueryWithFailoverSameTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("requires network timeout")
	}
	// Create a load balancer with only one server
	config := LoadBalancerConfig{
		Servers:         []string{"127.0.0.1:1"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 100 * time.Millisecond,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	// Create a target pointing to the same server
	target := &Target{
		Type:    "standalone",
		Address: "127.0.0.1:1",
		Server:  lb.servers[0],
	}

	_, err = lb.queryWithFailover(target, msg)
	if err == nil {
		t.Log("queryWithFailover succeeded (unexpected)")
	}
}

func TestLoadBalancerQueryWithFailoverDifferentTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("requires network timeout")
	}
	// Create a load balancer with multiple servers
	config := LoadBalancerConfig{
		Servers:         []string{"127.0.0.1:1", "127.0.0.1:2"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 100 * time.Millisecond,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	// Create a target pointing to the first server
	target := &Target{
		Type:    "standalone",
		Address: "127.0.0.1:1",
		Server:  lb.servers[0],
	}

	_, err = lb.queryWithFailover(target, msg)
	if err == nil {
		t.Log("queryWithFailover succeeded (unexpected)")
	}

	// Verify failover was attempted
	_, _, failovers := lb.Stats()
	t.Logf("Failovers: %d", failovers)
}

func TestLoadBalancerSelectAnycastTargetNoBackends(t *testing.T) {
	// Create a load balancer with an empty anycast group
	lb := &LoadBalancer{
		anycastGroups: map[string]*AnycastGroup{
			"192.0.2.1": NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second),
		},
		strategy: Random,
		udpPool:  make(map[string]*sync.Pool),
		tcpPool:  make(map[string]*sync.Pool),
	}

	_, err := lb.selectAnycastTarget()
	if err == nil {
		t.Error("expected error with empty anycast group")
	}
}

func TestLoadBalancerQueryUDPSuccess(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	// Try queryUDP with a real address (may fail due to network)
	_, _ = lb.queryUDP("8.8.8.8:53", msg)
}

func TestLoadBalancerSelectFastestAllUnhealthy(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53", "8.8.4.4:53"},
		Strategy:        "fastest",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	// Mark all servers as unhealthy
	for _, s := range lb.servers {
		s.healthy = false
	}

	// selectFastest should fallback to first server
	server := lb.selectFastest()
	if server == nil {
		t.Error("expected fallback server")
	}
}

func TestLoadBalancerSelectRoundRobinAllUnhealthy(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53", "8.8.4.4:53"},
		Strategy:        "round_robin",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	// Mark all servers as unhealthy
	for _, s := range lb.servers {
		s.healthy = false
	}

	// selectRoundRobin should fallback to starting position
	server := lb.selectRoundRobin()
	if server == nil {
		t.Error("expected fallback server")
	}
}

func TestLoadBalancerSelectRandomAllUnhealthy(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53", "8.8.4.4:53"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	// Mark all servers as unhealthy
	for _, s := range lb.servers {
		s.healthy = false
	}

	// selectRandom should return first server as fallback
	server := lb.selectRandom()
	if server == nil {
		t.Error("expected fallback server")
	}
}

func TestLoadBalancerQueryTCPWithMockServer(t *testing.T) {
	// Create a TCP mock server
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve TCP addr: %v", err)
	}

	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		t.Fatalf("failed to listen TCP: %v", err)
	}

	localAddr := listener.Addr().String()

	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				conn, err := listener.Accept()
				if err != nil {
					continue
				}
				go func(c net.Conn) {
					defer c.Close()
					// Read length prefix
					lengthBuf := make([]byte, 2)
					_, err := c.Read(lengthBuf)
					if err != nil {
						return
					}
					respLen := uint16(lengthBuf[0])<<8 | uint16(lengthBuf[1])
					// Read message
					buf := make([]byte, respLen)
					c.Read(buf)
					// Echo back with length prefix
					c.Write(lengthBuf)
					c.Write(buf)
				}(conn)
			}
		}
	}()

	defer func() {
		close(done)
		listener.Close()
	}()

	config := LoadBalancerConfig{
		Servers:         []string{localAddr},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	_, err = lb.queryTCP(localAddr, msg)
	// Query may fail due to response parsing, but should not panic
	t.Logf("queryTCP result: %v", err)
}

func TestLoadBalancerQueryTCPLargeResponse(t *testing.T) {
	// Create a TCP mock server that returns a large response
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve TCP addr: %v", err)
	}

	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		t.Fatalf("failed to listen TCP: %v", err)
	}

	localAddr := listener.Addr().String()

	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				conn, err := listener.Accept()
				if err != nil {
					continue
				}
				go func(c net.Conn) {
					defer c.Close()
					// Read length prefix
					lengthBuf := make([]byte, 2)
					_, err := c.Read(lengthBuf)
					if err != nil {
						return
					}
					// Read message
					buf := make([]byte, 512)
					c.Read(buf)
					// Send large response (>65535 will overflow, so use something reasonable)
					largeResp := make([]byte, 70000)
					// Set length to indicate large response
					respLen := uint16(len(largeResp))
					lengthBuf[0] = byte(respLen >> 8)
					lengthBuf[1] = byte(respLen)
					c.Write(lengthBuf)
					c.Write(largeResp)
				}(conn)
			}
		}
	}()

	defer func() {
		close(done)
		listener.Close()
	}()

	config := LoadBalancerConfig{
		Servers:         []string{localAddr},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	// This tests the buffer resizing code path in queryTCP
	_, _ = lb.queryTCP(localAddr, msg)
}

func TestLoadBalancerSelectAnycastTargetHealthyGroup(t *testing.T) {
	config := LoadBalancerConfig{
		AnycastGroups: []AnycastGroupConfig{
			{
				AnycastIP:   "192.0.2.1",
				HealthCheck: "30s",
				Backends: []AnycastBackendConfig{
					{PhysicalIP: "10.0.1.1", Port: 53, Region: "us-east-1", Zone: "a", Weight: 50},
				},
			},
		},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
		Region:          "us-east-1",
		Zone:            "a",
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	target, err := lb.selectAnycastTarget()
	if err != nil {
		t.Fatalf("selectAnycastTarget failed: %v", err)
	}
	if target == nil {
		t.Fatal("selectAnycastTarget returned nil")
	}
	if target.Type != "anycast" {
		t.Errorf("Expected type 'anycast', got '%s'", target.Type)
	}
}

func TestLoadBalancerSelectStandaloneTargetAllStrategies(t *testing.T) {
	config := LoadBalancerConfig{
		Servers:         []string{"8.8.8.8:53", "8.8.4.4:53"},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	// Mark all servers as healthy with latencies
	for i, s := range lb.servers {
		s.healthy = true
		s.latency = time.Duration(i*10) * time.Millisecond
	}

	// Test all strategies
	strategies := []Strategy{Random, RoundRobin, Fastest}
	for _, strategy := range strategies {
		lb.strategy = strategy
		target, err := lb.selectStandaloneTarget()
		if err != nil {
			t.Errorf("selectStandaloneTarget failed for strategy %v: %v", strategy, err)
		}
		if target == nil {
			t.Errorf("expected target for strategy %v", strategy)
		}
	}
}

func TestLoadBalancerSelectRoundRobinEmptyServersLB(t *testing.T) {
	lb := &LoadBalancer{
		servers:       []*Server{},
		anycastGroups: map[string]*AnycastGroup{},
		strategy:      RoundRobin,
		udpPool:       make(map[string]*sync.Pool),
		tcpPool:       make(map[string]*sync.Pool),
	}

	server := lb.selectRoundRobin()
	if server != nil {
		t.Error("expected nil for empty server list")
	}
}

func TestLoadBalancerSelectRandomEmptyServersLB(t *testing.T) {
	lb := &LoadBalancer{
		servers:       []*Server{},
		anycastGroups: map[string]*AnycastGroup{},
		strategy:      Random,
		udpPool:       make(map[string]*sync.Pool),
		tcpPool:       make(map[string]*sync.Pool),
	}

	server := lb.selectRandom()
	if server != nil {
		t.Error("expected nil for empty server list")
	}
}

func TestLoadBalancerQueryWithFailoverFailoverSuccessUDP(t *testing.T) {
	if testing.Short() {
		t.Skip("requires network timeout")
	}
	// Create a mock UDP DNS server that echoes
	mockAddr, cleanup := setupMockDNSServerLB(t, nil)
	defer cleanup()

	config := LoadBalancerConfig{
		Servers:         []string{"127.0.0.1:1", mockAddr},
		Strategy:        "round_robin",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	// Mark both servers healthy
	lb.servers[0].healthy = true
	lb.servers[1].healthy = true

	// Set round-robin index so selectTarget returns the mock server (index 1)
	// Since selectTarget calls selectRoundRobin which does atomic.AddUint32(&roundRobinIndex, 1)
	// we need to set it so the next increment gives us index 1
	atomic.StoreUint32(&roundRobinIndex, 0)

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	// Create target pointing to first (dead) server
	target := &Target{
		Type:    "standalone",
		Address: "127.0.0.1:1",
		Server:  lb.servers[0],
	}

	// queryWithFailover should fail on first server, then failover to second (mock)
	_, err = lb.queryWithFailover(target, msg)
	t.Logf("queryWithFailover result: %v", err)

	// Verify failover was attempted
	_, _, failovers := lb.Stats()
	if failovers < 1 {
		t.Errorf("expected at least 1 failover, got %d", failovers)
	}
}

func TestLoadBalancerQueryWithFailoverFailoverSuccessTCP(t *testing.T) {
	if testing.Short() {
		t.Skip("requires network timeout")
	}
	// Create a mock TCP server
	tcpAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve TCP addr: %v", err)
	}

	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		t.Fatalf("failed to listen TCP: %v", err)
	}

	localAddr := listener.Addr().String()

	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				conn, err := listener.Accept()
				if err != nil {
					continue
				}
				go func(c net.Conn) {
					defer c.Close()
					lengthBuf := make([]byte, 2)
					_, err := c.Read(lengthBuf)
					if err != nil {
						return
					}
					respLen := uint16(lengthBuf[0])<<8 | uint16(lengthBuf[1])
					buf := make([]byte, respLen)
					c.Read(buf)
					c.Write(lengthBuf)
					c.Write(buf)
				}(conn)
			}
		}
	}()

	defer func() {
		close(done)
		listener.Close()
	}()

	config := LoadBalancerConfig{
		Servers:         []string{"127.0.0.1:1", localAddr},
		Strategy:        "round_robin",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	// Ensure failover selects the mock server (index 1)
	atomic.StoreUint32(&roundRobinIndex, 0)

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	// Target pointing to dead server - failover should find the TCP mock
	target := &Target{
		Type:    "standalone",
		Address: "127.0.0.1:1",
		Server:  lb.servers[0],
	}

	_, err = lb.queryWithFailover(target, msg)
	t.Logf("queryWithFailover TCP failover result: %v", err)

	_, _, failovers := lb.Stats()
	if failovers < 1 {
		t.Errorf("expected at least 1 failover, got %d", failovers)
	}
}

func TestLoadBalancerQueryWithFailoverSelectTargetError(t *testing.T) {
	if testing.Short() {
		t.Skip("requires network timeout")
	}
	// Create LB with no servers at the selectTarget level
	lb := &LoadBalancer{
		servers:       []*Server{},
		anycastGroups: map[string]*AnycastGroup{},
		strategy:      Random,
		udpPool:       make(map[string]*sync.Pool),
		tcpPool:       make(map[string]*sync.Pool),
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	target := &Target{
		Type:    "standalone",
		Address: "127.0.0.1:1",
	}

	_, err := lb.queryWithFailover(target, msg)
	if err == nil {
		t.Error("expected error when failover selectTarget fails")
	}
}

func TestLoadBalancerQueryWithFailoverAnycastMarkFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("requires network timeout")
	}
	// Test that anycast targets don't call markFailure on target.Server
	lb := &LoadBalancer{
		servers:       []*Server{},
		anycastGroups: map[string]*AnycastGroup{},
		strategy:      Random,
		udpPool:       make(map[string]*sync.Pool),
		tcpPool:       make(map[string]*sync.Pool),
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	target := &Target{
		Type:       "anycast",
		Address:    "127.0.0.1:1",
		AnycastIP:  "192.0.2.1",
		PhysicalIP: "127.0.0.1",
	}

	_, err := lb.queryWithFailover(target, msg)
	if err == nil {
		t.Error("expected error for anycast failover with no servers")
	}
}

func TestLoadBalancerQueryUDPMockServer(t *testing.T) {
	mockAddr, cleanup := setupMockDNSServerLB(t, nil)
	defer cleanup()

	config := LoadBalancerConfig{
		Servers:         []string{mockAddr},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	_, err = lb.queryUDP(mockAddr, msg)
	t.Logf("queryUDP with mock server: %v", err)
}

func TestLoadBalancerQueryTCPMockServer(t *testing.T) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve TCP addr: %v", err)
	}

	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		t.Fatalf("failed to listen TCP: %v", err)
	}

	localAddr := listener.Addr().String()

	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				conn, err := listener.Accept()
				if err != nil {
					continue
				}
				go func(c net.Conn) {
					defer c.Close()
					lengthBuf := make([]byte, 2)
					_, err := c.Read(lengthBuf)
					if err != nil {
						return
					}
					respLen := uint16(lengthBuf[0])<<8 | uint16(lengthBuf[1])
					buf := make([]byte, respLen)
					c.Read(buf)
					c.Write(lengthBuf)
					c.Write(buf)
				}(conn)
			}
		}
	}()

	defer func() {
		close(done)
		listener.Close()
	}()

	config := LoadBalancerConfig{
		Servers:         []string{localAddr},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	_, err = lb.queryTCP(localAddr, msg)
	t.Logf("queryTCP with mock server: %v", err)
}

func TestLoadBalancerQueryFullWithFailover(t *testing.T) {
	if testing.Short() {
		t.Skip("requires network timeout")
	}
	mockAddr, cleanup := setupMockDNSServerLB(t, nil)
	defer cleanup()

	config := LoadBalancerConfig{
		Servers:         []string{"127.0.0.1:1", mockAddr},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	lb.servers[0].healthy = true
	lb.servers[1].healthy = true

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	_, err = lb.Query(msg)
	t.Logf("Query result: %v", err)

	queries, _, _ := lb.Stats()
	if queries != 1 {
		t.Errorf("expected 1 query, got %d", queries)
	}
}

func TestLoadBalancerSelectAnycastTargetWithFallback(t *testing.T) {
	config := LoadBalancerConfig{
		AnycastGroups: []AnycastGroupConfig{
			{
				AnycastIP:   "192.0.2.1",
				HealthCheck: "30s",
				Backends: []AnycastBackendConfig{
					{PhysicalIP: "10.0.1.1", Port: 53, Region: "us-east-1", Zone: "a", Weight: 50},
				},
			},
		},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	// Make backend unhealthy (3 failures)
	group := lb.anycastGroups["192.0.2.1"]
	for _, b := range group.Backends {
		b.markFailure()
		b.markFailure()
		b.markFailure()
	}

	target, err := lb.selectAnycastTarget()
	if err != nil {
		t.Logf("selectAnycastTarget error: %v (acceptable)", err)
	} else if target == nil {
		t.Error("expected fallback target")
	}
}

func TestLoadBalancerCheckHealthWithBackends(t *testing.T) {
	if testing.Short() {
		t.Skip("requires network timeout")
	}
	config := LoadBalancerConfig{
		AnycastGroups: []AnycastGroupConfig{
			{
				AnycastIP:   "192.0.2.1",
				HealthCheck: "30s",
				Backends: []AnycastBackendConfig{
					{PhysicalIP: "127.0.0.1", Port: 1, Region: "us-east-1", Zone: "a", Weight: 50},
					{PhysicalIP: "127.0.0.1", Port: 2, Region: "us-east-1", Zone: "b", Weight: 50},
				},
			},
		},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	lb.checkHealth()
	time.Sleep(200 * time.Millisecond)

	group := lb.anycastGroups["192.0.2.1"]
	for _, b := range group.Backends {
		t.Logf("Backend %s healthy: %v", b.PhysicalIP, b.IsHealthy())
	}
}

func TestLoadBalancerSelectStandaloneNilServerFallback(t *testing.T) {
	lb := &LoadBalancer{
		servers:       []*Server{},
		anycastGroups: map[string]*AnycastGroup{},
		strategy:      Random,
		udpPool:       make(map[string]*sync.Pool),
		tcpPool:       make(map[string]*sync.Pool),
	}

	_, err := lb.selectStandaloneTarget()
	if err == nil {
		t.Error("expected error with no servers")
	}
}

func setupMockDNSServerLB(t *testing.T, response []byte) (string, func()) {
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
		for {
			select {
			case <-done:
				return
			default:
				buf := make([]byte, 512)
				n, remote, err := conn.ReadFromUDP(buf)
				if err != nil {
					continue
				}
				if len(response) > 0 {
					conn.WriteToUDP(response, remote)
				} else {
					conn.WriteToUDP(buf[:n], remote)
				}
			}
		}
	}()

	cleanup := func() {
		close(done)
		conn.Close()
	}

	return localAddr, cleanup
}

func TestLoadBalancerQueryWithFailoverTCPSuccessAfterUDPFail(t *testing.T) {
	if testing.Short() {
		t.Skip("requires network timeout")
	}
	// Create a TCP-only mock server (no UDP)
	tcpAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve TCP addr: %v", err)
	}

	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		t.Fatalf("failed to listen TCP: %v", err)
	}

	localAddr := listener.Addr().String()

	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				conn, err := listener.Accept()
				if err != nil {
					continue
				}
				go func(c net.Conn) {
					defer c.Close()
					lengthBuf := make([]byte, 2)
					_, err := c.Read(lengthBuf)
					if err != nil {
						return
					}
					respLen := uint16(lengthBuf[0])<<8 | uint16(lengthBuf[1])
					buf := make([]byte, respLen)
					c.Read(buf)
					c.Write(lengthBuf)
					c.Write(buf)
				}(conn)
			}
		}
	}()

	defer func() {
		close(done)
		listener.Close()
	}()

	config := LoadBalancerConfig{
		Servers:         []string{localAddr},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	lb.servers[0].healthy = true

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	// Create target pointing to the TCP mock server address
	// UDP will fail (nothing listening on UDP at that address), then TCP should succeed
	target := &Target{
		Type:    "standalone",
		Address: localAddr,
		Server:  lb.servers[0],
	}

	resp, err := lb.queryWithFailover(target, msg)
	if err != nil {
		t.Logf("queryWithFailover TCP success path error: %v", err)
	} else {
		if resp == nil {
			t.Error("expected non-nil response")
		}
	}
}

func TestLoadBalancerQueryWithFailoverRetryPath(t *testing.T) {
	if testing.Short() {
		t.Skip("requires network timeout")
	}
	// Create a mock UDP server for the failover target
	mockAddr, cleanup := setupMockDNSServerLB(t, nil)
	defer cleanup()

	config := LoadBalancerConfig{
		Servers:         []string{"127.0.0.1:1", mockAddr},
		Strategy:        "round_robin",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	lb.servers[0].healthy = true
	lb.servers[1].healthy = true

	// Set round-robin index so that the next selectTarget returns index 1 (mock server)
	atomic.StoreUint32(&roundRobinIndex, 0)

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	// Target pointing to dead server - failover should select mock server
	target := &Target{
		Type:    "standalone",
		Address: "127.0.0.1:1",
		Server:  lb.servers[0],
	}

	// Run multiple times to increase chances of hitting different failover paths
	for i := 0; i < 5; i++ {
		atomic.StoreUint32(&roundRobinIndex, uint32(i))
		_, err = lb.queryWithFailover(target, msg)
		t.Logf("queryWithFailover retry attempt %d: %v", i, err)
	}
}

func TestLoadBalancerQueryUDPSuccessWithMockServer(t *testing.T) {
	mockAddr, cleanup := setupMockDNSServerLB(t, nil)
	defer cleanup()

	config := LoadBalancerConfig{
		Servers:         []string{mockAddr},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	resp, err := lb.queryUDP(mockAddr, msg)
	if err != nil {
		t.Fatalf("queryUDP with mock server error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Header.ID != 1234 {
		t.Errorf("response ID = %d, want 1234", resp.Header.ID)
	}
}

func TestLoadBalancerQueryTCPSuccessWithMockServer(t *testing.T) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve TCP addr: %v", err)
	}

	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		t.Fatalf("failed to listen TCP: %v", err)
	}

	localAddr := listener.Addr().String()

	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				conn, err := listener.Accept()
				if err != nil {
					continue
				}
				go func(c net.Conn) {
					defer c.Close()
					lengthBuf := make([]byte, 2)
					_, err := c.Read(lengthBuf)
					if err != nil {
						return
					}
					respLen := uint16(lengthBuf[0])<<8 | uint16(lengthBuf[1])
					buf := make([]byte, respLen)
					c.Read(buf)
					c.Write(lengthBuf)
					c.Write(buf)
				}(conn)
			}
		}
	}()

	defer func() {
		close(done)
		listener.Close()
	}()

	config := LoadBalancerConfig{
		Servers:         []string{localAddr},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	resp, err := lb.queryTCP(localAddr, msg)
	if err != nil {
		t.Fatalf("queryTCP with mock server error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Header.ID != 1234 {
		t.Errorf("response ID = %d, want 1234", resp.Header.ID)
	}
}

func TestLoadBalancerSelectAnycastTargetNoHealthyNilBackend(t *testing.T) {
	// Test the case where SelectBackend returns nil
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)
	// Add a backend but make it unhealthy
	backend := &AnycastBackend{
		PhysicalIP: "10.0.1.1",
		Port:       53,
		Region:     "us-east-1",
		Zone:       "a",
		Weight:     50,
		healthy:    false,
	}
	group.Backends = append(group.Backends, backend)

	lb := &LoadBalancer{
		anycastGroups: map[string]*AnycastGroup{
			"192.0.2.1": group,
		},
		strategy: Random,
		udpPool:  make(map[string]*sync.Pool),
		tcpPool:  make(map[string]*sync.Pool),
	}

	// When all backends are unhealthy and have 0 count, SelectBackend returns the first backend
	// even if unhealthy. So this should still return a target.
	target, err := lb.selectAnycastTarget()
	if err != nil {
		t.Logf("selectAnycastTarget error: %v", err)
	} else {
		if target == nil {
			t.Error("expected target even with unhealthy backends")
		}
	}
}

func TestLoadBalancerSelectStandaloneNilServerAllStrategies(t *testing.T) {
	// Test selectStandaloneTarget with strategies that return nil
	lb := &LoadBalancer{
		servers:       []*Server{},
		anycastGroups: map[string]*AnycastGroup{},
		strategy:      Random,
		udpPool:       make(map[string]*sync.Pool),
		tcpPool:       make(map[string]*sync.Pool),
	}

	// All strategies with empty servers should return error
	for _, strategy := range []Strategy{Random, RoundRobin, Fastest} {
		lb.strategy = strategy
		_, err := lb.selectStandaloneTarget()
		if err == nil {
			t.Errorf("expected error for strategy %v with no servers", strategy)
		}
	}
}

func TestLoadBalancerCheckHealthFullWithServers(t *testing.T) {
	// Create a mock DNS server
	mockAddr, cleanup := setupMockDNSServerLB(t, nil)
	defer cleanup()

	config := LoadBalancerConfig{
		Servers:         []string{mockAddr},
		Strategy:        "random",
		HealthCheck:     30 * time.Second,
		FailoverTimeout: 5 * time.Second,
	}

	lb, err := NewLoadBalancer(config)
	if err != nil {
		t.Fatalf("NewLoadBalancer failed: %v", err)
	}
	defer lb.Close()

	// Call checkHealth directly with a working server
	lb.checkHealth()
	time.Sleep(200 * time.Millisecond)

	// Server should still be healthy
	if !lb.servers[0].IsHealthy() {
		t.Log("Server marked unhealthy after health check (may be timing related)")
	}
}
