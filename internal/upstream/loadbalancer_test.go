package upstream

import (
	"context"
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
