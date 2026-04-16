package upstream

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Config.HealthCheckDuration
// ---------------------------------------------------------------------------

func TestConfig_HealthCheckDuration_Default(t *testing.T) {
	cfg := Config{}
	if d := cfg.HealthCheckDuration(); d != 30*time.Second {
		t.Errorf("expected default 30s, got %v", d)
	}
}

func TestConfig_HealthCheckDuration_Custom(t *testing.T) {
	cfg := Config{HealthCheck: 10 * time.Second}
	if d := cfg.HealthCheckDuration(); d != 10*time.Second {
		t.Errorf("expected 10s, got %v", d)
	}
}

// ---------------------------------------------------------------------------
// Client.IsHealthy
// ---------------------------------------------------------------------------

func TestClient_IsHealthy_AllHealthy(t *testing.T) {
	client, _ := NewClient(Config{
		Servers: []string{"8.8.8.8:53"},
		Timeout: 2 * time.Second,
	})
	defer client.Close()

	if !client.IsHealthy() {
		t.Error("expected healthy when server starts healthy")
	}
}

func TestClient_IsHealthy_NoneHealthy(t *testing.T) {
	client, _ := NewClient(Config{
		Servers: []string{"8.8.8.8:53"},
		Timeout: 2 * time.Second,
	})
	defer client.Close()

	client.mu.Lock()
	client.servers[0].healthy = false
	client.mu.Unlock()

	if client.IsHealthy() {
		t.Error("expected unhealthy when all servers are down")
	}
}

func TestClient_IsHealthy_Mixed(t *testing.T) {
	client, _ := NewClient(Config{
		Servers: []string{"8.8.8.8:53", "8.8.4.4:53"},
		Timeout: 2 * time.Second,
	})
	defer client.Close()

	client.mu.Lock()
	client.servers[0].healthy = false
	client.mu.Unlock()

	if !client.IsHealthy() {
		t.Error("expected healthy when at least one server is up")
	}
}

// ---------------------------------------------------------------------------
// Client.AddServer
// ---------------------------------------------------------------------------

func TestClient_AddServer_Success(t *testing.T) {
	client, _ := NewClient(Config{
		Servers: []string{"8.8.8.8:53"},
		Timeout: 2 * time.Second,
	})
	defer client.Close()

	err := client.AddServer("1.1.1.1:53")
	if err != nil {
		t.Fatalf("AddServer failed: %v", err)
	}

	client.mu.RLock()
	count := len(client.servers)
	_, hasUDP := client.udpPool["1.1.1.1:53"]
	_, hasTCP := client.tcpPool["1.1.1.1:53"]
	_, hasConn := client.tcpConnPools["1.1.1.1:53"]
	client.mu.RUnlock()

	if count != 2 {
		t.Errorf("expected 2 servers, got %d", count)
	}
	if !hasUDP {
		t.Error("expected UDP pool for new server")
	}
	if !hasTCP {
		t.Error("expected TCP pool for new server")
	}
	if !hasConn {
		t.Error("expected TCP conn pool for new server")
	}
}

func TestClient_AddServer_Duplicate(t *testing.T) {
	client, _ := NewClient(Config{
		Servers: []string{"8.8.8.8:53"},
		Timeout: 2 * time.Second,
	})
	defer client.Close()

	err := client.AddServer("8.8.8.8:53")
	if err == nil {
		t.Error("expected error for duplicate server")
	}
}

// ---------------------------------------------------------------------------
// Client.RemoveServer
// ---------------------------------------------------------------------------

func TestClient_RemoveServer_Success(t *testing.T) {
	client, _ := NewClient(Config{
		Servers: []string{"8.8.8.8:53", "1.1.1.1:53"},
		Timeout: 2 * time.Second,
	})
	defer client.Close()

	err := client.RemoveServer("8.8.8.8:53")
	if err != nil {
		t.Fatalf("RemoveServer failed: %v", err)
	}

	client.mu.RLock()
	count := len(client.servers)
	_, hasUDP := client.udpPool["8.8.8.8:53"]
	client.mu.RUnlock()

	if count != 1 {
		t.Errorf("expected 1 server, got %d", count)
	}
	if hasUDP {
		t.Error("UDP pool should be removed")
	}
}

func TestClient_RemoveServer_NotFound(t *testing.T) {
	client, _ := NewClient(Config{
		Servers: []string{"8.8.8.8:53"},
		Timeout: 2 * time.Second,
	})
	defer client.Close()

	err := client.RemoveServer("9.9.9.9:53")
	if err == nil {
		t.Error("expected error for non-existent server")
	}
}

func TestClient_RemoveServer_CleansConnPool(t *testing.T) {
	client, _ := NewClient(Config{
		Servers: []string{"8.8.8.8:53"},
		Timeout: 2 * time.Second,
	})
	defer client.Close()

	err := client.RemoveServer("8.8.8.8:53")
	if err != nil {
		t.Fatal(err)
	}

	client.mu.RLock()
	_, hasConn := client.tcpConnPools["8.8.8.8:53"]
	client.mu.RUnlock()

	if hasConn {
		t.Error("TCP conn pool should be removed")
	}
}

// ---------------------------------------------------------------------------
// AddServer + RemoveServer roundtrip
// ---------------------------------------------------------------------------

func TestClient_AddRemoveRoundtrip(t *testing.T) {
	client, _ := NewClient(Config{
		Servers: []string{"8.8.8.8:53"},
		Timeout: 2 * time.Second,
	})
	defer client.Close()

	client.AddServer("1.1.1.1:53")
	client.RemoveServer("1.1.1.1:53")

	client.mu.RLock()
	count := len(client.servers)
	client.mu.RUnlock()

	if count != 1 {
		t.Errorf("expected 1 server after add/remove, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// circuitBreaker.getBackoff
// ---------------------------------------------------------------------------

func TestCircuitBreaker_GetBackoff_ZeroAttempt(t *testing.T) {
	cb := &circuitBreaker{
		backoff: 30 * time.Second,
	}

	if d := cb.getBackoff(0); d != 100*time.Millisecond {
		t.Errorf("attempt 0: expected 100ms, got %v", d)
	}
}

func TestCircuitBreaker_GetBackoff_NegativeAttempt(t *testing.T) {
	cb := &circuitBreaker{
		backoff: 30 * time.Second,
	}

	if d := cb.getBackoff(-1); d != 100*time.Millisecond {
		t.Errorf("attempt -1: expected 100ms, got %v", d)
	}
}

func TestCircuitBreaker_GetBackoff_Exponential(t *testing.T) {
	cb := &circuitBreaker{
		backoff: 30 * time.Second,
	}

	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{1, 100 * time.Millisecond},
		{2, 200 * time.Millisecond},
		{3, 400 * time.Millisecond},
		{4, 800 * time.Millisecond},
		{5, 1600 * time.Millisecond},
		{6, 3200 * time.Millisecond},
		{7, 6400 * time.Millisecond},
		{8, 12800 * time.Millisecond},
	}

	for _, tt := range tests {
		got := cb.getBackoff(tt.attempt)
		if got != tt.want {
			t.Errorf("attempt %d: expected %v, got %v", tt.attempt, tt.want, got)
		}
	}
}

func TestCircuitBreaker_GetBackoff_CappedAtMax(t *testing.T) {
	cb := &circuitBreaker{
		backoff: 500 * time.Millisecond,
	}

	got := cb.getBackoff(10)
	if got != 500*time.Millisecond {
		t.Errorf("expected capped at 500ms, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer.IsHealthy
// ---------------------------------------------------------------------------

func TestLoadBalancer_IsHealthy_Servers(t *testing.T) {
	lb, _ := NewLoadBalancer(LoadBalancerConfig{
		Servers:     []string{"8.8.8.8:53"},
		HealthCheck: 30 * time.Second,
	})
	defer lb.Close()

	if !lb.IsHealthy() {
		t.Error("expected healthy with one server")
	}
}

func TestLoadBalancer_IsHealthy_NoHealthyServers(t *testing.T) {
	lb, _ := NewLoadBalancer(LoadBalancerConfig{
		Servers:     []string{"8.8.8.8:53"},
		HealthCheck: 30 * time.Second,
	})
	defer lb.Close()

	lb.mu.Lock()
	lb.servers[0].healthy = false
	lb.mu.Unlock()

	if lb.IsHealthy() {
		t.Error("expected unhealthy when all servers are down")
	}
}

func TestLoadBalancer_IsHealthy_AnycastGroup(t *testing.T) {
	lb, _ := NewLoadBalancer(LoadBalancerConfig{
		Servers:     []string{"8.8.8.8:53"},
		HealthCheck: 30 * time.Second,
	})
	defer lb.Close()

	lb.mu.Lock()
	lb.anycastGroups["test-group"] = &AnycastGroup{
		AnycastIP: "1.2.3.4",
		Backends: []*AnycastBackend{
			{PhysicalIP: "10.0.0.1", Port: 53, healthy: true},
		},
	}
	lb.servers[0].healthy = false
	lb.mu.Unlock()

	if !lb.IsHealthy() {
		t.Error("expected healthy due to anycast group backend")
	}
}

func TestLoadBalancer_IsHealthy_AnycastAllDown(t *testing.T) {
	lb, _ := NewLoadBalancer(LoadBalancerConfig{
		Servers:     []string{"8.8.8.8:53"},
		HealthCheck: 30 * time.Second,
	})
	defer lb.Close()

	lb.mu.Lock()
	lb.anycastGroups["test-group"] = &AnycastGroup{
		AnycastIP: "1.2.3.4",
		Backends: []*AnycastBackend{
			{PhysicalIP: "10.0.0.1", Port: 53, healthy: false},
		},
	}
	lb.servers[0].healthy = false
	lb.mu.Unlock()

	if lb.IsHealthy() {
		t.Error("expected unhealthy when all servers and anycast backends are down")
	}
}
