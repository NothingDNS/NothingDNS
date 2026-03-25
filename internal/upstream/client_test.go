package upstream

import (
	"testing"
	"time"
)

func TestStrategyFromString(t *testing.T) {
	tests := []struct {
		input    string
		expected Strategy
	}{
		{"random", Random},
		{"round_robin", RoundRobin},
		{"fastest", Fastest},
		{"", Random},
		{"unknown", Random},
	}

	for _, tt := range tests {
		result := StrategyFromString(tt.input)
		if result != tt.expected {
			t.Errorf("StrategyFromString(%q) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if len(config.Servers) != 2 {
		t.Errorf("expected 2 default servers, got %d", len(config.Servers))
	}

	if config.Strategy != "random" {
		t.Errorf("expected strategy 'random', got %q", config.Strategy)
	}

	if config.Timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", config.Timeout)
	}

	if config.HealthCheck != 30*time.Second {
		t.Errorf("expected health check 30s, got %v", config.HealthCheck)
	}
}

func TestNewClient(t *testing.T) {
	config := DefaultConfig()
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	if len(client.servers) != 2 {
		t.Errorf("expected 2 servers, got %d", len(client.servers))
	}

	if client.strategy != Random {
		t.Errorf("expected Random strategy, got %v", client.strategy)
	}
}

func TestNewClientNoServers(t *testing.T) {
	config := Config{
		Servers: []string{},
	}

	_, err := NewClient(config)
	if err == nil {
		t.Error("expected error for empty server list")
	}
}

func TestServerHealth(t *testing.T) {
	server := &Server{
		Address: "127.0.0.1:53",
		healthy: true,
	}

	if !server.IsHealthy() {
		t.Error("expected server to be healthy initially")
	}

	// Mark failure 3 times to make unhealthy
	server.markFailure()
	server.markFailure()
	server.markFailure()

	if server.IsHealthy() {
		t.Error("expected server to be unhealthy after 3 failures")
	}

	// Mark success to restore health
	server.markSuccess(10 * time.Millisecond)

	if !server.IsHealthy() {
		t.Error("expected server to be healthy after success")
	}
}

func TestSelectServer(t *testing.T) {
	// Test random strategy
	config := Config{
		Servers:  []string{"8.8.8.8:53", "8.8.4.4:53"},
		Strategy: "random",
		Timeout:  5 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	server := client.selectServer()
	if server == nil {
		t.Error("expected to select a server")
	}
}

func TestSelectRoundRobin(t *testing.T) {
	config := Config{
		Servers:  []string{"1.1.1.1:53", "1.0.0.1:53", "8.8.8.8:53"},
		Strategy: "round_robin",
		Timeout:  5 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Should cycle through servers
	selected := make(map[string]bool)
	for i := 0; i < 10; i++ {
		s := client.selectRoundRobin()
		if s == nil {
			t.Fatal("expected to select a server")
		}
		selected[s.Address] = true
	}

	// Should have selected multiple different servers
	if len(selected) < 2 {
		t.Error("expected round-robin to select multiple servers")
	}
}

func TestSelectFastest(t *testing.T) {
	config := Config{
		Servers:  []string{"1.1.1.1:53", "8.8.8.8:53"},
		Strategy: "fastest",
		Timeout:  5 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Set different latencies
	client.servers[0].markSuccess(10 * time.Millisecond)
	client.servers[1].markSuccess(50 * time.Millisecond)

	// Should select the fastest server
	server := client.selectFastest()
	if server == nil {
		t.Fatal("expected to select a server")
	}

	if server.Address != "1.1.1.1:53" {
		t.Errorf("expected fastest server (1.1.1.1), got %s", server.Address)
	}
}

func TestSelectNoHealthyServers(t *testing.T) {
	config := Config{
		Servers:  []string{"127.0.0.1:1"}, // Invalid address
		Strategy: "random",
		Timeout:  100 * time.Millisecond,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Mark server unhealthy
	client.servers[0].healthy = false

	// Should still return a server (fallback behavior)
	server := client.selectServer()
	if server == nil {
		t.Error("expected fallback server when none are healthy")
	}
}

func TestClientStats(t *testing.T) {
	config := DefaultConfig()
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	queries, failed, responses := client.Stats()
	if queries != 0 || failed != 0 || responses != 0 {
		t.Error("expected zero stats initially")
	}
}

func TestClientClose(t *testing.T) {
	config := DefaultConfig()
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Close should not panic
	if err := client.Close(); err != nil {
		t.Errorf("close failed: %v", err)
	}
}
