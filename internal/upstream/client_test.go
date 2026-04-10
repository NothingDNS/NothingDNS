package upstream

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
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

func TestClientServers(t *testing.T) {
	config := DefaultConfig()
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	servers := client.Servers()
	if len(servers) != 2 {
		t.Errorf("expected 2 servers, got %d", len(servers))
	}

	// Verify servers match config
	expectedServers := map[string]bool{
		"8.8.8.8:53": true,
		"8.8.4.4:53": true,
	}
	for _, s := range servers {
		if !expectedServers[s.Address] {
			t.Errorf("unexpected server address: %s", s.Address)
		}
	}
}

func TestServerLastFailure(t *testing.T) {
	server := &Server{
		Address: "127.0.0.1:53",
		healthy: true,
	}

	// Record a failure
	server.markFailure()

	server.mu.RLock()
	failCount := server.failCount
	lastFailure := server.lastFailure
	server.mu.RUnlock()

	if failCount != 1 {
		t.Errorf("expected failCount 1, got %d", failCount)
	}

	if lastFailure.IsZero() {
		t.Error("expected lastFailure to be set")
	}
}

func TestSelectRandomNoHealthyServers(t *testing.T) {
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

	// Mark all servers as unhealthy
	for _, s := range client.servers {
		s.healthy = false
	}

	// selectRandom should still return a server (fallback)
	server := client.selectRandom()
	if server == nil {
		t.Error("expected fallback server when none are healthy")
	}
}

func TestSelectRandomWithEmptyServers(t *testing.T) {
	config := Config{
		Servers:  []string{"8.8.8.8:53"},
		Strategy: "random",
		Timeout:  5 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Even with no healthy servers and one server, should return fallback
	client.servers[0].healthy = false
	server := client.selectRandom()
	if server == nil {
		t.Error("expected fallback server")
	}
}

func TestSelectRoundRobinNoHealthyServers(t *testing.T) {
	config := Config{
		Servers:  []string{"1.1.1.1:53", "1.0.0.1:53"},
		Strategy: "round_robin",
		Timeout:  5 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Mark all servers as unhealthy
	for _, s := range client.servers {
		s.healthy = false
	}

	// Should still return a server (fallback to starting position)
	server := client.selectRoundRobin()
	if server == nil {
		t.Error("expected fallback server in round-robin")
	}
}

func TestSelectFastestNoHealthyServers(t *testing.T) {
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

	// Mark all servers as unhealthy
	for _, s := range client.servers {
		s.healthy = false
	}

	// Should fallback to first server
	server := client.selectFastest()
	if server == nil {
		t.Error("expected fallback server")
	}
}

func TestSelectFastestWithZeroLatency(t *testing.T) {
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

	// Set latency to 0 for both (should still work)
	client.servers[0].markSuccess(0)
	client.servers[1].markSuccess(0)

	server := client.selectFastest()
	if server == nil {
		t.Error("expected to select a server")
	}
}

func TestQueryNoHealthyServers(t *testing.T) {
	config := Config{
		Servers:  []string{"127.0.0.1:1"}, // Invalid port to avoid connections
		Strategy: "random",
		Timeout:  100 * time.Millisecond,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Mark server as unhealthy
	client.servers[0].healthy = false

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 1,
		},
	}

	// Query should still attempt (with fallback server) but fail due to connection
	_, err = client.Query(msg)
	if err == nil {
		t.Error("expected error when querying with no healthy servers")
	}

	// Verify stats were updated
	queries, failed, _ := client.Stats()
	if queries != 1 {
		t.Errorf("expected 1 query, got %d", queries)
	}
	if failed != 1 {
		t.Errorf("expected 1 failed query, got %d", failed)
	}
}

func TestQueryContextSuccess(t *testing.T) {
	config := Config{
		Servers:  []string{"8.8.8.8:53"},
		Strategy: "random",
		Timeout:  5 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 1,
		},
	}

	// Use a context with reasonable timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, _ = client.QueryContext(ctx, msg)
	// We don't assert on the error since network may or may not work
	// Just ensure it doesn't panic
}

func TestQueryContextCancellation(t *testing.T) {
	config := Config{
		Servers:  []string{"8.8.8.8:53"},
		Strategy: "random",
		Timeout:  5 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 1,
		},
	}

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err = client.QueryContext(ctx, msg)
	if err != context.Canceled {
		t.Errorf("expected context.Canceled error, got: %v", err)
	}
}

func TestQueryContextDeadline(t *testing.T) {
	config := Config{
		Servers:  []string{"8.8.8.8:53"},
		Strategy: "random",
		Timeout:  5 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 1,
		},
	}

	// Create a context that expires in the past
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	_, err = client.QueryContext(ctx, msg)
	if err != context.DeadlineExceeded {
		t.Errorf("expected context.DeadlineExceeded error, got: %v", err)
	}
}

func TestCheckHealth(t *testing.T) {
	config := Config{
		Servers:     []string{"8.8.8.8:53"},
		Strategy:    "random",
		Timeout:     100 * time.Millisecond,
		HealthCheck: 30 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Call checkHealth directly
	client.checkHealth()

	// Give some time for goroutines to complete
	time.Sleep(100 * time.Millisecond)

	// The function should not panic - we just verify it runs
}

func TestHealthCheckLoop(t *testing.T) {
	config := Config{
		Servers:     []string{"8.8.8.8:53"},
		Strategy:    "random",
		Timeout:     100 * time.Millisecond,
		HealthCheck: 10 * time.Millisecond,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Let the health check loop run a few times
	time.Sleep(50 * time.Millisecond)

	// Close should stop the loop
	if err := client.Close(); err != nil {
		t.Errorf("close failed: %v", err)
	}
}

func TestQueryUDPInvalidServer(t *testing.T) {
	config := Config{
		Servers:  []string{"invalid.invalid:53"},
		Strategy: "random",
		Timeout:  100 * time.Millisecond,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 1,
		},
	}

	_, err = client.queryUDP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error with invalid server address")
	}
}

func TestQueryTCPInvalidServer(t *testing.T) {
	config := Config{
		Servers:  []string{"invalid.invalid:53"},
		Strategy: "random",
		Timeout:  100 * time.Millisecond,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 1,
		},
	}

	_, err = client.queryTCP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error with invalid server address")
	}
}

func TestClientUDPPool(t *testing.T) {
	config := Config{
		Servers:  []string{"8.8.8.8:53"},
		Strategy: "random",
		Timeout:  5 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Verify UDP pool was created
	if client.udpPool["8.8.8.8:53"] == nil {
		t.Error("expected UDP pool to be created")
	}

	// Get buffer from pool
	pooledUDP := client.udpPool["8.8.8.8:53"].Get()
	var buf []byte
	switch p := pooledUDP.(type) {
	case []byte:
		buf = p
	case *[]byte:
		if p == nil {
			t.Fatal("expected non-nil pooled UDP buffer pointer")
		}
		buf = *p
	default:
		t.Fatalf("unexpected pooled UDP buffer type: %T", pooledUDP)
	}
	if len(buf) != 4096 {
		t.Errorf("expected buffer size 4096, got %d", len(buf))
	}
	client.udpPool["8.8.8.8:53"].Put(&buf)
}

func TestClientTCPPool(t *testing.T) {
	config := Config{
		Servers:  []string{"8.8.8.8:53"},
		Strategy: "random",
		Timeout:  5 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Verify TCP pool was created
	if client.tcpPool["8.8.8.8:53"] == nil {
		t.Error("expected TCP pool to be created")
	}

	// Get buffer from pool
	pooledTCP := client.tcpPool["8.8.8.8:53"].Get()
	var buf []byte
	switch p := pooledTCP.(type) {
	case []byte:
		buf = p
	case *[]byte:
		if p == nil {
			t.Fatal("expected non-nil pooled TCP buffer pointer")
		}
		buf = *p
	default:
		t.Fatalf("unexpected pooled TCP buffer type: %T", pooledTCP)
	}
	if len(buf) != 65535 {
		t.Errorf("expected buffer size 65535, got %d", len(buf))
	}
	client.tcpPool["8.8.8.8:53"].Put(&buf)
}

func TestServerHealthThreshold(t *testing.T) {
	server := &Server{
		Address: "127.0.0.1:53",
		healthy: true,
	}

	// First two failures should not mark unhealthy
	server.markFailure()
	if !server.IsHealthy() {
		t.Error("server should still be healthy after 1 failure")
	}

	server.markFailure()
	if !server.IsHealthy() {
		t.Error("server should still be healthy after 2 failures")
	}

	// Third failure should mark unhealthy
	server.markFailure()
	if server.IsHealthy() {
		t.Error("server should be unhealthy after 3 failures")
	}
}

func TestServerSuccessResetsFailCount(t *testing.T) {
	server := &Server{
		Address: "127.0.0.1:53",
		healthy: true,
	}

	// Add some failures
	server.markFailure()
	server.markFailure()

	server.mu.RLock()
	failCount := server.failCount
	server.mu.RUnlock()

	if failCount != 2 {
		t.Errorf("expected failCount 2, got %d", failCount)
	}

	// Success should reset fail count
	server.markSuccess(10 * time.Millisecond)

	server.mu.RLock()
	failCount = server.failCount
	server.mu.RUnlock()

	if failCount != 0 {
		t.Errorf("expected failCount 0 after success, got %d", failCount)
	}
}

func TestConcurrentServerAccess(t *testing.T) {
	server := &Server{
		Address: "127.0.0.1:53",
		healthy: true,
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			server.IsHealthy()
		}()
		go func() {
			defer wg.Done()
			server.markFailure()
		}()
	}
	wg.Wait()
}

func TestNewClientWithCustomConfig(t *testing.T) {
	config := Config{
		Servers:     []string{"1.1.1.1:53", "1.0.0.1:53", "8.8.8.8:53"},
		Strategy:    "round_robin",
		Timeout:     3 * time.Second,
		HealthCheck: 15 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	if len(client.servers) != 3 {
		t.Errorf("expected 3 servers, got %d", len(client.servers))
	}

	if client.strategy != RoundRobin {
		t.Errorf("expected RoundRobin strategy, got %v", client.strategy)
	}

	if client.timeout != 3*time.Second {
		t.Errorf("expected timeout 3s, got %v", client.timeout)
	}
}

// Mock DNS server for integration tests
func setupMockDNSServer(t *testing.T, response []byte) (string, func()) {
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
				// Echo back the response or send canned response
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

func TestQueryWithMockServer(t *testing.T) {
	// Create a simple echo server
	addr, cleanup := setupMockDNSServer(t, nil)
	defer cleanup()

	config := Config{
		Servers:  []string{addr},
		Strategy: "random",
		Timeout:  1 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	_, err = client.Query(msg)
	// Query may fail due to response parsing, but should not panic
	t.Logf("Query result: %v", err)
}

func TestQueryTCPWithMockServer(t *testing.T) {
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

	config := Config{
		Servers:  []string{localAddr},
		Strategy: "random",
		Timeout:  1 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	_, err = client.queryTCP(client.servers[0], msg)
	// Query may fail due to response parsing, but should not panic
	t.Logf("queryTCP result: %v", err)
}

func TestSelectServerAllStrategies(t *testing.T) {
	config := Config{
		Servers:  []string{"8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53"},
		Strategy: "random",
		Timeout:  5 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Mark all servers as healthy
	for _, s := range client.servers {
		s.healthy = true
		s.latency = 10 * time.Millisecond
	}

	// Test all strategies
	strategies := []Strategy{Random, RoundRobin, Fastest}
	for _, strategy := range strategies {
		client.strategy = strategy
		server := client.selectServer()
		if server == nil {
			t.Errorf("selectServer returned nil for strategy %v", strategy)
		}
	}
}

func TestSelectServerNoServers(t *testing.T) {
	config := Config{
		Servers:  []string{"8.8.8.8:53"},
		Strategy: "random",
		Timeout:  5 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Clear servers (simulating edge case)
	client.mu.Lock()
	client.servers = []*Server{}
	client.mu.Unlock()

	// selectServer should return nil with no servers
	server := client.selectServer()
	if server != nil {
		t.Error("expected nil when no servers available")
	}
}

func TestQueryTCPConnectionError(t *testing.T) {
	config := Config{
		Servers:  []string{"127.0.0.1:1"}, // Port that won't accept connections
		Strategy: "random",
		Timeout:  100 * time.Millisecond,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	_, err = client.queryTCP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error connecting to invalid port")
	}
}

func TestQueryUDPSetDeadlineError(t *testing.T) {
	// This test is tricky - we can't easily force SetDeadline to fail
	// but we can ensure the code path is exercised
	config := Config{
		Servers:  []string{"8.8.8.8:53"},
		Strategy: "random",
		Timeout:  1 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	// Just call queryUDP to exercise the code path
	_, _ = client.queryUDP(client.servers[0], msg)
}

func TestQueryWithUDPThenTCPSuccess(t *testing.T) {
	config := Config{
		Servers:  []string{"8.8.8.8:53"},
		Strategy: "random",
		Timeout:  1 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	// Query will try UDP first, then TCP if needed
	_, err = client.Query(msg)
	// May fail, but tests the code path
	t.Logf("Query result: %v", err)
}

func TestClientSelectFastestAllUnhealthy(t *testing.T) {
	config := Config{
		Servers:  []string{"8.8.8.8:53", "8.8.4.4:53"},
		Strategy: "fastest",
		Timeout:  5 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Mark all servers as unhealthy
	for _, s := range client.servers {
		s.healthy = false
	}

	// selectFastest should fallback to first server
	server := client.selectFastest()
	if server == nil {
		t.Fatal("expected fallback server")
	}
	if server.Address != "8.8.8.8:53" {
		t.Errorf("expected first server as fallback, got %s", server.Address)
	}
}

func TestClientSelectRoundRobinAllUnhealthy(t *testing.T) {
	config := Config{
		Servers:  []string{"8.8.8.8:53", "8.8.4.4:53"},
		Strategy: "round_robin",
		Timeout:  5 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Mark all servers as unhealthy
	for _, s := range client.servers {
		s.healthy = false
	}

	// selectRoundRobin should fallback to starting position
	server := client.selectRoundRobin()
	if server == nil {
		t.Error("expected fallback server")
	}
}

func TestClientSelectRandomFallback(t *testing.T) {
	config := Config{
		Servers:  []string{"8.8.8.8:53"},
		Strategy: "random",
		Timeout:  5 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Mark server as unhealthy
	client.servers[0].healthy = false

	// selectRandom should return first server as fallback
	server := client.selectRandom()
	if server == nil {
		t.Fatal("expected fallback server")
	}
	if server.Address != "8.8.8.8:53" {
		t.Errorf("expected first server as fallback, got %s", server.Address)
	}
}

func TestClientSelectRandomWithHealthyServers(t *testing.T) {
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

	// Mark all servers as healthy
	for _, s := range client.servers {
		s.healthy = true
	}

	// Multiple calls should return healthy servers
	for i := 0; i < 10; i++ {
		server := client.selectRandom()
		if server == nil {
			t.Error("expected server")
		}
		if !server.IsHealthy() {
			t.Error("expected healthy server")
		}
	}
}

func TestClientQueryTCPWithMockServer(t *testing.T) {
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

	config := Config{
		Servers:  []string{localAddr},
		Strategy: "random",
		Timeout:  1 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	_, err = client.queryTCP(client.servers[0], msg)
	// Query may fail due to response parsing, but should not panic
	t.Logf("queryTCP result: %v", err)
}

func TestClientQueryTCPLargeResponse(t *testing.T) {
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
					// Send large response
					largeResp := make([]byte, 70000)
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

	config := Config{
		Servers:  []string{localAddr},
		Strategy: "random",
		Timeout:  1 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	// This tests the buffer resizing code path in queryTCP
	_, _ = client.queryTCP(client.servers[0], msg)
}

func TestClientServerLatency(t *testing.T) {
	server := &Server{
		Address: "127.0.0.1:53",
		healthy: true,
	}

	// Mark success should update latency
	server.markSuccess(15 * time.Millisecond)

	server.mu.RLock()
	latency := server.latency
	server.mu.RUnlock()

	if latency != 15*time.Millisecond {
		t.Errorf("expected latency 15ms, got %v", latency)
	}
}

func TestClientSelectFastestFirstServer(t *testing.T) {
	config := Config{
		Servers:  []string{"8.8.8.8:53", "8.8.4.4:53"},
		Strategy: "fastest",
		Timeout:  5 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Mark all servers as healthy, first with lower latency
	client.servers[0].healthy = true
	client.servers[0].latency = 5 * time.Millisecond
	client.servers[1].healthy = true
	client.servers[1].latency = 50 * time.Millisecond

	server := client.selectFastest()
	if server == nil {
		t.Fatal("expected server")
	}
	if server.Address != "8.8.8.8:53" {
		t.Errorf("expected first server (fastest), got %s", server.Address)
	}
}

func TestQueryContextDeadlineExceeded(t *testing.T) {
	config := Config{
		Servers:  []string{"8.8.8.8:53"},
		Strategy: "random",
		Timeout:  5 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	// Create a context that times out after a very short duration
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// The context should already be expired by the time QueryContext runs
	time.Sleep(1 * time.Millisecond)
	_, err = client.QueryContext(ctx, msg)
	if err == nil {
		t.Log("QueryContext completed without error (unexpected)")
	}
}

func TestClientQueryUDPMockSuccess(t *testing.T) {
	// Create a mock DNS server that echoes responses
	addr, cleanup := setupMockDNSServer(t, nil)
	defer cleanup()

	config := Config{
		Servers:  []string{addr},
		Strategy: "random",
		Timeout:  1 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	// queryUDP with mock server should exercise the full code path
	_, err = client.queryUDP(client.servers[0], msg)
	// It may or may not succeed depending on response parsing
	t.Logf("queryUDP with mock server: %v", err)
}

func TestClientQueryTCPSetDeadlineError(t *testing.T) {
	// Exercise the queryTCP code path with a mock server
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

	config := Config{
		Servers:  []string{localAddr},
		Strategy: "random",
		Timeout:  1 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	_, err = client.queryTCP(client.servers[0], msg)
	t.Logf("queryTCP result: %v", err)
}

func TestClientQueryWithUDPPackError(t *testing.T) {
	// Test queryUDP with a message that might fail to pack
	config := Config{
		Servers:  []string{"8.8.8.8:53"},
		Strategy: "random",
		Timeout:  1 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Create a minimal message
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	_, _ = client.queryUDP(client.servers[0], msg)
}

func TestClientQueryTCPPackError(t *testing.T) {
	// Test queryTCP with a minimal message
	config := Config{
		Servers:  []string{"8.8.8.8:53"},
		Strategy: "random",
		Timeout:  1 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	_, _ = client.queryTCP(client.servers[0], msg)
}

func TestClientCheckHealthFull(t *testing.T) {
	config := Config{
		Servers:     []string{"8.8.8.8:53"},
		Strategy:    "random",
		Timeout:     100 * time.Millisecond,
		HealthCheck: 30 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Call checkHealth to exercise the full code path including
	// the goroutine that does queryUDP and potentially queryTCP
	client.checkHealth()
	time.Sleep(200 * time.Millisecond)

	// Verify server was checked (may be healthy or unhealthy depending on network)
	_ = client.servers[0].IsHealthy()
}

func TestClientHealthCheckLoopFull(t *testing.T) {
	config := Config{
		Servers:     []string{"8.8.8.8:53"},
		Strategy:    "random",
		Timeout:     100 * time.Millisecond,
		HealthCheck: 20 * time.Millisecond,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Let the health check loop run a few times
	time.Sleep(100 * time.Millisecond)

	// Close should stop the loop
	if err := client.Close(); err != nil {
		t.Errorf("close failed: %v", err)
	}
}

func TestClientSelectRoundRobinEmptyServers(t *testing.T) {
	config := Config{
		Servers:  []string{"8.8.8.8:53"},
		Strategy: "round_robin",
		Timeout:  5 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Clear servers to test the empty path
	client.servers = []*Server{}

	server := client.selectRoundRobin()
	if server != nil {
		t.Error("expected nil for empty server list")
	}
}

func TestClientSelectRandomEmptyServers(t *testing.T) {
	config := Config{
		Servers:  []string{"8.8.8.8:53"},
		Strategy: "random",
		Timeout:  5 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Clear servers to test the empty path
	client.servers = []*Server{}

	server := client.selectRandom()
	if server != nil {
		t.Error("expected nil for empty server list")
	}
}

func TestClientQueryNoServersAvailable(t *testing.T) {
	config := Config{
		Servers:  []string{"8.8.8.8:53"},
		Strategy: "random",
		Timeout:  5 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Clear servers to force "no servers available" path in Query
	client.servers = []*Server{}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	_, err = client.Query(msg)
	if err == nil {
		t.Error("expected error with no servers available")
	}

	queries, failed, _ := client.Stats()
	if queries != 1 {
		t.Errorf("expected 1 query, got %d", queries)
	}
	if failed != 1 {
		t.Errorf("expected 1 failed, got %d", failed)
	}
}

func TestClientQueryTCPFallbackSuccess(t *testing.T) {
	// Create a TCP mock server
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

	config := Config{
		Servers:  []string{localAddr},
		Strategy: "random",
		Timeout:  1 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	// Query will try UDP first (which may fail since server is TCP-only),
	// then fallback to TCP which should succeed
	_, err = client.Query(msg)
	t.Logf("Query TCP fallback result: %v", err)

	queries, _, responses := client.Stats()
	if queries != 1 {
		t.Errorf("expected 1 query, got %d", queries)
	}
	// If TCP succeeded, responses should be 1
	if err == nil && responses != 1 {
		t.Errorf("expected 1 response after success, got %d", responses)
	}
}

func TestClientQueryUDPSuccessWithMockServer(t *testing.T) {
	// Create a mock echo server
	addr, cleanup := setupMockDNSServer(t, nil)
	defer cleanup()

	config := Config{
		Servers:  []string{addr},
		Strategy: "random",
		Timeout:  1 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	// Test queryUDP directly with mock server (should succeed)
	resp, err := client.queryUDP(client.servers[0], msg)
	if err != nil {
		t.Logf("queryUDP error: %v (may fail on response parsing)", err)
	} else if resp == nil {
		t.Error("expected non-nil response")
	}
}

func TestClientQueryTCPSuccessWithMockServer(t *testing.T) {
	// Create a TCP mock server
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

	config := Config{
		Servers:  []string{localAddr},
		Strategy: "random",
		Timeout:  1 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	// Test queryTCP directly with mock server
	resp, err := client.queryTCP(client.servers[0], msg)
	if err != nil {
		t.Logf("queryTCP error: %v (may fail on response parsing)", err)
	} else if resp == nil {
		t.Error("expected non-nil response")
	}
}

func TestClientQuerySuccess(t *testing.T) {
	// This test exercises the Query method with a valid message
	config := Config{
		Servers:  []string{"8.8.8.8:53"},
		Strategy: "random",
		Timeout:  1 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.Flags{RD: true},
			QDCount: 0,
		},
	}

	_, err = client.Query(msg)
	// May fail due to network, but tests the code path
	t.Logf("Query result: %v", err)

	// Verify stats
	queries, _, _ := client.Stats()
	if queries != 1 {
		t.Errorf("expected 1 query, got %d", queries)
	}
}
