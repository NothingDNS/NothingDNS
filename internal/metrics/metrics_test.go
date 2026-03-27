package metrics

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestMetricsCollector(t *testing.T) {
	cfg := Config{
		Enabled: true,
		Bind:    "127.0.0.1:19153",
		Path:    "/metrics",
	}

	m := New(cfg)

	// Start metrics server
	if err := m.Start(); err != nil {
		t.Fatalf("Failed to start metrics server: %v", err)
	}

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Test metrics endpoint
	resp, err := http.Get("http://127.0.0.1:19153/metrics")
	if err != nil {
		t.Fatalf("Failed to get metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}

	// Check for expected metrics
	expectedMetrics := []string{
		"nothingdns_server_uptime_seconds",
		"# HELP",
		"# TYPE",
	}

	bodyStr := string(body)
	for _, expected := range expectedMetrics {
		if !strings.Contains(bodyStr, expected) {
			t.Errorf("Expected metrics to contain %q", expected)
		}
	}

	// Stop server
	if err := m.Stop(); err != nil {
		t.Errorf("Failed to stop metrics server: %v", err)
	}
}

func TestMetricsCollectorDisabled(t *testing.T) {
	cfg := Config{
		Enabled: false,
		Bind:    "127.0.0.1:19154",
		Path:    "/metrics",
	}

	m := New(cfg)

	// Start should not fail when disabled
	if err := m.Start(); err != nil {
		t.Errorf("Start should not fail when disabled: %v", err)
	}

	// Stop should not fail when disabled
	if err := m.Stop(); err != nil {
		t.Errorf("Stop should not fail when disabled: %v", err)
	}
}

func TestRecordMetrics(t *testing.T) {
	cfg := Config{
		Enabled: true,
		Bind:    "127.0.0.1:19155",
		Path:    "/metrics",
	}

	m := New(cfg)

	// Record some metrics
	m.RecordQuery("A")
	m.RecordQuery("A")
	m.RecordQuery("AAAA")
	m.RecordResponse(0)
	m.RecordResponse(3)
	m.RecordCacheHit()
	m.RecordCacheMiss()
	m.RecordBlocklistBlock()
	m.RecordUpstreamQuery("8.8.8.8:53")

	// Start server
	if err := m.Start(); err != nil {
		t.Fatalf("Failed to start metrics server: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Fetch metrics
	resp, err := http.Get("http://127.0.0.1:19155/metrics")
	if err != nil {
		t.Fatalf("Failed to get metrics: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}

	bodyStr := string(body)

	// Check recorded metrics
	if !strings.Contains(bodyStr, `nothingdns_queries_total{type="A"} 2`) {
		t.Errorf("Expected A queries to be 2")
	}

	if !strings.Contains(bodyStr, `nothingdns_queries_total{type="AAAA"} 1`) {
		t.Errorf("Expected AAAA queries to be 1")
	}

	if !strings.Contains(bodyStr, "nothingdns_cache_hits_total 1") {
		t.Errorf("Expected cache hits to be 1")
	}

	if !strings.Contains(bodyStr, "nothingdns_cache_misses_total 1") {
		t.Errorf("Expected cache misses to be 1")
	}

	if !strings.Contains(bodyStr, "nothingdns_blocklist_blocks_total 1") {
		t.Errorf("Expected blocklist blocks to be 1")
	}

	if !strings.Contains(bodyStr, `nothingdns_upstream_queries_total{server="8.8.8.8:53"} 1`) {
		t.Errorf("Expected upstream queries to 8.8.8.8:53 to be 1")
	}

	m.Stop()
}

func TestHealthEndpoint(t *testing.T) {
	cfg := Config{
		Enabled: true,
		Bind:    "127.0.0.1:19156",
		Path:    "/metrics",
	}

	m := New(cfg)
	m.Start()

	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get("http://127.0.0.1:19156/health")
	if err != nil {
		t.Fatalf("Failed to get health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "healthy") {
		t.Errorf("Expected health response to contain 'healthy'")
	}

	m.Stop()
}

func TestRecordMetricsWhenDisabled(t *testing.T) {
	cfg := Config{
		Enabled: false,
	}

	m := New(cfg)

	// These should not panic when disabled
	m.RecordQuery("A")
	m.RecordResponse(0)
	m.RecordCacheHit()
	m.RecordCacheMiss()
	m.RecordBlocklistBlock()
	m.RecordUpstreamQuery("8.8.8.8:53")
	m.SetClusterMetrics(5, 3, true, 100, 200)
}

func TestSetClusterMetrics(t *testing.T) {
	cfg := Config{
		Enabled: true,
		Bind:    "127.0.0.1:19158",
		Path:    "/metrics",
	}

	m := New(cfg)

	// Set cluster metrics with healthy=true
	m.SetClusterMetrics(5, 3, true, 100, 200)

	// Start server and verify metrics output
	if err := m.Start(); err != nil {
		t.Fatalf("Failed to start metrics server: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get("http://127.0.0.1:19158/metrics")
	if err != nil {
		t.Fatalf("Failed to get metrics: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}

	bodyStr := string(body)

	// Verify cluster node count
	if !strings.Contains(bodyStr, "nothingdns_cluster_nodes_total 5") {
		t.Errorf("Expected cluster_nodes_total to be 5, got:\n%s", bodyStr)
	}

	// Verify cluster alive count
	if !strings.Contains(bodyStr, "nothingdns_cluster_nodes_alive 3") {
		t.Errorf("Expected cluster_nodes_alive to be 3, got:\n%s", bodyStr)
	}

	// Verify healthy=1 when healthy=true
	if !strings.Contains(bodyStr, "nothingdns_cluster_healthy 1") {
		t.Errorf("Expected cluster_healthy to be 1, got:\n%s", bodyStr)
	}

	// Verify gossip sent
	if !strings.Contains(bodyStr, "nothingdns_cluster_gossip_messages_sent_total 100") {
		t.Errorf("Expected gossip_messages_sent_total to be 100, got:\n%s", bodyStr)
	}

	// Verify gossip received
	if !strings.Contains(bodyStr, "nothingdns_cluster_gossip_messages_received_total 200") {
		t.Errorf("Expected gossip_messages_received_total to be 200, got:\n%s", bodyStr)
	}

	m.Stop()
}

func TestSetClusterMetricsUnhealthy(t *testing.T) {
	cfg := Config{
		Enabled: true,
		Bind:    "127.0.0.1:19159",
		Path:    "/metrics",
	}

	m := New(cfg)

	// Set cluster metrics with healthy=false
	m.SetClusterMetrics(10, 2, false, 50, 75)

	// Start server and verify metrics output
	if err := m.Start(); err != nil {
		t.Fatalf("Failed to start metrics server: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get("http://127.0.0.1:19159/metrics")
	if err != nil {
		t.Fatalf("Failed to get metrics: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}

	bodyStr := string(body)

	// Verify healthy=0 when healthy=false
	if !strings.Contains(bodyStr, "nothingdns_cluster_healthy 0") {
		t.Errorf("Expected cluster_healthy to be 0, got:\n%s", bodyStr)
	}

	// Verify node count
	if !strings.Contains(bodyStr, "nothingdns_cluster_nodes_total 10") {
		t.Errorf("Expected cluster_nodes_total to be 10, got:\n%s", bodyStr)
	}

	// Verify alive count
	if !strings.Contains(bodyStr, "nothingdns_cluster_nodes_alive 2") {
		t.Errorf("Expected cluster_nodes_alive to be 2, got:\n%s", bodyStr)
	}

	m.Stop()
}

func TestDefaultPath(t *testing.T) {
	cfg := Config{
		Enabled: true,
		Bind:    "127.0.0.1:19157",
		Path:    "", // Empty path should default to /metrics
	}

	m := New(cfg)
	if m.config.Path != "/metrics" {
		t.Errorf("Expected default path to be /metrics, got %s", m.config.Path)
	}
}
