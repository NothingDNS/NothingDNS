package metrics

import (
	"io"
	"net/http"
	"strings"
	"sync/atomic"
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

func TestRecordQueryLatency_BucketAssignment(t *testing.T) {
	cfg := Config{Enabled: true}
	m := New(cfg)

	cases := []struct {
		dur   time.Duration
		bound string
	}{
		{500 * time.Microsecond, "0.001"},
		{3 * time.Millisecond, "0.005"},
		{7 * time.Millisecond, "0.01"},
		{15 * time.Millisecond, "0.025"},
		{40 * time.Millisecond, "0.05"},
		{75 * time.Millisecond, "0.1"},
		{200 * time.Millisecond, "0.25"},
		{400 * time.Millisecond, "0.5"},
		{750 * time.Millisecond, "1.0"},
	}

	for _, tc := range cases {
		m.RecordQueryLatency("A", tc.dur)
	}

	m.latencyMu.RLock()
	h := m.latencyHists["A"]
	m.latencyMu.RUnlock()

	if h == nil {
		t.Fatal("expected histogram for type A")
	}

	count := atomic.LoadUint64(&h.totalCount)
	if count != uint64(len(cases)) {
		t.Errorf("expected totalCount %d, got %d", len(cases), count)
	}

	// Verify sum is positive
	sum := atomic.LoadUint64(&h.sumNs)
	if sum == 0 {
		t.Error("expected non-zero sumNs")
	}
}

func TestRecordQueryLatency_OverOneSecond(t *testing.T) {
	cfg := Config{Enabled: true}
	m := New(cfg)

	// 2 seconds should fall into implicit +Inf bucket (no explicit bucket)
	m.RecordQueryLatency("MX", 2*time.Second)

	m.latencyMu.RLock()
	h := m.latencyHists["MX"]
	m.latencyMu.RUnlock()

	if h == nil {
		t.Fatal("expected histogram for type MX")
	}

	count := atomic.LoadUint64(&h.totalCount)
	if count != 1 {
		t.Errorf("expected totalCount 1, got %d", count)
	}

	// No bucket should have a count since it fell into +Inf
	for i := 0; i < numLatencyBuckets; i++ {
		bc := atomic.LoadUint64(&h.bucketCounts[i])
		if bc != 0 {
			t.Errorf("bucket %d should be 0 for 2s duration, got %d", i, bc)
		}
	}
}

func TestRecordQueryLatency_Disabled(t *testing.T) {
	cfg := Config{Enabled: false}
	m := New(cfg)

	// Should not panic
	m.RecordQueryLatency("A", 10*time.Millisecond)

	m.latencyMu.RLock()
	_, ok := m.latencyHists["A"]
	m.latencyMu.RUnlock()

	if ok {
		t.Error("expected no histogram when disabled")
	}
}

func TestRecordQueryLatency_MultipleTypes(t *testing.T) {
	cfg := Config{Enabled: true}
	m := New(cfg)

	m.RecordQueryLatency("A", 5*time.Millisecond)
	m.RecordQueryLatency("AAAA", 10*time.Millisecond)
	m.RecordQueryLatency("A", 15*time.Millisecond)

	m.latencyMu.RLock()
	hA := m.latencyHists["A"]
	hAAAA := m.latencyHists["AAAA"]
	m.latencyMu.RUnlock()

	if hA == nil || hAAAA == nil {
		t.Fatal("expected histograms for both types")
	}

	countA := atomic.LoadUint64(&hA.totalCount)
	countAAAA := atomic.LoadUint64(&hAAAA.totalCount)

	if countA != 2 {
		t.Errorf("expected A totalCount 2, got %d", countA)
	}
	if countAAAA != 1 {
		t.Errorf("expected AAAA totalCount 1, got %d", countAAAA)
	}
}

func TestRecordQueryLatency_PrometheusOutput(t *testing.T) {
	cfg := Config{
		Enabled: true,
		Bind:    "127.0.0.1:19160",
		Path:    "/metrics",
	}
	m := New(cfg)

	m.RecordQueryLatency("A", 5*time.Millisecond)
	m.RecordQueryLatency("A", 50*time.Millisecond)

	if err := m.Start(); err != nil {
		t.Fatalf("Failed to start: %v", err)
	}
	defer m.Stop()

	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get("http://127.0.0.1:19160/metrics")
	if err != nil {
		t.Fatalf("Failed to get metrics: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Check histogram header
	if !strings.Contains(bodyStr, "# TYPE nothingdns_query_duration_seconds histogram") {
		t.Error("expected histogram type header in output")
	}

	// Check +Inf bucket
	if !strings.Contains(bodyStr, `le="+Inf"`) {
		t.Error("expected +Inf bucket in output")
	}

	// Check count label
	if !strings.Contains(bodyStr, `nothingdns_query_duration_seconds_count{type="A"}`) {
		t.Error("expected histogram count in output")
	}

	// Check sum label
	if !strings.Contains(bodyStr, `nothingdns_query_duration_seconds_sum{type="A"}`) {
		t.Error("expected histogram sum in output")
	}
}

func TestRecordRateLimited(t *testing.T) {
	cfg := Config{
		Enabled: true,
		Bind:    "127.0.0.1:19161",
		Path:    "/metrics",
	}
	m := New(cfg)

	m.RecordRateLimited()

	if err := m.Start(); err != nil {
		t.Fatalf("Failed to start: %v", err)
	}
	defer m.Stop()

	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get("http://127.0.0.1:19161/metrics")
	if err != nil {
		t.Fatalf("Failed to get metrics: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "nothingdns_rate_limited_total 1") {
		t.Errorf("expected rate_limited_total to be 1, got:\n%s", bodyStr)
	}
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
