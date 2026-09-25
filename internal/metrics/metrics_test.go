package metrics

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestConstantTimeTokenEqual(t *testing.T) {
	if !constantTimeTokenEqual("test-token", "test-token") {
		t.Fatal("expected matching tokens to compare equal")
	}
	if constantTimeTokenEqual("wrong-token", "test-token") {
		t.Fatal("expected different same-length token to fail")
	}
	if constantTimeTokenEqual("short", "test-token") {
		t.Fatal("expected different-length token to fail")
	}
	if constantTimeTokenEqual("", "") {
		t.Fatal("empty configured token must not authenticate")
	}
}

func TestMetricsCollector(t *testing.T) {
	cfg := Config{
		Enabled:   true,
		Bind:      "127.0.0.1:19153",
		Path:      "/metrics",
		AuthToken: "test-token",
	}

	m := New(cfg)

	// Start metrics server
	if err := m.Start(); err != nil {
		t.Fatalf("Failed to start metrics server: %v", err)
	}

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Test metrics endpoint (with auth header)
	req, _ := http.NewRequest("GET", "http://127.0.0.1:19153/metrics", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
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

func TestMetricsCollectorDoubleStartStopReturns(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	bind := ln.Addr().String()
	ln.Close()

	m := New(Config{
		Enabled:   true,
		Bind:      bind,
		Path:      "/metrics",
		AuthToken: "test-token",
	})

	if err := m.Start(); err != nil {
		t.Fatalf("Failed to start metrics server: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		conn, err := net.DialTimeout("tcp", bind, 10*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Metrics server did not start listening on %s: %v", bind, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Second Start failed: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- m.Stop()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Stop failed: %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Stop did not return after double Start")
	}
}

func TestMetricsCollectorStartReturnsBindError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()

	m := New(Config{
		Enabled:   true,
		Bind:      ln.Addr().String(),
		Path:      "/metrics",
		AuthToken: "test-token",
	})

	err = m.Start()
	if err == nil {
		t.Fatal("expected metrics bind conflict to be returned from Start")
	}
	if !strings.Contains(err.Error(), "listen metrics") {
		t.Fatalf("Start error = %v, want listen metrics context", err)
	}
	if stopErr := m.Stop(); stopErr != nil {
		t.Fatalf("Stop after failed Start returned error: %v", stopErr)
	}
}

func TestRecordMetrics(t *testing.T) {
	cfg := Config{
		Enabled:   true,
		Bind:      "127.0.0.1:19155",
		Path:      "/metrics",
		AuthToken: "test-token",
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

	// Fetch metrics with auth header
	req, _ := http.NewRequest("GET", "http://127.0.0.1:19155/metrics", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
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
		Enabled:   true,
		Bind:      "127.0.0.1:19156",
		Path:      "/metrics",
		AuthToken: "test-token",
	}

	m := New(cfg)
	m.Start()

	time.Sleep(100 * time.Millisecond)

	req, _ := http.NewRequest("GET", "http://127.0.0.1:19156/health", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
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

func TestSetClusterMetricsWhenDisabled(t *testing.T) {
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
		Enabled:   true,
		Bind:      "127.0.0.1:19158",
		Path:      "/metrics",
		AuthToken: "test-token",
	}

	m := New(cfg)

	// Set cluster metrics with healthy=true
	m.SetClusterMetrics(5, 3, true, 100, 200)

	// Start server and verify metrics output
	if err := m.Start(); err != nil {
		t.Fatalf("Failed to start metrics server: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	req, _ := http.NewRequest("GET", "http://127.0.0.1:19158/metrics", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
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
		Enabled:   true,
		Bind:      "127.0.0.1:19159",
		Path:      "/metrics",
		AuthToken: "test-token",
	}

	m := New(cfg)

	// Set cluster metrics with healthy=false
	m.SetClusterMetrics(10, 2, false, 50, 75)

	// Start server and verify metrics output
	if err := m.Start(); err != nil {
		t.Fatalf("Failed to start metrics server: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	req, _ := http.NewRequest("GET", "http://127.0.0.1:19159/metrics", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
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
	// Use OS-assigned port to avoid hardcoded port conflicts on Windows (Hyper-V reserves ranges)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	ln.Close()

	cfg := Config{
		Enabled:   true,
		Bind:      ln.Addr().String(),
		Path:      "/metrics",
		AuthToken: "test-token",
	}
	m := New(cfg)

	m.RecordQueryLatency("A", 5*time.Millisecond)
	m.RecordQueryLatency("A", 50*time.Millisecond)

	if err := m.Start(); err != nil {
		t.Fatalf("Failed to start: %v", err)
	}
	defer m.Stop()

	time.Sleep(100 * time.Millisecond)

	req, _ := http.NewRequest("GET", "http://"+cfg.Bind+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
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

func TestRecordQueryLatency_PrometheusBucketsAreCumulative(t *testing.T) {
	cfg := Config{Enabled: true}
	m := New(cfg)

	m.RecordQueryLatency("A", 2*time.Millisecond)
	m.RecordQueryLatency("A", 20*time.Millisecond)
	m.RecordQueryLatency("A", 2*time.Second)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()

	m.handleMetrics(rr, req)

	body := rr.Body.String()
	expected := []string{
		`nothingdns_query_duration_seconds_bucket{type="A",le="0.001"} 0`,
		`nothingdns_query_duration_seconds_bucket{type="A",le="0.005"} 1`,
		`nothingdns_query_duration_seconds_bucket{type="A",le="0.01"} 1`,
		`nothingdns_query_duration_seconds_bucket{type="A",le="0.025"} 2`,
		`nothingdns_query_duration_seconds_bucket{type="A",le="+Inf"} 3`,
		`nothingdns_query_duration_seconds_count{type="A"} 3`,
	}

	for _, line := range expected {
		if !strings.Contains(body, line) {
			t.Fatalf("expected metrics output to contain %q\nbody:\n%s", line, body)
		}
	}
}

func TestRecordRateLimited(t *testing.T) {
	cfg := Config{
		Enabled:   true,
		Bind:      "127.0.0.1:19161",
		Path:      "/metrics",
		AuthToken: "test-token",
	}
	m := New(cfg)

	m.RecordRateLimited()

	if err := m.Start(); err != nil {
		t.Fatalf("Failed to start: %v", err)
	}
	defer m.Stop()

	time.Sleep(100 * time.Millisecond)

	req, _ := http.NewRequest("GET", "http://127.0.0.1:19161/metrics", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
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

// Tests for 0% coverage functions

func TestSetTransportStats(t *testing.T) {
	cfg := Config{Enabled: true}
	m := New(cfg)

	// Should not panic
	m.SetTransportStats(100, 200, 3, 10, 5, 50, 2)
}

func TestGetHistory_Empty(t *testing.T) {
	cfg := Config{Enabled: true}
	m := New(cfg)

	history := m.GetHistory()
	_ = history
}

func TestRecordHistorySnapshot(t *testing.T) {
	cfg := Config{Enabled: true}
	m := New(cfg)

	// Should not panic - record a snapshot
	m.recordHistorySnapshot()

	// Record some data first
	m.RecordQuery("test")
	m.RecordCacheHit()
	m.RecordCacheMiss()

	// Now record snapshot with data
	m.recordHistorySnapshot()
}

func TestRecordHistorySnapshotLatencyAverage(t *testing.T) {
	cfg := Config{Enabled: true}
	m := New(cfg)

	m.RecordQueryLatency("A", 10*time.Millisecond)
	m.RecordQueryLatency("A", 30*time.Millisecond)
	m.RecordQueryLatency("MX", 100*time.Millisecond)
	m.recordHistorySnapshot()

	history := m.GetHistory()
	if history.Count != 1 {
		t.Fatalf("Expected one history sample, got %d", history.Count)
	}
	if history.LatencyMs[0] != 46 {
		t.Fatalf("Expected latency average across observations to be 46ms, got %dms", history.LatencyMs[0])
	}
}

func TestUptimeClampsFutureStartTime(t *testing.T) {
	m := New(Config{Enabled: true})
	m.startTime = time.Now().Add(time.Hour)

	metricsRecorder := httptest.NewRecorder()
	m.handleMetrics(metricsRecorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if body := metricsRecorder.Body.String(); !strings.Contains(body, "nothingdns_server_uptime_seconds 0.00") {
		t.Fatalf("future start time should render zero uptime, got:\n%s", body)
	}

	snapshot := m.Snapshot()
	if snapshot.UptimeSeconds != 0 {
		t.Fatalf("future start time snapshot uptime = %d, want 0", snapshot.UptimeSeconds)
	}

	healthRecorder := httptest.NewRecorder()
	m.handleHealth(healthRecorder, httptest.NewRequest(http.MethodGet, "/health", nil))
	if body := healthRecorder.Body.String(); !strings.Contains(body, `"uptime":"0s"`) {
		t.Fatalf("future start time health uptime should be zero, got %s", body)
	}
}

func TestStartWithoutTokenAllowedOnlyOnLoopback(t *testing.T) {
	public := New(Config{Enabled: true, Bind: "0.0.0.0:0", Path: "/metrics"})
	if err := public.Start(); err == nil {
		_ = public.Stop()
		t.Fatal("Start on a public bind without auth_token succeeded; want refusal")
	}

	local := New(Config{Enabled: true, Bind: "127.0.0.1:0", Path: "/metrics"})
	if err := local.Start(); err != nil {
		t.Fatalf("Start on loopback without auth_token: %v", err)
	}
	_ = local.Stop()
}

func TestIsLoopbackBind(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:9153": true, "[::1]:9153": true, "localhost:9153": true,
		":9153": false, "0.0.0.0:9153": false, "[::]:9153": false, "192.168.1.5:9153": false, "": false,
	} {
		if got := IsLoopbackBind(addr); got != want {
			t.Errorf("IsLoopbackBind(%q) = %v, want %v", addr, got, want)
		}
	}
}

// TestRecordQueryCardinalityBoundedByOtherLabel asserts that RecordQuery and
// RecordQueryLatency normalize unknown QTYPEs (those absent from
// protocol.TypeToString) to the single "OTHER" label, preventing unbounded
// Prometheus label cardinality.  An unbounded cardinality explosion in the
// nothingdns_queries_total{type="<qtype>"} and
// nothingdns_query_duration_seconds{type="<qtype>"} metrics would allow a
// single hostile client to exhaust the Prometheus TSDB's per-label cardinality
// budget by flooding distinct QTYPE strings.
//
// Regression test for: metrics cardinality explosion from unbounded QTYPE labels.
func TestRecordQueryCardinalityBoundedByOtherLabel(t *testing.T) {
	// Pick a QTYPE string that is NOT in protocol.TypeToString.
	// TypeToString covers roughly 35 standard record types; any value outside
	// that set must collapse to "OTHER".
	const unknownQtype = "TYPE999"
	const otherLabel = "OTHER"

	// Verify the unknown QTYPE is genuinely unknown so the test is meaningful.
	for _, v := range protocol.TypeToString {
		if v == unknownQtype {
			t.Fatalf("test precondition failed: %q is already in TypeToString", unknownQtype)
		}
	}

	m := New(Config{Enabled: true, Path: "/metrics"})

	// Record the unknown QTYPE via both APIs that carry the type label.
	m.RecordQuery(unknownQtype)
	m.RecordQueryLatency(unknownQtype, 5*time.Millisecond)

	// Scrape the Prometheus output.
	rec := httptest.NewRecorder()
	m.handleMetrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	body := rec.Body.String()

	// The unknown QTYPE string must NOT appear as a label value — that would
	// indicate unbounded cardinality.
	if strings.Contains(body, `type="`+unknownQtype+`"`) {
		t.Errorf("Prometheus output contains unbounded label type=%q; want only %q\n%s",
			unknownQtype, otherLabel, body)
	}

	// Unknown QTYPEs must be recorded under the single bounded "OTHER" label.
	if !strings.Contains(body, `type="`+otherLabel+`"`) {
		t.Errorf("Prometheus output missing bounded label type=%q for unknown QTYPE %q\n%s",
			otherLabel, unknownQtype, body)
	}
}

func TestMetricsWithoutTokenServesOnlyLoopbackPeers(t *testing.T) {
	m := New(Config{Enabled: true, Bind: "127.0.0.1:0", Path: "/metrics"})
	h := m.requireMetricsAuth(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	for remote, want := range map[string]int{
		"127.0.0.1:5555":  http.StatusOK,
		"[::1]:5555":      http.StatusOK,
		"192.168.1.9:555": http.StatusUnauthorized,
	} {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != want {
			t.Errorf("peer %s: status %d, want %d", remote, rec.Code, want)
		}
	}
}
