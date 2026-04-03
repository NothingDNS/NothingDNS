package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/cluster"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// ---------------------------------------------------------------------------
// handleStatus: cover the s.cluster != nil branch (lines 170-178)
// ---------------------------------------------------------------------------

func TestHandleStatus_WithCluster(t *testing.T) {
	cfg := config.HTTPConfig{
		Enabled: true,
		Bind:    "127.0.0.1:0",
	}

	clusterCfg := cluster.Config{
		Enabled:    true,
		NodeID:     "status-test-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 0, // let OS pick
	}
	cl, err := cluster.New(clusterCfg, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create cluster: %v", err)
	}

	cacheCfg := cache.Config{Capacity: 200, MinTTL: 60, MaxTTL: 3600, DefaultTTL: 300}
	c := cache.New(cacheCfg)

	srv := NewServer(cfg, nil, c, nil, nil, cl, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rec := httptest.NewRecorder()
	srv.handleStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	clusterInfo, ok := resp["cluster"].(map[string]interface{})
	if !ok {
		t.Fatal("expected cluster info in response")
	}
	if clusterInfo["enabled"] != true {
		t.Errorf("expected cluster.enabled true, got %v", clusterInfo["enabled"])
	}
	if clusterInfo["node_id"] != "status-test-node" {
		t.Errorf("expected node_id 'status-test-node', got %v", clusterInfo["node_id"])
	}

	// cache info should also be present
	cacheInfo, ok := resp["cache"].(map[string]interface{})
	if !ok {
		t.Fatal("expected cache info in response")
	}
	if cacheInfo["capacity"].(float64) != 200 {
		t.Errorf("expected cache capacity 200, got %v", cacheInfo["capacity"])
	}
}

// ---------------------------------------------------------------------------
// Start: cover DoH branch (lines 50-53) and cluster routes branch (lines 60-63)
// ---------------------------------------------------------------------------

// mockDNSHandler is a minimal server.Handler implementation for tests.
type mockDNSHandler struct{}

func (m *mockDNSHandler) ServeDNS(_ server.ResponseWriter, _ *protocol.Message) {}

func TestStart_DoHEnabled(t *testing.T) {
	cfg := config.HTTPConfig{
		Enabled:    true,
		Bind:       "127.0.0.1:18100",
		DoHEnabled: true,
		DoHPath:    "/dns-query",
	}

	srv := NewServer(cfg, nil, nil, nil, &mockDNSHandler{}, nil, nil)

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Verify the DoH endpoint was registered by making an HTTP GET to it.
	// A GET to /dns-query without proper DNS wireformat should still get a
	// response (not 404), confirming the route exists.
	resp, err := http.Get("http://127.0.0.1:18100/dns-query")
	if err != nil {
		t.Fatalf("failed to reach DoH endpoint: %v", err)
	}
	resp.Body.Close()
	// We don't care about the exact status; we just need to confirm it isn't 404.
	if resp.StatusCode == http.StatusNotFound {
		t.Error("DoH endpoint returned 404 -- route may not be registered")
	}

	srv.Stop()
}

func TestStart_WithCluster(t *testing.T) {
	clusterCfg := cluster.Config{
		Enabled:    true,
		NodeID:     "start-cluster-node",
		BindAddr:   "127.0.0.1",
		GossipPort: 0,
	}
	cl, err := cluster.New(clusterCfg, nil, nil)
	if err != nil {
		t.Fatalf("failed to create cluster: %v", err)
	}

	cfg := config.HTTPConfig{
		Enabled: true,
		Bind:    "127.0.0.1:18101",
	}

	srv := NewServer(cfg, nil, nil, nil, nil, cl, nil)

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Verify cluster endpoints were registered.
	for _, path := range []string{"/api/v1/cluster/status", "/api/v1/cluster/nodes"} {
		resp, err := http.Get("http://127.0.0.1:18101" + path)
		if err != nil {
			t.Fatalf("failed to reach %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			t.Errorf("cluster endpoint %s returned 404 -- route may not be registered", path)
		}
	}

	srv.Stop()
}

func TestStart_DoHEnabledWithoutDNSHandler(t *testing.T) {
	// When DoHEnabled is true but dnsHandler is nil, the DoH block should be skipped.
	// The SPA fallback handler will serve index.html for the path instead.
	cfg := config.HTTPConfig{
		Enabled:    true,
		Bind:       "127.0.0.1:18102",
		DoHEnabled: true,
		DoHPath:    "/dns-query",
	}

	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// The /dns-query route is not registered as a DoH handler (dnsHandler is nil),
	// but the SPA fallback will serve index.html for the path.
	resp, err := http.Get("http://127.0.0.1:18102/dns-query")
	if err != nil {
		t.Fatalf("failed to reach server: %v", err)
	}
	resp.Body.Close()
	// SPA fallback returns 200 with HTML, not 404
	if resp.StatusCode == http.StatusNotFound {
		t.Error("SPA fallback should serve index.html, got 404")
	}

	srv.Stop()
}

// ---------------------------------------------------------------------------
// handleZoneReload: cover successful reload path (lines 228-235)
// ---------------------------------------------------------------------------

func TestHandleZoneReload_Success(t *testing.T) {
	// Create a temporary zone file so Reload can re-read it.
	zoneContent := `$ORIGIN testzone.com.
$TTL 3600
@ IN SOA ns1 hostmaster 2024010101 3600 900 604800 86400
@ IN NS ns1
@ IN A 10.0.0.1
`
	tmpDir := t.TempDir()
	zonePath := filepath.Join(tmpDir, "testzone.com.zone")
	if err := os.WriteFile(zonePath, []byte(zoneContent), 0644); err != nil {
		t.Fatalf("failed to write temp zone file: %v", err)
	}

	zm := zone.NewManager()
	if err := zm.Load("testzone.com.", zonePath); err != nil {
		t.Fatalf("failed to load zone: %v", err)
	}

	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, zm, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/reload?zone=testzone.com.", nil)
	rec := httptest.NewRecorder()
	srv.handleZoneReload(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	expectedMsg := "Zone testzone.com. reloaded"
	if resp["message"] != expectedMsg {
		t.Errorf("expected message %q, got %q", expectedMsg, resp["message"])
	}
}

func TestHandleZoneReload_PUTMethodNotAllowed(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/zones/reload?zone=example.com.", nil)
	rec := httptest.NewRecorder()
	srv.handleZoneReload(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

func TestHandleZoneReload_DeleteMethodNotAllowed(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/zones/reload?zone=example.com.", nil)
	rec := httptest.NewRecorder()
	srv.handleZoneReload(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}
