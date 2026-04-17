package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/cluster"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// newTestServerWithAuth creates a server with a test auth store and returns a valid admin token.
func newTestServerWithAuth(t *testing.T, cfg config.HTTPConfig, zm *zone.Manager, c *cache.Cache) (*Server, string) {
	authCfg := &auth.Config{
		Secret:      "test-secret-for-tests",
		Users:       []auth.User{{Username: "testadmin", Password: "testpass", Role: auth.RoleAdmin}},
		TokenExpiry: auth.Duration{Duration: 24 * time.Hour},
	}
	store, _ := auth.NewStore(authCfg)
	srv := NewServer(cfg, zm, c, nil, nil, nil, nil).WithAuth(store)
	token, err := store.GenerateToken("testadmin", 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate test token: %v", err)
	}
	return srv, token.Token
}

// withTestAdminAuth injects the admin user into the request context and sets the Bearer token.
func withTestAdminAuth(req *http.Request, token string) *http.Request {
	req.Header.Set("Authorization", "Bearer "+token)
	user := &auth.User{Username: "testadmin", Role: auth.RoleAdmin}
	req = req.WithContext(WithUser(req.Context(), user))
	return req
}

// attachTestAuth adds a test auth store to an existing server and returns a valid admin token.
func attachTestAuth(s *Server) string {
	authCfg := &auth.Config{
		Secret:      "test-secret-for-tests",
		Users:       []auth.User{{Username: "testadmin", Password: "testpass", Role: auth.RoleAdmin}},
		TokenExpiry: auth.Duration{Duration: 24 * time.Hour},
	}
	store, _ := auth.NewStore(authCfg)
	s.WithAuth(store)
	token, err := store.GenerateToken("testadmin", 24*time.Hour)
	if err != nil {
		panic(err)
	}
	return token.Token
}

// ---------------------------------------------------------------------------
// handleStatus: cover the s.cluster != nil branch (lines 170-178)
// ---------------------------------------------------------------------------

func TestHandleStatus_WithCluster(t *testing.T) {
	cfg := config.HTTPConfig{
		Enabled: true,
		Bind:    "127.0.0.1:0",
	}

	clusterCfg := cluster.Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key required
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
	addr := pickFreeAddr(t)
	cfg := config.HTTPConfig{
		Enabled:   true,
		Bind:      addr,
		DoHEnabled: true,
		DoHPath:   "/dns-query",
	}

	srv := NewServer(cfg, nil, nil, nil, &mockDNSHandler{}, nil, nil)

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Verify the DoH endpoint was registered by making an HTTP GET to it.
	// A GET to /dns-query without proper DNS wireformat should still get a
	// response (not 404), confirming the route exists.
	resp, err := http.Get("http://" + addr + "/dns-query")
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
	addr := pickFreeAddr(t)
	clusterCfg := cluster.Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key required
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
		Bind:    addr,
	}

	srv := NewServer(cfg, nil, nil, nil, nil, cl, nil)

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Verify cluster endpoints were registered.
	for _, path := range []string{"/api/v1/cluster/status", "/api/v1/cluster/nodes"} {
		resp, err := http.Get("http://" + addr + path)
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
	addr := pickFreeAddr(t)
	cfg := config.HTTPConfig{
		Enabled:    true,
		Bind:       addr,
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
	resp, err := http.Get("http://" + addr + "/dns-query")
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

// pickFreeAddr returns a free "127.0.0.1:port" address by opening a
// temporary TCP listener. This avoids Windows Hyper-V port exclusion ranges.
func pickFreeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
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
	srv, token := newTestServerWithAuth(t, cfg, zm, nil)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodPost, "/api/v1/zones/reload?zone=testzone.com.", nil), token)
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

// ---------------------------------------------------------------------------
// handleServerConfig
// ---------------------------------------------------------------------------

func TestHandleServerConfig(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv, token := newTestServerWithAuth(t, cfg, nil, nil)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/server/config", nil), token)
	rec := httptest.NewRecorder()
	srv.handleServerConfig(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["version"] == nil {
		t.Error("expected version in response")
	}
}

func TestHandleServerConfig_MethodNotAllowed(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/api/v1/server/config", nil)
		rec := httptest.NewRecorder()
		srv.handleServerConfig(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405 for %s, got %d", method, rec.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// handleDashboardStats
// ---------------------------------------------------------------------------

func TestHandleDashboardStats(t *testing.T) {
	cacheCfg := cache.Config{Capacity: 500, MinTTL: 60, MaxTTL: 3600, DefaultTTL: 300}
	c := cache.New(cacheCfg)

	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv, token := newTestServerWithAuth(t, cfg, nil, c)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodGet, "/api/dashboard/stats", nil), token)
	rec := httptest.NewRecorder()
	srv.handleDashboardStats(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["queriesTotal"] == nil {
		t.Error("expected queriesTotal in response")
	}
}

func TestHandleDashboardStats_NoCache(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv, token := newTestServerWithAuth(t, cfg, nil, nil)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodGet, "/api/dashboard/stats", nil), token)
	rec := httptest.NewRecorder()
	srv.handleDashboardStats(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// handleDNSSECStatus
// ---------------------------------------------------------------------------

func TestHandleDNSSECStatus_Disabled(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv, token := newTestServerWithAuth(t, cfg, nil, nil)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/dnssec/status", nil), token)
	rec := httptest.NewRecorder()
	srv.handleDNSSECStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["enabled"] != false {
		t.Errorf("expected enabled=false, got %v", resp["enabled"])
	}
}

func TestHandleDNSSECStatus_MethodNotAllowed(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/api/v1/dnssec/status", nil)
		rec := httptest.NewRecorder()
		srv.handleDNSSECStatus(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405 for %s, got %d", method, rec.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// handleDNSSECKeys
// ---------------------------------------------------------------------------

func TestHandleDNSSECKeys_NoSigners(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv, token := newTestServerWithAuth(t, cfg, nil, nil)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/dnssec/keys", nil), token)
	rec := httptest.NewRecorder()
	srv.handleDNSSECKeys(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	// zones may be nil or empty slice when no signers are configured
	if zones, ok := resp["zones"].([]any); ok && zones != nil {
		if len(zones) != 0 {
			t.Errorf("expected 0 zones, got %d", len(zones))
		}
	}
}

func TestHandleDNSSECKeys_MethodNotAllowed(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/api/v1/dnssec/keys", nil)
		rec := httptest.NewRecorder()
		srv.handleDNSSECKeys(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405 for %s, got %d", method, rec.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// handleReadiness
// ---------------------------------------------------------------------------

func TestHandleReadiness_NoUpstream(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	srv.handleReadiness(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["status"] != "ready" {
		t.Errorf("expected status=ready, got %v", resp["status"])
	}
}

// ---------------------------------------------------------------------------
// handleLiveness
// ---------------------------------------------------------------------------

func TestHandleLiveness(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	rec := httptest.NewRecorder()
	srv.handleLiveness(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["status"] != "alive" {
		t.Errorf("expected status=alive, got %v", resp["status"])
	}
}

// ---------------------------------------------------------------------------
// handleRoles
// ---------------------------------------------------------------------------

func TestHandleRoles(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/roles", nil)
	rec := httptest.NewRecorder()
	srv.handleRoles(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	roles, ok := resp["roles"].([]interface{})
	if !ok {
		t.Fatal("expected roles array")
	}
	if len(roles) < 3 {
		t.Errorf("expected at least 3 roles, got %d", len(roles))
	}
}

// ---------------------------------------------------------------------------
// WithUser and GetUser
// ---------------------------------------------------------------------------

func TestWithUserAndGetUser(t *testing.T) {
	ctx := context.Background()

	// GetUser should return nil when no user in context
	if GetUser(ctx) != nil {
		t.Error("expected nil user from empty context")
	}

	// Create a mock user
	user := &auth.User{Username: "testuser", Role: auth.RoleAdmin}

	// WithUser should add user to context
	ctx = WithUser(ctx, user)

	// GetUser should retrieve it
	retrieved := GetUser(ctx)
	if retrieved == nil {
		t.Fatal("expected non-nil user from context")
	}
	if retrieved.Username != "testuser" {
		t.Errorf("expected username 'testuser', got %s", retrieved.Username)
	}
}

// ---------------------------------------------------------------------------
// handleListZones with zone manager
// ---------------------------------------------------------------------------

func TestHandleListZones_WithZones(t *testing.T) {
	zm := zone.NewManager()
	testZone := &zone.Zone{
		Origin:     "test.com.",
		DefaultTTL: 3600,
		Records:    map[string][]zone.Record{},
	}
	testZone.SOA = &zone.SOARecord{Serial: 12345}
	zm.LoadZone(testZone, "")

	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv, token := newTestServerWithAuth(t, cfg, zm, nil)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil), token)
	rec := httptest.NewRecorder()
	srv.handleZones(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	zones := resp["zones"].([]interface{})
	if len(zones) != 1 {
		t.Errorf("expected 1 zone, got %d", len(zones))
	}
}

// ---------------------------------------------------------------------------
// handleGetZone
// ---------------------------------------------------------------------------

func TestHandleGetZone(t *testing.T) {
	zm := zone.NewManager()
	testZone := &zone.Zone{
		Origin:     "example.com.",
		DefaultTTL: 3600,
		Records:    map[string][]zone.Record{},
	}
	testZone.SOA = &zone.SOARecord{
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minimum: 86400,
		MName:   "ns1.example.com.",
		RName:   "admin.example.com.",
	}
	testZone.NS = []zone.NSRecord{{NSDName: "ns1.example.com."}, {NSDName: "ns2.example.com."}}
	zm.LoadZone(testZone, "")

	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv, token := newTestServerWithAuth(t, cfg, zm, nil)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com.", nil), token)
	rec := httptest.NewRecorder()
	srv.handleZoneActions(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["serial"] != float64(2024010101) {
		t.Errorf("expected serial 2024010101, got %v", resp["serial"])
	}
}

func TestHandleGetZone_NotFound(t *testing.T) {
	zm := zone.NewManager()
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv, token := newTestServerWithAuth(t, cfg, zm, nil)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/zones/nonexistent.com.", nil), token)
	rec := httptest.NewRecorder()
	srv.handleZoneActions(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// handleDeleteZone
// ---------------------------------------------------------------------------

func TestHandleDeleteZone(t *testing.T) {
	zm := zone.NewManager()
	testZone := &zone.Zone{
		Origin:  "delete.me.",
		Records: map[string][]zone.Record{},
	}
	testZone.SOA = &zone.SOARecord{}
	zm.LoadZone(testZone, "")

	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv, token := newTestServerWithAuth(t, cfg, zm, nil)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodDelete, "/api/v1/zones/delete.me.", nil), token)
	rec := httptest.NewRecorder()
	srv.handleZoneActions(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	// Verify zone was deleted
	if _, ok := zm.Get("delete.me."); ok {
		t.Error("zone should have been deleted")
	}
}

func TestHandleDeleteZone_NotFound(t *testing.T) {
	zm := zone.NewManager()
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv, token := newTestServerWithAuth(t, cfg, zm, nil)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodDelete, "/api/v1/zones/nonexistent.com.", nil), token)
	rec := httptest.NewRecorder()
	srv.handleZoneActions(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// handleExportZone
// ---------------------------------------------------------------------------

func TestHandleExportZone(t *testing.T) {
	zm := zone.NewManager()
	testZone := &zone.Zone{
		Origin:     "export.com.",
		DefaultTTL: 3600,
		Records:    map[string][]zone.Record{},
	}
	testZone.SOA = &zone.SOARecord{Serial: 1}
	testZone.NS = []zone.NSRecord{{NSDName: "ns1.export.com."}}
	zm.LoadZone(testZone, "")

	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv, token := newTestServerWithAuth(t, cfg, zm, nil)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/zones/export.com./export", nil), token)
	rec := httptest.NewRecorder()
	srv.handleZoneActions(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	if !strings.Contains(rec.Body.String(), "export.com.") {
		t.Error("expected zone content in response")
	}
}

func TestHandleExportZone_NotFound(t *testing.T) {
	zm := zone.NewManager()
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv, token := newTestServerWithAuth(t, cfg, zm, nil)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/zones/nonexistent.com./export", nil), token)
	rec := httptest.NewRecorder()
	srv.handleZoneActions(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// handleConfigGet
// ---------------------------------------------------------------------------

func TestHandleConfigGet(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	getter := func() *config.Config {
		return &config.Config{}
	}
	srv, token := newTestServerWithAuth(t, cfg, nil, nil)
	srv.WithConfigGetter(getter)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/config", nil), token)
	rec := httptest.NewRecorder()
	srv.handleConfigGet(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestHandleConfigGet_NoGetter(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	rec := httptest.NewRecorder()
	srv.handleConfigGet(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", rec.Code)
	}
}

func TestHandleConfigGet_MethodNotAllowed(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/config", nil)
	rec := httptest.NewRecorder()
	srv.handleConfigGet(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// handleZoneActions method routing
// ---------------------------------------------------------------------------

func TestHandleZoneActions_SubpathNotFound(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	zm := zone.NewManager()
	testZone := &zone.Zone{Origin: "test.com.", Records: map[string][]zone.Record{}}
	testZone.SOA = &zone.SOARecord{}
	zm.LoadZone(testZone, "")

	srv, token := newTestServerWithAuth(t, cfg, zm, nil)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/zones/test.com./invalid-subpath", nil), token)
	rec := httptest.NewRecorder()
	srv.handleZoneActions(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}
}
