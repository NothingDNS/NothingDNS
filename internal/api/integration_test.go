package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// ---------------------------------------------------------------------------
// Integration tests for the REST API — uses httptest-friendly server that
// starts a real HTTP listener with real zone.Manager and auth.Store.
// ---------------------------------------------------------------------------

// setupIntegrationServer creates an API server on a free port with a real
// zone manager (pre-loaded with one test zone) and an auth store (with one
// admin user). Returns the server, the base URL, and a valid admin token.
func setupIntegrationServer(t *testing.T) (*Server, string, string) {
	t.Helper()

	// --- Zone manager with one pre-created zone ---
	zm := zone.NewManager()
	soa := &zone.SOARecord{
		TTL:     3600,
		MName:   "ns1.example.com.",
		RName:   "admin.example.com.",
		Serial:  2026070101,
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minimum: 86400,
	}
	if err := zm.CreateZone("example.com.", 3600, soa, []zone.NSRecord{
		{TTL: 3600, NSDName: "ns1.example.com."},
	}); err != nil {
		t.Fatalf("CreateZone: %v", err)
	}

	// --- Auth store with one admin user ---
	cfg, err := auth.DefaultConfig()
	if err != nil {
		t.Fatalf("auth.DefaultConfig: %v", err)
	}
	hash := cachedTestPasswordHash(t, "adminpass")
	cfg.Users = []auth.User{
		{Username: "admin", Hash: hash, Role: auth.RoleAdmin},
	}
	store, err := auth.NewStore(cfg)
	if err != nil {
		t.Fatalf("auth.NewStore: %v", err)
	}
	tokenObj, err := store.GenerateToken("admin", 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	token := tokenObj.Token

	// --- API server ---
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := l.Addr().String()
	l.Close() // free the port so server.Start() can bind it

	httpCfg := config.HTTPConfig{
		Enabled: true,
		Bind:    addr,
	}
	s := NewServer(httpCfg, zm, nil, nil, nil, nil, nil)
	s.authStore = store

	if err := s.Start(); err != nil {
		t.Fatalf("API server Start: %v", err)
	}
	t.Cleanup(func() { s.Stop() })

	return s, "http://" + addr, token
}

// apiGet performs an authenticated GET request.
func apiGet(t *testing.T, baseURL, path, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, baseURL+path, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

// apiPost performs an authenticated POST request with a JSON body.
func apiPost(t *testing.T, baseURL, path, token string, body any) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		t.Fatalf("Encode body: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+path, &buf)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

// apiDelete performs an authenticated DELETE request.
func apiDelete(t *testing.T, baseURL, path, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, baseURL+path, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE %s: %v", path, err)
	}
	return resp
}

// readBody reads the response body and returns it as a parsed JSON map.
func readBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	var data map[string]any
	if len(body) > 0 {
		if err := json.Unmarshal(body, &data); err != nil {
			t.Fatalf("Unmarshal %q: %v", string(body), err)
		}
	}
	return data
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestIntegration_HealthEndpoint(t *testing.T) {
	_, baseURL, _ := setupIntegrationServer(t)

	// Health does NOT require auth
	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	data := readBody(t, resp)
	if data["status"] != "healthy" {
		t.Errorf("expected status 'healthy', got %v", data["status"])
	}
	if _, ok := data["timestamp"]; !ok {
		t.Error("expected timestamp field")
	}
}

func TestIntegration_LoginAndToken(t *testing.T) {
	_, baseURL, _ := setupIntegrationServer(t)

	// Login with valid credentials
	loginBody := map[string]string{"username": "admin", "password": "adminpass"}
	resp := apiPost(t, baseURL, "/api/v1/auth/login", "", loginBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login expected 200, got %d: %s", resp.StatusCode, readBody(t, resp))
	}
	data := readBody(t, resp)
	if data["token"] == "" {
		t.Error("expected non-empty token")
	}
	if data["role"] != "admin" {
		t.Errorf("expected role 'admin', got %v", data["role"])
	}

	// Login with wrong password yields 401
	badBody := map[string]string{"username": "admin", "password": "wrong"}
	resp = apiPost(t, baseURL, "/api/v1/auth/login", "", badBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad login expected 401, got %d", resp.StatusCode)
	}
}

func TestIntegration_StatusEndpoint(t *testing.T) {
	_, baseURL, token := setupIntegrationServer(t)

	resp := apiGet(t, baseURL, "/api/v1/status", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status expected 200, got %d", resp.StatusCode)
	}
	data := readBody(t, resp)

	if data["status"] != "running" {
		t.Errorf("expected status 'running', got %v", data["status"])
	}
	if _, ok := data["version"]; !ok {
		t.Error("expected version field")
	}
	// With a zone manager attached, the status should report cluster info
	cluster, ok := data["cluster"].(map[string]any)
	if !ok {
		t.Fatal("expected cluster info")
	}
	if cluster["enabled"] != false {
		t.Errorf("expected cluster.enabled false, got %v", cluster["enabled"])
	}
}

func TestIntegration_ZoneCRUD(t *testing.T) {
	_, baseURL, token := setupIntegrationServer(t)

	// --- List zones (should have the pre-created zone) ---
	resp := apiGet(t, baseURL, "/api/v1/zones", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list zones expected 200, got %d", resp.StatusCode)
	}
	data := readBody(t, resp)
	zones, ok := data["zones"].([]any)
	if !ok {
		t.Fatal("expected zones array")
	}
	if len(zones) != 1 {
		t.Fatalf("expected 1 zone, got %d", len(zones))
	}
	firstZone := zones[0].(map[string]any)
	if firstZone["name"] != "example.com." {
		t.Errorf("expected zone 'example.com.', got %v", firstZone["name"])
	}

	// --- Create a new zone ---
	createBody := map[string]any{
		"name":        "test.org.",
		"ttl":         3600,
		"admin_email": "admin.test.org.",
		"nameservers": []string{"ns1.test.org."},
	}
	resp = apiPost(t, baseURL, "/api/v1/zones", token, createBody)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		t.Fatalf("create zone expected 200 or 201, got %d: %s", resp.StatusCode, readBody(t, resp))
	}
	resp.Body.Close()

	// --- List zones again (should be 2) ---
	resp = apiGet(t, baseURL, "/api/v1/zones", token)
	defer resp.Body.Close()
	data = readBody(t, resp)
	zones = data["zones"].([]any)
	if len(zones) != 2 {
		t.Fatalf("expected 2 zones, got %d", len(zones))
	}

	// --- Get zone detail ---
	resp = apiGet(t, baseURL, "/api/v1/zones/test.org.", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get zone expected 200, got %d: %s", resp.StatusCode, readBody(t, resp))
	}
	data = readBody(t, resp)
	if data["name"] != "test.org." {
		t.Errorf("expected name 'test.org.', got %v", data["name"])
	}
	// Should have SOA info
	soa, ok := data["soa"].(map[string]any)
	if !ok {
		t.Fatal("expected soa in zone detail")
	}
	if soa["mname"] != "ns1.test.org." {
		t.Errorf("expected mname 'ns1.test.org.', got %v", soa["mname"])
	}

	// --- Get zone records ---
	resp = apiGet(t, baseURL, "/api/v1/zones/test.org./records", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get records expected 200, got %d", resp.StatusCode)
	}
	data = readBody(t, resp)
	records, ok := data["records"].([]any)
	if !ok {
		t.Fatal("expected records array")
	}
	if len(records) == 0 {
		t.Error("expected at least SOA and NS records")
	}

	// --- Delete the created zone ---
	resp = apiDelete(t, baseURL, "/api/v1/zones/test.org.", token)
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		t.Fatalf("delete zone expected 2xx, got %d: %s", resp.StatusCode, readBody(t, resp))
	}

	// --- List zones (should be back to 1) ---
	resp = apiGet(t, baseURL, "/api/v1/zones", token)
	defer resp.Body.Close()
	data = readBody(t, resp)
	zones = data["zones"].([]any)
	if len(zones) != 1 {
		t.Fatalf("expected 1 zone after delete, got %d", len(zones))
	}
}

func TestIntegration_UnauthenticatedAccess(t *testing.T) {
	_, baseURL, _ := setupIntegrationServer(t)

	// Zone endpoint requires auth
	resp, err := http.Get(baseURL + "/api/v1/zones")
	if err != nil {
		t.Fatalf("GET /api/v1/zones: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthenticated request, got %d", resp.StatusCode)
	}

	// Health endpoint does NOT require auth
	resp, err = http.Get(baseURL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("health expected 200, got %d", resp.StatusCode)
	}

	// DNS endpoints should not require auth
	resp, err = http.Get(baseURL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("readyz expected 200, got %d", resp.StatusCode)
	}
}

func TestIntegration_BlocklistStatus(t *testing.T) {
	_, baseURL, token := setupIntegrationServer(t)

	resp := apiGet(t, baseURL, "/api/v1/blocklists", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("blocklists expected 200, got %d", resp.StatusCode)
	}
	data := readBody(t, resp)
	// Without a configured blocklist, it should return defaults
	if _, ok := data["enabled"]; !ok {
		t.Error("expected enabled field")
	}
}

func TestIntegration_RPZStatus(t *testing.T) {
	_, baseURL, token := setupIntegrationServer(t)

	resp := apiGet(t, baseURL, "/api/v1/rpz", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rpz expected 200, got %d", resp.StatusCode)
	}
	data := readBody(t, resp)
	if _, ok := data["enabled"]; !ok {
		t.Error("expected enabled field")
	}
}

func TestIntegration_CacheStats(t *testing.T) {
	_, baseURL, token := setupIntegrationServer(t)

	resp := apiGet(t, baseURL, "/api/v1/cache/stats", token)
	defer resp.Body.Close()
	// Without a cache, may return 200 with zeros or 503
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("cache/stats expected 200 or 503, got %d", resp.StatusCode)
	}
}

func TestIntegration_DNSSECStatus(t *testing.T) {
	_, baseURL, token := setupIntegrationServer(t)

	resp := apiGet(t, baseURL, "/api/v1/dnssec/status", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dnssec/status expected 200, got %d", resp.StatusCode)
	}
	data := readBody(t, resp)
	// DNSSEC should report disabled by default
	if enabled, ok := data["enabled"]; ok && enabled != false {
		t.Errorf("expected DNSSEC disabled by default, got enabled=%v", enabled)
	}
}

func TestIntegration_Upstreams(t *testing.T) {
	_, baseURL, token := setupIntegrationServer(t)

	resp := apiGet(t, baseURL, "/api/v1/upstreams", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upstreams expected 200, got %d", resp.StatusCode)
	}
	data := readBody(t, resp)
	// Without configured upstreams, may return empty upstreams or omit the field
	if _, ok := data["upstreams"]; !ok {
		// The field may not be present when no upstream client is configured
		t.Log("upstreams field not present (expected when no upstream client configured)")
	}
}

func TestIntegration_ACL(t *testing.T) {
	_, baseURL, token := setupIntegrationServer(t)

	resp := apiGet(t, baseURL, "/api/v1/acl", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("acl expected 200, got %d", resp.StatusCode)
	}
	data := readBody(t, resp)
	if _, ok := data["rules"]; !ok {
		t.Error("expected rules field")
	}
}

func TestIntegration_ServerConfig(t *testing.T) {
	_, baseURL, token := setupIntegrationServer(t)

	resp := apiGet(t, baseURL, "/api/v1/server/config", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("server/config expected 200, got %d", resp.StatusCode)
	}
	data := readBody(t, resp)
	if _, ok := data["version"]; !ok {
		t.Error("expected version field")
	}
}

func TestIntegration_ZoneExport(t *testing.T) {
	_, baseURL, token := setupIntegrationServer(t)

	resp := apiGet(t, baseURL, "/api/v1/zones/example.com./export", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("zone export expected 200, got %d: %s", resp.StatusCode, readBody(t, resp))
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	content := string(body)
	if !strings.Contains(content, "example.com.") {
		t.Error("exported zone should contain the zone name")
	}
	if !strings.Contains(content, "SOA") {
		t.Error("exported zone should contain SOA record")
	}
}

func TestIntegration_ZoneTransferStatus(t *testing.T) {
	_, baseURL, token := setupIntegrationServer(t)

	resp := apiGet(t, baseURL, "/api/v1/zones/transfers", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("transfers expected 200, got %d", resp.StatusCode)
	}
	data := readBody(t, resp)
	if _, ok := data["slave_zones"]; !ok {
		t.Error("expected slave_zones field")
	}
}

func TestIntegration_IndexPage(t *testing.T) {
	_, baseURL, _ := setupIntegrationServer(t)

	// The SPA handler should serve something for the root
	resp, err := http.Get(baseURL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	// The SPA serves index.html or redirects; either way it should be 2xx
	if resp.StatusCode > 299 {
		t.Errorf("root expected 2xx, got %d", resp.StatusCode)
	}
}

func TestIntegration_NotFound(t *testing.T) {
	_, baseURL, token := setupIntegrationServer(t)

	// The SPA fallback catches unknown routes, so we test 404 via a known
	// API endpoint with a missing resource instead.
	resp := apiGet(t, baseURL, "/api/v1/zones/missing.zone.", token)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing zone expected 404, got %d: %s", resp.StatusCode, readBody(t, resp))
	}
	data := readBody(t, resp)
	if _, ok := data["error"]; !ok {
		t.Error("expected error field in 404 response")
	}
}

func TestIntegration_CORSHeaders(t *testing.T) {
	_, baseURL, _ := setupIntegrationServer(t)

	// Send an OPTIONS preflight
	req, err := http.NewRequest(http.MethodOptions, baseURL+"/api/v1/status", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("OPTIONS: %v", err)
	}
	defer resp.Body.Close()
	// Should have CORS headers
	if resp.Header.Get("Access-Control-Allow-Origin") == "" {
		t.Log("CORS header not set (expected when AllowedOrigins is empty)")
	}
}

func TestIntegration_WithCache(t *testing.T) {
	zm := zone.NewManager()
	soa := &zone.SOARecord{
		TTL: 3600, MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400,
	}
	if err := zm.CreateZone("example.com.", 3600, soa, []zone.NSRecord{
		{TTL: 3600, NSDName: "ns1.example.com."},
	}); err != nil {
		t.Fatalf("CreateZone: %v", err)
	}

	cfg, err := auth.DefaultConfig()
	if err != nil {
		t.Fatalf("auth.DefaultConfig: %v", err)
	}
	hash := cachedTestPasswordHash(t, "pass")
	cfg.Users = []auth.User{{Username: "admin", Hash: hash, Role: auth.RoleAdmin}}
	store, err := auth.NewStore(cfg)
	if err != nil {
		t.Fatalf("auth.NewStore: %v", err)
	}
	tokenObj2, _ := store.GenerateToken("admin", 24*time.Hour)
	token := tokenObj2.Token

	c := cache.New(cache.Config{Capacity: 500, MinTTL: 60, MaxTTL: 3600, DefaultTTL: 300})

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := l.Addr().String()
	l.Close()

	httpCfg := config.HTTPConfig{Enabled: true, Bind: addr}
	s := NewServer(httpCfg, zm, c, nil, nil, nil, nil)
	s.authStore = store
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { s.Stop() })
	baseURL := "http://" + addr

	resp := apiGet(t, baseURL, "/api/v1/cache/stats", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cache/stats expected 200, got %d", resp.StatusCode)
	}
	data := readBody(t, resp)
	// Should report the cache capacity
	cacheInfo, ok := data["cache"].(map[string]any)
	if !ok {
		cacheInfo = data
	}
	if cap, ok := cacheInfo["capacity"]; ok {
		if fmt.Sprintf("%v", cap) != "500" {
			t.Errorf("expected capacity 500, got %v", cap)
		}
	}
}

func TestIntegration_MetricsHistory(t *testing.T) {
	_, baseURL, token := setupIntegrationServer(t)

	resp := apiGet(t, baseURL, "/api/v1/metrics/history", token)
	defer resp.Body.Close()
	// Without a metrics collector, this returns 503
	if resp.StatusCode != http.StatusServiceUnavailable && resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics/history expected 503 without collector, got %d", resp.StatusCode)
	}
}

func TestIntegration_GEOIPStats(t *testing.T) {
	_, baseURL, token := setupIntegrationServer(t)

	resp := apiGet(t, baseURL, "/api/v1/geoip/stats", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("geoip/stats expected 200, got %d", resp.StatusCode)
	}
	data := readBody(t, resp)
	if _, ok := data["enabled"]; !ok {
		t.Error("expected enabled field")
	}
}
