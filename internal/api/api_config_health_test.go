package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/filter"
)

// --- handleConfigReload tests ---

func TestHandleConfigReload_Success(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	s.reloadFunc = func() error { return nil }

	adminUser, _ := store.GetUser("admin")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/reload", nil)
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleConfigReload(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp MessageResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Message != "Configuration reloaded" {
		t.Errorf("unexpected message: %s", resp.Message)
	}
}

func TestHandleConfigReload_WrongMethod(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/config/reload", nil)
	rec := httptest.NewRecorder()

	s.handleConfigReload(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHandleConfigReload_NoReloadFunc(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	// reloadFunc is nil

	adminUser, _ := store.GetUser("admin")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/reload", nil)
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleConfigReload(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestHandleConfigReload_ReloadError(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	s.reloadFunc = func() error { return context.DeadlineExceeded }

	adminUser, _ := store.GetUser("admin")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/reload", nil)
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleConfigReload(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestHandleConfigReload_NoAuth(t *testing.T) {
	s := NewServer(config.HTTPConfig{Enabled: true}, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/reload", nil)
	rec := httptest.NewRecorder()

	s.handleConfigReload(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

// --- handleConfigGet tests ---

func TestHandleConfigGet_Success(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	s.configGetter = func() *config.Config {
		return &config.Config{
			Server: config.ServerConfig{
				HTTP: config.HTTPConfig{Enabled: true, AuthToken: "super-secret"},
			},
		}
	}

	adminUser, _ := store.GetUser("admin")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleConfigGet(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify sensitive fields are redacted
	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)
	server := result["Server"].(map[string]any)
	httpCfg := server["HTTP"].(map[string]any)
	if httpCfg["AuthToken"] != "" {
		t.Error("AuthToken should be redacted")
	}
}

func TestHandleConfigGet_WrongMethod(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/config", nil)
	rec := httptest.NewRecorder()

	s.handleConfigGet(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHandleConfigGet_NoConfigGetter(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	// configGetter is nil

	adminUser, _ := store.GetUser("admin")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleConfigGet(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestHandleConfigGet_NilConfig(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	s.configGetter = func() *config.Config { return nil }

	adminUser, _ := store.GetUser("admin")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleConfigGet(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestHandleConfigGet_DNSSECKeyRedacted(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	s.configGetter = func() *config.Config {
		return &config.Config{
			DNSSEC: config.DNSSECConfig{
				Signing: config.SigningConfig{
					Keys: []config.KeyConfig{
						{PrivateKey: "super-private-key", Algorithm: 15},
					},
				},
			},
		}
	}

	adminUser, _ := store.GetUser("admin")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleConfigGet(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)
	dnssec := result["DNSSEC"].(map[string]any)
	signing := dnssec["Signing"].(map[string]any)
	keys := signing["Keys"].([]any)
	key0 := keys[0].(map[string]any)
	if key0["PrivateKey"] != "" {
		t.Error("DNSSEC PrivateKey should be redacted")
	}
}

func TestHandleConfigGet_ClusterKeyRedacted(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	s.configGetter = func() *config.Config {
		return &config.Config{
			Cluster: config.ClusterConfig{
				EncryptionKey: "cluster-encryption-secret",
			},
		}
	}

	adminUser, _ := store.GetUser("admin")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleConfigGet(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)
	cluster := result["Cluster"].(map[string]any)
	if cluster["EncryptionKey"] != "" {
		t.Error("Cluster EncryptionKey should be redacted")
	}
}

// --- handleConfigLogging tests ---

func TestHandleConfigLogging_Success(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	adminUser, _ := store.GetUser("admin")
	body, _ := json.Marshal(map[string]string{"level": "debug"})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/config/logging", bytes.NewReader(body))
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleConfigLogging(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleConfigLogging_WrongMethod(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/config/logging", nil)
	rec := httptest.NewRecorder()

	s.handleConfigLogging(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHandleConfigLogging_InvalidJSON(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	adminUser, _ := store.GetUser("admin")
	req := httptest.NewRequest(http.MethodPut, "/api/v1/config/logging", bytes.NewReader([]byte("not json")))
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleConfigLogging(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleConfigLogging_InvalidLevel(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	adminUser, _ := store.GetUser("admin")
	body, _ := json.Marshal(map[string]string{"level": "nonsense"})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/config/logging", bytes.NewReader(body))
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleConfigLogging(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleConfigLogging_AllLevels(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	adminUser, _ := store.GetUser("admin")

	levels := []string{"debug", "info", "warn", "warning", "error", "fatal"}
	for _, level := range levels {
		body, _ := json.Marshal(map[string]string{"level": level})
		req := httptest.NewRequest(http.MethodPut, "/api/v1/config/logging", bytes.NewReader(body))
		ctx := WithUser(req.Context(), adminUser)
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()

		s.handleConfigLogging(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("level %q: expected 200, got %d", level, rec.Code)
		}
	}
}

// --- handleConfigRRL tests ---

func TestHandleConfigRRL_Success(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	s.rateLimiter = filter.NewRateLimiter(config.RRLConfig{Enabled: true, Rate: 5, Burst: 10})

	adminUser, _ := store.GetUser("admin")
	body, _ := json.Marshal(map[string]any{"enabled": true, "rate": 10.0, "burst": 20})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/config/rrl", bytes.NewReader(body))
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleConfigRRL(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleConfigRRL_WrongMethod(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	s.rateLimiter = filter.NewRateLimiter(config.RRLConfig{Enabled: true})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/config/rrl", nil)
	rec := httptest.NewRecorder()

	s.handleConfigRRL(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHandleConfigRRL_NoRateLimiter(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	// rateLimiter is nil

	adminUser, _ := store.GetUser("admin")
	req := httptest.NewRequest(http.MethodPut, "/api/v1/config/rrl", nil)
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleConfigRRL(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestHandleConfigRRL_InvalidJSON(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	s.rateLimiter = filter.NewRateLimiter(config.RRLConfig{Enabled: true})

	adminUser, _ := store.GetUser("admin")
	req := httptest.NewRequest(http.MethodPut, "/api/v1/config/rrl", bytes.NewReader([]byte("bad")))
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleConfigRRL(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

// --- handleConfigCache tests ---

func TestHandleConfigCache_Success(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	s.cache = cache.New(cache.Config{Capacity: 1000})

	adminUser, _ := store.GetUser("admin")
	body, _ := json.Marshal(map[string]any{
		"enabled":            true,
		"size":               5000,
		"default_ttl":        300,
		"max_ttl":            3600,
		"min_ttl":            60,
		"negative_ttl":       60,
		"prefetch":           true,
		"prefetch_threshold": 10,
		"serve_stale":        true,
		"stale_grace_secs":   300,
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/config/cache", bytes.NewReader(body))
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleConfigCache(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleConfigCache_WrongMethod(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	s.cache = cache.New(cache.Config{Capacity: 1000})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/config/cache", nil)
	rec := httptest.NewRecorder()

	s.handleConfigCache(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHandleConfigCache_NoCache(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	// cache is nil

	adminUser, _ := store.GetUser("admin")
	req := httptest.NewRequest(http.MethodPut, "/api/v1/config/cache", nil)
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleConfigCache(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestHandleConfigCache_InvalidJSON(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	s.cache = cache.New(cache.Config{Capacity: 1000})

	adminUser, _ := store.GetUser("admin")
	req := httptest.NewRequest(http.MethodPut, "/api/v1/config/cache", bytes.NewReader([]byte("not-json")))
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleConfigCache(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

// --- handleHealth tests ---

func TestHandleHealth_Success(t *testing.T) {
	s := NewServer(config.HTTPConfig{Enabled: true}, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	s.handleHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var resp HealthResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Status != "healthy" {
		t.Errorf("expected 'healthy', got %q", resp.Status)
	}
}

// --- handleReadiness tests ---

func TestHandleReadiness_Ready(t *testing.T) {
	s := NewServer(config.HTTPConfig{Enabled: true}, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	s.handleReadiness(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var resp HealthResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Status != "ready" {
		t.Errorf("expected 'ready', got %q", resp.Status)
	}
}

// --- handleLiveness tests ---

func TestHandleLiveness_Alive(t *testing.T) {
	s := NewServer(config.HTTPConfig{Enabled: true}, nil, nil, nil, nil, nil, nil)
	s.SetGoroutineBaseline()

	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	rec := httptest.NewRecorder()

	s.handleLiveness(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var resp HealthResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Status != "alive" {
		t.Errorf("expected 'alive', got %q", resp.Status)
	}
}

// --- handleServerConfig tests ---

func TestHandleServerConfig_Success(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	s.configGetter = func() *config.Config {
		return &config.Config{
			DNS64: config.DNS64Config{Enabled: true, Prefix: "64:ff9b::", PrefixLen: 96},
			Cookie: config.CookieConfig{
				Enabled:        true,
				SecretRotation: "1h",
			},
		}
	}

	adminUser, _ := store.GetUser("admin")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/config", nil)
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleServerConfig(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp ServerConfigResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if !resp.DNS64.Enabled {
		t.Error("expected DNS64 enabled")
	}
	if !resp.Cookie.Enabled {
		t.Error("expected Cookie enabled")
	}
}

func TestHandleServerConfig_WrongMethod(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/server/config", nil)
	rec := httptest.NewRecorder()

	s.handleServerConfig(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHandleServerConfig_NoConfigGetter(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	// configGetter is nil

	adminUser, _ := store.GetUser("admin")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/config", nil)
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleServerConfig(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var resp ServerConfigResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.DNS64.Enabled {
		t.Error("expected DNS64 disabled when no configGetter")
	}
}

// --- handleDashboardStats tests ---

func TestHandleDashboardStats_NoCacheAndZone(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	// cache and zoneManager are nil

	adminUser, _ := store.GetUser("admin")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/stats", nil)
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleDashboardStats(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestHandleDashboardStats_NoAuth(t *testing.T) {
	s := NewServer(config.HTTPConfig{Enabled: true}, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/stats", nil)
	rec := httptest.NewRecorder()

	s.handleDashboardStats(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

// --- handleMetricsHistory tests ---

func TestHandleMetricsHistory_NoMetrics(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	// metrics is nil

	adminUser, _ := store.GetUser("admin")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/history", nil)
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleMetricsHistory(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestHandleMetricsHistory_WrongMethod(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/metrics/history", nil)
	rec := httptest.NewRecorder()

	s.handleMetricsHistory(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

// --- handleQueryLog tests ---

func TestHandleQueryLog_NoDashboard(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	// dashboardServer is nil

	adminUser, _ := store.GetUser("admin")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/query-log", nil)
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleQueryLog(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestHandleQueryLog_WrongMethod(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/query-log", nil)
	rec := httptest.NewRecorder()

	s.handleQueryLog(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

// --- handleTopDomains tests ---

func TestHandleTopDomains_NoDashboard(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	// dashboardServer is nil

	adminUser, _ := store.GetUser("admin")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/top-domains", nil)
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleTopDomains(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestHandleTopDomains_WrongMethod(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/top-domains", nil)
	rec := httptest.NewRecorder()

	s.handleTopDomains(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

// --- handleDashboardQueries tests ---

func TestHandleDashboardQueries_NoDashboard(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	// dashboardServer is nil

	adminUser, _ := store.GetUser("admin")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/queries", nil)
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleDashboardQueries(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestHandleDashboardQueries_WrongMethod(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/dashboard/queries", nil)
	rec := httptest.NewRecorder()

	s.handleDashboardQueries(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

// --- handleDashboardZones tests ---

func TestHandleDashboardZones_NoDashboard(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	// dashboardServer is nil

	adminUser, _ := store.GetUser("admin")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/zones", nil)
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleDashboardZones(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestHandleDashboardZones_WrongMethod(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/dashboard/zones", nil)
	rec := httptest.NewRecorder()

	s.handleDashboardZones(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

// --- handleODoHConfig tests ---

func TestHandleODoHConfig_NoTarget(t *testing.T) {
	s := NewServer(config.HTTPConfig{Enabled: true}, nil, nil, nil, nil, nil, nil)
	// odohTarget is nil

	req := httptest.NewRequest(http.MethodGet, "/api/v1/odoh/config", nil)
	rec := httptest.NewRecorder()

	s.handleODoHConfig(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}
