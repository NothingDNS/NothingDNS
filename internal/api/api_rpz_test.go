package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/rpz"
)

// ---------------------------------------------------------------------------
// Helpers specific to RPZ tests
// ---------------------------------------------------------------------------

// newRPZServer creates a Server with auth and an optional rpz.Engine.
// If engine is nil, rpzEngine is left unset.
func newRPZServer(t *testing.T, engine *rpz.Engine) *Server {
	t.Helper()
	store := newAuthStoreWithUser(t, "op", "secret123", auth.RoleOperator)
	s := NewServer(config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}, nil, nil, nil, nil, nil, nil)
	s.authStore = store
	s.rpzEngine = engine
	return s
}

// rpzAuthenticatedRequest creates an httptest.Request with an operator user in context.
func rpzAuthenticatedRequest(method, target string, body []byte) *http.Request {
	var br *bytes.Reader
	if body != nil {
		br = bytes.NewReader(body)
		req := httptest.NewRequest(method, target, br)
		ctx := WithUser(req.Context(), &auth.User{Username: "op", Role: auth.RoleOperator})
		return req.WithContext(ctx)
	}
	req := httptest.NewRequest(method, target, nil)
	ctx := WithUser(req.Context(), &auth.User{Username: "op", Role: auth.RoleOperator})
	return req.WithContext(ctx)
}

// newEnabledEngine returns a fresh rpz.Engine with Enabled=true and an empty policy map.
func newEnabledEngine() *rpz.Engine {
	return rpz.NewEngine(rpz.Config{
		Policies: map[string]int{},
		Enabled:  true,
	})
}

// ---------------------------------------------------------------------------
// handleRPZ tests
// ---------------------------------------------------------------------------

func TestHandleRPZ_GetStats(t *testing.T) {
	engine := newEnabledEngine()
	s := newRPZServer(t, engine)

	req := rpzAuthenticatedRequest(http.MethodGet, "/api/v1/rpz", nil)
	rec := httptest.NewRecorder()
	s.handleRPZ(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp RPZStatsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Enabled {
		t.Error("expected enabled=true")
	}
}

func TestHandleRPZ_NilEngine(t *testing.T) {
	s := newRPZServer(t, nil)

	req := rpzAuthenticatedRequest(http.MethodGet, "/api/v1/rpz", nil)
	rec := httptest.NewRecorder()
	s.handleRPZ(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp RPZStatsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Enabled {
		t.Error("expected enabled=false for nil engine")
	}
	if resp.TotalRules != 0 {
		t.Errorf("expected 0 total rules, got %d", resp.TotalRules)
	}
}

func TestHandleRPZ_WrongMethod(t *testing.T) {
	engine := newEnabledEngine()
	s := newRPZServer(t, engine)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/rpz", nil)
	rec := httptest.NewRecorder()
	s.handleRPZ(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHandleRPZ_NoAuth(t *testing.T) {
	// Server without authStore -> requireOperator returns 503.
	s := NewServer(config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}, nil, nil, nil, nil, nil, nil)
	s.rpzEngine = newEnabledEngine()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rpz", nil)
	rec := httptest.NewRecorder()
	s.handleRPZ(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// handleRPZRules tests
// ---------------------------------------------------------------------------

func TestHandleRPZRules_GetRules(t *testing.T) {
	engine := newEnabledEngine()
	s := newRPZServer(t, engine)

	req := rpzAuthenticatedRequest(http.MethodGet, "/api/v1/rpz/rules", nil)
	rec := httptest.NewRecorder()
	s.handleRPZRules(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp RPZRulesResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Rules) != 0 {
		t.Errorf("expected empty rules, got %d", len(resp.Rules))
	}
}

func TestHandleRPZRules_GetRulesWithData(t *testing.T) {
	engine := newEnabledEngine()
	engine.AddQNAMERule("blocked.example.com.", rpz.ActionNXDOMAIN, "")
	s := newRPZServer(t, engine)

	req := rpzAuthenticatedRequest(http.MethodGet, "/api/v1/rpz/rules", nil)
	rec := httptest.NewRecorder()
	s.handleRPZRules(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp RPZRulesResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(resp.Rules))
	}
	if resp.Rules[0].Pattern != "blocked.example.com." {
		t.Errorf("expected pattern 'blocked.example.com.', got %q", resp.Rules[0].Pattern)
	}
	if resp.Rules[0].Action != "NXDOMAIN" {
		t.Errorf("expected action 'NXDOMAIN', got %q", resp.Rules[0].Action)
	}
}

func TestHandleRPZRules_AddRule(t *testing.T) {
	engine := newEnabledEngine()
	s := newRPZServer(t, engine)

	body, _ := json.Marshal(RPZAddRuleRequest{
		Pattern: "malware.example.com.",
		Action:  "NODATA",
	})
	req := rpzAuthenticatedRequest(http.MethodPost, "/api/v1/rpz/rules", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleRPZRules(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp MessageResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Message != "Rule added" {
		t.Errorf("expected 'Rule added', got %q", resp.Message)
	}

	// Verify rule was added
	rules := engine.ListQNAMERules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule in engine, got %d", len(rules))
	}
	if rules[0].Pattern != "malware.example.com." {
		t.Errorf("expected pattern 'malware.example.com.', got %q", rules[0].Pattern)
	}
}

func TestHandleRPZRules_AddRuleNoPattern(t *testing.T) {
	engine := newEnabledEngine()
	s := newRPZServer(t, engine)

	body, _ := json.Marshal(RPZAddRuleRequest{
		Action: "NXDOMAIN",
	})
	req := rpzAuthenticatedRequest(http.MethodPost, "/api/v1/rpz/rules", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleRPZRules(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleRPZRules_AddRuleInvalidBody(t *testing.T) {
	engine := newEnabledEngine()
	s := newRPZServer(t, engine)

	req := rpzAuthenticatedRequest(http.MethodPost, "/api/v1/rpz/rules", []byte("not-json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleRPZRules(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleRPZRules_DeleteRule(t *testing.T) {
	engine := newEnabledEngine()
	engine.AddQNAMERule("rm-me.example.com.", rpz.ActionNXDOMAIN, "")
	s := newRPZServer(t, engine)

	req := rpzAuthenticatedRequest(http.MethodDelete, "/api/v1/rpz/rules?pattern=rm-me.example.com.", nil)
	rec := httptest.NewRecorder()
	s.handleRPZRules(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp MessageResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Message != "Rule removed" {
		t.Errorf("expected 'Rule removed', got %q", resp.Message)
	}

	// Verify rule was removed
	rules := engine.ListQNAMERules()
	if len(rules) != 0 {
		t.Errorf("expected 0 rules after delete, got %d", len(rules))
	}
}

func TestHandleRPZRules_DeleteRuleNoPattern(t *testing.T) {
	engine := newEnabledEngine()
	s := newRPZServer(t, engine)

	req := rpzAuthenticatedRequest(http.MethodDelete, "/api/v1/rpz/rules", nil)
	rec := httptest.NewRecorder()
	s.handleRPZRules(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleRPZRules_NilEngine(t *testing.T) {
	s := newRPZServer(t, nil)

	req := rpzAuthenticatedRequest(http.MethodGet, "/api/v1/rpz/rules", nil)
	rec := httptest.NewRecorder()
	s.handleRPZRules(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp RPZRulesResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Rules == nil {
		t.Error("expected non-nil rules slice for nil engine")
	}
	if len(resp.Rules) != 0 {
		t.Errorf("expected empty rules, got %d", len(resp.Rules))
	}
}

func TestHandleRPZRules_WrongMethod(t *testing.T) {
	engine := newEnabledEngine()
	s := newRPZServer(t, engine)

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/rpz/rules", nil)
	rec := httptest.NewRecorder()
	s.handleRPZRules(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHandleRPZRules_NoAuth(t *testing.T) {
	s := NewServer(config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}, nil, nil, nil, nil, nil, nil)
	s.rpzEngine = newEnabledEngine()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rpz/rules", nil)
	rec := httptest.NewRecorder()
	s.handleRPZRules(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// handleRPZActions tests
// ---------------------------------------------------------------------------

func TestHandleRPZActions_Toggle(t *testing.T) {
	engine := newEnabledEngine()
	s := newRPZServer(t, engine)

	if !engine.IsEnabled() {
		t.Fatal("engine should start enabled")
	}

	req := rpzAuthenticatedRequest(http.MethodPost, "/api/v1/rpz/toggle", nil)
	rec := httptest.NewRecorder()
	s.handleRPZActions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp MessageResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Message != "RPZ disabled" {
		t.Errorf("expected 'RPZ disabled', got %q", resp.Message)
	}
	if engine.IsEnabled() {
		t.Error("engine should be disabled after toggle")
	}

	// Toggle back to enabled
	req2 := rpzAuthenticatedRequest(http.MethodPost, "/api/v1/rpz/toggle", nil)
	rec2 := httptest.NewRecorder()
	s.handleRPZActions(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 on second toggle, got %d", rec2.Code)
	}
	var resp2 MessageResponse
	if err := json.NewDecoder(rec2.Body).Decode(&resp2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp2.Message != "RPZ enabled" {
		t.Errorf("expected 'RPZ enabled', got %q", resp2.Message)
	}
	if !engine.IsEnabled() {
		t.Error("engine should be enabled after second toggle")
	}
}

func TestHandleRPZActions_ToggleWrongMethod(t *testing.T) {
	engine := newEnabledEngine()
	s := newRPZServer(t, engine)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rpz/toggle", nil)
	rec := httptest.NewRecorder()
	s.handleRPZActions(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHandleRPZActions_NilEngine(t *testing.T) {
	// No rpzEngine set on server.
	s := NewServer(config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/rpz/toggle", nil)
	rec := httptest.NewRecorder()
	s.handleRPZActions(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestHandleRPZActions_NotFound(t *testing.T) {
	engine := newEnabledEngine()
	s := newRPZServer(t, engine)

	req := rpzAuthenticatedRequest(http.MethodPost, "/api/v1/rpz/nonexistent", nil)
	rec := httptest.NewRecorder()
	s.handleRPZActions(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestHandleRPZActions_NoAuth(t *testing.T) {
	engine := newEnabledEngine()
	// Server with engine but no authStore.
	s := NewServer(config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}, nil, nil, nil, nil, nil, nil)
	s.rpzEngine = engine

	req := httptest.NewRequest(http.MethodPost, "/api/v1/rpz/toggle", nil)
	rec := httptest.NewRecorder()
	s.handleRPZActions(rec, req)

	// requireOperator should return 503 because authStore is nil.
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Edge case: AddRule with override_data
// ---------------------------------------------------------------------------

func TestHandleRPZRules_AddRuleWithOverrideData(t *testing.T) {
	engine := newEnabledEngine()
	s := newRPZServer(t, engine)

	body, _ := json.Marshal(RPZAddRuleRequest{
		Pattern:      "redirect.example.com.",
		Action:       "CNAME",
		OverrideData: "safe.example.com.",
	})
	req := rpzAuthenticatedRequest(http.MethodPost, "/api/v1/rpz/rules", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleRPZRules(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	rules := engine.ListQNAMERules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].OverrideData != "safe.example.com." {
		t.Errorf("expected override data 'safe.example.com.', got %q", rules[0].OverrideData)
	}
}

// ---------------------------------------------------------------------------
// Edge case: handleRPZStats with a non-zero LastReload
// ---------------------------------------------------------------------------

func TestHandleRPZ_StatsWithLastReload(t *testing.T) {
	engine := newEnabledEngine()
	// Trigger a Load so LastReload gets set. Load with no files still updates timestamp.
	_ = engine.Load()
	s := newRPZServer(t, engine)

	req := rpzAuthenticatedRequest(http.MethodGet, "/api/v1/rpz", nil)
	rec := httptest.NewRecorder()
	s.handleRPZ(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp RPZStatsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.LastReload == "" {
		t.Error("expected non-empty last_reload after Load()")
	}
}

// ---------------------------------------------------------------------------
// Edge case: viewer role (not operator) should be denied
// ---------------------------------------------------------------------------

func TestHandleRPZ_ViewerDenied(t *testing.T) {
	engine := newEnabledEngine()
	store := newAuthStoreWithUser(t, "viewer", "secret123", auth.RoleViewer)
	s := NewServer(config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}, nil, nil, nil, nil, nil, nil)
	s.authStore = store
	s.rpzEngine = engine

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rpz", nil)
	ctx := context.WithValue(req.Context(), userContextKey, &auth.User{Username: "viewer", Role: auth.RoleViewer})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	s.handleRPZ(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for viewer, got %d", rec.Code)
	}
}
