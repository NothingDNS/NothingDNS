package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/filter"
	"github.com/nothingdns/nothingdns/internal/upstream"
)

// newAuthenticatedServer creates a Server with auth store configured for the
// given role, returning both the server and the authenticated user.
func newAuthenticatedServer(t *testing.T, username string, role auth.Role) (*Server, *auth.User) {
	t.Helper()
	store := newAuthStoreWithUser(t, username, "testpass123", role)
	s := newServerWithAuth(store)
	user, err := store.GetUser(username)
	if err != nil {
		t.Fatalf("GetUser(%q): %v", username, err)
	}
	return s, user
}

// newAuthenticatedContext returns a context with the given user injected.
func newAuthenticatedContext(user *auth.User) context.Context {
	return WithUser(context.Background(), user)
}

// ---------------------------------------------------------------------------
// handleACL tests
// ---------------------------------------------------------------------------

// TestHandleACL_GetNoChecker verifies that GET with nil aclChecker returns
// an empty rules array.
func TestHandleACL_GetNoChecker(t *testing.T) {
	s, user := newAuthenticatedServer(t, "admin", auth.RoleAdmin)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/acl", nil)
	req = req.WithContext(newAuthenticatedContext(user))
	rec := httptest.NewRecorder()

	s.handleACL(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp ACLResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Rules) != 0 {
		t.Errorf("expected empty rules, got %d", len(resp.Rules))
	}
}

// TestHandleACL_GetWithRules verifies that GET returns the rules from a
// configured ACLChecker.
func TestHandleACL_GetWithRules(t *testing.T) {
	s, user := newAuthenticatedServer(t, "admin", auth.RoleAdmin)

	rules := []config.ACLRule{
		{
			Name:     "allow-lan",
			Networks: []string{"192.168.0.0/16"},
			Action:   "allow",
			Types:    []string{"A", "AAAA"},
		},
	}
	checker, err := filter.NewACLChecker(rules)
	if err != nil {
		t.Fatalf("NewACLChecker: %v", err)
	}
	s.aclChecker = checker

	req := httptest.NewRequest(http.MethodGet, "/api/v1/acl", nil)
	req = req.WithContext(newAuthenticatedContext(user))
	rec := httptest.NewRecorder()

	s.handleACL(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp ACLResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(resp.Rules))
	}
	if resp.Rules[0].Name != "allow-lan" {
		t.Errorf("expected rule name 'allow-lan', got %q", resp.Rules[0].Name)
	}
	if resp.Rules[0].Action != "allow" {
		t.Errorf("expected action 'allow', got %q", resp.Rules[0].Action)
	}
}

// TestHandleACL_PutUpdate verifies that PUT updates the ACL rules.
func TestHandleACL_PutUpdate(t *testing.T) {
	s, user := newAuthenticatedServer(t, "admin", auth.RoleAdmin)

	// Start with one rule
	initialRules := []config.ACLRule{
		{Name: "deny-bad", Networks: []string{"10.0.0.0/8"}, Action: "deny"},
	}
	checker, err := filter.NewACLChecker(initialRules)
	if err != nil {
		t.Fatalf("NewACLChecker: %v", err)
	}
	s.aclChecker = checker

	// Update to a different set of rules
	body := `{"rules":[{"name":"allow-all","networks":["0.0.0.0/0"],"action":"allow"}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/acl", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAuthenticatedContext(user))
	rec := httptest.NewRecorder()

	s.handleACL(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var msgResp MessageResponse
	if err := json.NewDecoder(rec.Body).Decode(&msgResp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if msgResp.Message != "ACL rules updated" {
		t.Errorf("expected message 'ACL rules updated', got %q", msgResp.Message)
	}

	// Verify the rules were actually updated
	rules := checker.GetRules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule after update, got %d", len(rules))
	}
	if rules[0].Name != "allow-all" {
		t.Errorf("expected rule name 'allow-all', got %q", rules[0].Name)
	}
}

// TestHandleACL_PutInvalidBody verifies that PUT with invalid JSON returns 400.
func TestHandleACL_PutInvalidBody(t *testing.T) {
	s, user := newAuthenticatedServer(t, "admin", auth.RoleAdmin)

	checker, err := filter.NewACLChecker([]config.ACLRule{
		{Name: "test", Networks: []string{"192.168.0.0/16"}, Action: "allow"},
	})
	if err != nil {
		t.Fatalf("NewACLChecker: %v", err)
	}
	s.aclChecker = checker

	req := httptest.NewRequest(http.MethodPut, "/api/v1/acl", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAuthenticatedContext(user))
	rec := httptest.NewRecorder()

	s.handleACL(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

// TestHandleACL_PutInvalidNetwork verifies that PUT with an invalid CIDR returns 400.
func TestHandleACL_PutInvalidNetwork(t *testing.T) {
	s, user := newAuthenticatedServer(t, "admin", auth.RoleAdmin)

	checker, err := filter.NewACLChecker([]config.ACLRule{
		{Name: "test", Networks: []string{"192.168.0.0/16"}, Action: "allow"},
	})
	if err != nil {
		t.Fatalf("NewACLChecker: %v", err)
	}
	s.aclChecker = checker

	body := `{"rules":[{"name":"bad-rule","networks":["not-a-cidr"],"action":"allow"}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/acl", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAuthenticatedContext(user))
	rec := httptest.NewRecorder()

	s.handleACL(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

// TestHandleACL_WrongMethod verifies that unsupported methods return 405.
func TestHandleACL_WrongMethod(t *testing.T) {
	s, user := newAuthenticatedServer(t, "admin", auth.RoleAdmin)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/acl", nil)
	req = req.WithContext(newAuthenticatedContext(user))
	rec := httptest.NewRecorder()

	s.handleACL(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

// TestHandleACL_NoAuth verifies that requests without an auth store return 503.
func TestHandleACL_NoAuth(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	s := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/acl", nil)
	rec := httptest.NewRecorder()

	s.handleACL(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

// TestHandleACL_PutEmptyRules verifies that PUT with an empty rules array succeeds.
func TestHandleACL_PutEmptyRules(t *testing.T) {
	s, user := newAuthenticatedServer(t, "admin", auth.RoleAdmin)

	// Start with a rule, then update to empty set
	checker, err := filter.NewACLChecker([]config.ACLRule{
		{Name: "old-rule", Networks: []string{"10.0.0.0/8"}, Action: "deny"},
	})
	if err != nil {
		t.Fatalf("NewACLChecker: %v", err)
	}
	s.aclChecker = checker

	body := `{"rules":[]}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/acl", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAuthenticatedContext(user))
	rec := httptest.NewRecorder()

	s.handleACL(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify the rules were cleared
	rules := checker.GetRules()
	if len(rules) != 0 {
		t.Errorf("expected 0 rules after clearing, got %d", len(rules))
	}
}

// ---------------------------------------------------------------------------
// handleUpstreams tests
// ---------------------------------------------------------------------------

// TestHandleUpstreams_GetNoUpstreams verifies that GET with nil upstreams
// returns an empty array.
func TestHandleUpstreams_GetNoUpstreams(t *testing.T) {
	s, user := newAuthenticatedServer(t, "admin", auth.RoleAdmin)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/upstreams", nil)
	req = req.WithContext(newAuthenticatedContext(user))
	rec := httptest.NewRecorder()

	s.handleUpstreams(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp UpstreamsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Upstreams) != 0 {
		t.Errorf("expected 0 upstreams, got %d", len(resp.Upstreams))
	}
}

// TestHandleUpstreams_GetWithUpstreamClient verifies that GET with an
// upstream.Client shows the direct-upstream status entry.
func TestHandleUpstreams_GetWithUpstreamClient(t *testing.T) {
	s, user := newAuthenticatedServer(t, "admin", auth.RoleAdmin)

	client, err := upstream.NewClient(upstream.Config{
		Servers:  []string{"8.8.8.8:53"},
		Strategy: "random",
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	s.upstreamClient = client

	req := httptest.NewRequest(http.MethodGet, "/api/v1/upstreams", nil)
	req = req.WithContext(newAuthenticatedContext(user))
	rec := httptest.NewRecorder()

	s.handleUpstreams(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp UpstreamsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Upstreams) < 1 {
		t.Fatalf("expected at least 1 upstream entry, got %d", len(resp.Upstreams))
	}

	// Find the direct-upstream entry
	found := false
	for _, u := range resp.Upstreams {
		if u.Address == "direct-upstream" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'direct-upstream' entry in response")
	}
}

// TestHandleUpstreams_PutAddServer verifies that PUT with action "add"
// adds a server to the upstream client.
func TestHandleUpstreams_PutAddServer(t *testing.T) {
	s, user := newAuthenticatedServer(t, "admin", auth.RoleAdmin)

	client, err := upstream.NewClient(upstream.Config{
		Servers:  []string{"8.8.8.8:53"},
		Strategy: "random",
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	s.upstreamClient = client

	body := `{"action":"add","server":"1.1.1.1:53"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/upstreams", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAuthenticatedContext(user))
	rec := httptest.NewRecorder()

	s.handleUpstreams(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var msgResp MessageResponse
	if err := json.NewDecoder(rec.Body).Decode(&msgResp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if msgResp.Message != "Server added: 1.1.1.1:53" {
		t.Errorf("expected 'Server added: 1.1.1.1:53', got %q", msgResp.Message)
	}
}

// TestHandleUpstreams_PutRemoveServer verifies that PUT with action "remove"
// removes a server from the upstream client.
func TestHandleUpstreams_PutRemoveServer(t *testing.T) {
	s, user := newAuthenticatedServer(t, "admin", auth.RoleAdmin)

	client, err := upstream.NewClient(upstream.Config{
		Servers:  []string{"8.8.8.8:53", "8.8.4.4:53"},
		Strategy: "random",
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	s.upstreamClient = client

	body := `{"action":"remove","server":"8.8.4.4:53"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/upstreams", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAuthenticatedContext(user))
	rec := httptest.NewRecorder()

	s.handleUpstreams(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var msgResp MessageResponse
	if err := json.NewDecoder(rec.Body).Decode(&msgResp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if msgResp.Message != "Server removed: 8.8.4.4:53" {
		t.Errorf("expected 'Server removed: 8.8.4.4:53', got %q", msgResp.Message)
	}
}

// TestHandleUpstreams_PutInvalidAction verifies that PUT with an unknown
// action returns 400.
func TestHandleUpstreams_PutInvalidAction(t *testing.T) {
	s, user := newAuthenticatedServer(t, "admin", auth.RoleAdmin)

	client, err := upstream.NewClient(upstream.Config{
		Servers:  []string{"8.8.8.8:53"},
		Strategy: "random",
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	s.upstreamClient = client

	body := `{"action":"bounce","server":"1.1.1.1:53"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/upstreams", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAuthenticatedContext(user))
	rec := httptest.NewRecorder()

	s.handleUpstreams(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

// TestHandleUpstreams_PutNoServer verifies that PUT with an empty server
// address returns 400.
func TestHandleUpstreams_PutNoServer(t *testing.T) {
	s, user := newAuthenticatedServer(t, "admin", auth.RoleAdmin)

	client, err := upstream.NewClient(upstream.Config{
		Servers:  []string{"8.8.8.8:53"},
		Strategy: "random",
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	s.upstreamClient = client

	body := `{"action":"add","server":""}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/upstreams", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAuthenticatedContext(user))
	rec := httptest.NewRecorder()

	s.handleUpstreams(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

// TestHandleUpstreams_PutNoUpstreamClient verifies that PUT without an
// upstream client configured returns 503.
func TestHandleUpstreams_PutNoUpstreamClient(t *testing.T) {
	s, user := newAuthenticatedServer(t, "admin", auth.RoleAdmin)

	body := `{"action":"add","server":"1.1.1.1:53"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/upstreams", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAuthenticatedContext(user))
	rec := httptest.NewRecorder()

	s.handleUpstreams(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

// TestHandleUpstreams_PutInvalidBody verifies that PUT with invalid JSON
// returns 400.
func TestHandleUpstreams_PutInvalidBody(t *testing.T) {
	s, user := newAuthenticatedServer(t, "admin", auth.RoleAdmin)

	client, err := upstream.NewClient(upstream.Config{
		Servers:  []string{"8.8.8.8:53"},
		Strategy: "random",
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	s.upstreamClient = client

	req := httptest.NewRequest(http.MethodPut, "/api/v1/upstreams", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAuthenticatedContext(user))
	rec := httptest.NewRecorder()

	s.handleUpstreams(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

// TestHandleUpstreams_WrongMethod verifies that unsupported methods return 405.
func TestHandleUpstreams_WrongMethod(t *testing.T) {
	s, user := newAuthenticatedServer(t, "admin", auth.RoleAdmin)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/upstreams", nil)
	req = req.WithContext(newAuthenticatedContext(user))
	rec := httptest.NewRecorder()

	s.handleUpstreams(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

// TestHandleUpstreams_NoAuth verifies that requests without an auth store
// return 503.
func TestHandleUpstreams_NoAuth(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	s := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/upstreams", nil)
	rec := httptest.NewRecorder()

	s.handleUpstreams(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

// TestHandleUpstreams_GetWithLoadBalancer verifies that GET with a
// upstream.LoadBalancer shows the load-balancer status entry.
func TestHandleUpstreams_GetWithLoadBalancer(t *testing.T) {
	s, user := newAuthenticatedServer(t, "admin", auth.RoleAdmin)

	lb, err := upstream.NewLoadBalancer(upstream.LoadBalancerConfig{Servers: []string{"8.8.8.8:53", "8.8.4.4:53"}, Strategy: "random", HealthCheck: 30 * time.Second})
	if err != nil {
		t.Fatalf("NewLoadBalancer: %v", err)
	}
	s.upstreamLB = lb

	req := httptest.NewRequest(http.MethodGet, "/api/v1/upstreams", nil)
	req = req.WithContext(newAuthenticatedContext(user))
	rec := httptest.NewRecorder()

	s.handleUpstreams(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp UpstreamsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	found := false
	for _, u := range resp.Upstreams {
		if u.Address == "load-balancer" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'load-balancer' entry in response")
	}
}

// TestHandleUpstreams_PutDuplicateServer verifies that adding a duplicate
// server returns 409.
func TestHandleUpstreams_PutDuplicateServer(t *testing.T) {
	s, user := newAuthenticatedServer(t, "admin", auth.RoleAdmin)

	client, err := upstream.NewClient(upstream.Config{
		Servers:  []string{"8.8.8.8:53"},
		Strategy: "random",
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	s.upstreamClient = client

	body := `{"action":"add","server":"8.8.8.8:53"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/upstreams", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAuthenticatedContext(user))
	rec := httptest.NewRecorder()

	s.handleUpstreams(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("expected 409 for duplicate server, got %d", rec.Code)
	}
}

// TestHandleUpstreams_PutRemoveNonexistent verifies that removing a
// nonexistent server returns 404.
func TestHandleUpstreams_PutRemoveNonexistent(t *testing.T) {
	s, user := newAuthenticatedServer(t, "admin", auth.RoleAdmin)

	client, err := upstream.NewClient(upstream.Config{
		Servers:  []string{"8.8.8.8:53"},
		Strategy: "random",
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	s.upstreamClient = client

	body := `{"action":"remove","server":"1.2.3.4:53"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/upstreams", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAuthenticatedContext(user))
	rec := httptest.NewRecorder()

	s.handleUpstreams(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent server, got %d", rec.Code)
	}
}
