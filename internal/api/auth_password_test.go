package api

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/config"
)

// passwordTestStore returns a store with the config admin "admin" plus the
// runtime users given as name → role. Runtime users get the password
// "<name>-pass-123"; config users cannot be changed through the API.
func passwordTestStore(t *testing.T, runtime map[string]auth.Role) *auth.Store {
	t.Helper()
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	for name, role := range runtime {
		if _, err := store.CreateUser(name, name+"-pass-123", role); err != nil {
			t.Fatalf("CreateUser(%s): %v", name, err)
		}
	}
	return store
}

func authRequest(t *testing.T, s *Server, h http.HandlerFunc, caller *auth.User, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var b []byte
	if body != nil {
		var err error
		if b, err = json.Marshal(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.10:5555"
	if caller != nil {
		req = req.WithContext(WithUser(req.Context(), caller))
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func mustToken(t *testing.T, store *auth.Store, username string) string {
	t.Helper()
	tok, err := store.GenerateToken(username, time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken(%s): %v", username, err)
	}
	return tok.Token
}

// Issue #18: a user changes their own password with the current one. Every
// earlier session ends and the caller gets a fresh token and cookie.
func TestChangePassword_RotatesSessions(t *testing.T) {
	store := passwordTestStore(t, map[string]auth.Role{"alice": auth.RoleViewer})
	s := newServerWithAuth(store)
	old1, old2 := mustToken(t, store, "alice"), mustToken(t, store, "alice")
	alice, _ := store.GetUser("alice")

	rec := authRequest(t, s, s.handleChangePassword, alice, http.MethodPost, "/api/v1/auth/password",
		ChangePasswordRequest{OldPassword: "alice-pass-123", NewPassword: "alice-new-pass-456"})
	if rec.Code != http.StatusOK {
		t.Fatalf("change password = %d %s", rec.Code, rec.Body.String())
	}
	var resp LoginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Token == "" || resp.Username != "alice" || resp.Role != "viewer" || resp.Expires == "" {
		t.Fatalf("response = %+v", resp)
	}
	if resp.Token == old1 || resp.Token == old2 {
		t.Fatal("response reused an earlier token")
	}
	for _, old := range []string{old1, old2} {
		if _, err := store.ValidateToken(old); err == nil {
			t.Fatal("an earlier session survived the password change")
		}
	}
	if _, err := store.ValidateToken(resp.Token); err != nil {
		t.Fatalf("new token invalid: %v", err)
	}
	if !store.VerifyUserPassword("alice", "alice-new-pass-456") || store.VerifyUserPassword("alice", "alice-pass-123") {
		t.Fatal("password not changed")
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "ndns_token="+resp.Token) {
		t.Fatalf("Set-Cookie = %q, want the new token", rec.Header().Get("Set-Cookie"))
	}
}

func TestChangePassword_Rejections(t *testing.T) {
	store := passwordTestStore(t, map[string]auth.Role{"alice": auth.RoleViewer})
	alice, _ := store.GetUser("alice")
	cfgAdmin, _ := store.GetUser("admin")

	cases := []struct {
		name   string
		caller *auth.User
		req    ChangePasswordRequest
		want   int
	}{
		{"wrong current password is 400, not 401", alice, ChangePasswordRequest{OldPassword: "not-the-pass", NewPassword: "alice-new-pass-456"}, http.StatusBadRequest},
		{"missing current password", alice, ChangePasswordRequest{NewPassword: "alice-new-pass-456"}, http.StatusBadRequest},
		{"new equals current", alice, ChangePasswordRequest{OldPassword: "alice-pass-123", NewPassword: "alice-pass-123"}, http.StatusBadRequest},
		{"new too short", alice, ChangePasswordRequest{OldPassword: "alice-pass-123", NewPassword: "short"}, http.StatusBadRequest},
		{"shared API token", legacyTokenUser(string(auth.RoleAdmin)), ChangePasswordRequest{OldPassword: "x", NewPassword: "whatever-pass-1"}, http.StatusForbidden},
		{"config-defined user", cfgAdmin, ChangePasswordRequest{OldPassword: "testpass123", NewPassword: "admin-new-pass-1"}, http.StatusConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A fresh server per case keeps the failure throttle of one case
			// from answering the next with 429.
			s := newServerWithAuth(store)
			rec := authRequest(t, s, s.handleChangePassword, tc.caller, http.MethodPost, "/api/v1/auth/password", tc.req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d %s, want %d", rec.Code, rec.Body.String(), tc.want)
			}
		})
	}
	if !store.VerifyUserPassword("alice", "alice-pass-123") || !store.VerifyUserPassword("admin", "testpass123") {
		t.Fatal("a refused request changed a password")
	}
}

// The current-password check shares the login throttle: after a failure the
// next attempt from the same IP waits, even with the right password.
func TestChangePassword_FailedCheckIsThrottled(t *testing.T) {
	store := passwordTestStore(t, map[string]auth.Role{"alice": auth.RoleViewer})
	s := newServerWithAuth(store)
	alice, _ := store.GetUser("alice")

	rec := authRequest(t, s, s.handleChangePassword, alice, http.MethodPost, "/api/v1/auth/password",
		ChangePasswordRequest{OldPassword: "guess-pass-1", NewPassword: "alice-new-pass-456"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("first guess = %d, want 400", rec.Code)
	}
	rec = authRequest(t, s, s.handleChangePassword, alice, http.MethodPost, "/api/v1/auth/password",
		ChangePasswordRequest{OldPassword: "alice-pass-123", NewPassword: "alice-new-pass-456"})
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("attempt after a failure = %d (Retry-After %q), want 429", rec.Code, rec.Header().Get("Retry-After"))
	}
}

// Issue #18: an admin resets another user's password and role; that user's
// sessions are revoked.
func TestHandleUsers_PutUpdatesUserAndRevokesSessions(t *testing.T) {
	store := passwordTestStore(t, map[string]auth.Role{"alice": auth.RoleViewer})
	s := newServerWithAuth(store)
	aliceToken := mustToken(t, store, "alice")
	admin, _ := store.GetUser("admin")

	rec := authRequest(t, s, s.handleUsers, admin, http.MethodPut, "/api/v1/auth/users/alice",
		UpdateUserRequest{Password: "reset-by-admin-1", Role: "operator"})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
	}
	var resp UserResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Username != "alice" || resp.Role != "operator" {
		t.Fatalf("response = %+v", resp)
	}
	if !store.VerifyUserPassword("alice", "reset-by-admin-1") {
		t.Fatal("password not reset")
	}
	if _, err := store.ValidateToken(aliceToken); err == nil {
		t.Fatal("alice's session survived the reset")
	}

	// Password only: the role stays.
	rec = authRequest(t, s, s.handleUsers, admin, http.MethodPut, "/api/v1/auth/users/alice",
		UpdateUserRequest{Password: "reset-by-admin-2"})
	if rec.Code != http.StatusOK {
		t.Fatalf("password-only PUT = %d %s", rec.Code, rec.Body.String())
	}
	if u, _ := store.GetUser("alice"); u.Role != auth.RoleOperator {
		t.Fatalf("role = %s, want operator kept", u.Role)
	}
}

func TestHandleUsers_PutRejections(t *testing.T) {
	store := passwordTestStore(t, map[string]auth.Role{"alice": auth.RoleViewer, "boss": auth.RoleAdmin, "ops": auth.RoleOperator})
	s := newServerWithAuth(store)
	boss, _ := store.GetUser("boss")
	ops, _ := store.GetUser("ops")

	cases := []struct {
		name   string
		caller *auth.User
		path   string
		body   any
		want   int
	}{
		{"own account", boss, "/api/v1/auth/users/boss", UpdateUserRequest{Password: "boss-new-pass-1"}, http.StatusBadRequest},
		{"nothing to change", boss, "/api/v1/auth/users/alice", UpdateUserRequest{}, http.StatusBadRequest},
		{"invalid role", boss, "/api/v1/auth/users/alice", UpdateUserRequest{Role: "root"}, http.StatusBadRequest},
		{"password too short", boss, "/api/v1/auth/users/alice", UpdateUserRequest{Password: "short"}, http.StatusBadRequest},
		{"operator caller", ops, "/api/v1/auth/users/alice", UpdateUserRequest{Password: "alice-new-pass-1"}, http.StatusForbidden},
		{"unknown user", boss, "/api/v1/auth/users/nobody", UpdateUserRequest{Password: "nobody-pass-123"}, http.StatusNotFound},
		{"config-defined user", boss, "/api/v1/auth/users/admin", UpdateUserRequest{Password: "admin-new-pass-1"}, http.StatusConflict},
		{"collection path", boss, "/api/v1/auth/users", UpdateUserRequest{Password: "alice-new-pass-1"}, http.StatusMethodNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := authRequest(t, s, s.handleUsers, tc.caller, http.MethodPut, tc.path, tc.body)
			if rec.Code != tc.want {
				t.Fatalf("status = %d %s, want %d", rec.Code, rec.Body.String(), tc.want)
			}
		})
	}
	if !store.VerifyUserPassword("alice", "alice-pass-123") || !store.VerifyUserPassword("boss", "boss-pass-123") {
		t.Fatal("a refused request changed a password")
	}
	if u, _ := store.GetUser("alice"); u.Role != auth.RoleViewer {
		t.Fatalf("alice role = %s, want viewer", u.Role)
	}
}

// Demoting the only admin is refused with a message about demotion, not the
// store's "cannot delete" text. Only a caller that is not that admin can try
// it, such as the shared API token with the admin role.
func TestHandleUsers_PutRefusesDemotingLastAdmin(t *testing.T) {
	store := newAuthStoreWithUser(t, "watcher", "testpass123", auth.RoleViewer)
	if _, err := store.CreateUser("boss", "boss-pass-123", auth.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	s := newServerWithAuth(store)

	rec := authRequest(t, s, s.handleUsers, legacyTokenUser(string(auth.RoleAdmin)), http.MethodPut,
		"/api/v1/auth/users/boss", UpdateUserRequest{Role: "viewer"})
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "Cannot demote the last admin user") {
		t.Fatalf("demote last admin = %d %s, want 409 demote message", rec.Code, rec.Body.String())
	}
	if u, _ := store.GetUser("boss"); u.Role != auth.RoleAdmin {
		t.Fatalf("boss role = %s, want admin kept", u.Role)
	}
}

// End to end through the auth middleware: the route is registered, the new
// token works and the old one is rejected.
func TestChangePassword_ThroughServer(t *testing.T) {
	store := passwordTestStore(t, map[string]auth.Role{"alice": auth.RoleViewer})
	oldToken := mustToken(t, store, "alice")

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	s := NewServer(config.HTTPConfig{Enabled: true, Bind: addr}, nil, nil, nil, nil, nil, nil)
	s.authStore = store
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { s.Stop() })
	base := "http://" + addr

	resp := apiPost(t, base, "/api/v1/auth/password", oldToken,
		ChangePasswordRequest{OldPassword: "alice-pass-123", NewPassword: "alice-new-pass-456"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /auth/password = %d", resp.StatusCode)
	}
	var lr LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		t.Fatal(err)
	}

	stale := apiGet(t, base, "/api/v1/auth/session", oldToken)
	stale.Body.Close()
	if stale.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old token after change = %d, want 401", stale.StatusCode)
	}
	fresh := apiGet(t, base, "/api/v1/auth/session", lr.Token)
	fresh.Body.Close()
	if fresh.StatusCode != http.StatusOK {
		t.Fatalf("new token = %d, want 200", fresh.StatusCode)
	}
}
