package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/config"
)

func newAuthStoreWithUser(t *testing.T, username, password string, role auth.Role) *auth.Store {
	t.Helper()
	cfg, err := auth.DefaultConfig()
	if err != nil {
		t.Fatalf("DefaultConfig: %v", err)
	}
	cfg.Users = []auth.User{
		{Username: username, Password: password, Role: role},
	}
	store, err := auth.NewStore(cfg)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}

func newServerWithAuth(store *auth.Store) *Server {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	s := NewServer(cfg, nil, nil, nil, nil, nil, nil)
	s.authStore = store
	return s
}

// --- handleLogin tests ---

func TestHandleLogin_Success(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	body, _ := json.Marshal(LoginRequest{Username: "admin", Password: "testpass123"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s.handleLogin(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp LoginResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Token == "" {
		t.Error("expected token in response")
	}
	if resp.Username != "admin" {
		t.Errorf("expected username 'admin', got %s", resp.Username)
	}
	if resp.Role != "admin" {
		t.Errorf("expected role 'admin', got %s", resp.Role)
	}
}

func TestHandleLogin_InvalidCredentials(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	body, _ := json.Marshal(LoginRequest{Username: "admin", Password: "wrongpass"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s.handleLogin(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestHandleLogin_WrongMethod(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/login", nil)
	rec := httptest.NewRecorder()

	s.handleLogin(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHandleLogin_NoAuthStore(t *testing.T) {
	s := NewServer(config.HTTPConfig{Enabled: true}, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	rec := httptest.NewRecorder()

	s.handleLogin(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestHandleLogin_InvalidBody(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s.handleLogin(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleLogin_SetsCookie(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	body, _ := json.Marshal(LoginRequest{Username: "admin", Password: "testpass123"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s.handleLogin(rec, req)

	cookies := rec.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "ndns_token" {
			found = true
			if c.Value == "" {
				t.Error("cookie value should not be empty")
			}
			if c.HttpOnly != true {
				t.Error("cookie should be HttpOnly")
			}
			if c.MaxAge != 86400 {
				t.Errorf("expected MaxAge 86400, got %d", c.MaxAge)
			}
		}
	}
	if !found {
		t.Error("ndns_token cookie should be set")
	}
}

// --- handleLogout tests ---

func TestHandleLogout_Success(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	// Generate a token first
	tok, _ := store.GenerateToken("admin", 24*time.Hour)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	rec := httptest.NewRecorder()

	s.handleLogout(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	// Cookie should be cleared
	cookies := rec.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "ndns_token" && c.MaxAge != -1 {
			t.Errorf("cookie should be cleared (MaxAge=-1), got %d", c.MaxAge)
		}
	}
}

func TestHandleLogout_WrongMethod(t *testing.T) {
	s := NewServer(config.HTTPConfig{Enabled: true}, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/logout", nil)
	rec := httptest.NewRecorder()

	s.handleLogout(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHandleLogout_NoToken(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	rec := httptest.NewRecorder()

	s.handleLogout(rec, req)

	// Should still succeed (idempotent logout)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

// --- handleBootstrap tests ---

func TestHandleBootstrap_WrongMethod(t *testing.T) {
	store, _ := auth.NewStore(&auth.Config{Secret: "test-secret-12345"})
	s := newServerWithAuth(store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/bootstrap", nil)
	rec := httptest.NewRecorder()

	s.handleBootstrap(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHandleBootstrap_NonLocalhost(t *testing.T) {
	store, _ := auth.NewStore(&auth.Config{Secret: "test-secret-12345"})
	s := newServerWithAuth(store)

	body, _ := json.Marshal(BootstrapRequest{Username: "admin", Password: "testpass123"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap", bytes.NewReader(body))
	req.RemoteAddr = "10.0.0.1:12345"
	rec := httptest.NewRecorder()

	s.handleBootstrap(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-localhost, got %d", rec.Code)
	}
}

func TestHandleBootstrap_NoAuthStore(t *testing.T) {
	s := NewServer(config.HTTPConfig{Enabled: true}, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	s.handleBootstrap(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestHandleBootstrap_EmptyUsername(t *testing.T) {
	store, _ := auth.NewStore(&auth.Config{Secret: "test-secret-12345"})
	s := newServerWithAuth(store)

	body, _ := json.Marshal(BootstrapRequest{Username: "", Password: "testpass123"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	s.handleBootstrap(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleBootstrap_ShortPassword(t *testing.T) {
	store, _ := auth.NewStore(&auth.Config{Secret: "test-secret-12345"})
	s := newServerWithAuth(store)

	body, _ := json.Marshal(BootstrapRequest{Username: "admin", Password: "short"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	s.handleBootstrap(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for short password, got %d", rec.Code)
	}
}

func TestHandleBootstrap_CreatesFirstAdmin(t *testing.T) {
	// Create a store that has users (so it won't auto-create a default admin)
	// but the user we're bootstrapping is different.
	store := newAuthStoreWithUser(t, "existing", "existingpass123", auth.RoleAdmin)
	// Remove the user to simulate no-users scenario
	store.DeleteUser("existing")

	s := newServerWithAuth(store)

	body, _ := json.Marshal(BootstrapRequest{Username: "admin", Password: "securepass123"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	s.handleBootstrap(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp BootstrapResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Username != "admin" {
		t.Errorf("expected username 'admin', got %s", resp.Username)
	}
	if resp.Role != "admin" {
		t.Errorf("expected role 'admin', got %s", resp.Role)
	}
	if resp.Token == "" {
		t.Error("expected token")
	}

	// User should now exist
	users := store.ListUsers()
	if len(users) != 1 {
		t.Errorf("expected 1 user, got %d", len(users))
	}
}

// --- handleUsers tests ---

func TestHandleUsers_ListUsers(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	// Set authenticated user context with operator role
	ctx := WithUser(req.Context(), &auth.User{Username: "admin", Role: auth.RoleAdmin})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleUsers(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var users []UserResponse
	if err := json.NewDecoder(rec.Body).Decode(&users); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(users) != 1 {
		t.Errorf("expected 1 user, got %d", len(users))
	}
	if users[0].Username != "admin" {
		t.Errorf("expected admin, got %s", users[0].Username)
	}
}

func TestHandleUsers_NoAuthStore(t *testing.T) {
	s := NewServer(config.HTTPConfig{Enabled: true}, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	rec := httptest.NewRecorder()

	s.handleUsers(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestHandleUsers_CreateUser(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	adminUser, _ := store.GetUser("admin")

	body, _ := json.Marshal(CreateUserRequest{
		Username: "viewer1",
		Password: "viewerpass123",
		Role:     "viewer",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Set admin user in context for role check
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleUsers(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp UserResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Username != "viewer1" {
		t.Errorf("expected viewer1, got %s", resp.Username)
	}
}

func TestHandleUsers_DeleteUser(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	// Create a user to delete
	store.CreateUser("todelete", "password123", auth.RoleViewer)

	s := newServerWithAuth(store)
	adminUser, _ := store.GetUser("admin")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users?username=todelete", nil)
	// Set admin user in context for role check
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleUsers(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// User should be gone
	users := store.ListUsers()
	for _, u := range users {
		if u.Username == "todelete" {
			t.Error("user should be deleted")
		}
	}
}

// --- handleRoles tests ---

func TestHandleRolesEndpoint(t *testing.T) {
	s := NewServer(config.HTTPConfig{Enabled: true}, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/roles", nil)
	rec := httptest.NewRecorder()

	s.handleRoles(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var resp RolesResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Roles) != 3 {
		t.Errorf("expected 3 roles, got %d", len(resp.Roles))
	}
}
