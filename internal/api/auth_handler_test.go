package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/config"
)

var testPasswordHashes sync.Map

func newAuthStoreWithUser(t *testing.T, username, password string, role auth.Role) *auth.Store {
	t.Helper()
	cfg, err := auth.DefaultConfig()
	if err != nil {
		t.Fatalf("DefaultConfig: %v", err)
	}
	hash := cachedTestPasswordHash(t, password)
	cfg.Users = []auth.User{
		{Username: username, Hash: hash, Role: role},
	}
	store, err := auth.NewStore(cfg)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}

func cachedTestPasswordHash(t *testing.T, password string) []byte {
	t.Helper()
	if cached, ok := testPasswordHashes.Load(password); ok {
		return cloneBytes(cached.([]byte))
	}
	hash, err := auth.HashPasswordWithError(password, nil)
	if err != nil {
		t.Fatalf("HashPasswordWithError: %v", err)
	}
	actual, _ := testPasswordHashes.LoadOrStore(password, cloneBytes(hash))
	return cloneBytes(actual.([]byte))
}

func cloneBytes(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
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

// --- handleSession tests ---

func TestHandleSession_FromCookie(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	tok, err := store.GenerateToken("admin", 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	user, err := store.GetUser("admin")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
	req.AddCookie(&http.Cookie{Name: "ndns_token", Value: tok.Token})
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleSession(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp LoginResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Token != tok.Token || resp.Username != "admin" || resp.Role != "admin" {
		t.Errorf("unexpected session: %+v", resp)
	}
}

func TestHandleSession_Unauthenticated(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
	rec := httptest.NewRecorder()
	s.handleSession(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestHandleSession_RejectsLegacyTokenUser(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
	req = req.WithContext(WithUser(req.Context(), legacyTokenUser(string(auth.RoleAdmin))))
	rec := httptest.NewRecorder()
	s.handleSession(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for legacy auth_token, got %d", rec.Code)
	}
}

func TestHandleSession_MethodNotAllowed(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/session", nil)
	rec := httptest.NewRecorder()
	s.handleSession(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
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

// TestHandleBootstrap_TakesOverAutoCreatedDefault verifies the
// unbootstrappable-default-admin escape hatch: when the only user
// in the store is the auto-created "admin" (IsAutoCreated=true,
// random unknowable password), a localhost bootstrap request must
// succeed without supplying OldPassword. Without this branch, the
// daemon ships in a permanently locked state: the startup warning
// promises "set password via dashboard or API," but the password-
// reset path required an OldPassword that, by construction, nobody
// can know.
func TestHandleBootstrap_TakesOverAutoCreatedDefault(t *testing.T) {
	// Fresh store with no configured users → auto-creates admin.
	store, _ := auth.NewStore(&auth.Config{Secret: "test-secret-12345"})
	users := store.ListUsers()
	if len(users) != 1 || users[0].Username != "admin" || !users[0].IsAutoCreated {
		t.Fatalf("expected single auto-created admin, got %+v", users)
	}

	s := newServerWithAuth(store)

	// No OldPassword supplied — must still succeed because the existing
	// user is the synthetic default.
	body, _ := json.Marshal(BootstrapRequest{
		Username: "operator",
		Password: "operatorpass123",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	s.handleBootstrap(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("bootstrap takeover: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// New user replaces the auto-created admin.
	users = store.ListUsers()
	if len(users) != 1 {
		t.Fatalf("expected 1 user after takeover, got %d", len(users))
	}
	if users[0].Username != "operator" {
		t.Errorf("expected operator, got %s", users[0].Username)
	}
	if users[0].IsAutoCreated {
		t.Error("post-bootstrap user must not carry IsAutoCreated flag")
	}

	// Subsequent bootstrap on the now-real user must require OldPassword.
	body2, _ := json.Marshal(BootstrapRequest{
		Username: "operator",
		Password: "differentpass456",
	})
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap", bytes.NewReader(body2))
	req2.RemoteAddr = "127.0.0.1:12345"
	rec2 := httptest.NewRecorder()
	s.handleBootstrap(rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Errorf("second bootstrap without OldPassword: expected 400, got %d", rec2.Code)
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

func TestHandleUsers_DeleteUserPathParameter(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	if _, err := store.CreateUser("delete/path@example", "password123", auth.RoleViewer); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	s := newServerWithAuth(store)
	adminUser, _ := store.GetUser("admin")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/users/delete%2Fpath%40example", nil)
	req = req.WithContext(WithUser(req.Context(), adminUser))
	rec := httptest.NewRecorder()

	s.handleUsers(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := store.GetUser("delete/path@example"); err == nil {
		t.Fatal("user should be deleted")
	}
}

func TestHandleUsers_DeleteRejectsCurrentUser(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	adminUser, _ := store.GetUser("admin")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/users/admin", nil)
	req = req.WithContext(WithUser(req.Context(), adminUser))
	rec := httptest.NewRecorder()

	s.handleUsers(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := store.GetUser("admin"); err != nil {
		t.Fatal("current user should not be deleted")
	}
}

func TestHandleUsers_DeleteRejectsLastAdmin(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	if _, err := store.CreateUser("operator", "operatorpass123", auth.RoleOperator); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	s := newServerWithAuth(store)
	operatorUser, _ := store.GetUser("operator")
	operatorUser.Role = auth.RoleAdmin

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/users/admin", nil)
	req = req.WithContext(WithUser(req.Context(), operatorUser))
	rec := httptest.NewRecorder()

	s.handleUsers(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := store.GetUser("admin"); err != nil {
		t.Fatal("last admin should not be deleted")
	}
}

func TestHandleUsers_DeleteAdminWhenAnotherAdminRemains(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	if _, err := store.CreateUser("otheradmin", "otheradminpass123", auth.RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	s := newServerWithAuth(store)
	adminUser, _ := store.GetUser("admin")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/users/otheradmin", nil)
	req = req.WithContext(WithUser(req.Context(), adminUser))
	rec := httptest.NewRecorder()

	s.handleUsers(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := store.GetUser("otheradmin"); err == nil {
		t.Fatal("other admin should be deleted")
	}
	if _, err := store.GetUser("admin"); err != nil {
		t.Fatal("current admin should remain")
	}
}

func TestHandleUsers_ItemPathRejectsNonDelete(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	adminUser, _ := store.GetUser("admin")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/users/admin", nil)
	req = req.WithContext(WithUser(req.Context(), adminUser))
	rec := httptest.NewRecorder()

	s.handleUsers(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAuthStoreRuntimeSwapDoesNotRaceWithHandlers(t *testing.T) {
	storeA := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	storeB := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(storeA)

	adminUser, err := storeA.GetUser("admin")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	token, err := storeA.GenerateToken("admin", storeA.TokenExpiry())
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	loginBody, err := json.Marshal(LoginRequest{Username: "admin", Password: "testpass123"})
	if err != nil {
		t.Fatalf("Marshal login request: %v", err)
	}

	errCh := make(chan string, 16)
	var wg sync.WaitGroup
	const iterations = 25
	wg.Add(4)

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			if i%2 == 0 {
				s.WithAuth(storeA)
			} else {
				s.WithAuth(storeB)
			}
		}
	}()

	go func() {
		defer wg.Done()
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		for i := 0; i < iterations; i++ {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
			req.Header.Set("Authorization", "Bearer "+token.Token)
			rec := httptest.NewRecorder()
			s.authMiddleware(next).ServeHTTP(rec, req)
			if rec.Code != http.StatusNoContent && rec.Code != http.StatusUnauthorized {
				errCh <- "unexpected auth middleware status"
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			s.handleLogin(rec, req)
			if rec.Code != http.StatusOK {
				errCh <- "unexpected login status"
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/users", nil)
			req = req.WithContext(WithUser(req.Context(), adminUser))
			rec := httptest.NewRecorder()
			s.handleUsers(rec, req)
			if rec.Code != http.StatusOK {
				errCh <- "unexpected users status"
				return
			}
		}
	}()

	wg.Wait()
	close(errCh)
	for errMsg := range errCh {
		t.Error(errMsg)
	}
}

// --- handleRoles tests ---

func TestHandleRolesEndpoint(t *testing.T) {
	store := newAuthStoreWithUser(t, "operator", "testpass123", auth.RoleOperator)
	s := newServerWithAuth(store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/roles", nil)
	operatorUser, _ := store.GetUser("operator")
	req = req.WithContext(WithUser(req.Context(), operatorUser))
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

func TestHandleRolesRequiresOperator(t *testing.T) {
	store := newAuthStoreWithUser(t, "viewer", "testpass123", auth.RoleViewer)
	s := newServerWithAuth(store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/roles", nil)
	viewerUser, _ := store.GetUser("viewer")
	req = req.WithContext(WithUser(req.Context(), viewerUser))
	rec := httptest.NewRecorder()

	s.handleRoles(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleRolesWrongMethod(t *testing.T) {
	store := newAuthStoreWithUser(t, "operator", "testpass123", auth.RoleOperator)
	s := newServerWithAuth(store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/roles", nil)
	operatorUser, _ := store.GetUser("operator")
	req = req.WithContext(WithUser(req.Context(), operatorUser))
	rec := httptest.NewRecorder()

	s.handleRoles(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d: %s", rec.Code, rec.Body.String())
	}
}
