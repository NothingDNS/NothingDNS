package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/nothingdns/nothingdns/internal/auth"
)

// configUsersAPIStore builds the store the way the daemon does at start:
// config users + the users file. Calling it again simulates a restart.
func configUsersAPIStore(t *testing.T, usersFile string) *auth.Store {
	t.Helper()
	cfg, err := auth.DefaultConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Users = []auth.User{
		{Username: "root", Hash: cachedTestPasswordHash(t, "root-config-pass1"), Role: auth.RoleAdmin},
		{Username: "cfguser", Hash: cachedTestPasswordHash(t, "cfg-config-pass1"), Role: auth.RoleViewer},
	}
	st, err := auth.NewStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.EnableUsersFile(usersFile); err != nil {
		t.Fatal(err)
	}
	return st
}

func configUsersDo(s *Server, h http.HandlerFunc, method, path string, body any) *httptest.ResponseRecorder {
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:5555"
	req = req.WithContext(WithUser(req.Context(), &auth.User{Username: "root", Role: auth.RoleAdmin}))
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

// F437: deleting or password-resetting a config-defined user via the API is
// refused with 409 instead of succeeding and being undone by a restart; the
// list endpoint marks such users with config_defined.
func TestHandleUsers_ConfigDefinedUserChangesRefused(t *testing.T) {
	usersFile := filepath.Join(t.TempDir(), "users.json")
	st := configUsersAPIStore(t, usersFile)
	s := newServerWithAuth(st)

	rec := configUsersDo(s, s.handleUsers, http.MethodDelete, "/api/v1/auth/users/cfguser", nil)
	if rec.Code != http.StatusConflict || !bytes.Contains(rec.Body.Bytes(), []byte("defined in the config file")) {
		t.Fatalf("delete config user = %d %s, want 409", rec.Code, rec.Body.String())
	}
	rec = configUsersDo(s, s.handleBootstrap, http.MethodPost, "/api/v1/auth/bootstrap",
		BootstrapRequest{Username: "cfguser", Password: "new-api-pass-123", OldPassword: "cfg-config-pass1"})
	if rec.Code != http.StatusConflict {
		t.Fatalf("bootstrap reset of config user = %d %s, want 409", rec.Code, rec.Body.String())
	}
	if _, err := st.GetUser("cfguser"); err != nil || !st.VerifyUserPassword("cfguser", "cfg-config-pass1") {
		t.Fatal("refused request changed the config user in memory")
	}

	// Runtime users: create, reset, delete all work and match a restart.
	if rec = configUsersDo(s, s.handleUsers, http.MethodPost, "/api/v1/auth/users",
		CreateUserRequest{Username: "rt", Password: "rt-runtime-pass1", Role: "viewer"}); rec.Code != http.StatusCreated {
		t.Fatalf("create runtime user = %d", rec.Code)
	}
	if rec = configUsersDo(s, s.handleBootstrap, http.MethodPost, "/api/v1/auth/bootstrap",
		BootstrapRequest{Username: "rt", Password: "rt-runtime-pass2", OldPassword: "rt-runtime-pass1"}); rec.Code != http.StatusOK {
		t.Fatalf("bootstrap reset of runtime user = %d %s", rec.Code, rec.Body.String())
	}
	restarted := configUsersAPIStore(t, usersFile)
	if !restarted.VerifyUserPassword("rt", "rt-runtime-pass2") || !restarted.VerifyUserPassword("cfguser", "cfg-config-pass1") {
		t.Fatal("restart does not match the state the API reported")
	}

	rec = configUsersDo(s, s.handleUsers, http.MethodGet, "/api/v1/auth/users", nil)
	var list []struct {
		Username      string `json:"username"`
		ConfigDefined *bool  `json:"config_defined"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	for _, u := range list {
		want := u.Username != "rt"
		if u.ConfigDefined == nil || *u.ConfigDefined != want {
			t.Errorf("list %s config_defined = %v, want %v", u.Username, u.ConfigDefined, want)
		}
	}

	if rec = configUsersDo(s, s.handleUsers, http.MethodDelete, "/api/v1/auth/users/rt", nil); rec.Code != http.StatusOK {
		t.Fatalf("delete runtime user = %d", rec.Code)
	}
	if _, err := configUsersAPIStore(t, usersFile).GetUser("rt"); err == nil {
		t.Fatal("runtime delete not persisted")
	}
}

// F438: a users-file write failure returns 500 and leaves the in-memory state
// unchanged, instead of reporting success for a change a restart undoes.
func TestHandleUsers_UsersFileWriteFailureReturns500(t *testing.T) {
	usersFile := filepath.Join(t.TempDir(), "users.json")
	st := configUsersAPIStore(t, usersFile)
	s := newServerWithAuth(st)
	if rec := configUsersDo(s, s.handleUsers, http.MethodPost, "/api/v1/auth/users",
		CreateUserRequest{Username: "keep", Password: "keep-runtime-1", Role: "viewer"}); rec.Code != http.StatusCreated {
		t.Fatalf("control create = %d", rec.Code)
	}
	if err := os.Remove(usersFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(usersFile, 0o700); err != nil {
		t.Fatal(err)
	}

	rec := configUsersDo(s, s.handleUsers, http.MethodPost, "/api/v1/auth/users",
		CreateUserRequest{Username: "ghost", Password: "ghost-runtime-1", Role: "viewer"})
	if rec.Code != http.StatusInternalServerError || bytes.Contains(rec.Body.Bytes(), []byte(usersFile)) {
		t.Fatalf("create with failing users file = %d %s, want 500 without path", rec.Code, rec.Body.String())
	}
	if _, err := st.GetUser("ghost"); err == nil {
		t.Fatal("failed create left the user in memory")
	}
	if rec = configUsersDo(s, s.handleUsers, http.MethodDelete, "/api/v1/auth/users/keep", nil); rec.Code != http.StatusInternalServerError {
		t.Fatalf("delete with failing users file = %d, want 500", rec.Code)
	}
	if _, err := st.GetUser("keep"); err != nil {
		t.Fatal("failed delete removed the user from memory")
	}
	if rec = configUsersDo(s, s.handleBootstrap, http.MethodPost, "/api/v1/auth/bootstrap",
		BootstrapRequest{Username: "keep", Password: "keep-runtime-2", OldPassword: "keep-runtime-1"}); rec.Code != http.StatusInternalServerError {
		t.Fatalf("bootstrap reset with failing users file = %d, want 500", rec.Code)
	}
	if !st.VerifyUserPassword("keep", "keep-runtime-1") {
		t.Fatal("failed reset changed the password in memory")
	}
}

// F438: bootstrap replacing the auto-created admin keeps the placeholder when
// the users file cannot be written, instead of leaving zero users.
func TestHandleBootstrap_ReplaceAutoAdminWriteFailureKeepsPlaceholder(t *testing.T) {
	usersFile := filepath.Join(t.TempDir(), "users.json")
	cfg, err := auth.DefaultConfig()
	if err != nil {
		t.Fatal(err)
	}
	st, err := auth.NewStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.EnableUsersFile(usersFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(usersFile, 0o700); err != nil {
		t.Fatal(err)
	}
	s := newServerWithAuth(st)
	rec := configUsersDo(s, s.handleBootstrap, http.MethodPost, "/api/v1/auth/bootstrap",
		BootstrapRequest{Username: "owner", Password: "owner-pass-1234"})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("bootstrap with failing users file = %d %s, want 500", rec.Code, rec.Body.String())
	}
	if !st.UsesAutoCreatedAdmin() || len(st.ListUsers()) != 1 {
		t.Fatalf("placeholder admin lost: users=%d", len(st.ListUsers()))
	}
}
