package api

// Round-13 proof: the bootstrap "take over the synthetic default admin" path
// destroys the only administrator BEFORE the replacement is created, and
// never rolls back if creation fails.
//
// internal/api/api_auth.go handleBootstrap:
//     if err := authStore.DeleteUser("admin"); err != nil { ... }
//     user, err = authStore.CreateUser(req.Username, req.Password, auth.RoleAdmin)
//     if err != nil { ...400/409/500...; return }
//
// The handler's own admission checks only constrain the username to 2-64
// characters and the password to >=8 and <=MaxPasswordBytes bytes. But
// auth.CreateUser additionally calls auth.ValidateUsername, which rejects any
// username containing a Unicode control character. So a localhost bootstrap
// with username "adm\x01in" passes the handler's validation, takes the
// takeover branch (the only user is the auto-created admin), DELETES that
// admin, and then fails CreateUser.
//
// Result: the store is left with zero users and no administrator. The
// takeover branch exists precisely to escape the "unbootstrappable default
// admin" state, so this converts a recoverable setup into an unrecoverable
// one, and the response is an error even though the caller did nothing
// unusual beyond a character their own input validation allowed.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nothingdns/nothingdns/internal/auth"
)

// bootstrapWith performs a localhost bootstrap request carrying the given
// credentials against the real production handler.
func bootstrapWith(t *testing.T, s *Server, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(BootstrapRequest{Username: username, Password: password})
	if err != nil {
		t.Fatalf("FAIL: harness setup: marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	s.handleBootstrap(rec, req)
	return rec
}

func TestProofRound013BootstrapTakeoverKeepsAdminOnCreateFailure(t *testing.T) {
	// CONTROL — the unaffected path. A plain takeover with a valid username
	// must still work exactly as before, and must leave exactly one admin.
	controlStore, _ := auth.NewStore(&auth.Config{Secret: "test-secret-12345"})
	if users := controlStore.ListUsers(); len(users) != 1 || users[0].Username != "admin" || !users[0].IsAutoCreated {
		t.Fatalf("FAIL: harness setup: expected a single auto-created admin, got %+v", users)
	}
	controlServer := newServerWithAuth(controlStore)
	rec := bootstrapWith(t, controlServer, "operator", "operatorpass123")
	if rec.Code != http.StatusOK {
		t.Fatalf("FAIL: harness setup: control takeover should succeed, got %d: %s", rec.Code, rec.Body.String())
	}
	if users := controlStore.ListUsers(); len(users) != 1 || users[0].Username != "operator" {
		t.Fatalf("FAIL: harness setup: control takeover should leave exactly the operator, got %+v", users)
	}

	// SUBJECT — a username containing a control character. It satisfies every
	// check handleBootstrap performs itself (non-empty, 2-64 chars) and so
	// reaches the destructive takeover branch.
	store, _ := auth.NewStore(&auth.Config{Secret: "test-secret-12345"})
	if users := store.ListUsers(); len(users) != 1 || users[0].Username != "admin" || !users[0].IsAutoCreated {
		t.Fatalf("FAIL: harness setup: expected a single auto-created admin, got %+v", users)
	}
	s := newServerWithAuth(store)

	rec = bootstrapWith(t, s, "adm\x01in", "operatorpass123")

	// auth.CreateUser must reject this username: it is what makes the
	// second step of the takeover fail.
	if err := auth.ValidateUsername("adm\x01in"); err == nil {
		t.Fatalf("FAIL: harness setup: expected auth.ValidateUsername to reject a control character, " +
			"otherwise the takeover would have succeeded and proved nothing")
	}

	// The response is an error, because the replacement account was rejected.
	if rec.Code < 400 {
		t.Fatalf("FAIL: harness setup: expected the bootstrap to report an error, got %d: %s",
			rec.Code, rec.Body.String())
	}

	// The contract that must hold: a bootstrap that did not succeed must not
	// have removed the server's only administrator. Every other rejection
	// path in this handler (bad length, weak password, wrong OldPassword)
	// leaves the existing administrator untouched; only the takeover branch
	// can delete it.
	users := store.ListUsers()
	if len(users) == 0 {
		t.Fatalf("FAIL: admin lockout — bootstrap reported failure (%d: %s) but the only "+
			"administrator was already deleted, leaving the server with zero users and no way "+
			"to authenticate; the takeover branch must not destroy the admin before the "+
			"replacement is created",
			rec.Code, rec.Body.String())
	}
	if users[0].Username != "admin" {
		t.Fatalf("FAIL: unexpected surviving user after rejected bootstrap: %q", users[0].Username)
	}
}
