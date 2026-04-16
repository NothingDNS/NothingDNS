package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/config"
)

// TestLegacyAuthTokenDefaultsToViewer locks in VULN-003 remediation:
// the legacy shared auth_token no longer silently synthesizes admin context.
// Unless auth_token_role is explicitly set to operator/admin, the token binds
// to viewer.
func TestLegacyAuthTokenDefaultsToViewer(t *testing.T) {
	cfg := config.HTTPConfig{
		Enabled:   true,
		Bind:      "127.0.0.1:0",
		AuthToken: "shared-secret-token",
		// AuthTokenRole intentionally unset
	}
	server := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	var gotUser *auth.User
	testHandler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotUser = GetUser(r.Context())
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer shared-secret-token")
	rec := httptest.NewRecorder()
	server.authMiddleware(testHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if gotUser == nil {
		t.Fatal("expected user in context, got nil")
	}
	if gotUser.Role != auth.RoleViewer {
		t.Errorf("legacy token role = %q, want %q (viewer default)", gotUser.Role, auth.RoleViewer)
	}
}

func TestLegacyAuthTokenHonorsConfiguredRole(t *testing.T) {
	for _, tc := range []struct {
		configured string
		want       auth.Role
	}{
		{"admin", auth.RoleAdmin},
		{"ADMIN", auth.RoleAdmin},
		{"operator", auth.RoleOperator},
		{"viewer", auth.RoleViewer},
		{"", auth.RoleViewer},
		{"garbage", auth.RoleViewer},
	} {
		u := legacyTokenUser(tc.configured)
		if u.Role != tc.want {
			t.Errorf("legacyTokenUser(%q).Role = %q, want %q", tc.configured, u.Role, tc.want)
		}
	}
}

// TestCookieAuthRejectedOnMutatingMethods locks in VULN-010 remediation: the
// ndns_token cookie is only accepted on safe methods (GET/HEAD/OPTIONS).
// POST/PUT/DELETE must use Authorization: Bearer, so a cross-site request
// that carries the cookie but not the header is denied.
func TestCookieAuthRejectedOnMutatingMethods(t *testing.T) {
	cfg := config.HTTPConfig{
		Enabled:   true,
		Bind:      "127.0.0.1:0",
		AuthToken: "shared-secret-token",
	}
	server := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		handlerCalled := false
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(method, "/api/v1/zones", nil)
		req.AddCookie(&http.Cookie{Name: "ndns_token", Value: "shared-secret-token"})
		rec := httptest.NewRecorder()
		server.authMiddleware(testHandler).ServeHTTP(rec, req)

		if handlerCalled {
			t.Errorf("method %s: cookie-only auth should be rejected on mutating request, but handler ran", method)
		}
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("method %s: want 401 Unauthorized, got %d", method, rec.Code)
		}
	}
}

func TestCookieAuthAcceptedOnSafeMethods(t *testing.T) {
	cfg := config.HTTPConfig{
		Enabled:   true,
		Bind:      "127.0.0.1:0",
		AuthToken: "shared-secret-token",
	}
	server := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		handlerCalled := false
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(method, "/api/v1/zones", nil)
		req.AddCookie(&http.Cookie{Name: "ndns_token", Value: "shared-secret-token"})
		rec := httptest.NewRecorder()
		server.authMiddleware(testHandler).ServeHTTP(rec, req)

		if !handlerCalled {
			t.Errorf("method %s: cookie auth should be accepted on safe method, got %d", method, rec.Code)
		}
	}
}
