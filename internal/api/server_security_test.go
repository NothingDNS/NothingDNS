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

// TestDoHPathsBypassAuth locks in VULN-044 remediation. DoH/DoWS/ODoH paths
// are DNS resolution endpoints, not admin API — clients never send Bearer
// tokens. Before the fix, enabling auth_token caused authMiddleware to 401
// every legitimate DoH query.
func TestDoHPathsBypassAuth(t *testing.T) {
	cfg := config.HTTPConfig{
		Enabled:      true,
		Bind:         "127.0.0.1:0",
		AuthToken:    "shared-secret-token",
		DoHEnabled:   true,
		DoHPath:      "/dns-query",
		DoWSEnabled:  true,
		DoWSPath:     "/dns-ws",
		ODoHEnabled:  true,
		ODoHPath:     "/odoh",
	}
	server := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	cases := []struct {
		name       string
		path       string
		wantStatus int
	}{
		{"DoH", "/dns-query", http.StatusOK},
		{"DoWS", "/dns-ws", http.StatusOK},
		{"ODoH", "/odoh", http.StatusOK},
		{"ODoH well-known config", "/.well-known/odoh-config", http.StatusOK},
		// Negative control: the admin API must still require auth.
		{"admin API is still gated", "/api/v1/zones", http.StatusUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handlerCalled := false
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				handlerCalled = true
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			// No Authorization header — emulates a real DoH client.
			rec := httptest.NewRecorder()
			server.authMiddleware(testHandler).ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Errorf("%s %s: got %d, want %d", http.MethodGet, tc.path, rec.Code, tc.wantStatus)
			}
			expectReach := tc.wantStatus == http.StatusOK
			if handlerCalled != expectReach {
				t.Errorf("%s %s: handlerCalled=%v, want %v", http.MethodGet, tc.path, handlerCalled, expectReach)
			}
		})
	}
}

// TestAPIRateLimitAppliesToUnauthenticatedRequests locks in VULN-055. The
// apiRateLimiter used to only fire inside the successful-auth branches of
// authMiddleware, so an attacker brute-forcing credentials (which fails auth
// every time) never consumed budget. After the fix the limit applies to all
// /api/ requests before any auth decision.
func TestAPIRateLimitAppliesToUnauthenticatedRequests(t *testing.T) {
	cfg := config.HTTPConfig{
		Enabled:   true,
		Bind:      "127.0.0.1:0",
		AuthToken: "shared-secret-token",
	}
	server := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Burn the per-IP budget with unauthenticated requests. The exact max
	// lives in apiRateLimitMaxRequests; use it directly to stay in sync if
	// the constant ever changes.
	var lastStatus int
	for i := 0; i < apiRateLimitMaxRequests+1; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
		// Route every simulated request from the same source IP.
		req.RemoteAddr = "203.0.113.10:40000"
		rec := httptest.NewRecorder()
		server.authMiddleware(testHandler).ServeHTTP(rec, req)
		lastStatus = rec.Code
	}

	if lastStatus != http.StatusTooManyRequests {
		t.Errorf("after %d unauthenticated /api/ requests, last status = %d, want %d (rate-limit must apply before auth)",
			apiRateLimitMaxRequests+1, lastStatus, http.StatusTooManyRequests)
	}
}

// TestDoHBypassOnlyWhenEnabled verifies the bypass is gated on the feature
// flag: if DoHEnabled=false, a request to DoHPath must NOT forward to the
// next handler (the bypass must not activate). The authMiddleware's own
// SPA fall-through handles the response in that case.
func TestDoHBypassOnlyWhenEnabled(t *testing.T) {
	cfg := config.HTTPConfig{
		Enabled:    true,
		Bind:       "127.0.0.1:0",
		AuthToken:  "shared-secret-token",
		DoHEnabled: false, // disabled
		DoHPath:    "/dns-query",
	}
	server := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	handlerCalled := false
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/dns-query", nil)
	rec := httptest.NewRecorder()
	server.authMiddleware(testHandler).ServeHTTP(rec, req)

	if handlerCalled {
		t.Error("DoH disabled: bypass should not have forwarded to the mux (handler was reached)")
	}
}
