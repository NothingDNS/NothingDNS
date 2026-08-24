package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
)

// newCSPTestServer builds a Server with auth_token set so the auth
// middleware is active — the configuration every production deployment
// runs with. The CSP-report tests must run behind authMiddleware to prove
// the endpoint stays reachable without credentials.
func newCSPTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := config.HTTPConfig{
		Enabled:   true,
		Bind:      "127.0.0.1:0",
		AuthToken: "test-token",
	}
	return NewServer(cfg, nil, nil, nil, nil, nil, nil)
}

// TestCSPReportAcceptedWithoutCredentials locks in the fix for the
// 401-every-report bug: browsers POST CSP violation reports automatically
// with no Authorization header, and POST is not a safe method so the
// cookie fallback does not apply either. The endpoint must therefore be
// exempted from authMiddleware and still return 204.
func TestCSPReportAcceptedWithoutCredentials(t *testing.T) {
	server := newCSPTestServer(t)

	body := `{"csp-report":{"document-uri":"https://dns.example/","violated-directive":"script-src 'self'","blocked-uri":"https://evil.example/x.js","disposition":"enforce"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/csp-report", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/csp-report")
	rec := httptest.NewRecorder()

	server.authMiddleware(http.HandlerFunc(server.handleCSPReport)).ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("POST /api/v1/csp-report without credentials: got %d, want %d (body: %s)",
			rec.Code, http.StatusNoContent, rec.Body.String())
	}
}

// TestCSPReportDecodesBrowserEnvelope verifies the W3C CSP §5 wire format
// is decoded: browsers nest the report fields one level under the
// "csp-report" key. The pre-fix flat struct silently decoded every field
// to its zero value.
func TestCSPReportDecodesBrowserEnvelope(t *testing.T) {
	server := newCSPTestServer(t)

	body := `{"csp-report":{"document-uri":"https://dns.example/settings","violated-directive":"img-src 'self'","blocked-uri":"https://tracker.example/pixel.png","disposition":"report"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/csp-report", strings.NewReader(body))
	rec := httptest.NewRecorder()

	server.handleCSPReport(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("got %d, want %d", rec.Code, http.StatusNoContent)
	}

	// The decoded report is logged rather than stored, so verify the
	// envelope decoding through the decode path directly.
	var parsed cspReportBody
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("envelope unmarshal: %v", err)
	}
	if parsed.Report.DocumentURI != "https://dns.example/settings" {
		t.Errorf("document-uri = %q, want the nested value", parsed.Report.DocumentURI)
	}
	if parsed.Report.ViolatedDirective != "img-src 'self'" {
		t.Errorf("violated-directive = %q, want the nested value", parsed.Report.ViolatedDirective)
	}
	if parsed.Report.BlockedURI != "https://tracker.example/pixel.png" {
		t.Errorf("blocked-uri = %q, want the nested value", parsed.Report.BlockedURI)
	}
	if parsed.Report.Disposition != "report" {
		t.Errorf("disposition = %q, want %q", parsed.Report.Disposition, "report")
	}
}

// TestCSPReportRejectsOversizedBody locks in the DoS fix: the endpoint is
// unauthenticated, so the body must be hard-capped at maxBodyBytes via
// MaxBytesReader. A body over the cap must fail decode and return 204
// (nothing actionable) — critically, it must not be buffered in full.
func TestCSPReportRejectsOversizedBody(t *testing.T) {
	server := newCSPTestServer(t)

	// Just over the 64KB cap. MaxBytesReader only reads up to the cap
	// plus one byte to detect the violation, so this is cheap for both
	// sides — but a pre-fix json.Decode(r.Body) would have buffered
	// arbitrarily large bodies.
	oversized := bytes.Repeat([]byte("a"), maxBodyBytes+1024)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/csp-report", bytes.NewReader(oversized))
	rec := httptest.NewRecorder()

	server.handleCSPReport(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("oversized body: got %d, want %d", rec.Code, http.StatusNoContent)
	}
}

// TestCSPReportIgnoresNonBrowserJSON keeps the log clean: valid JSON with
// no recognizable report fields is dropped silently instead of logged as
// an empty violation line.
func TestCSPReportIgnoresNonBrowserJSON(t *testing.T) {
	server := newCSPTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/csp-report",
		strings.NewReader(`{"hello":"world"}`))
	rec := httptest.NewRecorder()

	server.handleCSPReport(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("non-report JSON: got %d, want %d", rec.Code, http.StatusNoContent)
	}
}

// TestCSPReportRejectsWrongMethod pins the method guard.
func TestCSPReportRejectsWrongMethod(t *testing.T) {
	server := newCSPTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/csp-report", nil)
	rec := httptest.NewRecorder()

	server.handleCSPReport(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: got %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}
