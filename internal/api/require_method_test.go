package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// RFC 7231 §6.5.5: "The origin server MUST generate an Allow header field
// in a 405 (Method Not Allowed) response." requireMethod writes every 405
// across the whole API surface, so the Allow header must be set there.
func TestRequireMethodSetsAllowHeader(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rpz/rules", nil)

	rejected := s.requireMethod(rec, req, http.MethodGet)
	if !rejected {
		t.Fatal("FAIL: requireMethod did not reject a POST where only GET is allowed")
	}
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("FAIL: status = %d, want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != "GET" {
		t.Fatalf("FAIL: 405 response missing RFC 7231 §6.5.5 Allow header: got %q, want %q", got, "GET")
	}
}

// Multiple allowed methods must appear as a comma-separated Allow list.
func TestRequireMethodAllowHeaderListsAllMethods(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/rpz/rules", nil)

	rejected := s.requireMethod(rec, req, http.MethodGet, http.MethodPost)
	if !rejected {
		t.Fatal("FAIL: requireMethod did not reject a DELETE where only GET/POST are allowed")
	}
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("FAIL: status = %d, want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != "GET, POST" {
		t.Fatalf("FAIL: Allow = %q, want %q", got, "GET, POST")
	}
}

// An allowed method must not be rejected.
func TestRequireMethodAllowsListedMethod(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rpz/rules", nil)

	if s.requireMethod(rec, req, http.MethodGet, http.MethodPost) {
		t.Fatal("FAIL: requireMethod rejected GET although GET is allowed")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("FAIL: status = %d, want an unwritten 200", rec.Code)
	}
}
