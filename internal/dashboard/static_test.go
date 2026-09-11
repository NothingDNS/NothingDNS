package dashboard

import (
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Test SPAHandler returns a valid handler
func TestSPAHandler(t *testing.T) {
	handler := SPAHandler()
	if handler == nil {
		t.Error("Expected non-nil handler")
	}
}

// Test SPAHandler serves index.html for unknown routes
func TestSPAHandler_ServeIndexHTML(t *testing.T) {
	handler := SPAHandler()

	req := httptest.NewRequest("GET", "/zones", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for SPA route, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "doctype html") {
		t.Errorf("Expected HTML response for SPA route, got body length %d", len(body))
	}
}

// Test SPAHandler serves assets
func TestSPAHandler_ServesAssets(t *testing.T) {
	handler := SPAHandler()

	req := httptest.NewRequest("GET", "/assets/nonexistent.js", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should attempt to serve the file (404 if doesn't exist, but not SPA fallback)
	if w.Code == http.StatusOK && w.Body.Len() == 0 {
		t.Error("Expected file server behavior for /assets/ routes")
	}
}

func TestDistFSContainsIndexHTML(t *testing.T) {
	if staticInitErr != nil {
		t.Fatalf("Expected embedded dashboard assets to initialize: %v", staticInitErr)
	}
	data, err := fs.ReadFile(DistFS, "index.html")
	if err != nil {
		t.Fatalf("Expected embedded index.html to be readable: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("Expected embedded index.html to be non-empty")
	}
	if !strings.Contains(string(data), "doctype html") {
		t.Fatal("Expected embedded index.html to contain HTML doctype")
	}
}

// Test GetLoginHTML returns non-empty string
func TestGetLoginHTML(t *testing.T) {
	html := GetLoginHTML()
	if html == "" {
		t.Error("Expected non-empty login HTML")
	}
	if !containsString(html, "NothingDNS") {
		t.Error("Expected login HTML to contain NothingDNS")
	}
	if !containsString(html, "loginForm") {
		t.Error("Expected login HTML to contain login form")
	}
}

// Helper function
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestEmptyFSOpen(t *testing.T) {
	var fs emptyFS
	_, err := fs.Open("nonexistent")
	if err == nil {
		t.Error("Open should return error")
	}
}

func TestSPAHandlerInitError(t *testing.T) {
	// Save original, restore after test
	orig := staticInitErr
	staticInitErr = fmt.Errorf("simulated init error")
	defer func() { staticInitErr = orig }()

	handler := SPAHandler()
	if handler == nil {
		t.Fatal("SPAHandler returned nil")
	}
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestNonEmptyFS(t *testing.T) {
	var fs emptyFS
	if _, ok := any(fs).(emptyFS); !ok {
		t.Error("emptyFS should be a zero-value struct")
	}
}

// Test SPA cache-control discipline: index.html must be no-cache (a cached
// stale index references rotated content-hashed assets that 404 after a
// redeploy — the classic stale-deploy SPA outage), and the content-hashed
// /assets/* files must be safe to cache forever.
func TestSPAHandlerCacheControl(t *testing.T) {
	handler := SPAHandler()

	// The SPA entry point: revalidate-always.
	req := httptest.NewRequest("GET", "/zones", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if cc := w.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Fatalf("FAIL: index response missing Cache-Control: no-cache — browsers heuristic-cache the entry point, and after a redeploy the cached stale index requests rotated assets that no longer exist (got %q)", cc)
	}

	// A content-hashed asset: safe to cache forever.
	req2 := httptest.NewRequest("GET", "/assets/geoip-Cdizku_0.js", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if cc := w2.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Fatalf("FAIL: hashed asset response missing immutable caching: got %q", cc)
	}
}
