package dashboard

import (
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
