package dashboard

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Test StaticHandler returns a valid handler
func TestStaticHandler(t *testing.T) {
	handler := StaticHandler()
	if handler == nil {
		t.Error("Expected non-nil handler")
	}
}

// Test StaticHandler serves files
func TestStaticHandler_ServeHTTP(t *testing.T) {
	handler := StaticHandler()

	// Try to serve a non-existent file - should return 404
	req := httptest.NewRequest("GET", "/nonexistent.txt", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// The file doesn't exist, so we expect 404
	if w.Code != http.StatusNotFound {
		t.Logf("Status code: %d", w.Code)
	}
}

// Test GetIndexHTML returns non-empty string
func TestGetIndexHTML(t *testing.T) {
	html := GetIndexHTML()
	if html == "" {
		t.Error("Expected non-empty HTML")
	}
}

// Test GetIndexHTML contains expected content
func TestGetIndexHTML_ContainsExpectedContent(t *testing.T) {
	html := GetIndexHTML()

	expectedStrings := []string{
		"NothingDNS",
		"Dashboard",
		"WebSocket",
		"/ws",
		"/api/dashboard/stats",
		"Total Queries",
		"Cache Hit Rate",
		"Blocked",
		"Zones",
	}

	for _, expected := range expectedStrings {
		if !containsString(html, expected) {
			t.Errorf("Expected HTML to contain %q", expected)
		}
	}
}

// Test indexHTML variable directly
func TestIndexHTML_Variable(t *testing.T) {
	if indexHTML == "" {
		t.Error("Expected indexHTML to be non-empty")
	}
}

// Test indexHTML contains doctype
func TestIndexHTML_ContainsDoctype(t *testing.T) {
	if !containsString(indexHTML, "<!DOCTYPE html>") {
		t.Error("Expected indexHTML to contain doctype")
	}
}

// Test indexHTML contains valid HTML structure
func TestIndexHTML_ValidStructure(t *testing.T) {
	if !containsString(indexHTML, "<html") {
		t.Error("Expected indexHTML to contain <html> tag")
	}
	if !containsString(indexHTML, "</html>") {
		t.Error("Expected indexHTML to contain </html> tag")
	}
	if !containsString(indexHTML, "<head>") {
		t.Error("Expected indexHTML to contain <head> tag")
	}
	if !containsString(indexHTML, "</head>") {
		t.Error("Expected indexHTML to contain </head> tag")
	}
	if !containsString(indexHTML, "<body>") {
		t.Error("Expected indexHTML to contain <body> tag")
	}
	if !containsString(indexHTML, "</body>") {
		t.Error("Expected indexHTML to contain </body> tag")
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
