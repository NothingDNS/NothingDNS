package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAPISpec_ValidJSON(t *testing.T) {
	var spec map[string]interface{}
	if err := json.Unmarshal([]byte(OpenAPISpec), &spec); err != nil {
		t.Fatalf("OpenAPISpec is not valid JSON: %v", err)
	}

	// Verify required OpenAPI fields
	if v, ok := spec["openapi"]; !ok || !strings.HasPrefix(v.(string), "3.") {
		t.Error("missing or invalid openapi version")
	}
	if _, ok := spec["info"]; !ok {
		t.Error("missing info section")
	}
	if _, ok := spec["paths"]; !ok {
		t.Error("missing paths section")
	}
}

func TestOpenAPISpec_Paths(t *testing.T) {
	var spec map[string]interface{}
	if err := json.Unmarshal([]byte(OpenAPISpec), &spec); err != nil {
		t.Fatal(err)
	}

	paths := spec["paths"].(map[string]interface{})

	expectedPaths := []string{
		"/health",
		"/api/v1/status",
		"/api/v1/zones",
		"/api/v1/zones/{zone}",
		"/api/v1/zones/{zone}/records",
		"/api/v1/zones/{zone}/export",
		"/api/v1/zones/reload",
		"/api/v1/cache/stats",
		"/api/v1/cache/flush",
		"/api/v1/config/reload",
		"/api/v1/cluster/status",
		"/api/v1/cluster/nodes",
		"/api/v1/cluster/join",
		"/api/v1/cluster/leave",
		"/api/dashboard/stats",
	}

	for _, p := range expectedPaths {
		if _, ok := paths[p]; !ok {
			t.Errorf("missing path: %s", p)
		}
	}
}

func TestHandleOpenAPISpec(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/openapi.json", nil)
	w := httptest.NewRecorder()

	s.handleOpenAPISpec(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	// Verify the response is valid JSON
	var spec map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &spec); err != nil {
		t.Errorf("response is not valid JSON: %v", err)
	}
}

func TestHandleSwaggerUI(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/docs", nil)
	w := httptest.NewRecorder()

	s.handleSwaggerUI(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, `<script src="/api/docs/app.js">`) {
		t.Error("page should load the same-origin explorer script")
	}
	if !strings.Contains(body, "/api/openapi.json") {
		t.Error("response should reference /api/openapi.json")
	}
	// The CSP is script-src 'self': third-party or inline scripts would be
	// blocked in browsers (the old unpkg Swagger UI never rendered).
	if strings.Contains(body, "https://") || strings.Contains(body, "<script>") {
		t.Error("page must not load third-party resources or use inline scripts")
	}
}

func TestHandleAPIExplorerScript(t *testing.T) {
	s := &Server{}
	w := httptest.NewRecorder()
	s.handleAPIExplorerScript(w, httptest.NewRequest(http.MethodGet, "/api/docs/app.js", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("Content-Type = %q, want javascript", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "/api/openapi.json") || strings.Contains(body, "https://") {
		t.Error("script must fetch the local spec and nothing external")
	}
	if strings.Contains(body, "innerHTML") {
		t.Error("script must build DOM nodes rather than inject HTML from the spec")
	}
}

func TestOpenAPIHandlersHandleWriteError(t *testing.T) {
	s := &Server{}

	for _, tc := range []struct {
		name        string
		path        string
		handler     func(http.ResponseWriter, *http.Request)
		contentType string
	}{
		{
			name:        "openapi",
			path:        "/api/openapi.json",
			handler:     s.handleOpenAPISpec,
			contentType: "application/json",
		},
		{
			name:        "swagger",
			path:        "/api/docs",
			handler:     s.handleSwaggerUI,
			contentType: "text/html; charset=utf-8",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			w := &failingResponseWriter{header: make(http.Header)}

			tc.handler(w, req)

			if w.writes != 1 {
				t.Fatalf("writes = %d, want 1", w.writes)
			}
			if ct := w.Header().Get("Content-Type"); ct != tc.contentType {
				t.Fatalf("Content-Type = %q, want %q", ct, tc.contentType)
			}
		})
	}
}

func TestOpenAPISpec_Components(t *testing.T) {
	var spec map[string]interface{}
	if err := json.Unmarshal([]byte(OpenAPISpec), &spec); err != nil {
		t.Fatal(err)
	}

	components := spec["components"].(map[string]interface{})
	schemas := components["schemas"].(map[string]interface{})

	expectedSchemas := []string{
		"Error", "Success", "HealthResponse", "StatusResponse",
		"Zone", "ZoneDetail", "Record", "SOARecord",
		"CacheStats", "ClusterStatus", "ClusterNode",
	}
	for _, s := range expectedSchemas {
		if _, ok := schemas[s]; !ok {
			t.Errorf("missing schema: %s", s)
		}
	}
}

type failingResponseWriter struct {
	header http.Header
	writes int
	status int
}

func (w *failingResponseWriter) Header() http.Header {
	return w.header
}

func (w *failingResponseWriter) Write([]byte) (int, error) {
	w.writes++
	return 0, errors.New("write failed")
}

func (w *failingResponseWriter) WriteHeader(status int) {
	w.status = status
}
