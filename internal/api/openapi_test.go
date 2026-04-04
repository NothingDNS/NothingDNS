package api

import (
	"encoding/json"
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
	if !strings.Contains(w.Body.String(), "swagger-ui") {
		t.Error("response should contain swagger-ui reference")
	}
	if !strings.Contains(w.Body.String(), "/api/openapi.json") {
		t.Error("response should reference /api/openapi.json")
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
