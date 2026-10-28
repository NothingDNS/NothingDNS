package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The public spec, explorer and ODoH config endpoints are read-only: a POST, PUT or
// DELETE is 405 with an Allow header, not a 200 (F762).
func TestPublicEndpointsAllowOnlyReadMethods(t *testing.T) {
	s := &Server{}
	handlers := map[string]http.HandlerFunc{
		"/api/openapi.json": s.handleOpenAPISpec, "/api/docs": s.handleSwaggerUI,
		"/api/docs/app.js": s.handleAPIExplorerScript, "/.well-known/odoh-config": s.handleODoHConfig,
	}
	for path, h := range handlers {
		for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			rec := httptest.NewRecorder()
			h(rec, httptest.NewRequest(m, path, nil))
			if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") == "" {
				t.Errorf("%s %s: status %d Allow %q", m, path, rec.Code, rec.Header().Get("Allow"))
			}
		}
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code == http.StatusMethodNotAllowed {
			t.Errorf("GET %s: 405", path)
		}
	}
}
