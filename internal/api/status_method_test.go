package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// /api/v1/status is read-only: only GET and HEAD are served; every other
// method is 405 with an Allow header (F760).
func TestStatusAllowsOnlyReadMethods(t *testing.T) {
	s := &Server{}
	for method, want := range map[string]int{
		http.MethodGet: http.StatusOK, http.MethodHead: http.StatusOK,
		http.MethodPost: http.StatusMethodNotAllowed, http.MethodPut: http.StatusMethodNotAllowed,
		http.MethodDelete: http.StatusMethodNotAllowed, http.MethodPatch: http.StatusMethodNotAllowed,
	} {
		rec := httptest.NewRecorder()
		s.handleStatus(rec, httptest.NewRequest(method, "/api/v1/status", nil))
		if rec.Code != want {
			t.Errorf("%s: status %d, want %d", method, rec.Code, want)
		}
		if want == http.StatusMethodNotAllowed && rec.Header().Get("Allow") == "" {
			t.Errorf("%s: no Allow header", method)
		}
	}
}
