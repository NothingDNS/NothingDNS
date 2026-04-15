package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/blocklist"
	"github.com/nothingdns/nothingdns/internal/config"
)

// --- helpers ---

// newBlocklistTestServer creates a Server with an auth store (admin user) and
// optionally a blocklist. The returned *auth.User can be injected into request
// contexts via WithUser to satisfy requireOperator.
func newBlocklistTestServer(t *testing.T, bl *blocklist.Blocklist) (*Server, *auth.User) {
	t.Helper()
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	s := NewServer(cfg, nil, nil, nil, nil, nil, nil)
	s.authStore = store
	s.blocklist = bl
	user, _ := store.GetUser("admin")
	return s, user
}

// newBlocklistWithFile creates a blocklist loaded from a temp file with the
// given hosts-format content.
func newBlocklistWithFile(t *testing.T, content string) *blocklist.Blocklist {
	t.Helper()
	tmpDir := t.TempDir()
	path := tmpDir + "/blocklist.txt"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp blocklist: %v", err)
	}
	bl := blocklist.New(blocklist.Config{Enabled: true, Files: []string{path}})
	if err := bl.Load(); err != nil {
		t.Fatalf("load blocklist: %v", err)
	}
	return bl
}

// reqWithUser returns a copy of r with the given user injected into the context.
func reqWithUser(r *http.Request, u *auth.User) *http.Request {
	return r.WithContext(WithUser(r.Context(), u))
}

// =============================================================================
// handleBlocklists tests
// =============================================================================

func TestHandleBlocklists_GetNoBlocklist(t *testing.T) {
	srv, user := newBlocklistTestServer(t, nil)

	req := reqWithUser(httptest.NewRequest(http.MethodGet, "/api/v1/blocklists", nil), user)
	rec := httptest.NewRecorder()

	srv.handleBlocklists(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp BlocklistResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Enabled {
		t.Error("expected enabled=false")
	}
	if resp.TotalRules != 0 {
		t.Errorf("expected total_rules=0, got %d", resp.TotalRules)
	}
	if resp.FilesCount != 0 {
		t.Errorf("expected files_count=0, got %d", resp.FilesCount)
	}
	if resp.URLsCount != 0 {
		t.Errorf("expected urls_count=0, got %d", resp.URLsCount)
	}
}

func TestHandleBlocklists_GetWithBlocklist(t *testing.T) {
	bl := newBlocklistWithFile(t, "0.0.0.0 ad.example.com\n0.0.0.0 tracker.example.net\n")
	srv, user := newBlocklistTestServer(t, bl)

	req := reqWithUser(httptest.NewRequest(http.MethodGet, "/api/v1/blocklists", nil), user)
	rec := httptest.NewRecorder()

	srv.handleBlocklists(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp BlocklistResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Enabled {
		t.Error("expected enabled=true")
	}
	if resp.TotalRules != 2 {
		t.Errorf("expected total_rules=2, got %d", resp.TotalRules)
	}
	if resp.FilesCount != 1 {
		t.Errorf("expected files_count=1, got %d", resp.FilesCount)
	}
	if resp.URLsCount != 0 {
		t.Errorf("expected urls_count=0, got %d", resp.URLsCount)
	}
}

func TestHandleBlocklists_PostAddFile(t *testing.T) {
	// Create a temp blocklist file to add via the API.
	tmpDir := t.TempDir()
	path := tmpDir + "/extra-blocks.txt"
	content := "0.0.0.0 malware.example.com\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	bl := blocklist.New(blocklist.Config{Enabled: true})
	srv, user := newBlocklistTestServer(t, bl)

	body, _ := json.Marshal(BlocklistAddRequest{File: path})
	req := reqWithUser(httptest.NewRequest(http.MethodPost, "/api/v1/blocklists", bytes.NewReader(body)), user)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.handleBlocklists(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp MessageResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Message != "Blocklist file added" {
		t.Errorf("expected message 'Blocklist file added', got %q", resp.Message)
	}
}

func TestHandleBlocklists_PostAddURL(t *testing.T) {
	// SSRF protection rejects loopback/hostnames, so expect 400.
	bl := blocklist.New(blocklist.Config{Enabled: true})
	srv, user := newBlocklistTestServer(t, bl)

	body, _ := json.Marshal(BlocklistAddRequest{URL: "https://127.0.0.1:9999/list.txt"})
	req := reqWithUser(httptest.NewRequest(http.MethodPost, "/api/v1/blocklists", bytes.NewReader(body)), user)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.handleBlocklists(rec, req)

	// URL should be rejected by SSRF protection.
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 (SSRF rejection), got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleBlocklists_PostNoFileOrURL(t *testing.T) {
	bl := blocklist.New(blocklist.Config{Enabled: true})
	srv, user := newBlocklistTestServer(t, bl)

	body, _ := json.Marshal(BlocklistAddRequest{})
	req := reqWithUser(httptest.NewRequest(http.MethodPost, "/api/v1/blocklists", bytes.NewReader(body)), user)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.handleBlocklists(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleBlocklists_WrongMethod(t *testing.T) {
	srv, _ := newBlocklistTestServer(t, nil)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/blocklists", nil)
	rec := httptest.NewRecorder()

	srv.handleBlocklists(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHandleBlocklists_NoAuth(t *testing.T) {
	// Server with no auth store; requireOperator should return 503.
	srv := NewServer(config.HTTPConfig{Enabled: true}, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/blocklists", nil)
	rec := httptest.NewRecorder()

	srv.handleBlocklists(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestHandleBlocklists_InvalidBody(t *testing.T) {
	bl := blocklist.New(blocklist.Config{Enabled: true})
	srv, user := newBlocklistTestServer(t, bl)

	req := reqWithUser(httptest.NewRequest(http.MethodPost, "/api/v1/blocklists", bytes.NewReader([]byte("not json"))), user)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.handleBlocklists(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

// =============================================================================
// handleBlocklistActions tests
// =============================================================================

func TestHandleBlocklistActions_Toggle(t *testing.T) {
	bl := blocklist.New(blocklist.Config{Enabled: true})
	srv, user := newBlocklistTestServer(t, bl)

	req := reqWithUser(httptest.NewRequest(http.MethodPost, "/api/v1/blocklists/toggle", nil), user)
	rec := httptest.NewRecorder()

	srv.handleBlocklistActions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp MessageResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Blocklist was enabled, so toggling should disable it.
	if resp.Message != "Blocklist disabled" {
		t.Errorf("expected 'Blocklist disabled', got %q", resp.Message)
	}

	// Toggle again to re-enable.
	req2 := reqWithUser(httptest.NewRequest(http.MethodPost, "/api/v1/blocklists/toggle", nil), user)
	rec2 := httptest.NewRecorder()
	srv.handleBlocklistActions(rec2, req2)

	var resp2 MessageResponse
	if err := json.NewDecoder(rec2.Body).Decode(&resp2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp2.Message != "Blocklist enabled" {
		t.Errorf("expected 'Blocklist enabled', got %q", resp2.Message)
	}
}

func TestHandleBlocklistActions_ToggleWrongMethod(t *testing.T) {
	bl := blocklist.New(blocklist.Config{Enabled: true})
	srv, user := newBlocklistTestServer(t, bl)

	req := reqWithUser(httptest.NewRequest(http.MethodGet, "/api/v1/blocklists/toggle", nil), user)
	rec := httptest.NewRecorder()

	srv.handleBlocklistActions(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHandleBlocklistActions_Sources(t *testing.T) {
	bl := newBlocklistWithFile(t, "0.0.0.0 ad.example.com\n")
	srv, user := newBlocklistTestServer(t, bl)

	req := reqWithUser(httptest.NewRequest(http.MethodGet, "/api/v1/blocklists/sources", nil), user)
	rec := httptest.NewRecorder()

	srv.handleBlocklistActions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var sources []blocklist.SourceInfo
	if err := json.NewDecoder(rec.Body).Decode(&sources); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(sources))
	}
	if sources[0].Type != "file" {
		t.Errorf("expected type 'file', got %q", sources[0].Type)
	}
	if !sources[0].Enabled {
		t.Error("expected source to be enabled")
	}
}

func TestHandleBlocklistActions_SourcesEmpty(t *testing.T) {
	bl := blocklist.New(blocklist.Config{Enabled: true})
	srv, user := newBlocklistTestServer(t, bl)

	req := reqWithUser(httptest.NewRequest(http.MethodGet, "/api/v1/blocklists/sources", nil), user)
	rec := httptest.NewRecorder()

	srv.handleBlocklistActions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// The response body should decode as a nil/empty JSON array.
	var sources []blocklist.SourceInfo
	if err := json.NewDecoder(rec.Body).Decode(&sources); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(sources) != 0 {
		t.Errorf("expected 0 sources, got %d", len(sources))
	}
}

func TestHandleBlocklistActions_ToggleSource(t *testing.T) {
	tmpDir := t.TempDir()
	path := tmpDir + "/bl.txt"
	os.WriteFile(path, []byte("0.0.0.0 ad.example.com\n"), 0644)

	bl := blocklist.New(blocklist.Config{Enabled: true, Files: []string{path}})
	if err := bl.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	srv, user := newBlocklistTestServer(t, bl)

	url := "/api/v1/blocklists/" + path + "/toggle"
	req := reqWithUser(httptest.NewRequest(http.MethodPost, url, nil), user)
	rec := httptest.NewRecorder()

	srv.handleBlocklistActions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp MessageResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Message != "Source disabled" {
		t.Errorf("expected 'Source disabled', got %q", resp.Message)
	}
}

func TestHandleBlocklistActions_ToggleSourceWrongMethod(t *testing.T) {
	bl := blocklist.New(blocklist.Config{Enabled: true})
	srv, user := newBlocklistTestServer(t, bl)

	req := reqWithUser(httptest.NewRequest(http.MethodGet, "/api/v1/blocklists/nonexistent/toggle", nil), user)
	rec := httptest.NewRecorder()

	srv.handleBlocklistActions(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHandleBlocklistActions_ToggleSourceNotFound(t *testing.T) {
	bl := blocklist.New(blocklist.Config{Enabled: true})
	srv, user := newBlocklistTestServer(t, bl)

	req := reqWithUser(httptest.NewRequest(http.MethodPost, "/api/v1/blocklists/nonexistent-source/toggle", nil), user)
	rec := httptest.NewRecorder()

	srv.handleBlocklistActions(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleBlocklistActions_DeleteSource(t *testing.T) {
	tmpDir := t.TempDir()
	path1 := tmpDir + "/list1.txt"
	path2 := tmpDir + "/list2.txt"
	os.WriteFile(path1, []byte("0.0.0.0 ad.example.com\n"), 0644)
	os.WriteFile(path2, []byte("0.0.0.0 tracker.example.net\n"), 0644)

	bl := blocklist.New(blocklist.Config{Enabled: true, Files: []string{path1, path2}})
	if err := bl.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	srv, user := newBlocklistTestServer(t, bl)

	url := "/api/v1/blocklists/" + path1
	req := reqWithUser(httptest.NewRequest(http.MethodDelete, url, nil), user)
	rec := httptest.NewRecorder()

	srv.handleBlocklistActions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp MessageResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Message != "Blocklist source removed" {
		t.Errorf("expected 'Blocklist source removed', got %q", resp.Message)
	}
}

func TestHandleBlocklistActions_DeleteSourceNotFound(t *testing.T) {
	bl := blocklist.New(blocklist.Config{Enabled: true})
	srv, user := newBlocklistTestServer(t, bl)

	req := reqWithUser(httptest.NewRequest(http.MethodDelete, "/api/v1/blocklists/nonexistent", nil), user)
	rec := httptest.NewRecorder()

	srv.handleBlocklistActions(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleBlocklistActions_NoBlocklist(t *testing.T) {
	srv, user := newBlocklistTestServer(t, nil)

	req := reqWithUser(httptest.NewRequest(http.MethodPost, "/api/v1/blocklists/toggle", nil), user)
	rec := httptest.NewRecorder()

	srv.handleBlocklistActions(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestHandleBlocklistActions_NotFound(t *testing.T) {
	bl := blocklist.New(blocklist.Config{Enabled: true})
	srv, user := newBlocklistTestServer(t, bl)

	// GET on an unknown sub-path that does not match any known pattern.
	req := reqWithUser(httptest.NewRequest(http.MethodGet, "/api/v1/blocklists/unknown-action", nil), user)
	rec := httptest.NewRecorder()

	srv.handleBlocklistActions(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestHandleBlocklistActions_NoAuth(t *testing.T) {
	// No auth store set; requireOperator should return 503.
	srv := NewServer(config.HTTPConfig{Enabled: true}, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/blocklists/toggle", nil)
	rec := httptest.NewRecorder()

	srv.handleBlocklistActions(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestHandleBlocklistActions_ForbiddenRole(t *testing.T) {
	// Viewer role should not have operator access.
	store := newAuthStoreWithUser(t, "viewer", "pass123", auth.RoleViewer)
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)
	srv.authStore = store
	srv.blocklist = blocklist.New(blocklist.Config{Enabled: true})

	viewerUser, _ := store.GetUser("viewer")
	req := reqWithUser(httptest.NewRequest(http.MethodPost, "/api/v1/blocklists/toggle", nil), viewerUser)
	rec := httptest.NewRecorder()

	srv.handleBlocklistActions(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestHandleBlocklists_GetStatsAfterToggle(t *testing.T) {
	// Verify that toggle changes the enabled state reflected in subsequent GET stats.
	bl := newBlocklistWithFile(t, "0.0.0.0 ad.example.com\n")
	srv, user := newBlocklistTestServer(t, bl)

	// Toggle to disable.
	req := reqWithUser(httptest.NewRequest(http.MethodPost, "/api/v1/blocklists/toggle", nil), user)
	rec := httptest.NewRecorder()
	srv.handleBlocklistActions(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("toggle: expected 200, got %d", rec.Code)
	}

	// GET stats should now show enabled=false.
	getReq := reqWithUser(httptest.NewRequest(http.MethodGet, "/api/v1/blocklists", nil), user)
	getRec := httptest.NewRecorder()
	srv.handleBlocklists(getRec, getReq)

	var resp BlocklistResponse
	if err := json.NewDecoder(getRec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Enabled {
		t.Error("expected enabled=false after toggle")
	}
}

func TestHandleBlocklistActions_SourcesWithMultipleFiles(t *testing.T) {
	tmpDir := t.TempDir()
	path1 := tmpDir + "/ads.txt"
	path2 := tmpDir + "/malware.txt"
	os.WriteFile(path1, []byte("0.0.0.0 ad.example.com\n"), 0644)
	os.WriteFile(path2, []byte("0.0.0.0 malware.example.net\n0.0.0.0 virus.example.org\n"), 0644)

	bl := blocklist.New(blocklist.Config{Enabled: true, Files: []string{path1, path2}})
	if err := bl.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	srv, user := newBlocklistTestServer(t, bl)

	req := reqWithUser(httptest.NewRequest(http.MethodGet, "/api/v1/blocklists/sources", nil), user)
	rec := httptest.NewRecorder()

	srv.handleBlocklistActions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var sources []blocklist.SourceInfo
	if err := json.NewDecoder(rec.Body).Decode(&sources); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(sources) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(sources))
	}
}

func TestHandleBlocklists_PUTMethodNotAllowed(t *testing.T) {
	srv, _ := newBlocklistTestServer(t, nil)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/blocklists", nil)
	rec := httptest.NewRecorder()

	srv.handleBlocklists(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}
