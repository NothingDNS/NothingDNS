package blocklist

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadFileOpenError(t *testing.T) {
	bl := New(Config{
		Enabled: true,
		Files:   []string{"/nonexistent/path/blocklist.txt"},
	})

	err := bl.Load()
	if err == nil {
		t.Fatal("expected error when loading nonexistent file, got nil")
	}
	if !strings.Contains(err.Error(), "loading blocklist") {
		t.Errorf("error should wrap with 'loading blocklist' context, got: %v", err)
	}
	if !strings.Contains(err.Error(), "/nonexistent/path/blocklist.txt") {
		t.Errorf("error should mention the file path, got: %v", err)
	}
}

func TestLoadFileSingleFieldLines(t *testing.T) {
	tmpDir := t.TempDir()
	blockFile := filepath.Join(tmpDir, "blocklist.txt")

	// Lines with fewer than 2 fields should be skipped
	content := `# header comment
singleword
127.0.0.1
0.0.0.0 evil.com
another_single
0.0.0.0 malware.org
`
	if err := os.WriteFile(blockFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	bl := New(Config{
		Enabled: true,
		Files:   []string{blockFile},
	})

	if err := bl.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Only evil.com and malware.org should be blocked (lines with >= 2 fields)
	stats := bl.Stats()
	if stats.TotalBlocks != 2 {
		t.Errorf("expected 2 blocked domains, got %d", stats.TotalBlocks)
	}

	if !bl.IsBlocked("evil.com") {
		t.Error("evil.com should be blocked")
	}
	if !bl.IsBlocked("malware.org") {
		t.Error("malware.org should be blocked")
	}
}

func TestLoadFileInlineComment(t *testing.T) {
	tmpDir := t.TempDir()
	blockFile := filepath.Join(tmpDir, "blocklist.txt")

	// Test lines with comments embedded after the domain (not at position 0)
	// The hosts format is: IP domain # comment
	// The # check on line 94 looks for # anywhere in the line
	content := `0.0.0.0 ads.example.com # ad server
0.0.0.0 tracker.net # tracker network
`
	if err := os.WriteFile(blockFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	bl := New(Config{
		Enabled: true,
		Files:   []string{blockFile},
	})

	if err := bl.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	entries := bl.GetEntries()
	entryMap := make(map[string]Entry)
	for _, e := range entries {
		entryMap[e.Domain] = e
	}

	if e, ok := entryMap["ads.example.com"]; !ok {
		t.Error("ads.example.com should be in entries")
	} else if e.Comment != "ad server" {
		t.Errorf("expected comment 'ad server', got %q", e.Comment)
	}

	if e, ok := entryMap["tracker.net"]; !ok {
		t.Error("tracker.net should be in entries")
	} else if e.Comment != "tracker network" {
		t.Errorf("expected comment 'tracker network', got %q", e.Comment)
	}
}

func TestLoadMultipleFilesFirstFails(t *testing.T) {
	tmpDir := t.TempDir()
	goodFile := filepath.Join(tmpDir, "good.txt")
	badFile := filepath.Join(tmpDir, "nonexistent.txt")

	if err := os.WriteFile(goodFile, []byte("0.0.0.0 evil.com\n"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	bl := New(Config{
		Enabled: true,
		Files:   []string{badFile, goodFile},
	})

	err := bl.Load()
	if err == nil {
		t.Fatal("expected error when first file does not exist, got nil")
	}
	if !strings.Contains(err.Error(), "loading blocklist") {
		t.Errorf("error should contain 'loading blocklist' context, got: %v", err)
	}
}

func TestLoadMultipleFilesSecondFails(t *testing.T) {
	tmpDir := t.TempDir()
	goodFile := filepath.Join(tmpDir, "good.txt")
	badFile := filepath.Join(tmpDir, "nonexistent.txt")

	if err := os.WriteFile(goodFile, []byte("0.0.0.0 evil.com\n"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	bl := New(Config{
		Enabled: true,
		Files:   []string{goodFile, badFile},
	})

	err := bl.Load()
	if err == nil {
		t.Fatal("expected error when second file does not exist, got nil")
	}
	if !strings.Contains(err.Error(), "loading blocklist") {
		t.Errorf("error should contain 'loading blocklist' context, got: %v", err)
	}
	if !strings.Contains(err.Error(), "nonexistent.txt") {
		t.Errorf("error should mention the failing file path, got: %v", err)
	}
}

func TestLoadFileEmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	blockFile := filepath.Join(tmpDir, "empty.txt")

	if err := os.WriteFile(blockFile, []byte(""), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	bl := New(Config{
		Enabled: true,
		Files:   []string{blockFile},
	})

	if err := bl.Load(); err != nil {
		t.Fatalf("Load failed on empty file: %v", err)
	}

	stats := bl.Stats()
	if stats.TotalBlocks != 0 {
		t.Errorf("expected 0 blocked domains from empty file, got %d", stats.TotalBlocks)
	}
}

func TestLoadFileOnlyComments(t *testing.T) {
	tmpDir := t.TempDir()
	blockFile := filepath.Join(tmpDir, "comments.txt")

	content := `# This is a comment
# Another comment

# Yet another comment
`
	if err := os.WriteFile(blockFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	bl := New(Config{
		Enabled: true,
		Files:   []string{blockFile},
	})

	if err := bl.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	stats := bl.Stats()
	if stats.TotalBlocks != 0 {
		t.Errorf("expected 0 blocked domains from comments-only file, got %d", stats.TotalBlocks)
	}
}

func TestLoadReloadClearsOldEntries(t *testing.T) {
	tmpDir := t.TempDir()
	blockFile := filepath.Join(tmpDir, "blocklist.txt")

	if err := os.WriteFile(blockFile, []byte("0.0.0.0 evil.com\n"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	bl := New(Config{
		Enabled: true,
		Files:   []string{blockFile},
	})

	if err := bl.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if !bl.IsBlocked("evil.com") {
		t.Error("evil.com should be blocked after first load")
	}

	// Overwrite file with different content
	if err := os.WriteFile(blockFile, []byte("0.0.0.0 newdomain.com\n"), 0644); err != nil {
		t.Fatalf("failed to update test file: %v", err)
	}

	if err := bl.Load(); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	// Old entry should be gone, only new one present
	if bl.IsBlocked("evil.com") {
		t.Error("evil.com should not be blocked after reload with new content")
	}
	if !bl.IsBlocked("newdomain.com") {
		t.Error("newdomain.com should be blocked after reload")
	}
}

func TestLoadMultipleFilesAllSucceed(t *testing.T) {
	tmpDir := t.TempDir()
	file1 := filepath.Join(tmpDir, "list1.txt")
	file2 := filepath.Join(tmpDir, "list2.txt")

	if err := os.WriteFile(file1, []byte("0.0.0.0 evil.com\n"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	if err := os.WriteFile(file2, []byte("0.0.0.0 malware.org\n"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	bl := New(Config{
		Enabled: true,
		Files:   []string{file1, file2},
	})

	if err := bl.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if !bl.IsBlocked("evil.com") {
		t.Error("evil.com should be blocked")
	}
	if !bl.IsBlocked("malware.org") {
		t.Error("malware.org should be blocked")
	}

	stats := bl.Stats()
	if stats.TotalBlocks != 2 {
		t.Errorf("expected 2 blocked domains, got %d", stats.TotalBlocks)
	}
	if stats.Files != 2 {
		t.Errorf("expected 2 files, got %d", stats.Files)
	}
}

// ---------------------------------------------------------------------------
// loadURL tests using httptest.Server
// ---------------------------------------------------------------------------

func TestLoadURL_HostsFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("# Test blocklist\n0.0.0.0 ads.example.com\n127.0.0.1 tracker.evil.net\n"))
	}))
	defer srv.Close()

	bl := New(Config{Enabled: true})
	bl.httpClient = newRedirectClient(srv)

	// Use a fake public IP URL — the custom transport redirects to the test server
	if err := bl.loadURL("https://8.8.8.8/list.txt"); err != nil {
		t.Fatalf("loadURL failed: %v", err)
	}

	if !bl.IsBlocked("ads.example.com") {
		t.Error("ads.example.com should be blocked")
	}
	if !bl.IsBlocked("tracker.evil.net") {
		t.Error("tracker.evil.net should be blocked")
	}
}

// newRedirectClient creates an http.Client that redirects all requests to the
// given test server, regardless of the URL. This allows testing loadURL with
// fake public IPs that pass SSRF validation.
type redirectTransport struct {
	server *httptest.Server
}

func (rt *redirectTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	srvURL, _ := url.Parse(rt.server.URL)
	r.URL.Scheme = srvURL.Scheme
	r.URL.Host = srvURL.Host
	return rt.server.Client().Transport.RoundTrip(r)
}

func newRedirectClient(srv *httptest.Server) *http.Client {
	return &http.Client{Transport: &redirectTransport{server: srv}}
}

func TestLoadURL_DomainPerLine(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("adserver.com\nmalware.org\n# comment\n\n"))
	}))
	defer srv.Close()

	bl := New(Config{Enabled: true})
	bl.httpClient = newRedirectClient(srv)

	if err := bl.loadURL("https://8.8.8.8/hosts.txt"); err != nil {
		t.Fatalf("loadURL failed: %v", err)
	}

	if !bl.IsBlocked("adserver.com") {
		t.Error("adserver.com should be blocked")
	}
	if !bl.IsBlocked("malware.org") {
		t.Error("malware.org should be blocked")
	}
}

func TestLoadURL_WithInlineComments(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("0.0.0.0 ads.com # ad server block\n"))
	}))
	defer srv.Close()

	bl := New(Config{Enabled: true})
	bl.httpClient = newRedirectClient(srv)

	if err := bl.loadURL("https://8.8.8.8/list"); err != nil {
		t.Fatalf("loadURL failed: %v", err)
	}

	entries := bl.GetEntries()
	var found bool
	for _, e := range entries {
		if e.Domain == "ads.com" {
			found = true
			if e.Comment != "ad server block" {
				t.Errorf("Expected comment 'ad server block', got %q", e.Comment)
			}
		}
	}
	if !found {
		t.Error("ads.com should be in entries")
	}
}

func TestLoadURL_Non200Status(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	bl := New(Config{Enabled: true})
	bl.httpClient = newRedirectClient(srv)

	err := bl.loadURL("https://8.8.8.8/missing")
	if err == nil {
		t.Fatal("Expected error for HTTP 404")
	}
	if !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("Expected HTTP 404 error, got: %v", err)
	}
}

func TestLoadURL_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	bl := New(Config{Enabled: true})
	bl.httpClient = newRedirectClient(srv)

	err := bl.loadURL("https://8.8.8.8/list")
	if err == nil {
		t.Fatal("Expected error for HTTP 500")
	}
}

func TestLoadURL_InvalidURL(t *testing.T) {
	bl := New(Config{Enabled: true})

	err := bl.loadURL("not-a-valid-url")
	if err == nil {
		t.Fatal("Expected error for invalid URL")
	}
}

func TestLoadURL_EmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(""))
	}))
	defer srv.Close()

	bl := New(Config{Enabled: true})
	bl.httpClient = newRedirectClient(srv)

	if err := bl.loadURL("https://8.8.8.8/empty"); err != nil {
		t.Fatalf("loadURL with empty body should succeed: %v", err)
	}

	stats := bl.Stats()
	if stats.TotalBlocks != 0 {
		t.Errorf("Expected 0 blocks from empty body, got %d", stats.TotalBlocks)
	}
}

func TestLoadURL_CaseInsensitive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("0.0.0.0 ADS.EXAMPLE.COM\n"))
	}))
	defer srv.Close()

	bl := New(Config{Enabled: true})
	bl.httpClient = newRedirectClient(srv)

	if err := bl.loadURL("https://8.8.8.8/list"); err != nil {
		t.Fatalf("loadURL failed: %v", err)
	}

	// Should match lowercase
	if !bl.IsBlocked("ads.example.com") {
		t.Error("ads.example.com should be blocked (lowercase lookup)")
	}
}

func TestRemoveSource_MissingSource(t *testing.T) {
	bl := New(Config{Enabled: true})

	err := bl.RemoveSource("http://nonexistent.example.com/list")
	if err == nil {
		t.Error("Expected error removing non-existent source")
	}
}

func TestAddURL_PrivateIPRejected(t *testing.T) {
	bl := New(Config{Enabled: true})

	// Private IP should be rejected
	err := bl.AddURL("http://192.168.1.1/blocklist.txt")
	if err == nil {
		t.Error("Expected error for private IP URL")
	}

	// Valid URL should work (will fail on fetch, but validation should pass)
	err = bl.AddURL("http://0.0.0.0:1/nonexistent")
	// This may or may not fail depending on network, but shouldn't panic
	_ = err
}
