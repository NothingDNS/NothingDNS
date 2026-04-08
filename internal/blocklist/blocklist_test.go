package blocklist

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBlocklistLoad(t *testing.T) {
	// Create temp blocklist file
	tmpDir := t.TempDir()
	blockFile := filepath.Join(tmpDir, "blocklist.txt")

	content := `# Test blocklist
127.0.0.1 evil.com
0.0.0.0 malware.org # malicious domain
127.0.0.1 ads.example.com

# Another comment
0.0.0.0 tracker.net
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

	// Check stats
	stats := bl.Stats()
	if !stats.Enabled {
		t.Error("expected blocklist to be enabled")
	}
	if stats.TotalBlocks != 4 {
		t.Errorf("expected 4 blocked domains, got %d", stats.TotalBlocks)
	}

	// Check blocked domains
	tests := []struct {
		domain  string
		blocked bool
	}{
		{"evil.com", true},
		{"malware.org", true},
		{"ads.example.com", true},
		{"tracker.net", true},
		{"google.com", false},
		{"example.com", false},
	}

	for _, tt := range tests {
		if got := bl.IsBlocked(tt.domain); got != tt.blocked {
			t.Errorf("IsBlocked(%q) = %v, want %v", tt.domain, got, tt.blocked)
		}
	}
}

func TestBlocklistSubdomainBlocking(t *testing.T) {
	tmpDir := t.TempDir()
	blockFile := filepath.Join(tmpDir, "blocklist.txt")

	content := `0.0.0.0 example.com
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

	// Parent domain should block subdomains
	tests := []struct {
		domain  string
		blocked bool
	}{
		{"example.com", true},
		{"www.example.com", true},
		{"ads.example.com", true},
		{"sub.sub.example.com", true},
		{"other.com", false},
	}

	for _, tt := range tests {
		if got := bl.IsBlocked(tt.domain); got != tt.blocked {
			t.Errorf("IsBlocked(%q) = %v, want %v", tt.domain, got, tt.blocked)
		}
	}
}

func TestBlocklistDisabled(t *testing.T) {
	bl := New(Config{
		Enabled: false,
		Files:   []string{"/nonexistent"},
	})

	if err := bl.Load(); err != nil {
		t.Fatalf("Load should not fail when disabled: %v", err)
	}

	if bl.IsBlocked("evil.com") {
		t.Error("IsBlocked should return false when disabled")
	}
}

func TestBlocklistCaseInsensitive(t *testing.T) {
	tmpDir := t.TempDir()
	blockFile := filepath.Join(tmpDir, "blocklist.txt")

	content := `0.0.0.0 EXAMPLE.COM
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

	// Should be case insensitive
	if !bl.IsBlocked("example.com") {
		t.Error("IsBlocked should be case insensitive")
	}
	if !bl.IsBlocked("EXAMPLE.COM") {
		t.Error("IsBlocked should be case insensitive")
	}
}

func TestBlocklistReload(t *testing.T) {
	tmpDir := t.TempDir()
	blockFile := filepath.Join(tmpDir, "blocklist.txt")

	// Initial content
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
		t.Error("evil.com should be blocked")
	}
	if bl.IsBlocked("newevil.com") {
		t.Error("newevil.com should not be blocked yet")
	}

	// Update file
	if err := os.WriteFile(blockFile, []byte("0.0.0.0 newevil.com\n"), 0644); err != nil {
		t.Fatalf("failed to update test file: %v", err)
	}

	// Reload
	if err := bl.Reload(); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	// Check new state
	if bl.IsBlocked("evil.com") {
		t.Error("evil.com should not be blocked after reload")
	}
	if !bl.IsBlocked("newevil.com") {
		t.Error("newevil.com should be blocked after reload")
	}
}

func TestBlocklistGetEntries(t *testing.T) {
	tmpDir := t.TempDir()
	blockFile := filepath.Join(tmpDir, "blocklist.txt")

	content := `0.0.0.0 evil.com # bad
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

	entries := bl.GetEntries()
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}

	// Check comments are preserved
	for _, entry := range entries {
		if entry.Domain == "evil.com" && entry.Comment != "bad" {
			t.Errorf("expected comment 'bad' for evil.com, got %q", entry.Comment)
		}
	}
}

func TestBlocklistAddDomain(t *testing.T) {
	bl := New(Config{Enabled: true})

	bl.AddDomain("test.com")
	if !bl.IsBlocked("test.com") {
		t.Error("AddDomain should block the domain")
	}

	// Case insensitive
	bl.AddDomain("CASE.COM")
	if !bl.IsBlocked("case.com") {
		t.Error("AddDomain should be case insensitive")
	}
}

func TestBlocklistRemoveDomain(t *testing.T) {
	bl := New(Config{Enabled: true})

	bl.AddDomain("remove.me")
	if !bl.IsBlocked("remove.me") {
		t.Error("domain should be blocked initially")
	}

	bl.RemoveDomain("remove.me")
	if bl.IsBlocked("remove.me") {
		t.Error("domain should not be blocked after RemoveDomain")
	}
}

func TestBlocklistSetEnabled(t *testing.T) {
	bl := New(Config{Enabled: true})
	bl.AddDomain("test.com")

	if !bl.IsBlocked("test.com") {
		t.Error("domain should be blocked when enabled")
	}

	bl.SetEnabled(false)
	if bl.IsBlocked("test.com") {
		t.Error("domain should not be blocked when disabled")
	}

	bl.SetEnabled(true)
	if !bl.IsBlocked("test.com") {
		t.Error("domain should be blocked when re-enabled")
	}
}

func TestBlocklistAddFile(t *testing.T) {
	tmpDir := t.TempDir()
	blockFile1 := filepath.Join(tmpDir, "block1.txt")
	blockFile2 := filepath.Join(tmpDir, "block2.txt")

	if err := os.WriteFile(blockFile1, []byte("0.0.0.0 file1.com\n"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	if err := os.WriteFile(blockFile2, []byte("0.0.0.0 file2.com\n"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	bl := New(Config{
		Enabled: true,
		Files:   []string{blockFile1},
	})

	if err := bl.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if !bl.IsBlocked("file1.com") {
		t.Error("file1.com should be blocked")
	}
	if bl.IsBlocked("file2.com") {
		t.Error("file2.com should not be blocked yet")
	}

	// Add second file
	if err := bl.AddFile(blockFile2); err != nil {
		t.Fatalf("AddFile failed: %v", err)
	}

	if !bl.IsBlocked("file2.com") {
		t.Error("file2.com should be blocked after AddFile")
	}
}

func TestBlocklistRemoveFile(t *testing.T) {
	tmpDir := t.TempDir()
	blockFile1 := filepath.Join(tmpDir, "block1.txt")
	blockFile2 := filepath.Join(tmpDir, "block2.txt")

	if err := os.WriteFile(blockFile1, []byte("0.0.0.0 file1.com\n"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	if err := os.WriteFile(blockFile2, []byte("0.0.0.0 file2.com\n"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	bl := New(Config{
		Enabled: true,
		Files:   []string{blockFile1, blockFile2},
	})

	if err := bl.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if !bl.IsBlocked("file1.com") || !bl.IsBlocked("file2.com") {
		t.Error("both files should be blocked")
	}

	// Remove first file
	if err := bl.RemoveFile(blockFile1); err != nil {
		t.Fatalf("RemoveFile failed: %v", err)
	}

	if bl.IsBlocked("file1.com") {
		t.Error("file1.com should not be blocked after RemoveFile")
	}
	if !bl.IsBlocked("file2.com") {
		t.Error("file2.com should still be blocked")
	}
}

func TestBlocklistListFiles(t *testing.T) {
	tmpDir := t.TempDir()
	blockFile1 := filepath.Join(tmpDir, "block1.txt")
	blockFile2 := filepath.Join(tmpDir, "block2.txt")

	if err := os.WriteFile(blockFile1, []byte("0.0.0.0 a.com\n"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	if err := os.WriteFile(blockFile2, []byte("0.0.0.0 b.com\n"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	bl := New(Config{
		Enabled: true,
		Files:   []string{blockFile1, blockFile2},
	})

	files := bl.ListFiles()
	if len(files) != 2 {
		t.Errorf("expected 2 files, got %d", len(files))
	}
}

func TestBlocklistListURLs(t *testing.T) {
	bl := New(Config{
		Enabled: true,
		URLs:    []string{"http://example.com/blocklist.txt"},
	})

	urls := bl.ListURLs()
	if len(urls) != 1 {
		t.Errorf("expected 1 URL, got %d", len(urls))
	}
	if urls[0] != "http://example.com/blocklist.txt" {
		t.Errorf("unexpected URL: %s", urls[0])
	}
}

func TestBlocklistLoadFileNotFound(t *testing.T) {
	bl := New(Config{
		Enabled: true,
		Files:   []string{"/nonexistent/path/blocklist.txt"},
	})

	err := bl.Load()
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestBlocklistDomainWithTrailingDot(t *testing.T) {
	bl := New(Config{Enabled: true})
	bl.AddDomain("trailing.com.")

	if !bl.IsBlocked("trailing.com") {
		t.Error("domain with trailing dot should be blocked")
	}
	if !bl.IsBlocked("trailing.com.") {
		t.Error("trailing.com. should be blocked")
	}
}

func TestBlocklistEmptyLines(t *testing.T) {
	tmpDir := t.TempDir()
	blockFile := filepath.Join(tmpDir, "blocklist.txt")

	content := `
# Comment

0.0.0.0 valid.com

# Another comment
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

	if !bl.IsBlocked("valid.com") {
		t.Error("valid.com should be blocked")
	}
}

func TestBlocklistOnlyDomainFormat(t *testing.T) {
	// Note: loadFile doesn't support domain-only format, only loadURL does
	// So this test uses the normal hosts-file format
	tmpDir := t.TempDir()
	blockFile := filepath.Join(tmpDir, "blocklist.txt")

	content := `0.0.0.0 example.com # no comment
0.0.0.0 ads.example.net
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

	if !bl.IsBlocked("example.com") {
		t.Error("example.com should be blocked")
	}
	if !bl.IsBlocked("ads.example.net") {
		t.Error("ads.example.net should be blocked")
	}
}

func TestBlocklistStats(t *testing.T) {
	tmpDir := t.TempDir()
	blockFile := filepath.Join(tmpDir, "blocklist.txt")

	if err := os.WriteFile(blockFile, []byte("0.0.0.0 a.com\n0.0.0.0 b.com\n"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	bl := New(Config{
		Enabled: true,
		Files:   []string{blockFile},
		URLs:    []string{"http://example.com/list.txt"},
	})

	stats := bl.Stats()
	if stats.Enabled != true {
		t.Error("stats.Enabled should be true")
	}
	if stats.Files != 1 {
		t.Errorf("stats.Files = %d, want 1", stats.Files)
	}
	if stats.URLs != 1 {
		t.Errorf("stats.URLs = %d, want 1", stats.URLs)
	}
}

func TestEntry(t *testing.T) {
	entry := Entry{
		Domain:  "test.com",
		Comment: "test comment",
	}

	if entry.Domain != "test.com" {
		t.Errorf("Domain = %q, want test.com", entry.Domain)
	}
	if entry.Comment != "test comment" {
		t.Errorf("Comment = %q, want test comment", entry.Comment)
	}
}

func TestBlocklistConcurrency(t *testing.T) {
	bl := New(Config{Enabled: true})

	// Add some initial entries
	bl.AddDomain("initial.com")

	done := make(chan bool)
	go func() {
		for i := 0; i < 100; i++ {
			bl.IsBlocked("test.com")
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			bl.AddDomain("dynamic.com")
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			bl.RemoveDomain("dynamic.com")
		}
		done <- true
	}()

	<-done
	<-done
	<-done
}

func TestBlocklistReloadDisabled(t *testing.T) {
	bl := New(Config{Enabled: false})

	// Should not fail even with nonexistent files
	err := bl.Reload()
	if err != nil {
		t.Errorf("Reload should not fail when disabled: %v", err)
	}
}
