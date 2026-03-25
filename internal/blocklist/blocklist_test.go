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
