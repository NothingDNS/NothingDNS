package blocklist

import (
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
