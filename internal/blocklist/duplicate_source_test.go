package blocklist

import (
	"os"
	"path/filepath"
	"testing"
)

// Adding a source that is already registered must refresh it, not register it
// a second time: RemoveSource drops one registration, so a duplicate left the
// source listed (with no domains) after it was "removed".
func TestAddFileTwiceRegistersSourceOnce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(path, []byte("0.0.0.0 a.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bl := New(Config{Enabled: true, BaseDir: dir})
	if err := bl.AddFile(path); err != nil {
		t.Fatal(err)
	}

	// Refreshing picks up the edited file.
	if err := os.WriteFile(path, []byte("0.0.0.0 a.example\n0.0.0.0 b.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := bl.AddFile(path); err != nil {
		t.Fatal(err)
	}
	if !bl.IsBlocked("b.example") {
		t.Fatal("control: second AddFile did not load the new domain")
	}

	if got := bl.ListFiles(); len(got) != 1 {
		t.Fatalf("FAIL: file registered %d times: %v", len(got), got)
	}
	if err := bl.RemoveSource(path); err != nil {
		t.Fatal(err)
	}
	if got := bl.GetSources(); len(got) != 0 {
		t.Fatalf("FAIL: source still listed after RemoveSource: %+v", got)
	}
	if bl.IsBlocked("a.example") {
		t.Fatal("removed source still blocks")
	}
}
