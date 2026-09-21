// Round-005 proof: Blocklist.Load() must be all-or-nothing. The current
// implementation clears entries and sourceEntries before iterating the
// configured files and URLs, so a load error in any source leaves the
// blocklist with zero entries (or only entries from sources that loaded
// before the failure) — silently destroying the previous rule set.
//
// Pre-fix expected: after a successful Load() with N files, then a
// modified file that fails to open, the blocklist loses all
// previously-loaded entries.
// Post-fix expected: the blocklist retains the full previous rule set.
package blocklist

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProofRound005_LoadAtomicity(t *testing.T) {
	dir := t.TempDir()

	// Two well-formed blocklist files with different domains.
	fileA := filepath.Join(dir, "a.list")
	if err := os.WriteFile(fileA, []byte("a.example.com\n"), 0o644); err != nil {
		t.Fatalf("write a: %v", err)
	}
	fileB := filepath.Join(dir, "b.list")
	if err := os.WriteFile(fileB, []byte("b.example.com\n"), 0o644); err != nil {
		t.Fatalf("write b: %v", err)
	}

	bl := New(Config{
		Enabled: true,
		Files:   []string{fileA, fileB},
	})
	if err := bl.Load(); err != nil {
		t.Fatalf("initial Load: %v", err)
	}

	// Sanity: both domains blocked after the initial load.
	if !bl.IsBlocked("a.example.com") {
		t.Fatalf("setup: expected a.example.com blocked")
	}
	if !bl.IsBlocked("b.example.com") {
		t.Fatalf("setup: expected b.example.com blocked")
	}

	// Replace fileA with a directory so the next Load() fails at os.Open.
	// loadFile only returns an error for os.Open failures or scanner.Err();
	// the hosts-file parser is permissive. Using a directory forces
	// os.Open to return EISDIR, which Load() propagates.
	if err := os.Remove(fileA); err != nil {
		t.Fatalf("remove a: %v", err)
	}
	if err := os.Mkdir(fileA, 0o755); err != nil {
		t.Fatalf("mkdir a: %v", err)
	}

	// Reload. The corruption should cause loadFile(fileA) to fail.
	// Pre-fix, the blocklist's entries map was cleared at line 141
	// before the loop, so the previous rule set is destroyed.
	err := bl.Load()
	if err == nil {
		t.Fatalf("setup: expected Load() to fail after replacing fileA with a directory")
	}

	// The contract: after a failed Load(), the blocklist must still hold
	// the previous full rule set. Pre-fix, entries were cleared before
	// the loop, so they are gone.
	if !bl.IsBlocked("a.example.com") {
		t.Fatalf("FAIL: after a failed Load() (err=%v), a.example.com is no longer blocked. "+
			"Load() must be all-or-nothing: a load error in any file must leave the previous full rule set intact.",
			err)
	}
	if !bl.IsBlocked("b.example.com") {
		t.Fatalf("FAIL: after a failed Load() (err=%v), b.example.com is no longer blocked. "+
			"Load() must be all-or-nothing.",
			err)
	}

	t.Logf("PROOF PASS: after a failed Load(), the blocklist retained the full previous rule set (a and b)")
}
