package blocklist

import (
	"os"
	"path/filepath"
	"testing"
)

// Removing one source must leave the entry set describing everything that is
// still blocked: the other sources and the manually added domains. Stats and
// GetEntries (the API's total rule count) read it.
func TestRemoveSourceKeepsRemainingEntries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		remove func(bl *Blocklist, path string) error
	}{
		{"RemoveSource", func(bl *Blocklist, p string) error { return bl.RemoveSource(p) }},
		{"RemoveFile", func(bl *Blocklist, p string) error { return bl.RemoveFile(p) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			f1 := filepath.Join(dir, "one.txt")
			f2 := filepath.Join(dir, "two.txt")
			if err := os.WriteFile(f1, []byte("0.0.0.0 a.example\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f2, []byte("0.0.0.0 b.example\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			bl := New(Config{Enabled: true, Files: []string{f1, f2}})
			if err := bl.Load(); err != nil {
				t.Fatal(err)
			}
			bl.AddDomain("manual.example")

			if got := bl.Stats().TotalBlocks; got != 3 {
				t.Fatalf("control: TotalBlocks = %d, want 3", got)
			}
			if err := tc.remove(bl, f2); err != nil {
				t.Fatal(err)
			}

			// Control: blocking itself is unaffected.
			for _, d := range []string{"a.example", "manual.example"} {
				if !bl.IsBlocked(d) {
					t.Fatalf("control: %s no longer blocked", d)
				}
			}
			if bl.IsBlocked("b.example") {
				t.Fatal("removed source still blocks b.example")
			}
			if got := bl.Stats().TotalBlocks; got != 2 {
				t.Fatalf("FAIL: TotalBlocks = %d after removing one of two files, want 2 (a.example + manual.example)", got)
			}
		})
	}
}
