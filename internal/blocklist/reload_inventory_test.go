package blocklist

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReloadRetainsManualInventory(t *testing.T) {
	f := filepath.Join(t.TempDir(), "list")
	if err := os.WriteFile(f, []byte("source.test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, files := range [][]string{nil, {f}} {
		b := New(Config{Enabled: true, Files: files})
		defer b.Close()
		b.AddDomain("manual.test")
		for i := 0; i < 3; i++ {
			if err := b.Reload(); err != nil {
				t.Fatal(err)
			}
			want := 1 + len(files)
			if got := b.Stats().TotalBlocks; got != want {
				t.Fatalf("stats=%d, want %d", got, want)
			}
			if got := len(b.GetEntries()); got != want {
				t.Fatalf("entries=%d, want %d", got, want)
			}
		}
		b.RemoveDomain("manual.test")
		if err := b.Reload(); err != nil {
			t.Fatal(err)
		}
		if got := len(b.GetEntries()); got != len(files) {
			t.Fatalf("removed manual entry returned: %d", got)
		}
	}
	b := New(Config{Enabled: true, Files: []string{filepath.Join(t.TempDir(), "missing")}})
	defer b.Close()
	b.AddDomain("manual.test")
	if err := b.Reload(); err == nil {
		t.Fatal("expected error")
	}
	if len(b.GetEntries()) != 1 || b.Stats().TotalBlocks != 1 {
		t.Fatal("failed reload changed inventory")
	}
}
