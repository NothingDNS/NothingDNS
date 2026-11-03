package rpz

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewEngineCopiesConfigCollections(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.zone")
	if err := os.WriteFile(path, []byte("bad.example 60 IN CNAME .\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	files := []string{path}
	policies := map[string]int{path: 7}
	e := NewEngine(Config{Enabled: true, Files: files, Policies: policies})

	files[0] = filepath.Join(dir, "missing.zone")
	policies[path] = 99
	policies["injected"] = 1
	if err := e.Load(); err != nil {
		t.Fatalf("Load followed caller-mutated file slice: %v", err)
	}
	got := e.GetPolicies()
	if got[path] != 7 || len(got) != 1 {
		t.Fatalf("engine policies changed through caller map: %#v", got)
	}
}
