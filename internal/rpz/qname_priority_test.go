package rpz

import (
	"os"
	"path/filepath"
	"testing"
)

func TestQNAMEPolicyPriorityBeforeSpecificity(t *testing.T) {
	for _, tc := range []struct {
		name             string
		exact, near, far int
		want             string
	}{
		{"higher wildcard priority", 10, 5, 1, "192.0.2.1"},
		{"higher exact priority", 1, 5, 10, "192.0.2.3"},
		{"exact wins equal priority", 1, 1, 1, "192.0.2.3"},
		{"closest wildcard wins equal priority", 10, 1, 1, "192.0.2.2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			contents := []string{"*.example.test.rpz-zone. IN A 192.0.2.1\n", "*.sub.example.test.rpz-zone. IN A 192.0.2.2\n", "www.sub.example.test.rpz-zone. IN A 192.0.2.3\n"}
			priorities := []int{tc.far, tc.near, tc.exact}
			files := []string{filepath.Join(dir, "far"), filepath.Join(dir, "near"), filepath.Join(dir, "exact")}
			policies := make(map[string]int)
			for i, file := range files {
				if err := os.WriteFile(file, []byte(contents[i]), 0600); err != nil {
					t.Fatal(err)
				}
				policies[file] = priorities[i]
			}
			e := NewEngine(Config{Enabled: true, Files: files, Policies: policies})
			if err := e.Load(); err != nil {
				t.Fatal(err)
			}
			got := e.QNAMEPolicy("WWW.SUB.EXAMPLE.TEST.")
			if got == nil || got.OverrideData != tc.want {
				t.Fatalf("selected %+v, want %s", got, tc.want)
			}
			if e.Stats().TotalMatches != 1 {
				t.Fatalf("matches = %d, want 1", e.Stats().TotalMatches)
			}
			if e.QNAMEPolicy("example.test") != nil {
				t.Fatal("wildcard matched its base name")
			}
			if e.Stats().TotalMatches != 1 {
				t.Fatal("unmatched query incremented matches")
			}
		})
	}
}
