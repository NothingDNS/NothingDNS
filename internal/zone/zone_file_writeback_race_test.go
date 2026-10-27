package zone

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// F727: concurrent write-backs could rename an older snapshot over a newer
// one. Writer A takes its snapshot (record a only) and is held before it
// replaces the file; later mutations then write back; A is released last.
// The file must hold every mutation.
func TestWriteBackKeepsLatestSnapshot(t *testing.T) {
	run := func(t *testing.T, names []string) string {
		dir := t.TempDir()
		path := filepath.Join(dir, "f727.test.zone")
		text := "$ORIGIN f727.test.\n$TTL 300\n@ IN SOA ns1 h 1 3600 600 604800 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\n"
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		m := NewManager()
		if err := m.Load("f727.test.", path); err != nil {
			t.Fatal(err)
		}
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		zoneFileSnapshotHook = func(string) {
			first := false
			once.Do(func() { first = true })
			if first {
				close(entered)
				<-release
			}
		}
		defer func() { zoneFileSnapshotHook = nil }()

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = m.AddRecord("f727.test.", Record{Name: names[0], Type: "A", TTL: 300, RData: "192.0.2.10"})
		}()
		<-entered
		for _, n := range names[1:] {
			wg.Add(1)
			go func(n string) {
				defer wg.Done()
				_ = m.AddRecord("f727.test.", Record{Name: n, Type: "A", TTL: 300, RData: "192.0.2.11"})
			}(n)
		}
		// Wait (state, not ordering) until every later mutation is in memory.
		for {
			z, _ := m.Get("f727.test.")
			all := true
			for _, n := range names[1:] {
				if len(z.Lookup(n+".f727.test.", "A")) == 0 {
					all = false
				}
			}
			if all {
				break
			}
			runtime.Gosched()
		}
		close(release)
		wg.Wait()
		b, _ := os.ReadFile(path)
		return string(b)
	}
	for _, tc := range [][]string{{"a", "b"}, {"a", "b", "c", "d"}} {
		got := run(t, tc)
		for _, n := range tc {
			if !strings.Contains(got, "\n"+n+"\t") {
				t.Fatalf("%v: file lacks %s after the held writer finished:\n%s", tc, n, got)
			}
		}
	}
}
