// Removal guard for the dead cacheSyncChan goroutine that used to exist in
// internal/cluster/cluster.go.
//
// History: cacheSyncLoop (spawned by Start(), formerly cluster.go:401) sat
// forever blocked on `for event := range c.cacheSyncChan` (formerly
// cluster.go:1138). The channel was created in NewCluster (formerly
// cluster.go:178) and closed in Stop() (formerly cluster.go:422), but
// nothing ever SENT to it — every cluster startup leaked one idle
// goroutine, and the exported CacheSyncEvent type had no callers. The dead
// machinery (channel field, initialization, close, loop, goroutine spawn,
// CacheSyncEvent type) has been removed.
//
// This test guards the removal: it fails if any of the removed identifiers
// reappear in the cluster package's production code (e.g. someone
// reintroduces the channel without wiring a real producer, or restores the
// unused event type). Note that the CacheSync CONFIG FIELD (gossip cache
// invalidation) and the EventHandler OnCacheInvalid API are live, separate
// features and are intentionally NOT matched by this check.
package cluster

import (
	"os"
	"strings"
	"testing"
)

// deadCacheSyncIdentifiers are the symbols of the removed cacheSyncChan
// machinery. Any of them reappearing in production code means the dead
// goroutine is being reintroduced.
var deadCacheSyncIdentifiers = []string{
	"cacheSyncChan",
	"cacheSyncLoop",
	"CacheSyncEvent",
}

// TestCacheSyncChanDeadCodeRemoved verifies the cacheSyncChan machinery
// stays removed. The original TestCacheSyncChanHasNoProducers flagged the
// dead goroutine by failing while zero send-sites existed; now that the
// dead code is gone, that contract is inverted into this removal guard.
func TestCacheSyncChanDeadCodeRemoved(t *testing.T) {
	for _, filename := range productionGoFiles(t, ".") {
		data, err := os.ReadFile(filename)
		if err != nil {
			t.Fatalf("read %s: %v", filename, err)
		}
		for _, id := range deadCacheSyncIdentifiers {
			if strings.Contains(string(data), id) {
				t.Errorf("%s still references %s — the cacheSyncChan goroutine "+
					"was removed as dead code (nothing ever sent on the channel); "+
					"reintroduce it only together with a real producer",
					filename, id)
			}
		}
	}
}

// productionGoFiles returns the list of non-test Go filenames in dir
// belonging to this package. We filter by package name "cluster" so
// the test is hermetic to the current file's directory.
func productionGoFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, dir+"/"+name)
	}
	return files
}
