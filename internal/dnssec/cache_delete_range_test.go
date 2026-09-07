package dnssec

import (
	"testing"
	"time"
)

// TestValidationCachePurge_MustNotDeleteDuringIteration reproduces the bug where
// Purge() calls delete(c.items, key) inside the range loop over c.items. Per the
// Go spec, deleting from a map during iteration causes the loop to "skip map
// entries" — the first delete advances the iterator arbitrarily far, leaving
// most stale entries in place.
//
// The correct pattern collects stale keys first, then deletes outside the loop.
func TestValidationCachePurge_MustNotDeleteDuringIteration(t *testing.T) {
	// Use a long TTL so Set does not auto-expire entries.
	cache := NewValidationCache(time.Hour)

	// Populate 100 entries via Set, matching the key generation used internally.
	for i := 0; i < 100; i++ {
		name := "a" + string(rune('a'+i)) + ".example.com"
		cache.Set(name, 1, ValidationSecure)
	}

	// Directly expire all entries by mutating the internal map entries.
	// This bypasses Set() key generation — we use cacheKey() directly.
	cache.mu.Lock()
	for i := 0; i < 100; i++ {
		name := "a" + string(rune('a'+i)) + ".example.com"
		key := cacheKey(name, 1)
		if entry, ok := cache.items[key]; ok {
			entry.expiresAt = time.Now().Add(-time.Hour) // definitely expired
		}
	}
	cache.mu.Unlock()

	// Verify all entries are in the map and reported as expired.
	total, expired := cache.Stats()
	if total != 100 {
		t.Fatalf("Stats total = %d, want 100", total)
	}
	if expired != 100 {
		t.Fatalf("Stats expired = %d, want 100", expired)
	}

	// Purge must remove every expired entry. With the bug (delete inside range),
	// the first delete advances the iterator past all remaining entries, so Purge
	// returns 0 and leaves all 100 entries in the map.
	purged := cache.Purge()
	if purged != 100 {
		t.Errorf("Purge returned %d, want 100", purged)
	}
	if remaining, _ := cache.Stats(); remaining != 0 {
		t.Errorf("Stats total = %d after Purge, want 0", remaining)
	}
}
