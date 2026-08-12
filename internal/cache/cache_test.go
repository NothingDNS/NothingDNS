package cache

import (
	"fmt"
	"hash/maphash"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// keysForShard generates n distinct keys whose maphash lands in the given
// shard index. Used by LRU-semantics tests that need entries to share a
// shard so per-shard eviction is deterministic.
func keysForShard(shardIdx, n int) []string {
	keys := make([]string, 0, n)
	for i := 0; len(keys) < n; i++ {
		k := fmt.Sprintf("k%d.example.com:1", i)
		if int(maphash.String(shardSeed, k)&shardMask) == shardIdx {
			keys = append(keys, k)
		}
	}
	return keys
}

func TestCacheBasic(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	c := New(config)

	// Create a simple test entry (no protocol.Message for basic tests)
	key := "example.com:1"

	// Set entry using SetNegative for simple testing
	c.SetNegative(key, 3) // NXDOMAIN

	// Get entry
	entry := c.Get(key)
	if entry == nil {
		t.Fatal("expected to find entry")
	}

	if !entry.IsNegative {
		t.Error("expected entry to be marked as negative")
	}

	// Check stats
	stats := c.Stats()
	if stats.Hits != 1 {
		t.Errorf("expected 1 hit, got %d", stats.Hits)
	}
	if stats.Misses != 0 {
		t.Errorf("expected 0 misses, got %d", stats.Misses)
	}
}

func TestCacheMiss(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	c := New(config)

	key := "nonexistent.com:1"

	// Get non-existent entry
	entry := c.Get(key)
	if entry != nil {
		t.Error("expected nil for non-existent entry")
	}

	// Check stats
	stats := c.Stats()
	if stats.Hits != 0 {
		t.Errorf("expected 0 hits, got %d", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Errorf("expected 1 miss, got %d", stats.Misses)
	}
}

func TestCacheExpiration(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	config.MinTTL = 50 * time.Millisecond
	config.NegativeTTL = 100 * time.Millisecond
	clock := newFakeCacheClock()
	c := New(config)
	c.setClockForTest(clock)

	key := "test.com:1"
	c.SetNegative(key, 3)

	// Should exist immediately
	entry := c.Get(key)
	if entry == nil {
		t.Fatal("expected entry to exist")
	}

	clock.Advance(150 * time.Millisecond)

	// Should be expired now
	entry = c.Get(key)
	if entry != nil {
		t.Error("expected entry to be expired")
	}

	stats := c.Stats()
	if stats.Expirations != 1 {
		t.Errorf("expected 1 expiration, got %d", stats.Expirations)
	}
}

func TestCacheLRUEviction(t *testing.T) {
	// Per-shard capacity = 3 (Capacity / numShards rounded up). All four test
	// keys are forced into the same shard so eviction order is deterministic.
	config := DefaultConfig()
	config.Capacity = numShards * 3
	c := New(config)

	keys := keysForShard(0, 4)
	a, b, cKey, d := keys[0], keys[1], keys[2], keys[3]

	c.SetNegative(a, 3)
	c.SetNegative(b, 3)
	c.SetNegative(cKey, 3)

	if c.Size() != 3 {
		t.Fatalf("expected size 3, got %d", c.Size())
	}

	// Access a to make it most recently used within shard 0.
	c.Get(a)

	// Add 4th entry into the same shard — evicts the LRU (b).
	c.SetNegative(d, 3)

	if c.Size() != 3 {
		t.Errorf("expected size 3 after eviction, got %d", c.Size())
	}

	if c.Get(a) == nil {
		t.Error("expected a to still exist")
	}
	if c.Get(b) != nil {
		t.Error("expected b to be evicted")
	}

	stats := c.Stats()
	if stats.Evictions != 1 {
		t.Errorf("expected 1 eviction, got %d", stats.Evictions)
	}
}

// TestCacheRefreshExistingKeyAtCapacityDoesNotEvict regresses fc40eb7:
// when a shard is at capacity and the caller re-sets an existing key,
// the net entry count is unchanged so no eviction should occur.
// Before the fix, addEntry left the stale map entry in place while
// removing it from the LRU list — the eviction loop then saw
// len == capacity and dropped an unrelated victim every time the hot
// key refreshed.
func TestCacheRefreshExistingKeyAtCapacityDoesNotEvict(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = numShards * 3
	c := New(config)

	keys := keysForShard(0, 3)
	a, b, cKey := keys[0], keys[1], keys[2]

	c.SetNegative(a, 3)
	c.SetNegative(b, 3)
	c.SetNegative(cKey, 3)

	if got := c.Size(); got != 3 {
		t.Fatalf("setup: expected size 3, got %d", got)
	}
	if pre := c.Stats().Evictions; pre != 0 {
		t.Fatalf("setup: expected 0 evictions, got %d", pre)
	}

	// Refresh: same key set again. Should overwrite in place.
	c.SetNegative(a, 3)

	if got := c.Size(); got != 3 {
		t.Errorf("after refresh: expected size 3, got %d", got)
	}
	if ev := c.Stats().Evictions; ev != 0 {
		t.Errorf("after refresh: expected 0 evictions, got %d (regression: refresh evicted unrelated victim)", ev)
	}
	if c.Get(a) == nil {
		t.Error("expected a still present after refresh")
	}
	if c.Get(b) == nil {
		t.Error("expected b still present (would have been evicted before fix)")
	}
	if c.Get(cKey) == nil {
		t.Error("expected cKey still present (would have been evicted before fix)")
	}
}

func TestCacheNegative(t *testing.T) {
	config := DefaultConfig()
	config.MinTTL = 50 * time.Millisecond
	config.NegativeTTL = 100 * time.Millisecond
	config.Capacity = 128
	clock := newFakeCacheClock()
	c := New(config)
	c.setClockForTest(clock)

	key := "nxdomain.com:1"
	c.SetNegative(key, 3) // NXDOMAIN

	// Should find negative entry
	entry := c.Get(key)
	if entry == nil {
		t.Fatal("expected to find negative entry")
	}

	if !entry.IsNegative {
		t.Error("expected entry to be marked as negative")
	}

	if entry.RCode != 3 {
		t.Errorf("expected NXDOMAIN (3), got %v", entry.RCode)
	}

	if entry.Message != nil {
		t.Error("expected nil message for negative entry")
	}

	clock.Advance(150 * time.Millisecond)

	// Should be expired
	entry = c.Get(key)
	if entry != nil {
		t.Error("expected negative entry to expire")
	}
}

func TestCacheTTLConstraints(t *testing.T) {
	config := DefaultConfig()
	config.MinTTL = 5 * time.Second
	config.MaxTTL = 10 * time.Second
	config.NegativeTTL = 60 * time.Second
	c := New(config)

	// Test minimum TTL constraint with negative entry
	c.SetNegative("min.com:1", 3)
	entry := c.Get("min.com:1")
	if entry == nil {
		t.Fatal("expected entry")
	}
	// Entry should not expire before 4 seconds
	if entry.IsExpired(time.Now().Add(4 * time.Second)) {
		t.Error("entry expired too early (should respect minTTL)")
	}

	// Add another entry for max TTL test
	c.SetNegative("max.com:1", 3)
	entry = c.Get("max.com:1")
	if entry == nil {
		t.Fatal("expected entry")
	}
	// Entry should expire after 10 seconds (negativeTTL clamped to maxTTL)
	if !entry.IsExpired(time.Now().Add(11 * time.Second)) {
		t.Error("entry should have expired (should respect maxTTL)")
	}
}

func TestCacheDelete(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	c := New(config)

	key := "delete.com:1"

	c.SetNegative(key, 3)
	if c.Get(key) == nil {
		t.Fatal("expected entry to exist")
	}

	c.Delete(key)
	if c.Get(key) != nil {
		t.Error("expected entry to be deleted")
	}
}

func TestCacheClear(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	c := New(config)

	c.SetNegative("a.com:1", 3)
	c.SetNegative("b.com:1", 3)
	c.SetNegative("c.com:1", 3)

	if c.Size() != 3 {
		t.Fatalf("expected size 3, got %d", c.Size())
	}

	c.Clear()

	if c.Size() != 0 {
		t.Errorf("expected size 0 after clear, got %d", c.Size())
	}

	if c.Get("a.com:1") != nil {
		t.Error("expected all entries to be cleared")
	}
}

func TestCachePrefetch(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	config.PrefetchEnabled = true
	config.PrefetchThreshold = 30 * time.Second
	c := New(config)

	// We can't easily test prefetch with SetNegative since it uses negativeTTL
	// Let's test the internal logic instead

	// Create an entry directly with prefetch enabled
	c.Set("prefetch.com:1", nil, 60) // 60 second TTL

	entry := c.Get("prefetch.com:1")
	if entry == nil {
		t.Fatal("expected entry")
	}

	if !entry.CanPrefetch {
		t.Error("expected entry to be prefetchable")
	}

	// Check if prefetch is due after 31 seconds
	if !entry.ShouldPrefetch(time.Now().Add(31 * time.Second)) {
		t.Error("expected prefetch to be due")
	}

	// Check if prefetch is not due before 30 seconds
	if entry.ShouldPrefetch(time.Now().Add(29 * time.Second)) {
		t.Error("expected prefetch not to be due yet")
	}
}

func TestCachePrefetchDisabled(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	config.PrefetchEnabled = false
	c := New(config)

	c.Set("noprefetch.com:1", nil, 300)

	entry := c.Get("noprefetch.com:1")
	if entry == nil {
		t.Fatal("expected entry")
	}

	if entry.CanPrefetch {
		t.Error("expected entry not to be prefetchable when disabled")
	}
}

func TestCacheStatsHitRate(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	c := New(config)

	// 0% hit rate initially
	stats := c.Stats()
	if stats.HitRate() != 0 {
		t.Errorf("expected 0%% hit rate, got %f", stats.HitRate())
	}

	// Add entry
	c.SetNegative("stats.com:1", 3)

	// 5 hits
	for i := 0; i < 5; i++ {
		c.Get("stats.com:1")
	}

	// 5 misses
	for i := 0; i < 5; i++ {
		c.Get("missing:1")
	}

	stats = c.Stats()
	expectedRate := 50.0
	if stats.HitRate() != expectedRate {
		t.Errorf("expected %f%% hit rate, got %f", expectedRate, stats.HitRate())
	}
}

func TestCacheConcurrency(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 1280
	c := New(config)

	// Run concurrent operations
	done := make(chan bool)

	// Writers
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				key := MakeKey("test.com", uint16(j%10), false)
				c.SetNegative(key, 3)
			}
			done <- true
		}(i)
	}

	// Readers
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				key := MakeKey("test.com", uint16(j%10), false)
				c.Get(key)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}

	// Should not have panicked
	stats := c.Stats()
	if stats.Size == 0 {
		t.Error("expected some entries in cache")
	}
}

func TestEntryRemainingTTL(t *testing.T) {
	now := time.Now()
	entry := &Entry{
		ExpireTime: now.Add(60 * time.Second),
	}

	remaining := entry.RemainingTTL(now)
	if remaining != 60 {
		t.Errorf("expected 60 seconds remaining, got %d", remaining)
	}

	remaining = entry.RemainingTTL(now.Add(30 * time.Second))
	if remaining != 30 {
		t.Errorf("expected 30 seconds remaining, got %d", remaining)
	}

	remaining = entry.RemainingTTL(now.Add(61 * time.Second))
	if remaining != 0 {
		t.Errorf("expected 0 seconds remaining (expired), got %d", remaining)
	}

	entry.ExpireTime = now
	if !entry.IsExpired(now) {
		t.Error("expected entry to be expired exactly at ExpireTime")
	}
	remaining = entry.RemainingTTL(now)
	if remaining != 0 {
		t.Errorf("expected 0 seconds remaining at exact expiry, got %d", remaining)
	}

	var nilEntry *Entry
	if !nilEntry.IsExpired(now) {
		t.Error("expected nil entry to be treated as expired")
	}
	remaining = nilEntry.RemainingTTL(now)
	if remaining != 0 {
		t.Errorf("expected 0 seconds remaining for nil entry, got %d", remaining)
	}

	entry.ExpireTime = now.Add(time.Duration(int64(^uint32(0))+1) * time.Second)
	remaining = entry.RemainingTTL(now)
	if remaining != ^uint32(0) {
		t.Errorf("expected saturated remaining TTL %d, got %d", ^uint32(0), remaining)
	}
}

func TestMakeKey(t *testing.T) {
	key := MakeKey("example.com", 1, false)
	expected := "example.com|1|0"
	if key != expected {
		t.Errorf("expected key %q, got %q", expected, key)
	}

	key = MakeKey("test.com", 28, true)
	expected = "test.com|28|1"
	if key != expected {
		t.Errorf("expected key %q, got %q", expected, key)
	}

	// Case-insensitive: mixed-case names hash to the same key as lowercase.
	if got, want := MakeKey("EXAMPLE.com", 1, false), MakeKey("example.com", 1, false); got != want {
		t.Errorf("case-insensitive: expected %q, got %q", want, got)
	}
}

func TestExtractQueryInfo(t *testing.T) {
	// Round-trip with the canonical MakeKey output.
	name, qtype := ExtractQueryInfo(MakeKey("example.com", 1, false))
	if name != "example.com" {
		t.Errorf("expected name 'example.com', got %q", name)
	}
	if qtype != 1 {
		t.Errorf("expected type 1 (A), got %d", qtype)
	}

	name, qtype = ExtractQueryInfo(MakeKey("test.com", 28, true))
	if name != "test.com" {
		t.Errorf("expected name 'test.com', got %q", name)
	}
	if qtype != 28 {
		t.Errorf("expected type 28 (AAAA), got %d", qtype)
	}

	// Invalid key (no separator)
	name, qtype = ExtractQueryInfo("nopipe")
	if name != "" || qtype != 0 {
		t.Error("expected empty values for invalid key")
	}
}

func TestCacheUpdateExisting(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	c := New(config)

	key := "update.com:1"

	// Set initial entry
	c.SetNegative(key, 3)

	// Update entry with different rcode
	c.SetNegative(key, 2)

	entry := c.Get(key)
	if entry == nil {
		t.Fatal("expected entry")
	}

	if entry.RCode != 2 {
		t.Error("expected updated rcode")
	}

	if c.Size() != 1 {
		t.Errorf("expected size 1, got %d", c.Size())
	}
}

func TestCacheHitRatio(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	c := New(config)

	// Add entry
	c.SetNegative("test.com:1", 3)

	// Generate some hits
	for i := 0; i < 8; i++ {
		c.Get("test.com:1")
	}

	// Generate some misses
	for i := 0; i < 2; i++ {
		c.Get("missing.com:1")
	}

	stats := c.Stats()
	ratio := stats.HitRatio()
	// 8 hits out of 10 queries = 80%
	if ratio != 80.0 {
		t.Errorf("expected hit ratio 80.0%%, got %f%%", ratio)
	}
}

func TestCacheSetInvalidateFunc(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	c := New(config)

	called := false
	c.SetInvalidateFunc(func(key string) {
		called = true
	})

	c.SetNegative("test.com:1", 3)
	c.Delete("test.com:1")

	if !called {
		t.Error("expected invalidate function to be called")
	}
}

func TestCacheFlush(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	c := New(config)

	// Add several entries
	c.SetNegative("a.com:1", 3)
	c.SetNegative("b.com:1", 3)
	c.SetNegative("c.com:1", 3)

	if c.Size() != 3 {
		t.Fatalf("expected size 3, got %d", c.Size())
	}

	// Flush all entries
	c.Flush()

	if c.Size() != 0 {
		t.Errorf("expected size 0 after flush, got %d", c.Size())
	}
}

func TestCacheDeleteLocal(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	c := New(config)

	// Add entry
	c.SetNegative("test.com:1", 3)

	// Delete local (should not call invalidate callback)
	c.DeleteLocal("test.com:1")

	if c.Get("test.com:1") != nil {
		t.Error("expected entry to be deleted")
	}
}

func TestCacheInvalidate(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	c := New(config)

	called := false
	c.SetInvalidateFunc(func(key string) {
		called = true
	})

	// Add entry
	c.SetNegative("test.com:1", 3)

	// Invalidate
	c.Invalidate("test.com:1")

	if !called {
		t.Error("expected invalidate function to be called")
	}

	if c.Get("test.com:1") != nil {
		t.Error("expected entry to be invalidated")
	}
}

func TestCacheInvalidatePattern(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	c := New(config)

	// Add entries with different patterns
	c.SetNegative(MakeKey("test.example.com", 1, false), 3)
	c.SetNegative(MakeKey("www.example.com", 1, false), 3)
	c.SetNegative(MakeKey("other.test.com", 1, false), 3)

	// Invalidate all example.com entries
	c.InvalidatePattern("example.com")

	// example.com entries should be gone
	if c.Get(MakeKey("test.example.com", 1, false)) != nil {
		t.Error("expected test.example.com to be invalidated")
	}
	if c.Get(MakeKey("www.example.com", 1, false)) != nil {
		t.Error("expected www.example.com to be invalidated")
	}

	// other.test.com should still exist
	if c.Get(MakeKey("other.test.com", 1, false)) == nil {
		t.Error("expected other.test.com to still exist")
	}
}

func TestCacheInvalidatePatternRequiresLabelBoundary(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	c := New(config)

	exampleKey := MakeKey("www.example.com", 1, false)
	partialSuffixKey := MakeKey("www.badexample.com", 1, false)
	substringKey := MakeKey("www.sample.com", 1, false)
	c.SetNegative(exampleKey, 3)
	c.SetNegative(partialSuffixKey, 3)
	c.SetNegative(substringKey, 3)

	invalidated := c.InvalidatePattern("example.com.")
	if len(invalidated) != 1 || invalidated[0] != exampleKey {
		t.Fatalf("InvalidatePattern invalidated %v, want only %q", invalidated, exampleKey)
	}

	if c.Get(exampleKey) != nil {
		t.Error("expected www.example.com to be invalidated")
	}
	if c.Get(partialSuffixKey) == nil {
		t.Error("expected www.badexample.com to survive partial-label suffix pattern")
	}
	if c.Get(substringKey) == nil {
		t.Error("expected www.sample.com to survive substring pattern")
	}
}

func TestCacheInvalidatePatternEmptyNoop(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	c := New(config)

	key := MakeKey("example.com", 1, false)
	c.SetNegative(key, 3)

	if invalidated := c.InvalidatePattern("  .  "); len(invalidated) != 0 {
		t.Fatalf("empty pattern invalidated %v, want none", invalidated)
	}
	if c.Get(key) == nil {
		t.Error("expected cache entry to survive empty invalidation pattern")
	}
}

func TestCacheGetPrefetchable(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	config.PrefetchEnabled = true
	config.PrefetchThreshold = 30 * time.Second
	c := New(config)

	// Add entry with short TTL - won't be due yet since we just added it
	c.Set("prefetch.com:1", nil, 60)

	// Right now it shouldn't be due for prefetch yet (just added)
	entries := c.GetPrefetchable()
	// At creation time, prefetch is not due, so should be 0
	if len(entries) != 0 {
		t.Log("entries are not due for prefetch immediately after creation")
	}

	// Verify the entry exists and has prefetch capability
	entry := c.Get("prefetch.com:1")
	if entry == nil {
		t.Fatal("expected entry to exist")
	}
	if !entry.CanPrefetch {
		t.Error("expected entry to be prefetchable")
	}
}

func TestCacheSetPrefetchFunc(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	config.PrefetchEnabled = true
	c := New(config)

	called := false
	c.SetPrefetchFunc(func(key string, qtype uint16) {
		called = true
	})

	// Prefetch function should be set (we can't easily test the actual prefetch)
	c.Set("test.com:1", nil, 300)
	// The prefetch function would be called in a background goroutine
	_ = called
}

// mustParseName builds a protocol.Name or fails the test.
func mustParseName(t *testing.T, s string) *protocol.Name {
	t.Helper()
	n, err := protocol.ParseName(s)
	if err != nil {
		t.Fatalf("ParseName(%q): %v", s, err)
	}
	return n
}

// TestCachePrefetch_FiresOnceOnHit verifies that once an entry crosses
// its PrefetchDue point, the registered prefetch callback is invoked
// asynchronously on the next Get — and exactly once, no matter how
// many subsequent hits arrive in the prefetch window. Pre-fix the
// callback was registered but never wired into Get, so the prefetch
// feature was a no-op for years.
func TestCachePrefetch_FiresOnceOnHit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Capacity = 16
	cfg.PrefetchEnabled = true
	// Generous prefetch threshold so even a 1s TTL crosses PrefetchDue
	// the moment we Get. minTTL=0 lets us use a short TTL.
	cfg.PrefetchThreshold = 10 * time.Second
	cfg.MinTTL = 0
	c := New(cfg)

	msg := &protocol.Message{
		Questions: []*protocol.Question{
			{
				Name:   mustParseName(t, "prefetch.example."),
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
	}

	var calls atomic.Uint32
	gotKey := make(chan string, 4)
	c.SetPrefetchFunc(func(key string, qtype uint16) {
		calls.Add(1)
		select {
		case gotKey <- key:
		default:
		}
		if qtype != protocol.TypeA {
			t.Errorf("prefetch qtype: got %d, want %d", qtype, protocol.TypeA)
		}
	})

	// Set with TTL=1s; PrefetchThreshold=10s ensures CanPrefetch=false
	// at construction because duration <= prefetchOffset. Use TTL larger
	// than the threshold but tweak PrefetchDue to "now" via re-Set.
	c.Set("prefetch.example.:1", msg, 30)

	// Force PrefetchDue into the past so the next Get fires the callback.
	// (Easier than waiting in the test.)
	entry := c.Get("prefetch.example.:1")
	if entry == nil {
		t.Fatal("expected entry to exist after Set")
	}
	entry.PrefetchDue = time.Now().Add(-1 * time.Second)
	// Clear the prefetchFired flag the Get above may have set when
	// PrefetchDue was in the future (it wouldn't have, but be safe).
	atomic.StoreUint32(&entry.prefetchFired, 0)

	// Multiple Gets in the prefetch window should fire prefetch exactly once.
	for i := 0; i < 5; i++ {
		_ = c.Get("prefetch.example.:1")
	}

	// Give the goroutine a moment to run.
	select {
	case key := <-gotKey:
		if key != "prefetch.example.:1" {
			t.Errorf("prefetch key: got %q, want %q", key, "prefetch.example.:1")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("prefetch callback never fired")
	}

	if got := calls.Load(); got != 1 {
		t.Errorf("prefetch fired %d times, want exactly 1 (dedup broken)", got)
	}
}

func TestCacheOnPrefetchComplete(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	c := New(config)

	// Add entry first
	c.Set("test.com:1", nil, 300)

	// Call OnPrefetchComplete
	c.OnPrefetchComplete("test.com:1", nil, 600)

	// Entry should be updated
	entry := c.Get("test.com:1")
	if entry == nil {
		t.Error("expected entry to still exist")
	}
}

func TestEntryShouldPrefetch(t *testing.T) {
	now := time.Now()
	entry := &Entry{
		ExpireTime:  now.Add(60 * time.Second),
		CanPrefetch: true,
		PrefetchDue: now.Add(30 * time.Second), // Prefetch at 50% TTL
	}

	// Before prefetch time
	if entry.ShouldPrefetch(now.Add(20 * time.Second)) {
		t.Error("should not prefetch before prefetch time")
	}

	// Exactly at prefetch time
	if !entry.ShouldPrefetch(now.Add(30 * time.Second)) {
		t.Error("should prefetch exactly at prefetch time")
	}

	// After prefetch time
	if !entry.ShouldPrefetch(now.Add(35 * time.Second)) {
		t.Error("should prefetch after prefetch time")
	}

	// Entry that can't prefetch
	entry2 := &Entry{
		ExpireTime:  now.Add(60 * time.Second),
		CanPrefetch: false,
		PrefetchDue: now.Add(30 * time.Second),
	}

	if entry2.ShouldPrefetch(now.Add(35 * time.Second)) {
		t.Error("should not prefetch when CanPrefetch is false")
	}

	var nilEntry *Entry
	if nilEntry.ShouldPrefetch(now) {
		t.Error("nil entry should not prefetch")
	}
}

// ---------------------------------------------------------------------------
// MakeKey hash (M-2), EvictPercent, UpdateConfig, Save/Load tests
// ---------------------------------------------------------------------------

// TestMakeKey_LongName_KnownPolynomialCollisionDoesNotCollide regresses
// SECURITY-REPORT.md M-2. The pre-fix long-name hash was a Java-style
// polynomial (`h*31 + byte`, mislabelled crc32Hash). It has a well-
// known 2-byte collision pair ("Aa" / "BB") that generalises to any
// length by appending the same suffix — so an attacker could craft a
// second name that hashed to the cache key of a victim's long name
// and inject poisoned RDATA. Replaced with a keyed maphash whose seed
// is process-random; the same name pair must now produce distinct
// keys.
//
// The pair below is over the 128-byte threshold (130 bytes each)
// where MakeKey switches to the hashed path. The suffix "x"*128 is
// the same for both names, so polynomial-hash equality of the 2-byte
// prefixes ("Aa" vs "BB" both hash to 2112) carried into the full
// strings — that was the bug. The keyed hash breaks the carry.
func TestMakeKey_LongName_KnownPolynomialCollisionDoesNotCollide(t *testing.T) {
	suffix := strings.Repeat("x", 128)
	name1 := "Aa" + suffix // 130 bytes, > 128 → hashed path
	name2 := "BB" + suffix

	// Sanity-check the precondition: both names are long enough to
	// hit the hashed branch.
	if len(name1) <= 128 || len(name2) <= 128 {
		t.Fatalf("test setup error: names must be > 128 bytes; got %d / %d", len(name1), len(name2))
	}

	k1 := MakeKey(name1, 1, false)
	k2 := MakeKey(name2, 1, false)

	if k1 == k2 {
		t.Errorf("M-2 regression: known polynomial-collision pair produced identical cache keys %q — attacker can poison victim name's cache entry", k1)
	}
}

func TestEvictPercent(t *testing.T) {
	// Capacity 256 keeps per-shard cap at 16, large enough that 50 random
	// keys never silently evict regardless of shard distribution.
	cache := New(Config{Capacity: 256})

	// Fill cache with entries
	msg := &protocol.Message{
		Header:    protocol.Header{ID: 1, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Questions: []*protocol.Question{{Name: mustName("test.com."), QType: protocol.TypeA, QClass: protocol.ClassIN}},
	}
	for i := 0; i < 50; i++ {
		cache.Set(fmt.Sprintf("key%d.example.com:1", i), msg, 300)
	}

	stats := cache.Stats()
	if stats.Size != 50 {
		t.Fatalf("Expected 50 entries, got %d", stats.Size)
	}

	// Evict 50%. With sharded eviction the per-shard count uses integer
	// floor, so the realised total varies by ±numShards from the ideal.
	// Verify it's in a sensible band rather than exactly 25.
	cache.EvictPercent(50)
	stats = cache.Stats()
	if stats.Size < 16 || stats.Size > 34 {
		t.Errorf("Expected ~25 entries after 50%% eviction, got %d (outside [16,34])", stats.Size)
	}
	sizeAfter := stats.Size

	// Invalid percent should be no-op
	cache.EvictPercent(0)
	cache.EvictPercent(-1)
	cache.EvictPercent(101)
	stats = cache.Stats()
	if stats.Size != sizeAfter {
		t.Errorf("Invalid percent should not change cache, was %d, got %d", sizeAfter, stats.Size)
	}
}

func TestEvictPercent_EmptyCache(t *testing.T) {
	cache := New(Config{Capacity: 100})
	cache.EvictPercent(50) // Should not panic on empty cache
	stats := cache.Stats()
	if stats.Size != 0 {
		t.Errorf("Empty cache should stay empty, got %d", stats.Size)
	}
}

func TestUpdateConfig(t *testing.T) {
	cache := New(Config{Capacity: 100, MinTTL: 60, MaxTTL: 3600})

	newCfg := Config{
		Capacity:          500,
		MinTTL:            120,
		MaxTTL:            7200,
		DefaultTTL:        300,
		NegativeTTL:       60,
		PrefetchEnabled:   true,
		PrefetchThreshold: 60 * time.Second,
		ServeStale:        true,
		StaleGrace:        30 * time.Second,
	}
	cache.UpdateConfig(newCfg)

	stats := cache.Stats()
	if stats.Capacity != 500 {
		t.Errorf("Expected capacity 500, got %d", stats.Capacity)
	}
	if cache.minTTL != 120 {
		t.Errorf("Expected minTTL 120, got %d", cache.minTTL)
	}
	if cache.maxTTL != 7200 {
		t.Errorf("Expected maxTTL 7200, got %d", cache.maxTTL)
	}
	if !cache.prefetchEnabled {
		t.Error("prefetchEnabled should be true")
	}
	if !cache.serveStale {
		t.Error("serveStale should be true")
	}
}

func TestSaveLoad_RoundTrip(t *testing.T) {
	cache := New(Config{Capacity: 100, MinTTL: 60 * time.Second, MaxTTL: 3600 * time.Second, DefaultTTL: 300 * time.Second})

	// Add entries
	msg := &protocol.Message{
		Header:    protocol.Header{ID: 1, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Questions: []*protocol.Question{{Name: mustName("test.com."), QType: protocol.TypeA, QClass: protocol.ClassIN}},
		Answers: []*protocol.ResourceRecord{
			{Name: mustName("test.com."), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}},
		},
	}
	cache.Set("test.com:1", msg, 300)
	cache.Set("other.com:1", msg, 300)

	// Save
	saved := cache.Save()
	if len(saved) != 2 {
		t.Fatalf("Expected 2 saved entries, got %d", len(saved))
	}

	// Load into new cache
	cache2 := New(Config{Capacity: 100, MinTTL: 60 * time.Second, MaxTTL: 3600 * time.Second})
	restored := cache2.Load(saved)
	if restored != 2 {
		t.Errorf("Expected 2 restored entries, got %d", restored)
	}

	// Verify entries are accessible
	entry := cache2.Get("test.com:1")
	if entry == nil {
		t.Error("test.com:1 should be in restored cache")
	}
	entry2 := cache2.Get("other.com:1")
	if entry2 == nil {
		t.Error("other.com:1 should be in restored cache")
	}
}

func TestSetCopiesMessage(t *testing.T) {
	cache := New(Config{Capacity: 100, MinTTL: time.Second, MaxTTL: time.Hour})
	msg := newTestMessage()

	cache.Set("test.com:1", msg, 300)

	msg.Header.ID = 0xBEEF
	msg.Questions[0].QType = protocol.TypeAAAA
	msg.Answers[0].TTL = 1

	entry := cache.Get("test.com:1")
	if entry == nil || entry.Message == nil {
		t.Fatal("expected cached message")
	}
	if entry.Message.Header.ID != 1234 {
		t.Fatalf("cached header ID mutated through Set input: got %#x", entry.Message.Header.ID)
	}
	if entry.Message.Questions[0].QType != protocol.TypeA {
		t.Fatalf("cached question mutated through Set input: got %d", entry.Message.Questions[0].QType)
	}
	if entry.Message.Answers[0].TTL != 300 {
		t.Fatalf("cached answer TTL mutated through Set input: got %d", entry.Message.Answers[0].TTL)
	}
}

func TestSave_SkipsNegative(t *testing.T) {
	cache := New(Config{Capacity: 100, MinTTL: 60 * time.Second, NegativeTTL: 30 * time.Second})

	cache.SetNegative("test.com:1", protocol.RcodeNameError)

	saved := cache.Save()
	if len(saved) != 0 {
		t.Errorf("Save should skip negative entries, got %d", len(saved))
	}
}

func TestLoad_SkipsExpired(t *testing.T) {
	cache := New(Config{Capacity: 100})

	// Create an entry that's already expired
	entries := []CacheEntryJSON{
		{
			Key:        "expired.com:1",
			WireBytes:  validWireMessage(t),
			TTL:        300,
			ExpireTime: time.Now().Add(-1 * time.Hour), // already expired
		},
	}

	restored := cache.Load(entries)
	if restored != 0 {
		t.Errorf("Load should skip expired entries, got %d restored", restored)
	}
}

func TestLoad_InvalidWire(t *testing.T) {
	cache := New(Config{Capacity: 100})

	entries := []CacheEntryJSON{
		{
			Key:        "bad.com:1",
			WireBytes:  []byte("not a valid DNS message"),
			TTL:        300,
			ExpireTime: time.Now().Add(1 * time.Hour),
		},
	}

	restored := cache.Load(entries)
	if restored != 0 {
		t.Errorf("Load should skip invalid wire data, got %d restored", restored)
	}
}

func TestLoad_ClampsFarFutureExpiry(t *testing.T) {
	cache := New(Config{Capacity: 100, MinTTL: time.Second, MaxTTL: time.Hour})
	entries := []CacheEntryJSON{
		{
			Key:        "future.com:1",
			WireBytes:  validWireMessage(t),
			TTL:        300,
			ExpireTime: time.Now().Add(time.Duration(int64(^uint32(0))+1) * time.Second),
		},
	}

	restored := cache.Load(entries)
	if restored != 1 {
		t.Fatalf("Load restored %d entries, want 1", restored)
	}
	entry := cache.Get("future.com:1")
	if entry == nil {
		t.Fatal("future.com:1 should be restored")
	}
	if entry.RemainingTTL(time.Now()) > uint32(time.Hour/time.Second) {
		t.Errorf("restored TTL = %d, want <= 3600 after cache maxTTL clamp", entry.RemainingTTL(time.Now()))
	}
}

func validWireMessage(t *testing.T) []byte {
	t.Helper()
	msg := &protocol.Message{
		Header:    protocol.Header{ID: 1, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Questions: []*protocol.Question{{Name: mustName("test.com."), QType: protocol.TypeA, QClass: protocol.ClassIN}},
	}
	buf := make([]byte, msg.WireLength())
	n, err := msg.Pack(buf)
	if err != nil {
		t.Fatalf("Failed to pack test message: %v", err)
	}
	return buf[:n]
}

// TestSetNegativeWithTTLCeiling verifies the operator-configured negative TTL
// acts as a ceiling on RFC 2308 SOA-derived negative TTLs: a hostile or
// misconfigured upstream SOA can shorten negative caching but never extend it
// past cache.negative_ttl.
func TestSetNegativeWithTTLCeiling(t *testing.T) {
	c := New(Config{
		Capacity:    16,
		NegativeTTL: 60 * time.Second,
		MaxTTL:      24 * time.Hour,
	})

	// SOA-derived TTL far above the configured ceiling → clamped to 60s.
	c.SetNegativeWithTTL("pinned.example.|1|0", 3, 86400)
	entry := c.Get("pinned.example.|1|0")
	if entry == nil || !entry.IsNegative {
		t.Fatal("expected negative cache entry")
	}
	if remaining := time.Until(entry.ExpireTime); remaining > 61*time.Second {
		t.Fatalf("negative TTL = %v, want <= configured negative_ttl (60s)", remaining)
	}

	// SOA-derived TTL below the ceiling → honored as-is (RFC 2308).
	c.SetNegativeWithTTL("short.example.|1|0", 3, 5)
	entry = c.Get("short.example.|1|0")
	if entry == nil || !entry.IsNegative {
		t.Fatal("expected negative cache entry")
	}
	if remaining := time.Until(entry.ExpireTime); remaining > 6*time.Second {
		t.Fatalf("negative TTL = %v, want SOA-derived ~5s", remaining)
	}
}

// TestSetNegativeMessage verifies negative entries can retain the full
// response message — the Authority section's SOA (RFC 2308) and NSEC/NSEC3
// denial proofs must survive so cache hits can serve them back to clients
// and to the DNSSEC validator's DS-lookup path. The stored message must be a
// deep copy (caller's message is mutated/Released after caching), and the
// operator negative-TTL ceiling applies exactly as in SetNegativeWithTTL.
func TestSetNegativeMessage(t *testing.T) {
	c := New(Config{
		Capacity:    16,
		NegativeTTL: 60 * time.Second,
		MaxTTL:      24 * time.Hour,
	})

	msg := &protocol.Message{
		Header: protocol.Header{Flags: protocol.Flags{QR: true, RCODE: 3}},
		Questions: []*protocol.Question{
			{Name: mustParseName(t, "gone.example."), QType: protocol.TypeA, QClass: protocol.ClassIN},
		},
	}
	msg.AddAuthority(&protocol.ResourceRecord{
		Name: mustParseName(t, "example."), Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 900,
		Data: &protocol.RDataSOA{
			MName:   mustParseName(t, "ns1.example."),
			RName:   mustParseName(t, "admin.example."),
			Minimum: 900,
		},
	})

	c.SetNegativeMessage("gone.example.|1|0", 3, msg, 86400)

	entry := c.Get("gone.example.|1|0")
	if entry == nil || !entry.IsNegative {
		t.Fatal("expected negative cache entry")
	}
	if entry.Message == nil || len(entry.Message.Authorities) != 1 {
		t.Fatal("negative entry lost its message / SOA authority")
	}
	// Deep copy: mutating the original must not affect the cached message.
	msg.Authorities = nil
	if len(entry.Message.Authorities) != 1 {
		t.Error("cached negative message shares state with the caller's message")
	}
	// Ceiling: SOA TTL 86400 clamped to configured 60s negative TTL.
	if remaining := time.Until(entry.ExpireTime); remaining > 61*time.Second {
		t.Fatalf("negative TTL = %v, want <= configured negative_ttl (60s)", remaining)
	}

	// ttl==0 falls back to the configured negative TTL instead of expiring
	// immediately.
	c.SetNegativeMessage("nodata.example.|1|0", 0, msg, 0)
	entry = c.Get("nodata.example.|1|0")
	if entry == nil || !entry.IsNegative {
		t.Fatal("expected negative entry for ttl=0 fallback")
	}
	if remaining := time.Until(entry.ExpireTime); remaining < 30*time.Second {
		t.Fatalf("ttl=0 negative entry expires in %v, want ~negative_ttl (60s)", remaining)
	}
}

// TestMakeKeyOversizedName is a regression test: MakeKey previously wrote into
// a fixed [256]byte stack buffer bounded by len(name), so any name of 257+
// bytes panicked with "index out of range [256] with length 256". Wire-parsed
// names cap at 255 bytes, but zone-file records, CNAME targets and
// API-supplied names reach MakeKey without wire validation.
func TestMakeKeyOversizedName(t *testing.T) {
	for _, n := range []int{255, 256, 257, 300, 1024, 4096} {
		name := strings.Repeat("a", n)
		if key := MakeKey(name, 1, false); key == "" {
			t.Fatalf("empty cache key for name length %d", n)
		}
	}
}

// TestMakeKeyOversizedNameCaseFold verifies the hashed long-name path stays
// case-insensitive per RFC 1035 section 2.3.3.
func TestMakeKeyOversizedNameCaseFold(t *testing.T) {
	lower := strings.Repeat("a", 300)
	upper := strings.Repeat("A", 300)
	if MakeKey(lower, 1, false) != MakeKey(upper, 1, false) {
		t.Fatal("long-name cache keys are not case-folded")
	}
}

// TestInvalidatePatternLongName is a regression test: MakeKey hashes names
// longer than maxKeyNameLen (128), so InvalidatePattern — which recovered the
// domain via ExtractQueryInfo(key) — saw hash digits instead of a domain and
// silently never matched those entries. Such entries survived an explicit
// flush and kept being served until their TTL expired.
func TestInvalidatePatternLongName(t *testing.T) {
	c := New(Config{Capacity: 100, DefaultTTL: time.Hour})

	// A name comfortably past the 128-byte hashing threshold.
	longName := strings.Repeat("sub.", 40) + "example.com"
	if len(longName) <= 128 {
		t.Fatalf("test name is %d bytes, expected >128", len(longName))
	}

	msg := protocol.NewMessage(protocol.Header{ID: 1, QDCount: 1})
	q, err := protocol.NewQuestion(longName, protocol.TypeA, protocol.ClassIN)
	if err != nil {
		t.Fatalf("NewQuestion(%q): %v", longName, err)
	}
	msg.AddQuestion(q)

	key := MakeKey(longName, protocol.TypeA, false)
	c.Set(key, msg, 3600)
	if c.Get(key) == nil {
		t.Fatal("entry not cached")
	}

	invalidated := c.InvalidatePattern("example.com")
	if len(invalidated) != 1 {
		t.Fatalf("InvalidatePattern removed %d entries, want 1 (long-name entry was skipped)", len(invalidated))
	}
	if c.Get(key) != nil {
		t.Fatal("long-name entry survived InvalidatePattern")
	}
}
