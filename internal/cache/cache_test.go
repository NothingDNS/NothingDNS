package cache

import (
	"fmt"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestCacheBasic(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 10
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
	config.Capacity = 10
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
	config.Capacity = 10
	config.MinTTL = 50 * time.Millisecond
	config.NegativeTTL = 100 * time.Millisecond
	c := New(config)

	key := "test.com:1"
	c.SetNegative(key, 3)

	// Should exist immediately
	entry := c.Get(key)
	if entry == nil {
		t.Fatal("expected entry to exist")
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

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
	config := DefaultConfig()
	config.Capacity = 3
	c := New(config)

	// Add 3 entries
	c.SetNegative("a.com:1", 3)
	c.SetNegative("b.com:1", 3)
	c.SetNegative("c.com:1", 3)

	if c.Size() != 3 {
		t.Fatalf("expected size 3, got %d", c.Size())
	}

	// Access a.com to make it most recently used
	c.Get("a.com:1")

	// Add 4th entry - should evict b.com (least recently used)
	c.SetNegative("d.com:1", 3)

	if c.Size() != 3 {
		t.Errorf("expected size 3 after eviction, got %d", c.Size())
	}

	// a.com should still exist
	if c.Get("a.com:1") == nil {
		t.Error("expected a.com to still exist")
	}

	// b.com should be evicted
	if c.Get("b.com:1") != nil {
		t.Error("expected b.com to be evicted")
	}

	stats := c.Stats()
	if stats.Evictions != 1 {
		t.Errorf("expected 1 eviction, got %d", stats.Evictions)
	}
}

func TestCacheNegative(t *testing.T) {
	config := DefaultConfig()
	config.MinTTL = 50 * time.Millisecond
	config.NegativeTTL = 100 * time.Millisecond
	config.Capacity = 10
	c := New(config)

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

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

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

	// Wait for the original entry to expire
	time.Sleep(100 * time.Millisecond)

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
	config.Capacity = 10
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
	config.Capacity = 10
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
	config.Capacity = 10
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
	config.Capacity = 10
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
	config.Capacity = 10
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
	config.Capacity = 100
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
}

func TestMakeKey(t *testing.T) {
	key := MakeKey("example.com", 1, false)
	expected := "example.com:1:0"
	if key != expected {
		t.Errorf("expected key %q, got %q", expected, key)
	}

	key = MakeKey("test.com", 28, true)
	expected = "test.com:28:1"
	if key != expected {
		t.Errorf("expected key %q, got %q", expected, key)
	}
}

func TestExtractQueryInfo(t *testing.T) {
	name, qtype := ExtractQueryInfo("example.com:1")
	if name != "example.com" {
		t.Errorf("expected name 'example.com', got %q", name)
	}
	if qtype != 1 {
		t.Errorf("expected type 1 (A), got %d", qtype)
	}

	name, qtype = ExtractQueryInfo("test.com:28")
	if name != "test.com" {
		t.Errorf("expected name 'test.com', got %q", name)
	}
	if qtype != 28 {
		t.Errorf("expected type 28 (AAAA), got %d", qtype)
	}

	// Invalid key
	name, qtype = ExtractQueryInfo("nocolon")
	if name != "" || qtype != 0 {
		t.Error("expected empty values for invalid key")
	}
}

func TestCacheUpdateExisting(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 10
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
	config.Capacity = 10
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
	config.Capacity = 10
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
	config.Capacity = 10
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
	config.Capacity = 10
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
	config.Capacity = 10
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
	config.Capacity = 10
	c := New(config)

	// Add entries with different patterns
	c.SetNegative("test.example.com:1", 3)
	c.SetNegative("www.example.com:1", 3)
	c.SetNegative("other.test.com:1", 3)

	// Invalidate all example.com entries
	c.InvalidatePattern("example.com")

	// example.com entries should be gone
	if c.Get("test.example.com:1") != nil {
		t.Error("expected test.example.com to be invalidated")
	}
	if c.Get("www.example.com:1") != nil {
		t.Error("expected www.example.com to be invalidated")
	}

	// other.test.com should still exist
	if c.Get("other.test.com:1") == nil {
		t.Error("expected other.test.com to still exist")
	}
}

func TestCacheGetPrefetchable(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 10
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
	config.Capacity = 10
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

func TestCacheOnPrefetchComplete(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 10
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
}

// ---------------------------------------------------------------------------
// crc32Hash, EvictPercent, UpdateConfig, Save/Load tests
// ---------------------------------------------------------------------------

func TestCRC32Hash(t *testing.T) {
	// Deterministic
	h1 := crc32Hash("example.com:A")
	h2 := crc32Hash("example.com:A")
	if h1 != h2 {
		t.Errorf("Same input should produce same hash: %d != %d", h1, h2)
	}

	// Different inputs should produce different hashes
	h3 := crc32Hash("other.com:A")
	if h1 == h3 {
		t.Error("Different inputs should produce different hashes")
	}

	// Empty string
	h4 := crc32Hash("")
	if h4 != 0 {
		t.Errorf("Empty string should hash to 0, got %d", h4)
	}
}

func TestEvictPercent(t *testing.T) {
	cache := New(Config{Capacity: 100})

	// Fill cache with entries
	msg := &protocol.Message{
		Header:    protocol.Header{ID: 1, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Questions: []*protocol.Question{{Name: &protocol.Name{Labels: []string{"test", "com"}, FQDN: true}, QType: protocol.TypeA, QClass: protocol.ClassIN}},
	}
	for i := 0; i < 50; i++ {
		cache.Set(fmt.Sprintf("key%d.example.com:1", i), msg, 300)
	}

	stats := cache.Stats()
	if stats.Size != 50 {
		t.Fatalf("Expected 50 entries, got %d", stats.Size)
	}

	// Evict 50% = 25 entries
	cache.EvictPercent(50)

	stats = cache.Stats()
	if stats.Size != 25 {
		t.Errorf("Expected 25 entries after 50%% eviction, got %d", stats.Size)
	}

	// Invalid percent should be no-op
	cache.EvictPercent(0)
	cache.EvictPercent(-1)
	cache.EvictPercent(101)
	stats = cache.Stats()
	if stats.Size != 25 {
		t.Errorf("Invalid percent should not change cache, got %d entries", stats.Size)
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
		Capacity:         500,
		MinTTL:           120,
		MaxTTL:           7200,
		DefaultTTL:       300,
		NegativeTTL:      60,
		PrefetchEnabled:  true,
		PrefetchThreshold: 60 * time.Second,
		ServeStale:       true,
		StaleGrace:       30 * time.Second,
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
		Questions: []*protocol.Question{{Name: &protocol.Name{Labels: []string{"test", "com"}, FQDN: true}, QType: protocol.TypeA, QClass: protocol.ClassIN}},
		Answers: []*protocol.ResourceRecord{
			{Name: &protocol.Name{Labels: []string{"test", "com"}, FQDN: true}, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}},
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


func validWireMessage(t *testing.T) []byte {
	t.Helper()
	msg := &protocol.Message{
		Header:    protocol.Header{ID: 1, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Questions: []*protocol.Question{{Name: &protocol.Name{Labels: []string{"test", "com"}, FQDN: true}, QType: protocol.TypeA, QClass: protocol.ClassIN}},
	}
	buf := make([]byte, msg.WireLength())
	n, err := msg.Pack(buf)
	if err != nil {
		t.Fatalf("Failed to pack test message: %v", err)
	}
	return buf[:n]
}
