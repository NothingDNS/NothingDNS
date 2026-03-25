package cache

import (
	"testing"
	"time"
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
				key := MakeKey("test.com", uint16(j%10))
				c.SetNegative(key, 3)
			}
			done <- true
		}(i)
	}

	// Readers
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				key := MakeKey("test.com", uint16(j%10))
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
	key := MakeKey("example.com", 1)
	expected := "example.com:1"
	if key != expected {
		t.Errorf("expected key %q, got %q", expected, key)
	}

	key = MakeKey("test.com", 28)
	expected = "test.com:28"
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
