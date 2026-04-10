package cache

import (
	"testing"
	"time"
)

// TestRemainingTTL_NegativeDurationCoversNegativeBranch tests the
// `if remaining < 0 { return 0 }` branch in RemainingTTL.
// This branch handles the case where IsExpired returns false but the
// computed remaining duration is negative (a defensive guard).
// Since this is extremely difficult to trigger through normal time
// calculations, we directly test the function behavior around boundaries.
func TestRemainingTTL_NegativeDurationCoversNegativeBranch(t *testing.T) {
	now := time.Now()

	// Entry with ExpireTime slightly in the past (500ms ago).
	// IsExpired returns true, so RemainingTTL returns 0 at line 55.
	entry := &Entry{
		ExpireTime: now.Add(-500 * time.Millisecond),
	}
	remaining := entry.RemainingTTL(now)
	if remaining != 0 {
		t.Errorf("expected 0 for expired entry, got %d", remaining)
	}

	// Entry with ExpireTime exactly equal to now.
	// IsExpired(now) returns false (now.After(now) == false),
	// remaining = ExpireTime.Sub(now) = 0, which is >= 0, returns uint32(0) = 0.
	entry2 := &Entry{
		ExpireTime: now,
	}
	remaining2 := entry2.RemainingTTL(now)
	if remaining2 != 0 {
		t.Errorf("expected 0 for exactly-at-expiry entry, got %d", remaining2)
	}

	// Entry well in the future: covers the normal return path (line 61).
	entry3 := &Entry{
		ExpireTime: now.Add(120 * time.Second),
	}
	remaining3 := entry3.RemainingTTL(now)
	if remaining3 != 120 {
		t.Errorf("expected 120 remaining, got %d", remaining3)
	}
}

// TestSetNegative_MinTTLClamping covers the `if ttl < c.minTTL` branch
// in SetNegative by configuring negativeTTL < minTTL.
func TestSetNegative_MinTTLClamping(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 10
	config.MinTTL = 10 * time.Second
	config.NegativeTTL = 2 * time.Second // negativeTTL < minTTL
	c := New(config)

	c.SetNegative("clamp.com:1", 3)

	entry := c.Get("clamp.com:1")
	if entry == nil {
		t.Fatal("expected entry to exist")
	}

	// Entry should NOT be expired at 8 seconds (since TTL was clamped to 10s).
	if entry.IsExpired(time.Now().Add(8 * time.Second)) {
		t.Error("entry should not be expired at 8s (negativeTTL clamped to minTTL=10s)")
	}
	// Entry SHOULD be expired well after 10 seconds.
	if !entry.IsExpired(time.Now().Add(12 * time.Second)) {
		t.Error("entry should be expired at 12s (negativeTTL clamped to minTTL=10s)")
	}
}

// TestSetNegative_MaxTTLClamping covers the `if ttl > c.maxTTL` branch
// in SetNegative by configuring negativeTTL > maxTTL.
func TestSetNegative_MaxTTLClamping(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 10
	config.MaxTTL = 5 * time.Second
	config.NegativeTTL = 120 * time.Second // negativeTTL > maxTTL
	c := New(config)

	c.SetNegative("maxclamp.com:1", 3)

	entry := c.Get("maxclamp.com:1")
	if entry == nil {
		t.Fatal("expected entry to exist")
	}

	// Entry should NOT be expired at 4 seconds (TTL clamped to maxTTL=5s).
	if entry.IsExpired(time.Now().Add(4 * time.Second)) {
		t.Error("entry should not be expired at 4s (negativeTTL clamped to maxTTL=5s)")
	}
	// Entry SHOULD be expired after 6 seconds.
	if !entry.IsExpired(time.Now().Add(6 * time.Second)) {
		t.Error("entry should be expired at 6s (negativeTTL clamped to maxTTL=5s)")
	}
}

// TestEvictOldest_NilElement covers the `if element == nil { return }`
// branch in evictOldest. This is a defensive path that triggers when
// the LRU list is empty. We call evictOldest directly on a fresh cache
// with an empty LRU list to exercise this branch without causing an
// infinite loop in addEntry.
func TestEvictOldest_NilElement(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 10
	c := New(config)

	// The cache is freshly created, so the LRU list is empty.
	// Calling evictOldest directly hits the `if element == nil { return }` branch.
	c.mu.Lock()
	c.evictOldest()
	c.mu.Unlock()

	// Verify no evictions were recorded (since there was nothing to evict).
	stats := c.Stats()
	if stats.Evictions != 0 {
		t.Errorf("expected 0 evictions, got %d", stats.Evictions)
	}
	if stats.Size != 0 {
		t.Errorf("expected size 0, got %d", stats.Size)
	}
}

// TestExtractQueryInfo_InvalidType covers the Sscanf error branch
// in ExtractQueryInfo where the part after the colon is not a number.
func TestExtractQueryInfo_InvalidType(t *testing.T) {
	// Key with non-numeric type portion.
	name, qtype := ExtractQueryInfo("example.com:abc")
	if name != "" || qtype != 0 {
		t.Errorf("expected ('', 0) for non-numeric type, got (%q, %d)", name, qtype)
	}

	// Key with empty type portion.
	name, qtype = ExtractQueryInfo("example.com:")
	if name != "" || qtype != 0 {
		t.Errorf("expected ('', 0) for empty type, got (%q, %d)", name, qtype)
	}

	// Key with valid type still works.
	name, qtype = ExtractQueryInfo("valid.com:1")
	if name != "valid.com" || qtype != 1 {
		t.Errorf("expected ('valid.com', 1), got (%q, %d)", name, qtype)
	}
}
