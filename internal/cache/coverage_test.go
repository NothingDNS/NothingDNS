package cache

import (
	"sort"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
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
	config.Capacity = 128
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
	config.Capacity = 128
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

// TestEvictOldest_NilElement covers the empty-list branch in
// cacheShard.evictOldest (returns false when lruBack is nil). Calls into
// the per-shard helper directly since this defensive path is unreachable
// via the public API.
func TestEvictOldest_NilElement(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	c := New(config)

	// Fresh cache: every shard has an empty LRU list. Call evictOldest on
	// shard 0 to exercise the `if s.lruBack == nil { return false }` branch.
	s := &c.shards[0]
	s.mu.Lock()
	if s.evictOldest() {
		t.Error("evictOldest on empty shard should return false")
	}
	s.mu.Unlock()

	// Verify no evictions were recorded (since there was nothing to evict).
	stats := c.Stats()
	if stats.Evictions != 0 {
		t.Errorf("expected 0 evictions, got %d", stats.Evictions)
	}
	if stats.Size != 0 {
		t.Errorf("expected size 0, got %d", stats.Size)
	}
}

// TestExtractQueryInfo_InvalidType covers invalid qtype parsing in
// ExtractQueryInfo where the part between separators is not a uint16.
func TestExtractQueryInfo_InvalidType(t *testing.T) {
	// Key with non-numeric type portion.
	name, qtype := ExtractQueryInfo("example.com|abc|0")
	if name != "" || qtype != 0 {
		t.Errorf("expected ('', 0) for non-numeric type, got (%q, %d)", name, qtype)
	}

	// Key with empty type portion.
	name, qtype = ExtractQueryInfo("example.com||0")
	if name != "" || qtype != 0 {
		t.Errorf("expected ('', 0) for empty type, got (%q, %d)", name, qtype)
	}

	// Key with a partially numeric type must not be accepted as its prefix.
	name, qtype = ExtractQueryInfo("example.com|1abc|0")
	if name != "" || qtype != 0 {
		t.Errorf("expected ('', 0) for partially numeric type, got (%q, %d)", name, qtype)
	}

	// Key with a type outside the uint16 DNS RRType range must be rejected.
	name, qtype = ExtractQueryInfo("example.com|65536|0")
	if name != "" || qtype != 0 {
		t.Errorf("expected ('', 0) for overflow type, got (%q, %d)", name, qtype)
	}

	// Key with valid type still works.
	name, qtype = ExtractQueryInfo("valid.com|1|0")
	if name != "valid.com" || qtype != 1 {
		t.Errorf("expected ('valid.com', 1), got (%q, %d)", name, qtype)
	}
}

// ---------------------------------------------------------------------------
// cache.go:58-60 - RemainingTTL negative remaining branch
// The branch `if remaining < 0 { return 0 }` in RemainingTTL is
// a defensive guard. With IsExpired treating now >= ExpireTime as expired,
// this branch is effectively unreachable through normal time API.
//
// We test the function's behavior at the boundary to confirm it
// returns 0 for all edge cases.
// ---------------------------------------------------------------------------

func TestRemainingTTL_NegativeBranch_SyntheticEntry(t *testing.T) {
	now := time.Now()

	// Case 1: Entry that is exactly at expiry time.
	// Exact boundary is expired, so RemainingTTL returns 0.
	entry := &Entry{
		ExpireTime: now,
	}
	remaining := entry.RemainingTTL(now)
	if remaining != 0 {
		t.Errorf("expected 0 for exact-expiry entry, got %d", remaining)
	}

	// Case 2: Entry well in the past.
	// IsExpired returns true, so RemainingTTL returns 0 at line 55.
	entry2 := &Entry{
		ExpireTime: now.Add(-1 * time.Millisecond),
	}
	remaining2 := entry2.RemainingTTL(now)
	if remaining2 != 0 {
		t.Errorf("expected 0 for past-expiry entry, got %d", remaining2)
	}

	// Case 3: Entry well in the future.
	entry3 := &Entry{
		ExpireTime: now.Add(60 * time.Second),
	}
	remaining3 := entry3.RemainingTTL(now)
	if remaining3 != 60 {
		t.Errorf("expected 60 for future entry, got %d", remaining3)
	}

	// Case 4: Entry 1 second in the future.
	entry4 := &Entry{
		ExpireTime: now.Add(1 * time.Second),
	}
	remaining4 := entry4.RemainingTTL(now)
	if remaining4 != 1 {
		t.Errorf("expected 1 for 1-second future entry, got %d", remaining4)
	}

	// Case 5: Entry 500ms in the future - should return 0 because
	// uint32(500ms.Seconds()) = uint32(0.5) = 0
	entry5 := &Entry{
		ExpireTime: now.Add(500 * time.Millisecond),
	}
	remaining5 := entry5.RemainingTTL(now)
	if remaining5 != 0 {
		t.Errorf("expected 0 for sub-second future entry, got %d", remaining5)
	}
}

// TestRemainingTTL_NegativeBranch_JustBeforeExpiry verifies behavior
// when the entry is very close to expiry but not yet expired.
func TestRemainingTTL_NegativeBranch_JustBeforeExpiry(t *testing.T) {
	now := time.Now()

	// Entry 1 nanosecond in the future - not expired, remaining = 0 seconds
	entry := &Entry{
		ExpireTime: now.Add(1 * time.Nanosecond),
	}
	if entry.IsExpired(now) {
		t.Error("entry should not be expired (1ns in the future)")
	}
	remaining := entry.RemainingTTL(now)
	if remaining != 0 {
		t.Errorf("expected 0 for sub-second remaining, got %d", remaining)
	}
}

// TestSetInternal_MinTTLClamping verifies that Set with a TTL below minTTL
// gets clamped up to minTTL.
func TestSetInternal_MinTTLClamping(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	config.MinTTL = 5 * time.Second
	c := New(config)

	// Set with TTL=1s, but minTTL is 5s, so the entry should live for 5s.
	c.Set("minttl.com:1", nil, 1)

	entry := c.Get("minttl.com:1")
	if entry == nil {
		t.Fatal("expected entry to exist")
	}

	// The original TTL stored should be 1 (as passed in), but ExpireTime
	// should be based on the clamped duration (5s). Verify by checking that
	// the entry is NOT expired 4 seconds from now.
	if entry.IsExpired(time.Now().Add(4 * time.Second)) {
		t.Error("entry should not be expired after 4s (minTTL=5s should clamp TTL=1s up)")
	}
	// And it should be expired well after 5s.
	if !entry.IsExpired(time.Now().Add(6 * time.Second)) {
		t.Error("entry should be expired after 6s")
	}
}

// TestSetInternal_MaxTTLClamping verifies that Set with a TTL above maxTTL
// gets clamped down to maxTTL.
func TestSetInternal_MaxTTLClamping(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	config.MaxTTL = 1 * time.Hour
	c := New(config)

	// Set with TTL=86400s (24h), but maxTTL is 1h.
	c.Set("maxttl.com:1", nil, 86400)

	entry := c.Get("maxttl.com:1")
	if entry == nil {
		t.Fatal("expected entry to exist")
	}

	// Entry should be expired after 1 hour + a little, but not before.
	if entry.IsExpired(time.Now().Add(59 * time.Minute)) {
		t.Error("entry should not be expired before maxTTL (1h)")
	}
	if !entry.IsExpired(time.Now().Add(61 * time.Minute)) {
		t.Error("entry should be expired after maxTTL (1h)")
	}
}

// TestSetInternal_ShortTTLNoPrefetch verifies that when the TTL duration is
// less than or equal to the prefetch threshold offset, CanPrefetch is false.
func TestSetInternal_ShortTTLNoPrefetch(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	config.PrefetchEnabled = true
	config.PrefetchThreshold = 30 * time.Second
	config.MinTTL = 1 * time.Second // allow short TTL
	c := New(config)

	// TTL=10s, prefetchThreshold=30s. Since 10s <= 30s, canPrefetch should be false.
	c.Set("shortttl.com:1", nil, 10)

	entry := c.Get("shortttl.com:1")
	if entry == nil {
		t.Fatal("expected entry to exist")
	}
	if entry.CanPrefetch {
		t.Error("expected CanPrefetch=false when TTL duration <= prefetchThreshold")
	}
}

// TestSetInternal_PrefetchEnabledDurationGreaterThanThreshold verifies that
// when the TTL is larger than the prefetch threshold, the entry is prefetchable
// and PrefetchDue is set correctly.
func TestSetInternal_PrefetchEnabledDurationGreaterThanThreshold(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	config.PrefetchEnabled = true
	config.PrefetchThreshold = 30 * time.Second
	c := New(config)

	// TTL=120s, prefetchThreshold=30s. duration(120s) > offset(30s), so prefetchable.
	c.Set("prefetchable.com:1", nil, 120)

	entry := c.Get("prefetchable.com:1")
	if entry == nil {
		t.Fatal("expected entry to exist")
	}
	if !entry.CanPrefetch {
		t.Error("expected CanPrefetch=true when TTL > prefetchThreshold")
	}

	// PrefetchDue should be ExpireTime - 30s, which is now + 120s - 30s = now + 90s.
	// Verify: prefetch should NOT be due at now+80s but SHOULD be due at now+91s.
	now := time.Now()
	if entry.ShouldPrefetch(now.Add(80 * time.Second)) {
		t.Error("prefetch should not be due at now+80s (PrefetchDue ~= now+90s)")
	}
	if !entry.ShouldPrefetch(now.Add(91 * time.Second)) {
		t.Error("prefetch should be due at now+91s (PrefetchDue ~= now+90s)")
	}
}

// TestOnPrefetchComplete_RearmsNextCycle verifies that a successful refresh
// remains eligible for prefetch in its new TTL cycle. PrefetchDue keeps the
// callback from firing immediately and prefetchFired gates it to once/cycle.
func TestOnPrefetchComplete_RearmsNextCycle(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	config.PrefetchEnabled = true
	config.PrefetchThreshold = 30 * time.Second
	c := New(config)

	// Create a prefetchable entry first.
	c.Set("prefetch-done.com:1", nil, 120)
	entry := c.Get("prefetch-done.com:1")
	if entry == nil {
		t.Fatal("expected entry to exist after initial Set")
	}
	if !entry.CanPrefetch {
		t.Fatal("expected initial entry to be prefetchable")
	}

	// Complete prefetch: the replacement starts a fresh TTL cycle.
	c.OnPrefetchComplete("prefetch-done.com:1", nil, 200)

	entry = c.Get("prefetch-done.com:1")
	if entry == nil {
		t.Fatal("expected entry to still exist after OnPrefetchComplete")
	}
	if !entry.CanPrefetch {
		t.Error("expected CanPrefetch=true after OnPrefetchComplete so the next TTL cycle can refresh")
	}
}

// TestOnPrefetchComplete_WithMessage verifies that OnPrefetchComplete stores
// a non-nil protocol.Message in the updated entry.
func TestOnPrefetchComplete_WithMessage(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	c := New(config)

	// Create initial entry.
	c.Set("msg-test.com:1", nil, 60)

	// Build a real protocol.Message to pass in using the constructor.
	msg := protocol.NewMessage(protocol.Header{
		ID:      42,
		QDCount: 1,
		ANCount: 1,
	})

	c.OnPrefetchComplete("msg-test.com:1", msg, 300)

	entry := c.Get("msg-test.com:1")
	if entry == nil {
		t.Fatal("expected entry to exist")
	}
	if entry.Message == nil {
		t.Fatal("expected non-nil Message after OnPrefetchComplete with message")
	}
	if entry.Message.Header.ID != 42 {
		t.Errorf("expected message header ID 42, got %d", entry.Message.Header.ID)
	}
}

// TestEvictOldest_EmptyCache verifies eviction triggers when a shard hits
// capacity. Forces both keys into shard 0 with a per-shard cap of 1 so the
// second insertion deterministically evicts the first.
func TestEvictOldest_EmptyCache(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = numShards // per-shard cap = 1
	c := New(config)

	keys := keysForShard(0, 2)
	first, second := keys[0], keys[1]

	// Add first entry — shard 0 is at capacity.
	c.SetNegative(first, 3)
	// Add second entry — triggers evictOldest on the first entry.
	c.SetNegative(second, 3)

	if c.Get(first) != nil {
		t.Error("expected first to be evicted")
	}
	if c.Get(second) == nil {
		t.Error("expected second to exist")
	}

	stats := c.Stats()
	if stats.Evictions != 1 {
		t.Errorf("expected 1 eviction, got %d", stats.Evictions)
	}
}

// TestRemainingTTL_ExactlyExpired tests the boundary case where now is
// exactly at ExpireTime.
func TestRemainingTTL_ExactlyExpired(t *testing.T) {
	now := time.Now()
	entry := &Entry{
		ExpireTime: now,
	}

	remaining := entry.RemainingTTL(now)
	// At the exact expiry boundary the entry is expired and has no TTL left.
	if remaining != 0 {
		t.Errorf("expected 0 remaining TTL when now == ExpireTime, got %d", remaining)
	}
}

// TestRemainingTTL_NegativeDuration tests the case where ExpireTime is
// slightly before now, producing a negative duration.
func TestRemainingTTL_NegativeDuration(t *testing.T) {
	now := time.Now()

	// Case 1: ExpireTime in the past by a large margin.
	// IsExpired returns true (now.After(ExpireTime)), so RemainingTTL returns 0.
	entry := &Entry{
		ExpireTime: now.Add(-500 * time.Millisecond),
	}
	remaining := entry.RemainingTTL(now)
	if remaining != 0 {
		t.Errorf("expected 0 remaining TTL for expired entry, got %d", remaining)
	}

	// Case 2: ExpireTime just barely in the past.
	// IsExpired still returns true, so RemainingTTL returns 0.
	entry2 := &Entry{
		ExpireTime: now.Add(-1 * time.Nanosecond),
	}
	remaining2 := entry2.RemainingTTL(now)
	if remaining2 != 0 {
		t.Errorf("expected 0 remaining TTL for barely expired entry, got %d", remaining2)
	}

	// Case 3: Well in the future to verify a positive result.
	entry3 := &Entry{
		ExpireTime: now.Add(90 * time.Second),
	}
	remaining3 := entry3.RemainingTTL(now)
	if remaining3 != 90 {
		t.Errorf("expected 90 remaining TTL, got %d", remaining3)
	}
}

// TestGetPrefetchable_EntriesDueForPrefetch verifies that GetPrefetchable
// returns entries whose PrefetchDue time is in the past.
func TestGetPrefetchable_EntriesDueForPrefetch(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	config.PrefetchEnabled = true
	config.PrefetchThreshold = 50 * time.Millisecond
	config.MinTTL = 1 * time.Second
	c := New(config)

	c.Set("due.com:1", nil, 120)

	// Manually set PrefetchDue to the past so it's immediately due.
	s := c.shardOf("due.com:1")
	s.mu.Lock()
	if e, ok := s.entries["due.com:1"]; ok {
		e.PrefetchDue = time.Now().Add(-1 * time.Second)
		e.CanPrefetch = true
		e.IsNegative = false
	}
	s.mu.Unlock()

	keys := c.GetPrefetchable()
	found := false
	for _, k := range keys {
		if k == "due.com:1" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'due.com:1' to be returned by GetPrefetchable")
	}
}

// TestGetPrefetchable_MixedDueAndNotDue verifies that GetPrefetchable
// returns only entries that are due, not all prefetchable entries.
func TestGetPrefetchable_MixedDueAndNotDue(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	config.PrefetchEnabled = true
	config.PrefetchThreshold = 50 * time.Millisecond
	config.MinTTL = 1 * time.Second
	c := New(config)

	// Add two entries.
	c.Set("due.com:1", nil, 120)
	c.Set("notdue.com:1", nil, 120)

	// Manipulate: one is due, one is not. Each key may live in a different
	// shard, so resolve and lock per-key.
	for _, kc := range []struct {
		key string
		due time.Duration
	}{
		{"due.com:1", -1 * time.Second},
		{"notdue.com:1", 1 * time.Hour},
	} {
		s := c.shardOf(kc.key)
		s.mu.Lock()
		if e, ok := s.entries[kc.key]; ok {
			e.PrefetchDue = time.Now().Add(kc.due)
			e.CanPrefetch = true
			e.IsNegative = false
		}
		s.mu.Unlock()
	}

	keys := c.GetPrefetchable()

	foundDue := false
	foundNotDue := false
	for _, k := range keys {
		if k == "due.com:1" {
			foundDue = true
		}
		if k == "notdue.com:1" {
			foundNotDue = true
		}
	}
	if !foundDue {
		t.Error("expected 'due.com:1' to be in prefetchable list")
	}
	if foundNotDue {
		t.Error("expected 'notdue.com:1' to NOT be in prefetchable list (not due yet)")
	}
}

// TestSet_WithNonNilMessage verifies that Set stores a non-nil protocol.Message.
func TestSet_WithNonNilMessage(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	c := New(config)

	msg := protocol.NewMessage(protocol.Header{
		ID:      1234,
		QDCount: 1,
		ANCount: 2,
	})
	msg.Header.Flags.QR = true

	q, err := protocol.NewQuestion("example.com", 1, 1)
	if err != nil {
		t.Fatalf("failed to create question: %v", err)
	}
	msg.Questions = append(msg.Questions, q)

	c.Set("example.com:1", msg, 300)

	entry := c.Get("example.com:1")
	if entry == nil {
		t.Fatal("expected entry to exist")
	}
	if entry.Message == nil {
		t.Fatal("expected non-nil Message in entry")
	}
	if entry.Message.Header.ID != 1234 {
		t.Errorf("expected message header ID 1234, got %d", entry.Message.Header.ID)
	}
	if !entry.Message.Header.Flags.QR {
		t.Error("expected QR flag to be true")
	}
	if len(entry.Message.Questions) != 1 {
		t.Errorf("expected 1 question, got %d", len(entry.Message.Questions))
	}
	if entry.Message.Questions[0].Name.String() != "example.com." {
		t.Errorf("expected question name 'example.com.', got %q", entry.Message.Questions[0].Name.String())
	}
}

// TestDeleteLocal_DoesNotCallCallback verifies that DeleteLocal does not
// invoke the invalidate callback.
func TestDeleteLocal_DoesNotCallCallback(t *testing.T) {
	config := DefaultConfig()
	config.Capacity = 128
	c := New(config)

	var callbackKeys []string
	c.SetInvalidateFunc(func(key string) {
		callbackKeys = append(callbackKeys, key)
	})

	c.SetNegative("local.com:1", 3)
	c.DeleteLocal("local.com:1")

	if len(callbackKeys) != 0 {
		t.Errorf("expected invalidate callback NOT to be called, but it was called with keys: %v", callbackKeys)
	}

	// Verify the entry is actually deleted.
	if c.Get("local.com:1") != nil {
		t.Error("expected entry to be deleted locally")
	}
}

// TestInvalidatePattern_ReturnsKeys verifies that InvalidatePattern returns
// the list of invalidated keys.
func TestInvalidatePattern_ReturnsKeys(t *testing.T) {
	config := DefaultConfig()
	// Per-shard cap = 8 so all three keys survive insertion regardless of
	// shard distribution.
	config.Capacity = 128
	c := New(config)

	c.SetNegative(MakeKey("test.example.com", 1, false), 3)
	c.SetNegative(MakeKey("www.example.com", 1, false), 3)
	c.SetNegative(MakeKey("other.test.com", 1, false), 3)

	invalidated := c.InvalidatePattern("example.com")

	// Should return exactly the two example.com keys.
	if len(invalidated) != 2 {
		t.Fatalf("expected 2 invalidated keys, got %d: %v", len(invalidated), invalidated)
	}

	sort.Strings(invalidated)
	expected := []string{MakeKey("test.example.com", 1, false), MakeKey("www.example.com", 1, false)}
	sort.Strings(expected)

	for i, key := range invalidated {
		if key != expected[i] {
			t.Errorf("expected key %q, got %q", expected[i], key)
		}
	}
}

// TestInvalidatePattern_WithCallback verifies that the invalidate callback
// is called for each key invalidated by InvalidatePattern.
func TestInvalidatePattern_WithCallback(t *testing.T) {
	config := DefaultConfig()
	// Cap per-shard at 8 so all three keys survive regardless of which shard
	// each lands in (per-shard cap = ceil(128/16) = 8).
	config.Capacity = 128
	c := New(config)

	var callbackKeys []string
	c.SetInvalidateFunc(func(key string) {
		callbackKeys = append(callbackKeys, key)
	})

	c.SetNegative(MakeKey("alpha.example.com", 1, false), 3)
	c.SetNegative(MakeKey("beta.example.com", 1, false), 3)
	c.SetNegative(MakeKey("unrelated.com", 1, false), 3)

	c.InvalidatePattern("example.com")

	if len(callbackKeys) != 2 {
		t.Errorf("expected invalidate callback to be called 2 times, got %d: %v", len(callbackKeys), callbackKeys)
	}

	// Verify unrelated.com still exists.
	if c.Get(MakeKey("unrelated.com", 1, false)) == nil {
		t.Error("expected unrelated.com to still exist")
	}
}

// TestShouldPrefetch_NegativeEntry verifies that a negative entry with
// CanPrefetch=true still returns false from ShouldPrefetch due to the
// IsNegative guard.
func TestShouldPrefetch_NegativeEntry(t *testing.T) {
	now := time.Now()
	entry := &Entry{
		ExpireTime:  now.Add(60 * time.Second),
		CanPrefetch: true,
		PrefetchDue: now.Add(-1 * time.Second), // Due in the past
		IsNegative:  true,
	}

	if entry.ShouldPrefetch(now) {
		t.Error("expected ShouldPrefetch=false for negative entry, even with CanPrefetch=true and past PrefetchDue")
	}
}
