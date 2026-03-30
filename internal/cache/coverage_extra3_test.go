package cache

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// cache.go:58-60 - RemainingTTL negative remaining branch
// The branch `if remaining < 0 { return 0 }` in RemainingTTL is
// a defensive guard. It's triggered when IsExpired(now) returns false
// but ExpireTime.Sub(now) is negative. This can theoretically happen
// due to clock adjustments or nanosecond precision issues.
//
// Since IsExpired checks `now.After(e.ExpireTime)`, and Sub returns
// negative when ExpireTime < now, the only way to hit this branch is
// when now is not After ExpireTime but ExpireTime.Sub(now) < 0, which
// means now == ExpireTime exactly (Sub returns 0, not negative).
// So this branch is effectively unreachable through normal time API.
//
// We test the function's behavior at the boundary to confirm it
// returns 0 for all edge cases.
// ---------------------------------------------------------------------------

func TestRemainingTTL_NegativeBranch_SyntheticEntry(t *testing.T) {
	now := time.Now()

	// Case 1: Entry that is exactly at expiry time.
	// IsExpired(now) = now.After(now) = false
	// remaining = now.Sub(now) = 0 >= 0, so returns uint32(0) = 0
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
