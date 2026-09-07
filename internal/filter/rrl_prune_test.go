package filter

import (
	"testing"
	"unsafe"
)

// TestRRLPruneStale_ConcurrentModification reproduces the bug where pruneStale
// calls delete(rrl.buckets, key) inside the range loop over rrl.buckets.
// Per the Go spec this causes undefined behavior: entries may be skipped or
// the iteration may panic if the map is rehashed. The correct pattern collects
// stale keys first, then deletes outside the loop.
func TestRRLPruneStale_ConcurrentModification(t *testing.T) {
	cfg := RRLConfig{
		Enabled:    true,
		Rate:       5,
		Burst:      20,
		Window:     10,
		MaxBuckets: 10000,
	}
	rrl := NewRRL(cfg)

	// Add entries via Allow (each call creates a new bucket)
	for i := uint16(0); i < 100; i++ {
		rrl.Allow([]byte{byte(i), 0, 0, 0}, i, 0)
	}

	// Backdate all bucket lastTime fields to force them to be "stale"
	// (more than 5 minutes old). We use unsafe to bypass the unexported field.
	type bucketType struct {
		tokens     float64
		lastTime   int64
		createdAt  int64
		suppressed int64
	}
	for _, b := range rrl.buckets {
		bp := (*bucketType)(unsafe.Pointer(b))
		bp.lastTime = 0 // epoch = definitely before 5 minutes ago
	}

	// Call pruneStale — the buggy version deletes inside the range loop.
	// Repeated calls increase the chance of a map rehash mid-iteration.
	for i := 0; i < 200; i++ {
		rrl.pruneStale()
	}

	// All 100 buckets should be gone
	if len(rrl.buckets) != 0 {
		t.Errorf("FAIL: %d buckets remain after pruneStale (want 0)", len(rrl.buckets))
	}
}
