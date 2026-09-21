//go:build proof_round006

// Round-006 proof: WAL.AppendBatch must be atomic. The current
// implementation writes EntryTypeBegin, then each entry, then
// EntryTypeCommit. If appendLocked fails on any entry, the function
// returns the error immediately — but the Begin marker and already-written
// entries are left in the WAL with no Commit. The recovery path
// (readSegment → ReadAll) returns all entries without filtering by
// Begin/Commit markers, so callers replay uncommitted entries.
//
// Pre-fix expected: after a failed AppendBatch, ReadAll returns the
// Begin marker and the entries written before the failure (without a
// Commit marker). This means recovery treats them as committed.
// Post-fix expected: ReadAll returns only entries from committed batches.
//
// Build tag `proof_round006` keeps this proof as durable regression
// evidence without dirtying the default suite. Run with:
//   go test -tags proof_round006 ./internal/storage/ -run TestProofRound006 -v
package storage

import (
	"os"
	"testing"
)

// TestProofRound006_AppendBatchAtomicity verifies that a partial batch
// left in the WAL after AppendBatch failure is not returned by ReadAll
// as if it were committed.
func TestProofRound006_AppendBatchAtomicity(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	// Tiny segment size to force a rotation mid-batch, which is the most
	// likely place for appendLocked to fail under resource pressure.
	opts.MaxSegmentSize = 512

	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })

	// First, write a successful batch so the WAL has at least one
	// committed batch as a control.
	committedEntries := []WALEntry{
		{Type: 0x01, Data: []byte("committed-1")},
	}
	if err := wal.AppendBatch(committedEntries); err != nil {
		t.Fatalf("control AppendBatch: %v", err)
	}

	// Read back the control entries to establish a baseline.
	before, err := wal.ReadAll()
	if err != nil {
		t.Fatalf("control ReadAll: %v", err)
	}

	// Now force appendLocked to fail mid-batch by making the WAL
	// directory read-only so the next segment rotation fails with EACCES.
	// The sequence in AppendBatch is:
	//   1. write Begin marker (succeeds, fits in current segment)
	//   2. write entry 1 → triggers createNewSegment → fails (EACCES)
	//   3. AppendBatch returns the error
	// Pre-fix: the Begin marker and the (empty) entry are left in the
	// WAL with no Commit marker. Recovery via ReadAll returns them.
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	// Use an entry large enough to force a segment rotation in the
	// current segment, so createNewSegment is called and fails with EACCES.
	big := make([]byte, opts.MaxSegmentSize/2)
	for i := range big {
		big[i] = 0x42
	}

	failingEntries := []WALEntry{
		{Type: 0x01, Data: big},
		{Type: 0x01, Data: big},
	}
	err = wal.AppendBatch(failingEntries)
	if err == nil {
		// Restore permissions so the skip cleanup works.
		_ = os.Chmod(dir, 0o755)
		t.Skipf("setup: AppendBatch did not fail with read-only directory; cannot demonstrate atomicity defect. err=nil")
	}

	// Read back everything after the failed batch.
	after, err := wal.ReadAll()
	if err != nil {
		t.Fatalf("post-failure ReadAll: %v", err)
	}

	// Count how many entries appear after the control batch.
	extraEntries := len(after) - len(before)

	// The contract: a failed AppendBatch must leave the WAL in a state
	// where ReadAll returns only the previous committed entries — the
	// partial batch must NOT be visible. Pre-fix, the Begin marker and
	// the entries written before the failure are returned as if
	// committed, so extraEntries > 0.
	if extraEntries > 0 {
		t.Fatalf("FAIL: after a failed AppendBatch, ReadAll returned %d extra entries beyond the control batch. "+
			"These are entries from a partial batch (Begin + N entries without Commit) that must be discarded on recovery. "+
			"The Begin/Commit markers are written but never checked by readSegment/ReadAll.",
			extraEntries)
	}

	t.Logf("PROOF PASS: after a failed AppendBatch, ReadAll returned no extra entries beyond the committed control batch")
}
