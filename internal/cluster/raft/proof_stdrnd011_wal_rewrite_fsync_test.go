package raft

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// writeWALEntries writes n entries with sequential indices starting at 1.
func writeWALEntries(t *testing.T, w *WAL, first, n Index) {
	t.Helper()
	for i := Index(0); i < n; i++ {
		idx := first + i
		if err := w.Write(entry{Index: idx, Term: 1, Type: EntryNormal,
			Command: []byte("cmd")}); err != nil {
			t.Fatalf("Write(index=%d): %v", idx, err)
		}
	}
}

// reopenWAL closes w and opens a fresh WAL on the same dir, mirroring what a
// node restart does.
func reopenWAL(t *testing.T, w *WAL, dir string) *WAL {
	t.Helper()
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	w2, err := NewWAL(dir)
	if err != nil {
		t.Fatalf("reopen NewWAL: %v", err)
	}
	return w2
}

func lastIndex(entries []entry) Index {
	if len(entries) == 0 {
		return 0
	}
	return entries[len(entries)-1].Index
}

// TestProofRound011_RewriteDirFsyncFailureKeepsAppendsReachable is the claim.
//
// TruncateAfter/CompactBefore rewrite the WAL via tmp+rename+dirfsync. The
// dir fsync is what makes the rename durable; if it FAILS, the rewrite has
// not actually happened durably. The contract those two methods must honour
// (they are the raft log persister behind TruncateAfter in state.go, whose
// whole purpose is to stop stale entries being replayed on restart) is that a
// reported error leaves the WAL in a state that is still coherent, so the
// caller can refuse to ack and the node keeps making progress.
//
// The defect: on dir-fsync failure rewriteLocked returns BEFORE swapping
// w.logFile to the new inode, so w.logFile still points at the ORIGINAL file
// that the rename has already unlinked. Subsequent Write() calls then succeed
// while appending into an unlinked inode, and the content is silently lost on
// restart. The function reports an error, but the node has already lost the
// entries it writes from then on.
func TestProofRound011_RewriteDirFsyncFailureKeepsAppendsReachable(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWAL(dir)
	if err != nil {
		t.Fatalf("NewWAL: %v", err)
	}
	// Entries 1..3.
	writeWALEntries(t, w, 1, 3)

	// Inject a dir-fsync failure into the rewrite path only.
	orig := syncHardStateParentDir
	syncHardStateParentDir = func(string) error { return errors.New("injected dir fsync failure") }
	truncErr := w.TruncateAfter(1) // keep entry 1, drop 2 and 3
	syncHardStateParentDir = orig

	if truncErr == nil {
		t.Fatal("precondition: TruncateAfter should have reported the injected dir-fsync failure")
	}

	// The node keeps running and appends. These writes MUST be durable.
	writeWALEntries(t, w, 2, 2) // indices 2 and 3 again, after the rewrite

	w2 := reopenWAL(t, w, dir)
	defer w2.Close()

	entries, err := w2.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll after restart: %v", err)
	}
	if got := lastIndex(entries); got != 3 {
		t.Errorf("FAIL: after a failed rewrite (%v), entries appended at "+
			"indices 2-3 were lost on restart: recovered up to index %d, want 3. "+
			"rewriteLocked returned before swapping w.logFile, so writes went to the "+
			"unlinked old inode", truncErr, got)
	}
}

// TestProofRound011_RewriteDirFsyncFailureControl is the control: the exact
// same sequence, with dir fsync succeeding, must keep the appended entries.
// It passes both before and after any fix, so a broken harness cannot
// masquerade as the defect.
func TestProofRound011_RewriteDirFsyncFailureControl(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWAL(dir)
	if err != nil {
		t.Fatalf("NewWAL: %v", err)
	}
	writeWALEntries(t, w, 1, 3)

	if err := w.TruncateAfter(1); err != nil {
		t.Fatalf("TruncateAfter with healthy dir fsync: %v", err)
	}

	writeWALEntries(t, w, 2, 2)

	w2 := reopenWAL(t, w, dir)
	defer w2.Close()

	entries, err := w2.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll after restart: %v", err)
	}
	if got := lastIndex(entries); got != 3 {
		t.Errorf("CONTROL FAILED: healthy rewrite lost entries: recovered to index %d, want 3", got)
	}
}

// TestProofRound011_RewriteFailureLeavesFileReachable asserts the underlying
// invariant directly: after a failed rewrite, appending and reopening must
// still see the appended entry. This is the same defect expressed as an
// invariant, so it stays meaningful if the TruncateAfter framing changes.
func TestProofRound011_RewriteFailureLeavesFileReachable(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWAL(dir)
	if err != nil {
		t.Fatalf("NewWAL: %v", err)
	}
	writeWALEntries(t, w, 1, 1)

	orig := syncHardStateParentDir
	syncHardStateParentDir = func(string) error { return errors.New("injected dir fsync failure") }
	_ = w.CompactBefore(1) // drop entry 1
	syncHardStateParentDir = orig

	const marker = 42
	if err := w.Write(entry{Index: marker, Term: 1, Type: EntryNormal,
		Command: []byte("after-failure")}); err != nil {
		t.Fatalf("Write after failed rewrite must succeed: %v", err)
	}

	w2 := reopenWAL(t, w, dir)
	defer w2.Close()

	entries, err := w2.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Index == marker {
			found = true
		}
	}
	if !found {
		var got []Index
		for _, e := range entries {
			got = append(got, e.Index)
		}
		t.Errorf("FAIL: entry %d written after a failed rewrite is not present after "+
			"restart; recovered indices %v. Writes are going to an unlinked inode", marker, got)
	}
	_ = os.Remove(filepath.Join(dir, "unused"))
}
