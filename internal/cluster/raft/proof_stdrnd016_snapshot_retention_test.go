package raft

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProofRound016_SnapshotterDiscardsSupersededSnapshots drives the real
// Snapshotter through the same repeated-Save sequence ClusterIntegration
// performs every SnapshotInterval while leading, then asserts the on-disk
// snapshot count stays bounded.
//
// Contract being asserted: Snapshotter exists to BOUND durable state.
// takeSnapshot compacts the in-memory log and calls WAL CompactBefore
// precisely because "entries up to the snapshot are now redundant", and
// Load() reads only the highest-index file — so superseded snapshots are
// dead weight by construction. A store that keeps every historical copy
// converts a bounded log into an unbounded snapshot pile: with the default
// 30s interval the directory grows forever, and each file holds a full
// serialization of the zone store.
func TestProofRound016_SnapshotterDiscardsSupersededSnapshots(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSnapshotter(dir)
	if err != nil {
		t.Fatalf("NewSnapshotter: %v", err)
	}

	// One save per snapshot interval, as ClusterIntegration.takeSnapshot does.
	const saves = 50
	for i := 1; i <= saves; i++ {
		if err := s.Save(&Snapshot{
			Index:     Index(i),
			Term:      1,
			LastIndex: Index(i),
			LastTerm:  1,
			Data:      []byte("zone-state"),
		}); err != nil {
			t.Fatalf("Save(%d): %v", i, err)
		}
	}

	// Control: Load must return the newest snapshot regardless — the fix
	// must not break recovery. This passes before AND after the fix.
	snap, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if snap == nil {
		t.Fatal("Load returned nil snapshot")
	}
	if snap.Index != Index(saves) {
		t.Fatalf("Load returned index %d, want latest %d", snap.Index, saves)
	}

	var retained int
	var bytesOnDisk int64
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "snapshot-") {
			continue
		}
		retained++
		if info, statErr := e.Info(); statErr == nil {
			bytesOnDisk += info.Size()
		}
	}

	// Load() consumes exactly one file. Anything beyond a small retention
	// window is unreachable state that can never be read again.
	const maxRetainedSnapshots = 2
	if retained > maxRetainedSnapshots {
		t.Fatalf("FAIL: after %d saves the snapshot dir retains %d files (%d bytes); "+
			"Load() only ever reads the newest, so superset files are unbounded "+
			"dead weight (want <= %d)",
			saves, retained, bytesOnDisk, maxRetainedSnapshots)
	}
}

// TestProofRound016_SnapshotterPrunesOnSave checks the pruning happens as part
// of Save itself, so a long-running leader reclaims space continuously rather
// than only at some later compaction step. A crash between Saves must still
// leave a loadable snapshot (retained >= 1), which this asserts.
func TestProofRound016_SnapshotterPrunesOnSave(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSnapshotter(dir)
	if err != nil {
		t.Fatalf("NewSnapshotter: %v", err)
	}

	const saves = 5
	for i := 1; i <= saves; i++ {
		if err := s.Save(&Snapshot{
			Index: Index(i * 10), Term: 2, LastIndex: Index(i * 10), LastTerm: 2,
			Data: []byte("state"),
		}); err != nil {
			t.Fatalf("Save(%d): %v", i, err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	retained := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "snapshot-") {
			retained++
		}
	}

	if retained == 0 {
		t.Fatal("FAIL: Save pruned every snapshot, including the newest — a crash " +
			"here would leave the node with no recoverable snapshot and force a full log replay")
	}
	if retained > 2 {
		names := make([]string, 0, retained)
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "snapshot-") {
				names = append(names, e.Name())
			}
		}
		t.Fatalf("FAIL: retained %d snapshots after %d saves: %v", retained, saves, names)
	}
	_ = filepath.Base(dir)
}
