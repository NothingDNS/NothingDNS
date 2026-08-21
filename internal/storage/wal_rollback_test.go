package storage

import (
	"io"
	"os"
	"strings"
	"testing"
)

// ============================================================================
// WAL.rollbackActiveAppend — simulated-crash fixtures
//
// rollbackActiveAppend is the torn-write recovery path: when Append's
// write fails midway, the active segment is truncated back to the last
// known-clean size and reseeked, so recovery never replays partial bytes
// and the next Append starts at a clean offset.
//
// Reachable branches: clean rollback (truncate+seek succeed), truncate
// failure (closed file), and the two caller paths that combine the write
// error with a failed rollback (Append wal.go:412, AppendBatch :488).
// The seek-only-failure branch is unreachable with a real *os.File: any
// fd state that breaks Seek also breaks Truncate first.
// ============================================================================

// TestWALRollback_TruncatesTornBytes simulates a crash mid-Append: garbage
// bytes land past the clean size (the write partially succeeded), but
// wal.active.size was never advanced. rollbackActiveAppend must restore
// the file to the clean append point, and a reopen must replay exactly
// the pre-crash entries.
func TestWALRollback_TruncatesTornBytes(t *testing.T) {
	dir := t.TempDir()
	wal, err := OpenWAL(dir, DefaultWALOptions())
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}

	for i := 0; i < 2; i++ {
		if _, err := wal.Append(EntryTypePut, []byte("clean_entry")); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	wal.Sync()
	cleanSize := wal.active.size
	if cleanSize == 0 {
		t.Fatal("clean size is zero; fixture broken")
	}

	// Simulated torn write: bytes appear in the file past the clean size
	// (writeWALBuffer partially succeeded) but size was never advanced —
	// exactly the state Append sees when its write fails mid-entry.
	torn := make([]byte, 17)
	for i := range torn {
		torn[i] = 0xEE
	}
	if _, err := wal.active.file.Write(torn); err != nil {
		t.Fatalf("write torn bytes: %v", err)
	}

	// Confirm the file really is beyond the clean size before rollback.
	segPath := wal.active.Path
	if info, err := os.Stat(segPath); err != nil {
		t.Fatalf("stat segment: %v", err)
	} else if info.Size() <= cleanSize {
		t.Fatalf("torn write did not extend file: size=%d clean=%d", info.Size(), cleanSize)
	}

	// The rollback under test.
	if err := wal.rollbackActiveAppend(cleanSize); err != nil {
		t.Fatalf("rollbackActiveAppend: %v", err)
	}

	// The rollback must have restored the clean append point.
	if info, err := os.Stat(segPath); err != nil {
		t.Fatalf("stat after rollback: %v", err)
	} else if info.Size() != cleanSize {
		t.Errorf("file size after rollback = %d, want clean size %d", info.Size(), cleanSize)
	}

	wal.Close()

	// Recovery view: reopen must replay exactly the two clean entries —
	// no torn bytes, no truncation warnings needed.
	wal2, err := OpenWAL(dir, DefaultWALOptions())
	if err != nil {
		t.Fatalf("OpenWAL reopen: %v", err)
	}
	defer wal2.Close()
	entries, err := wal2.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("replayed %d entries, want 2", len(entries))
	}
	for i, e := range entries {
		if string(e.Data) != "clean_entry" {
			t.Errorf("entry %d data = %q, want %q", i, string(e.Data), "clean_entry")
		}
	}
}

// TestWALRollback_TruncateFailsOnClosedFile drives the truncate-error
// branch: a closed underlying fd makes Truncate fail, and the error must
// surface (never be swallowed — hidden torn bytes are the failure mode
// the function exists to prevent).
func TestWALRollback_TruncateFailsOnClosedFile(t *testing.T) {
	dir := t.TempDir()
	wal, err := OpenWAL(dir, DefaultWALOptions())
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	if _, err := wal.Append(EntryTypePut, []byte("entry")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := wal.active.file.Close(); err != nil {
		t.Fatalf("close underlying file: %v", err)
	}

	err = wal.rollbackActiveAppend(wal.active.size)
	if err == nil {
		t.Fatal("rollback on closed file: expected truncate error, got nil")
	}
	if !strings.Contains(err.Error(), "truncate active segment") {
		t.Errorf("error = %v, want truncate failure", err)
	}
}

// TestWALAppend_WriteFailureTriggersRollback covers Append's caller path
// (wal.go:412) end-to-end: a write failure invokes the rollback; when the
// rollback also fails, both errors surface in the combined message.
func TestWALAppend_WriteFailureTriggersRollback(t *testing.T) {
	dir := t.TempDir()
	wal, err := OpenWAL(dir, DefaultWALOptions())
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	if _, err := wal.Append(EntryTypePut, []byte("first")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	// Drain the pending background sync while the fd is still open. Every
	// successful Append signals syncChan, and OpenWAL's syncLoop goroutine
	// (wal.go:170) would otherwise hit the closed fd after the close below,
	// set wal.syncErr, and make the next Append short-circuit at
	// checkSyncErrLocked (wal.go:375) with "previous WAL sync failed"
	// instead of the write-entry error this test asserts — observed under
	// -race in CI (run 32526413421).
	wal.Sync()
	// Break the fd so the next write fails mid-Append and the rollback
	// behind it fails too (closed fd).
	if err := wal.active.file.Close(); err != nil {
		t.Fatalf("close underlying file: %v", err)
	}

	_, err = wal.Append(EntryTypePut, []byte("second"))
	if err == nil {
		t.Fatal("Append after fd close: expected error")
	}
	if !strings.Contains(err.Error(), "write entry") {
		t.Errorf("error = %v, want write-entry failure", err)
	}
	if !strings.Contains(err.Error(), "rollback failed") {
		t.Errorf("error = %v, want combined rollback failure", err)
	}
}

// TestWALAppendBatch_WriteFailureTriggersRollback covers the AppendBatch
// variant of the same rollback path (wal.go:488).
func TestWALAppendBatch_WriteFailureTriggersRollback(t *testing.T) {
	dir := t.TempDir()
	wal, err := OpenWAL(dir, DefaultWALOptions())
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	if err := wal.active.file.Close(); err != nil {
		t.Fatalf("close underlying file: %v", err)
	}

	err = wal.AppendBatch([]WALEntry{{Type: EntryTypePut, Data: []byte("batched")}})
	if err == nil {
		t.Fatal("AppendBatch after fd close: expected error")
	}
	if !strings.Contains(err.Error(), "write entry") {
		t.Errorf("error = %v, want write-entry failure", err)
	}
	if !strings.Contains(err.Error(), "rollback failed") {
		t.Errorf("error = %v, want combined rollback failure", err)
	}
}

// TestWALRollback_SeekRestoresAppendOffset pins the post-rollback seek
// contract: after truncation the fd offset is at the clean end, so the
// next Append writes contiguously (no hole between entries).
func TestWALRollback_SeekRestoresAppendOffset(t *testing.T) {
	dir := t.TempDir()
	wal, err := OpenWAL(dir, DefaultWALOptions())
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	defer wal.Close()
	if _, err := wal.Append(EntryTypePut, []byte("one")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	cleanSize := wal.active.size

	// Leave the fd offset stranded past the end (as a partial write does),
	// then roll back and verify the offset follows the truncation point.
	torn := []byte{0xEE, 0xEE, 0xEE}
	if _, err := wal.active.file.Write(torn); err != nil {
		t.Fatalf("write torn bytes: %v", err)
	}
	if err := wal.rollbackActiveAppend(cleanSize); err != nil {
		t.Fatalf("rollbackActiveAppend: %v", err)
	}
	off, err := wal.active.file.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatalf("seek(0, CUR): %v", err)
	}
	if off != cleanSize {
		t.Errorf("fd offset after rollback = %d, want %d", off, cleanSize)
	}

	// And the next Append still lands contiguously and replays cleanly.
	if _, err := wal.Append(EntryTypePut, []byte("two")); err != nil {
		t.Fatalf("Append after rollback: %v", err)
	}
	wal.Sync()
	entries, err := wal.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != 2 || string(entries[1].Data) != "two" {
		t.Errorf("entries after rollback+append = %+v, want [one two]", entries)
	}
}
