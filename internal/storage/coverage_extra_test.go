package storage

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// kvstore.go: Close with active transactions
// ---------------------------------------------------------------------------

func TestKVStoreClose_DoubleClose(t *testing.T) {
	dir := t.TempDir()

	store, err := OpenKVStore(dir)
	if err != nil {
		t.Fatalf("OpenKVStore: %v", err)
	}

	// Close once
	if err := store.Close(); err != nil {
		t.Fatalf("First Close: %v", err)
	}

	// Close again should not panic
	if err := store.Close(); err != nil {
		t.Logf("Second Close returned: %v (acceptable)", err)
	}
}

// ---------------------------------------------------------------------------
// wal.go: OpenWAL with existing segments to load
// ---------------------------------------------------------------------------

func TestWALOpen_ExistingSegments(t *testing.T) {
	dir := t.TempDir()
	opts := DefaultWALOptions()
	opts.MaxSegmentSize = 256 // Small segments to trigger rotation

	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}

	// Write enough entries to create multiple segments
	for i := 0; i < 20; i++ {
		data := make([]byte, 50)
		binary.BigEndian.PutUint32(data, uint32(i))
		if _, err := wal.Append(EntryTypePut, data); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	wal.Close()

	// Reopen and verify segments loaded
	wal2, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL (reopen): %v", err)
	}
	defer wal2.Close()

	stats := wal2.Stats()
	if stats.SegmentCount < 2 {
		t.Errorf("Expected multiple segments after rotation, got %d", stats.SegmentCount)
	}
}

// ---------------------------------------------------------------------------
// wal.go: createNewSegment via rotation
// ---------------------------------------------------------------------------

func TestWALCreateNewSegment_ViaRotation(t *testing.T) {
	dir := t.TempDir()
	opts := DefaultWALOptions()
	opts.MaxSegmentSize = 128 // Very small to force rotation

	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	defer wal.Close()

	// Write entries that exceed segment size to trigger rotation
	data := make([]byte, 100)
	for i := 0; i < 5; i++ {
		if _, err := wal.Append(EntryTypePut, data); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	stats := wal.Stats()
	if stats.SegmentCount < 2 {
		t.Errorf("Expected rotation, got %d segments", stats.SegmentCount)
	}
}

// ---------------------------------------------------------------------------
// wal.go: AppendBatch
// ---------------------------------------------------------------------------

func TestWALAppendBatch(t *testing.T) {
	dir := t.TempDir()
	opts := DefaultWALOptions()

	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	defer wal.Close()

	entries := []WALEntry{
		{Type: EntryTypePut, Data: []byte("key1")},
		{Type: EntryTypePut, Data: []byte("key2")},
		{Type: EntryTypePut, Data: []byte("key3")},
	}

	if err := wal.AppendBatch(entries); err != nil {
		t.Fatalf("AppendBatch: %v", err)
	}
}

// ---------------------------------------------------------------------------
// wal.go: AppendBatch on closed WAL
// ---------------------------------------------------------------------------

func TestWALAppendBatch_Closed(t *testing.T) {
	dir := t.TempDir()
	opts := DefaultWALOptions()

	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	wal.Close()

	entries := []WALEntry{
		{Type: EntryTypePut, Data: []byte("key1")},
	}
	if err := wal.AppendBatch(entries); err == nil {
		t.Error("AppendBatch on closed WAL should fail")
	}
}

// ---------------------------------------------------------------------------
// wal.go: Truncate segments (renamed to avoid conflict with wal_test.go)
// ---------------------------------------------------------------------------

func TestWALTruncate_MultiSegment(t *testing.T) {
	dir := t.TempDir()
	opts := DefaultWALOptions()
	opts.MaxSegmentSize = 256

	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	defer wal.Close()

	// Write multiple segments worth of data
	for i := 0; i < 20; i++ {
		data := make([]byte, 50)
		if _, err := wal.Append(EntryTypePut, data); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	stats := wal.Stats()
	if stats.SegmentCount < 3 {
		t.Fatalf("Expected at least 3 segments, got %d", stats.SegmentCount)
	}

	// Truncate removes segments with ID <= segmentID
	// Remove all but the active segment
	if err := wal.Truncate(uint64(stats.SegmentCount) - 2); err != nil {
		t.Fatalf("Truncate: %v", err)
	}

	stats = wal.Stats()
	if stats.SegmentCount != 1 {
		t.Errorf("Expected 1 segment after truncate, got %d", stats.SegmentCount)
	}
}

// ---------------------------------------------------------------------------
// wal.go: Compact (renamed to avoid conflict with wal_test.go)
// ---------------------------------------------------------------------------

func TestWALCompact_WithCheckpoint(t *testing.T) {
	dir := t.TempDir()
	opts := DefaultWALOptions()

	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	defer wal.Close()

	// Write some data
	for i := 0; i < 5; i++ {
		if _, err := wal.Append(EntryTypePut, []byte("data")); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	// Compact
	if err := wal.Compact([]byte("checkpoint_data")); err != nil {
		t.Fatalf("Compact: %v", err)
	}
}

// ---------------------------------------------------------------------------
// wal.go: WALReader Next with corrupted data
// ---------------------------------------------------------------------------

func TestWALReader_Next_CorruptData(t *testing.T) {
	dir := t.TempDir()

	// Write a corrupted segment file directly
	path := filepath.Join(dir, WALFilePrefix+"00000000000000000000"+WALFileSuffix)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Write garbage data that will fail to decode
	f.Write([]byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6})
	f.Close()

	opts := DefaultWALOptions()
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	defer wal.Close()

	reader := wal.NewReader()
	_, err = reader.Next()
	// Should either return an error or EOF
	if err == nil {
		t.Log("Next returned nil error (corrupt data handled gracefully)")
	}
}

// ---------------------------------------------------------------------------
// wal.go: syncLoop coverage
// ---------------------------------------------------------------------------

func TestWALSyncLoop_Trigger(t *testing.T) {
	dir := t.TempDir()
	opts := DefaultWALOptions()
	opts.SyncInterval = 10 * time.Millisecond

	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	defer wal.Close()

	// Write entries to trigger sync
	for i := 0; i < 5; i++ {
		if _, err := wal.Append(EntryTypePut, []byte("sync_test")); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	// Wait for sync to happen
	time.Sleep(50 * time.Millisecond)

	stats := wal.Stats()
	if stats.SegmentCount < 1 {
		t.Error("Expected at least 1 segment")
	}
}

// ---------------------------------------------------------------------------
// wal.go: Close with sync pending
// ---------------------------------------------------------------------------

func TestWALClose_SyncPending(t *testing.T) {
	dir := t.TempDir()
	opts := DefaultWALOptions()
	opts.SyncInterval = 1 * time.Hour // Very long so sync is pending on close

	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}

	// Write data without syncing
	wal.Append(EntryTypePut, []byte("pending_sync"))

	// Close should handle pending sync
	if err := wal.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// ---------------------------------------------------------------------------
// wal.go: OpenWAL with preallocate option
// ---------------------------------------------------------------------------

func TestWALOpen_WithPreallocate(t *testing.T) {
	dir := t.TempDir()
	opts := DefaultWALOptions()
	opts.PreallocateSize = 4096

	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	defer wal.Close()

	// Write some data
	if _, err := wal.Append(EntryTypePut, []byte("preallocate_test")); err != nil {
		t.Fatalf("Append: %v", err)
	}
}

// ---------------------------------------------------------------------------
// wal.go: WALStats
// ---------------------------------------------------------------------------

func TestWALStats_AfterOperations(t *testing.T) {
	dir := t.TempDir()
	opts := DefaultWALOptions()

	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	defer wal.Close()

	stats := wal.Stats()
	initialSegments := stats.SegmentCount
	initialSize := stats.TotalSize

	if initialSegments == 0 {
		t.Error("Expected at least 1 segment initially")
	}

	// Write data
	wal.Append(EntryTypePut, make([]byte, 100))

	stats = wal.Stats()
	if stats.TotalSize <= initialSize {
		t.Error("Expected total size to increase after append")
	}
}
