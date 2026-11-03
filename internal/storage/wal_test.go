package storage

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWALCreate(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	stats := wal.Stats()
	if stats.SegmentCount != 1 {
		t.Errorf("Expected 1 segment, got %d", stats.SegmentCount)
	}
}

func TestOpenWALNormalizesInvalidOptions(t *testing.T) {
	dir := t.TempDir()

	wal, err := OpenWAL(dir, WALOptions{
		MaxSegmentSize:  -1,
		SyncInterval:    0,
		PreallocateSize: -1,
	})
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	if wal.opts.MaxSegmentSize != MaxSegmentSize {
		t.Fatalf("MaxSegmentSize = %d, want %d", wal.opts.MaxSegmentSize, MaxSegmentSize)
	}
	if wal.opts.SyncInterval != SyncInterval {
		t.Fatalf("SyncInterval = %v, want %v", wal.opts.SyncInterval, SyncInterval)
	}
	if wal.opts.PreallocateSize != 0 {
		t.Fatalf("PreallocateSize = %d, want 0", wal.opts.PreallocateSize)
	}

	if _, err := wal.Append(EntryTypePut, []byte("normalized")); err != nil {
		t.Fatalf("Append failed: %v", err)
	}
}

func TestWALAppend(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	// Append entries
	for i := 0; i < 10; i++ {
		_, err := wal.Append(EntryTypePut, []byte("test_data"))
		if err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}

	// Sync
	if err := wal.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}
}

func TestWALReadAll(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}

	// Append entries
	testData := [][]byte{
		[]byte("data1"),
		[]byte("data2"),
		[]byte("data3"),
	}

	for _, data := range testData {
		_, err := wal.Append(EntryTypePut, data)
		if err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}

	// Sync and read
	if err := wal.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	entries, err := wal.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if len(entries) != len(testData) {
		t.Errorf("Expected %d entries, got %d", len(testData), len(entries))
	}

	for i, entry := range entries {
		if string(entry.Data) != string(testData[i]) {
			t.Errorf("Entry %d: expected %s, got %s", i, testData[i], entry.Data)
		}
	}

	wal.Close()
}

func TestWALBatchAppend(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	entries := []WALEntry{
		{Type: EntryTypePut, Data: []byte("batch1")},
		{Type: EntryTypePut, Data: []byte("batch2")},
		{Type: EntryTypePut, Data: []byte("batch3")},
	}

	if err := wal.AppendBatch(entries); err != nil {
		t.Fatalf("AppendBatch failed: %v", err)
	}
}

func TestWALTruncate(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	// Create multiple segments by appending large data
	for i := 0; i < 100; i++ {
		data := make([]byte, 1024) // 1KB each
		_, err := wal.Append(EntryTypePut, data)
		if err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}

	stats := wal.Stats()
	initialSegments := stats.SegmentCount

	// Truncate
	if err := wal.Truncate(0); err != nil {
		t.Fatalf("Truncate failed: %v", err)
	}

	stats = wal.Stats()
	if stats.SegmentCount > initialSegments {
		t.Errorf("Segment count should not increase after truncate")
	}
}

func TestWALTruncateReportsSegmentCloseError(t *testing.T) {
	dir := t.TempDir()

	removedPath := filepath.Join(dir, WALFilePrefix+"00000000000000000000"+WALFileSuffix)
	removedFile, err := os.OpenFile(removedPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open removed segment: %v", err)
	}
	if err := removedFile.Close(); err != nil {
		t.Fatalf("close removed segment fixture: %v", err)
	}

	activePath := filepath.Join(dir, WALFilePrefix+"00000000000000000001"+WALFileSuffix)
	if err := os.WriteFile(activePath, nil, 0600); err != nil {
		t.Fatalf("write active segment fixture: %v", err)
	}
	active := &WALSegment{ID: 1, Path: activePath}
	wal := &WAL{
		segments: []*WALSegment{
			{ID: 0, Path: removedPath, file: removedFile},
			active,
		},
		active: active,
	}

	err = wal.Truncate(0)
	if err == nil {
		t.Fatal("Truncate should report segment close error")
	}
	if !strings.Contains(err.Error(), "close segment 0") {
		t.Fatalf("Truncate error should include segment close context, got: %v", err)
	}
}

func TestWALRecovery(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()

	// Write data
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}

	testData := []byte("recovery_test")
	_, err = wal.Append(EntryTypePut, testData)
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	if err := wal.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	wal.Close()

	// Reopen and read
	wal2, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer wal2.Close()

	entries, err := wal2.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if len(entries) != 1 {
		t.Errorf("Expected 1 entry, got %d", len(entries))
	}

	if string(entries[0].Data) != string(testData) {
		t.Errorf("Expected %s, got %s", testData, entries[0].Data)
	}
}

func TestWALCompact(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	// Write some data
	for i := 0; i < 10; i++ {
		_, err := wal.Append(EntryTypePut, []byte("data"))
		if err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}

	// Compact
	checkpoint := []byte("checkpoint_data")
	if err := wal.Compact(checkpoint); err != nil {
		t.Fatalf("Compact failed: %v", err)
	}
}

func TestWALReader(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}

	// Write data
	for i := 0; i < 5; i++ {
		_, err := wal.Append(EntryTypePut, []byte("reader_test"))
		if err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}

	wal.Sync()

	// Read with ReadAll
	entries, err := wal.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if len(entries) != 5 {
		t.Errorf("Expected 5 entries, got %d", len(entries))
	}

	wal.Close()
}

func TestWALReaderNextReportsCloseErrorAtEOF(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, WALFilePrefix+"00000000000000000000"+WALFileSuffix)
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatalf("write empty segment: %v", err)
	}

	originalCloseWALReaderFile := closeWALReaderFile
	closeWALReaderFile = func(*os.File) error {
		return errors.New("reader close failed")
	}
	t.Cleanup(func() { closeWALReaderFile = originalCloseWALReaderFile })

	wal := &WAL{
		segments: []*WALSegment{{ID: 0, Path: path}},
	}
	reader := wal.NewReader()
	_, err := reader.Next()
	if err == nil {
		t.Fatal("Next should report close error after EOF")
	}
	if !strings.Contains(err.Error(), "close segment after EOF") {
		t.Fatalf("Next error should include close context, got: %v", err)
	}
}

// TestWALReader_MultiEntry guards against a regression where
// WALReader.Next() used bytes.Buffer.Truncate to "consume" a
// decoded payload — Truncate keeps the front and discards the
// tail, so a stream containing more than one entry returned
// garbage from the second call onward. Next() now uses
// bytes.Buffer.Next() to advance past the payload bytes.
func TestWALReader_MultiEntry(t *testing.T) {
	dir := t.TempDir()
	opts := DefaultWALOptions()
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}

	const n = 5
	payloads := [][]byte{
		[]byte("alpha"),
		[]byte("beta-payload"),
		[]byte("gamma"),
		[]byte("delta-payload-data"),
		[]byte("epsilon"),
	}
	for i := 0; i < n; i++ {
		if _, err := wal.Append(EntryTypePut, payloads[i]); err != nil {
			t.Fatalf("Append %d failed: %v", i, err)
		}
	}
	wal.Sync()

	reader := wal.NewReader()
	defer reader.Close()
	defer wal.Close()

	for i := 0; i < n; i++ {
		entry, err := reader.Next()
		if err != nil {
			t.Fatalf("Next %d returned error: %v", i, err)
		}
		if entry == nil {
			t.Fatalf("Next %d returned nil entry", i)
		}
		if string(entry.Data) != string(payloads[i]) {
			t.Errorf("entry %d: expected payload %q, got %q", i, payloads[i], entry.Data)
		}
	}
}

func TestWALReader_LargeEntrySpanningReads(t *testing.T) {
	dir := t.TempDir()
	opts := DefaultWALOptions()
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}

	largePayload := strings.Repeat("x", 5000)
	if _, err := wal.Append(EntryTypePut, []byte(largePayload)); err != nil {
		t.Fatalf("Append large payload failed: %v", err)
	}
	if _, err := wal.Append(EntryTypePut, []byte("after-large")); err != nil {
		t.Fatalf("Append second payload failed: %v", err)
	}
	if err := wal.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	reader := wal.NewReader()
	defer reader.Close()
	defer wal.Close()

	entry, err := reader.Next()
	if err != nil {
		t.Fatalf("Next large payload returned error: %v", err)
	}
	if string(entry.Data) != largePayload {
		t.Fatalf("large payload mismatch: got %d bytes, want %d", len(entry.Data), len(largePayload))
	}

	entry, err = reader.Next()
	if err != nil {
		t.Fatalf("Next second payload returned error: %v", err)
	}
	if string(entry.Data) != "after-large" {
		t.Fatalf("second payload = %q, want %q", entry.Data, "after-large")
	}
}

func TestWALEntryEncoding(t *testing.T) {
	wal := &WAL{}

	entry := &WALEntry{
		Type:      EntryTypePut,
		Data:      []byte("test_data_for_encoding"),
		Timestamp: time.Now().UnixNano(),
	}

	encoded, err := wal.encodeEntry(entry)
	if err != nil {
		t.Fatalf("encodeEntry failed: %v", err)
	}

	decoded, err := wal.decodeEntry(encoded)
	if err != nil {
		t.Fatalf("decodeEntry failed: %v", err)
	}

	if decoded.Type != entry.Type {
		t.Errorf("Type mismatch: expected %d, got %d", entry.Type, decoded.Type)
	}

	if string(decoded.Data) != string(entry.Data) {
		t.Errorf("Data mismatch: expected %s, got %s", entry.Data, decoded.Data)
	}
}

// TestWALRecovery_PartialTrailingEntry simulates a power-loss crash
// that left a torn entry at the end of the active segment: the
// first valid entry is intact, then the file ends mid-header (or
// mid-body) of what would have been the next entry. Recovery should
// return the valid entries it can read and stop cleanly, rather
// than failing the whole segment with "read header at N: unexpected
// EOF" — which is what the pre-fix code did.
func TestWALRecovery_PartialTrailingEntry(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	if _, err := wal.Append(EntryTypePut, []byte("alpha")); err != nil {
		t.Fatalf("Append alpha: %v", err)
	}
	if _, err := wal.Append(EntryTypePut, []byte("beta")); err != nil {
		t.Fatalf("Append beta: %v", err)
	}
	if err := wal.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	wal.Close()

	// Find the active segment file and truncate the last few bytes
	// to simulate a torn write. Any segment file in the dir works.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var segPath string
	for _, e := range entries {
		if !e.IsDir() {
			segPath = filepath.Join(dir, e.Name())
		}
	}
	if segPath == "" {
		t.Fatal("no segment file found")
	}
	info, err := os.Stat(segPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// Append 3 garbage bytes (less than a header) to mimic a torn write.
	f, err := os.OpenFile(segPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatalf("open append: %v", err)
	}
	if _, err := f.Write([]byte{0x01, 0x02, 0x03}); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	f.Close()
	if newInfo, _ := os.Stat(segPath); newInfo.Size() != info.Size()+3 {
		t.Fatalf("size mismatch: expected +3, got %d", newInfo.Size()-info.Size())
	}

	// Reopen and ReadAll should succeed and return both valid entries.
	wal2, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("Reopen: %v", err)
	}
	defer wal2.Close()
	got, err := wal2.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll on partial-tail segment: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries surviving torn trailer, got %d", len(got))
	}
	if string(got[0].Data) != "alpha" || string(got[1].Data) != "beta" {
		t.Errorf("entry data mismatch: %q, %q", got[0].Data, got[1].Data)
	}
}

// TestWALRecovery_AppendAfterTornTail verifies that after a torn write
// leaves garbage at the segment tail, the next OpenWAL → Append → close
// → re-Open cycle still surfaces the post-crash entries. The previous
// fix made readSegment stop *cleanly* at the torn bytes, but OpenWAL
// continued to use the file's raw size as the active offset and
// appended past the garbage. Recovery then re-stopped at the same
// torn bytes and never reached the new entries.
func TestWALRecovery_AppendAfterTornTail(t *testing.T) {
	dir := t.TempDir()
	opts := DefaultWALOptions()

	// Write entry, fsync, close.
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	if _, err := wal.Append(EntryTypePut, []byte("pre-crash")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	wal.Sync()
	wal.Close()

	// Simulate torn tail.
	entries, _ := os.ReadDir(dir)
	var segPath string
	for _, e := range entries {
		segPath = filepath.Join(dir, e.Name())
	}
	f, _ := os.OpenFile(segPath, os.O_WRONLY|os.O_APPEND, 0)
	_, _ = f.Write([]byte{0xAA, 0xBB, 0xCC})
	f.Close()

	// Reopen, Append a recovery entry, close.
	wal2, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("Reopen: %v", err)
	}
	if _, err := wal2.Append(EntryTypePut, []byte("post-crash")); err != nil {
		t.Fatalf("Append after torn tail: %v", err)
	}
	wal2.Sync()
	wal2.Close()

	// Re-open and ReadAll. Both entries must come back.
	wal3, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("Final reopen: %v", err)
	}
	defer wal3.Close()
	got, err := wal3.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries post-recovery, got %d", len(got))
	}
	if string(got[0].Data) != "pre-crash" || string(got[1].Data) != "post-crash" {
		t.Errorf("entry data: pre=%q post=%q", got[0].Data, got[1].Data)
	}
}

func TestWALRecovery_AppendAfterChecksumCorruption_F820(t *testing.T) {
	dir := t.TempDir()
	opts := DefaultWALOptions()

	w, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(EntryTypePut, []byte("corrupt-me")); err != nil {
		t.Fatal(err)
	}
	if err := w.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("segment lookup: entries=%d err=%v", len(entries), err)
	}
	path := filepath.Join(dir, entries[0].Name())
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[WALHeaderSize] ^= 0xff
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	w, err = OpenWAL(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(EntryTypePut, []byte("post-recovery")); err != nil {
		t.Fatal(err)
	}
	if err := w.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	w, err = OpenWAL(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	got, err := w.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || string(got[0].Data) != "post-recovery" {
		t.Fatalf("replayed entries = %+v, want only post-recovery entry", got)
	}
}

func TestWALCorruptedEntry(t *testing.T) {
	wal := &WAL{}

	// Create corrupted entry (bad checksum)
	corrupted := make([]byte, WALHeaderSize+10)
	corrupted[4] = EntryTypePut
	// Wrong checksum
	corrupted[0] = 0xFF
	corrupted[1] = 0xFF
	corrupted[2] = 0xFF
	corrupted[3] = 0xFF
	// Length
	corrupted[5] = 0
	corrupted[6] = 0
	corrupted[7] = 0
	corrupted[8] = 10

	_, err := wal.decodeEntry(corrupted)
	if err != ErrInvalidChecksum {
		t.Errorf("Expected ErrInvalidChecksum, got %v", err)
	}
}

func TestWALAppendReportsRollbackFailure(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	if err := wal.active.file.Close(); err != nil {
		t.Fatalf("close active file: %v", err)
	}

	_, err = wal.Append(EntryTypePut, []byte("test_data"))
	if err == nil {
		t.Fatal("Append with closed active file should fail")
	}
	if !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("Append error should include rollback failure, got: %v", err)
	}
}

func TestWALCloseReportsFinalSyncError(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	opts.SyncInterval = time.Hour
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}

	wal.mu.Lock()
	wal.syncPending = true
	if err := wal.active.file.Close(); err != nil {
		wal.mu.Unlock()
		t.Fatalf("close active file: %v", err)
	}
	wal.mu.Unlock()

	err = wal.Close()
	if err == nil {
		t.Fatal("Close with pending sync on closed active file should fail")
	}
	if !strings.Contains(err.Error(), "final sync") {
		t.Fatalf("Close error should include final sync context, got: %v", err)
	}
}

func TestWALSyncLoopRecordsAsyncSyncError(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	opts.SyncInterval = time.Hour
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}

	if _, err := wal.Append(EntryTypePut, []byte("test_data")); err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	wal.mu.Lock()
	if err := wal.active.file.Close(); err != nil {
		wal.mu.Unlock()
		t.Fatalf("close active file: %v", err)
	}
	wal.syncPending = true
	wal.mu.Unlock()

	select {
	case wal.syncChan <- struct{}{}:
	default:
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		wal.mu.Lock()
		syncErr := wal.syncErr
		wal.mu.Unlock()
		if syncErr != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("syncLoop did not record async sync error")
		}
		time.Sleep(time.Millisecond)
	}

	if _, err := wal.Append(EntryTypePut, []byte("after_error")); err == nil {
		t.Fatal("Append after async sync error should fail")
	} else if !strings.Contains(err.Error(), "previous WAL sync failed") {
		t.Fatalf("Append error should mention previous sync failure, got: %v", err)
	}

	wal.mu.Lock()
	wal.closed = true
	close(wal.stopChan)
	wal.active.file = nil
	wal.mu.Unlock()
	wal.wg.Wait()
}

func TestWALSyncClearsPreviousSyncError(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	opts.SyncInterval = time.Hour
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	wal.mu.Lock()
	wal.syncErr = errors.New("old sync error")
	wal.syncPending = true
	wal.mu.Unlock()

	if err := wal.Sync(); err != nil {
		t.Fatalf("Sync should clear previous error after successful fsync: %v", err)
	}
	if _, err := wal.Append(EntryTypePut, []byte("after_clear")); err != nil {
		t.Fatalf("Append after successful Sync failed: %v", err)
	}
}

func TestWALCreateNewSegmentSyncsPendingActiveSegment(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	opts.SyncInterval = time.Hour
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	if _, err := wal.Append(EntryTypePut, []byte("test_data")); err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	wal.mu.Lock()
	wal.syncPending = true
	oldActive := wal.active
	oldID := oldActive.ID
	err = wal.createNewSegment()
	syncPending := wal.syncPending
	oldSealed := oldActive.sealed
	oldFileNil := oldActive.file == nil
	newID := wal.active.ID
	wal.mu.Unlock()
	if err != nil {
		t.Fatalf("createNewSegment failed: %v", err)
	}
	if syncPending {
		t.Fatal("createNewSegment should sync pending active segment before rotation")
	}
	if !oldSealed {
		t.Fatal("old active segment should be sealed")
	}
	if !oldFileNil {
		t.Fatal("old active segment file should be closed and cleared")
	}
	if newID != oldID+1 {
		t.Fatalf("active segment ID = %d, want %d", newID, oldID+1)
	}
}

func TestWALCreateNewSegmentKeepsActiveSegmentOnCreateFailure(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	opts.SyncInterval = time.Hour
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	nextPath := filepath.Join(dir, WALFilePrefix+"00000000000000000001"+WALFileSuffix)
	if err := os.Mkdir(nextPath, 0700); err != nil {
		t.Fatalf("create next segment directory: %v", err)
	}

	wal.mu.Lock()
	oldActive := wal.active
	oldID := oldActive.ID
	err = wal.createNewSegment()
	activeSame := wal.active == oldActive
	activeFileNil := wal.active.file == nil
	activeSealed := wal.active.sealed
	segmentCount := len(wal.segments)
	wal.mu.Unlock()

	if err == nil {
		t.Fatal("createNewSegment should fail when next segment path is a directory")
	}
	if !strings.Contains(err.Error(), "create segment file") {
		t.Fatalf("createNewSegment error should include create context, got: %v", err)
	}
	if !activeSame {
		t.Fatal("active segment changed after failed createNewSegment")
	}
	if activeFileNil {
		t.Fatal("active segment file should remain open after failed createNewSegment")
	}
	if activeSealed {
		t.Fatal("active segment should not be sealed after failed createNewSegment")
	}
	if segmentCount != 1 {
		t.Fatalf("segment count = %d, want 1", segmentCount)
	}
	if _, err := wal.Append(EntryTypePut, []byte("after_failed_rotation")); err != nil {
		t.Fatalf("Append after failed createNewSegment for active %d failed: %v", oldID, err)
	}
}

func TestWALCreateNewSegmentReportsPendingSyncError(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	opts.SyncInterval = time.Hour
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	if _, err := wal.Append(EntryTypePut, []byte("test_data")); err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	nextPath := filepath.Join(dir, WALFilePrefix+"00000000000000000001"+WALFileSuffix)
	wal.mu.Lock()
	if err := wal.active.file.Close(); err != nil {
		wal.mu.Unlock()
		t.Fatalf("close active file: %v", err)
	}
	wal.syncPending = true
	err = wal.createNewSegment()
	wal.syncPending = false
	wal.syncErr = nil
	wal.active.file = nil
	wal.mu.Unlock()

	if err == nil {
		t.Fatal("createNewSegment should return pending sync error")
	}
	if !strings.Contains(err.Error(), "sync active segment before rotation") {
		t.Fatalf("createNewSegment error should include sync context, got: %v", err)
	}
	if _, statErr := os.Stat(nextPath); !os.IsNotExist(statErr) {
		t.Fatalf("failed rotation should remove new segment path, stat err: %v", statErr)
	}
}

func TestWALMultipleSegments(t *testing.T) {
	dir := t.TempDir()

	// Use small max segment size to force multiple segments
	opts := WALOptions{
		MaxSegmentSize:  1024, // 1KB
		SyncInterval:    100 * time.Millisecond,
		PreallocateSize: 0,
	}

	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	// Write enough data to create multiple segments
	for i := 0; i < 50; i++ {
		data := make([]byte, 100)
		_, err := wal.Append(EntryTypePut, data)
		if err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}

	stats := wal.Stats()
	if stats.SegmentCount < 2 {
		t.Errorf("Expected multiple segments, got %d", stats.SegmentCount)
	}
}

func TestWALFileExists(t *testing.T) {
	dir := t.TempDir()

	opts := DefaultWALOptions()
	wal, err := OpenWAL(dir, opts)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	wal.Close()

	// Check that WAL files exist
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}

	found := false
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".log" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected to find .log files in WAL directory")
	}
}

func TestWriteWALBufferCompletesPartialWrites(t *testing.T) {
	writer := &chunkedWriter{maxWrite: 2}
	data := []byte("wal-entry")

	written, err := writeWALBuffer(writer, data)
	if err != nil {
		t.Fatalf("writeWALBuffer error: %v", err)
	}
	if written != len(data) {
		t.Fatalf("writeWALBuffer wrote %d bytes, want %d", written, len(data))
	}
	if got := writer.buf.String(); got != string(data) {
		t.Fatalf("writeWALBuffer wrote %q, want %q", got, string(data))
	}
	if writer.calls < 2 {
		t.Fatalf("chunked writer should require multiple writes, got %d", writer.calls)
	}
}

func TestWriteWALBufferRejectsZeroProgress(t *testing.T) {
	written, err := writeWALBuffer(zeroProgressWriter{}, []byte("wal-entry"))
	if err != io.ErrShortWrite {
		t.Fatalf("writeWALBuffer error = %v, want %v", err, io.ErrShortWrite)
	}
	if written != 0 {
		t.Fatalf("writeWALBuffer wrote %d bytes, want 0", written)
	}
}

type zeroProgressWriter struct{}

func (zeroProgressWriter) Write([]byte) (int, error) {
	return 0, nil
}
