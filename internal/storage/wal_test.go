package storage

import (
	"os"
	"path/filepath"
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
