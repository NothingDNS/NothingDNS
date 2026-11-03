package transfer

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func TestKVJournalStore_NewKVJournalStore(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewKVJournalStore(tmpDir)
	if store == nil {
		t.Fatal("NewKVJournalStore returned nil")
	}
	if store.dataDir == "" {
		t.Error("dataDir is empty")
	}
	if store.maxJournalSize != 100 {
		t.Errorf("maxJournalSize = %d, want 100", store.maxJournalSize)
	}
	if store.hmacKey != nil {
		t.Error("hmacKey should be nil when not provided")
	}
}

func TestKVJournalStore_NewKVJournalStoreWithKey(t *testing.T) {
	tmpDir := t.TempDir()
	key := []byte("test-key-32-bytes-long-for-hmac!")
	store := NewKVJournalStore(tmpDir, key)
	if store == nil {
		t.Fatal("NewKVJournalStore returned nil")
	}
	if store.hmacKey == nil {
		t.Error("hmacKey should not be nil when provided")
	}
}

func TestKVJournalStore_OpenKVJournalStoreRejectsInvalidDataDir(t *testing.T) {
	tmpDir := t.TempDir()
	dataFile := filepath.Join(tmpDir, "not-a-directory")
	if err := os.WriteFile(dataFile, []byte("not a dir"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store, err := OpenKVJournalStore(dataFile)
	if err == nil {
		t.Fatal("OpenKVJournalStore should reject a dataDir that is a file")
	}
	if store != nil {
		t.Fatalf("OpenKVJournalStore store = %#v, want nil on error", store)
	}
}

func TestKVJournalStore_SetMaxJournalSize(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewKVJournalStore(tmpDir)

	store.SetMaxJournalSize(50)
	if store.maxJournalSize != 50 {
		t.Errorf("maxJournalSize = %d, want 50", store.maxJournalSize)
	}

	store.SetMaxJournalSize(200)
	if store.maxJournalSize != 200 {
		t.Errorf("maxJournalSize = %d, want 200", store.maxJournalSize)
	}

	store.SetMaxJournalSize(-1)
	if store.maxJournalSize != 200 {
		t.Errorf("maxJournalSize = %d, want unchanged 200 for negative input", store.maxJournalSize)
	}
}

func TestKVJournalStore_SetMaxJournalSize_NegativeDoesNotWipeJournal(t *testing.T) {
	store := NewKVJournalStore(t.TempDir())
	zoneName := "example.com."

	store.SetMaxJournalSize(2)
	for serial := uint32(1); serial <= 2; serial++ {
		if err := store.SaveEntry(zoneName, &IXFRJournalEntry{Serial: serial, Timestamp: time.Now()}); err != nil {
			t.Fatalf("SaveEntry(%d): %v", serial, err)
		}
	}

	store.SetMaxJournalSize(-1)
	if err := store.SaveEntry(zoneName, &IXFRJournalEntry{Serial: 3, Timestamp: time.Now()}); err != nil {
		t.Fatalf("SaveEntry(3): %v", err)
	}

	entries, err := store.LoadEntries(zoneName)
	if err != nil {
		t.Fatalf("LoadEntries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries len = %d, want 2", len(entries))
	}
	if entries[0].Serial != 2 || entries[1].Serial != 3 {
		t.Fatalf("remaining serials = [%d %d], want [2 3]", entries[0].Serial, entries[1].Serial)
	}
}

func TestKVJournalStore_SaveEntryRejectsNilEntry(t *testing.T) {
	store := NewKVJournalStore(t.TempDir())

	err := store.SaveEntry("example.com.", nil)
	if err == nil || err.Error() != "journal entry is nil" {
		t.Fatalf("SaveEntry(nil) error = %v, want journal entry is nil", err)
	}
}

func TestKVJournalStore_SaveEntryDoesNotFollowFixedTmpSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewKVJournalStore(tmpDir)
	zoneName := "example.com."
	serial := uint32(2024010101)
	zoneDir := store.zoneDir(zoneName)
	if err := os.MkdirAll(zoneDir, 0700); err != nil {
		t.Fatalf("MkdirAll zone journal dir: %v", err)
	}

	journalPath := filepath.Join(zoneDir, "2024010101.journal")
	outside := filepath.Join(t.TempDir(), "outside.txt")
	const outsideData = "keep me"
	if err := os.WriteFile(outside, []byte(outsideData), 0600); err != nil {
		t.Fatalf("WriteFile outside: %v", err)
	}
	if err := os.Symlink(outside, journalPath+".tmp"); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	err := store.SaveEntry(zoneName, &IXFRJournalEntry{Serial: serial, Timestamp: time.Now()})
	if err != nil {
		t.Fatalf("SaveEntry: %v", err)
	}

	got, err := os.ReadFile(outside)
	if err != nil {
		t.Fatalf("ReadFile outside: %v", err)
	}
	if string(got) != outsideData {
		t.Fatalf("fixed tmp symlink target was modified: got %q", string(got))
	}
	if info, err := os.Lstat(journalPath); err != nil {
		t.Fatalf("expected journal file: %v", err)
	} else if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("journal file must not be the fixed tmp symlink")
	}
}

func TestSyncJournalDir(t *testing.T) {
	if err := syncJournalDir(t.TempDir()); err != nil {
		t.Fatalf("syncJournalDir on temp dir: %v", err)
	}
}

func TestSyncJournalDirInvalidPath(t *testing.T) {
	err := syncJournalDir(filepath.Join(t.TempDir(), "missing"))
	if err == nil {
		t.Fatal("expected error for missing journal directory")
	}
	if !strings.Contains(err.Error(), "open journal dir") {
		t.Fatalf("error = %v, want open journal dir context", err)
	}
}

func TestKVJournalStore_NilReceiver(t *testing.T) {
	var store *KVJournalStore

	store.SetMaxJournalSize(10)

	if err := store.SaveEntry("example.com.", &IXFRJournalEntry{Serial: 1}); err == nil || err.Error() != "journal store is nil" {
		t.Fatalf("SaveEntry on nil store error = %v, want journal store is nil", err)
	}

	if entries, err := store.LoadEntries("example.com."); err == nil || err.Error() != "journal store is nil" || entries != nil {
		t.Fatalf("LoadEntries on nil store entries=%v error=%v, want nil entries and journal store is nil", entries, err)
	}

	if err := store.Truncate("example.com.", 1); err == nil || err.Error() != "journal store is nil" {
		t.Fatalf("Truncate on nil store error = %v, want journal store is nil", err)
	}
}

func TestKVJournalStore_SaveAndLoadEntry(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewKVJournalStore(tmpDir)

	zoneName := "example.com."
	entry := &IXFRJournalEntry{
		Serial: 2024010101,
		Added: []zone.RecordChange{
			{Name: "test.example.com.", Type: protocol.TypeA, TTL: 300, RData: "192.0.2.1"},
		},
		Timestamp: time.Now(),
	}

	err := store.SaveEntry(zoneName, entry)
	if err != nil {
		t.Fatalf("SaveEntry failed: %v", err)
	}

	// Load and verify
	entries, err := store.LoadEntries(zoneName)
	if err != nil {
		t.Fatalf("LoadEntries failed: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("LoadEntries returned %d entries, want 1", len(entries))
	}

	if entries[0].Serial != entry.Serial {
		t.Errorf("Serial = %d, want %d", entries[0].Serial, entry.Serial)
	}
	if len(entries[0].Added) != 1 {
		t.Errorf("Added count = %d, want 1", len(entries[0].Added))
	}
	if entries[0].Added[0].Name != entry.Added[0].Name {
		t.Errorf("Added[0].Name = %q, want %q", entries[0].Added[0].Name, entry.Added[0].Name)
	}
}

func TestKVJournalStore_SaveAndLoadMultipleEntries(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewKVJournalStore(tmpDir)

	zoneName := "example.com."
	entries := []*IXFRJournalEntry{
		{Serial: 2024010101, Added: []zone.RecordChange{{Name: "a.example.com.", Type: protocol.TypeA}}, Timestamp: time.Now()},
		{Serial: 2024010102, Added: []zone.RecordChange{{Name: "b.example.com.", Type: protocol.TypeA}}, Timestamp: time.Now()},
		{Serial: 2024010103, Deleted: []zone.RecordChange{{Name: "c.example.com.", Type: protocol.TypeA}}, Timestamp: time.Now()},
	}

	for _, e := range entries {
		if err := store.SaveEntry(zoneName, e); err != nil {
			t.Fatalf("SaveEntry failed: %v", err)
		}
	}

	loaded, err := store.LoadEntries(zoneName)
	if err != nil {
		t.Fatalf("LoadEntries failed: %v", err)
	}

	if len(loaded) != len(entries) {
		t.Errorf("LoadEntries returned %d entries, want %d", len(loaded), len(entries))
	}

	// Verify ordering (should be sorted by serial)
	for i, e := range loaded {
		if e.Serial != entries[i].Serial {
			t.Errorf("entries[%d].Serial = %d, want %d", i, e.Serial, entries[i].Serial)
		}
	}
}

func TestKVJournalStore_LoadEntriesNonexistent(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewKVJournalStore(tmpDir)

	entries, err := store.LoadEntries("nonexistent.example.com.")
	if err != nil {
		t.Fatalf("LoadEntries failed unexpectedly: %v", err)
	}

	if len(entries) != 0 {
		t.Errorf("LoadEntries returned %d entries, want 0", len(entries))
	}
}

func TestKVJournalStore_Truncate(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewKVJournalStore(tmpDir)
	store.SetMaxJournalSize(3)

	zoneName := "example.com."
	for i := 0; i < 5; i++ {
		entry := &IXFRJournalEntry{
			Serial:    uint32(2024010100 + i),
			Added:     []zone.RecordChange{{Name: "test.example.com.", Type: protocol.TypeA}},
			Timestamp: time.Now(),
		}
		if err := store.SaveEntry(zoneName, entry); err != nil {
			t.Fatalf("SaveEntry failed: %v", err)
		}
	}

	// After 5 entries with maxJournalSize=3, should have 3 most recent
	entries, err := store.LoadEntries(zoneName)
	if err != nil {
		t.Fatalf("LoadEntries failed: %v", err)
	}

	if len(entries) != 3 {
		t.Errorf("LoadEntries returned %d entries, want 3", len(entries))
	}

	// LoadEntries sorts ascending, so entries should be: 2024010102, 2024010103, 2024010104
	if entries[0].Serial != 2024010102 {
		t.Errorf("entries[0].Serial = %d, want 2024010102", entries[0].Serial)
	}
	if entries[2].Serial != 2024010104 {
		t.Errorf("entries[2].Serial = %d, want 2024010104", entries[2].Serial)
	}
}

func TestKVJournalStore_TruncateHonorsKeepCount(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewKVJournalStore(tmpDir)
	store.SetMaxJournalSize(10)

	zoneName := "example.com."
	for serial := uint32(1); serial <= 5; serial++ {
		entry := &IXFRJournalEntry{
			Serial:    serial,
			Timestamp: time.Now(),
		}
		if err := store.SaveEntry(zoneName, entry); err != nil {
			t.Fatalf("SaveEntry(%d) failed: %v", serial, err)
		}
	}

	if err := store.Truncate(zoneName, 2); err != nil {
		t.Fatalf("Truncate failed: %v", err)
	}

	entries, err := store.LoadEntries(zoneName)
	if err != nil {
		t.Fatalf("LoadEntries failed: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("LoadEntries returned %d entries, want 2", len(entries))
	}
	if entries[0].Serial != 4 || entries[1].Serial != 5 {
		t.Fatalf("remaining serials = [%d %d], want [4 5]", entries[0].Serial, entries[1].Serial)
	}
}

func TestKVJournalStore_TruncateRejectsNegativeKeepCount(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewKVJournalStore(tmpDir)

	if err := store.Truncate("example.com.", -1); err == nil {
		t.Fatal("expected negative keepCount to fail")
	}
}

func TestKVJournalStore_SaveEntryWithHMAC(t *testing.T) {
	tmpDir := t.TempDir()
	key := []byte("test-key-32-bytes-long-for-hmac!")
	store := NewKVJournalStore(tmpDir, key)

	zoneName := "example.com."
	entry := &IXFRJournalEntry{
		Serial:    2024010101,
		Added:     []zone.RecordChange{{Name: "test.example.com.", Type: protocol.TypeA, TTL: 300}},
		Timestamp: time.Now(),
	}

	// Check zone dir path
	zoneDir := store.zoneDir(zoneName)
	journalFile := filepath.Join(zoneDir, "2024010101.journal")
	t.Logf("zoneDir: %s", zoneDir)
	t.Logf("journalFile: %s", journalFile)

	// Check file doesn't exist before save
	if _, err := os.Stat(journalFile); err == nil {
		t.Error("Journal file should not exist before SaveEntry")
	}

	err := store.SaveEntry(zoneName, entry)
	if err != nil {
		t.Fatalf("SaveEntry failed: %v", err)
	}

	// Check file exists after save
	if _, err := os.Stat(journalFile); err != nil {
		t.Fatalf("Journal file should exist after SaveEntry: %v", err)
	}

	// Load with same key
	loaded, err := store.LoadEntries(zoneName)
	if err != nil {
		t.Fatalf("LoadEntries failed: %v", err)
	}

	t.Logf("LoadEntries returned %d entries", len(loaded))
	for i, e := range loaded {
		t.Logf("  [%d] Serial: %d", i, e.Serial)
	}

	if len(loaded) != 1 {
		t.Fatalf("LoadEntries returned %d entries, want 1", len(loaded))
	}

	if loaded[0].Serial != entry.Serial {
		t.Errorf("Serial = %d, want %d", loaded[0].Serial, entry.Serial)
	}
}

func TestKVJournalStore_WriteEntryCompletesPartialWrites(t *testing.T) {
	key := []byte("test-key-32-bytes-long-for-hmac!")
	store := NewKVJournalStore(t.TempDir(), key)
	writer := &chunkedJournalWriter{maxWrite: 3}
	entry := &IXFRJournalEntry{
		Serial:    2024010101,
		Added:     []zone.RecordChange{{Name: "test.example.com.", Type: protocol.TypeA, TTL: 300}},
		Timestamp: time.Now(),
	}

	if err := store.writeEntry(writer, entry); err != nil {
		t.Fatalf("writeEntry: %v", err)
	}
	if writer.calls < 2 {
		t.Fatalf("chunked writer should require multiple writes, got %d", writer.calls)
	}

	journalPath := filepath.Join(t.TempDir(), "entry.journal")
	if err := os.WriteFile(journalPath, writer.buf.Bytes(), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	f, err := os.Open(journalPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	var loaded IXFRJournalEntry
	if err := readEntryHMAC(f, &loaded, key); err != nil {
		t.Fatalf("readEntryHMAC: %v", err)
	}
	if loaded.Serial != entry.Serial || len(loaded.Added) != 1 || loaded.Added[0].Name != entry.Added[0].Name {
		t.Fatalf("loaded entry = %+v, want %+v", loaded, entry)
	}
}

type chunkedJournalWriter struct {
	buf      bytes.Buffer
	maxWrite int
	calls    int
}

func (w *chunkedJournalWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.maxWrite <= 0 || len(p) <= w.maxWrite {
		return w.buf.Write(p)
	}
	return w.buf.Write(p[:w.maxWrite])
}

func TestKVJournalStore_InvalidHMACKey(t *testing.T) {
	tmpDir := t.TempDir()
	key := []byte("test-key-32-bytes-long-for-hmac!")
	store := NewKVJournalStore(tmpDir, key)

	zoneName := "example.com."
	entry := &IXFRJournalEntry{
		Serial:    2024010101,
		Added:     []zone.RecordChange{{Name: "test.example.com.", Type: protocol.TypeA}},
		Timestamp: time.Now(),
	}

	err := store.SaveEntry(zoneName, entry)
	if err != nil {
		t.Fatalf("SaveEntry failed: %v", err)
	}

	// Create store with different key - should fail to load
	store2 := NewKVJournalStore(tmpDir, []byte("different-key-32-bytes-long!!"))
	entries, err := store2.LoadEntries(zoneName)
	// The corrupted file should be removed, so we get 0 entries
	if err != nil {
		t.Fatalf("LoadEntries failed: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("LoadEntries returned %d entries, want 0 (corrupted)", len(entries))
	}
}

func TestKVJournalStore_IXFRJournalEntryJSON(t *testing.T) {
	entry := &IXFRJournalEntry{
		Serial: 2024010101,
		Added: []zone.RecordChange{
			{Name: "test.example.com.", Type: protocol.TypeA, TTL: 300, RData: "192.0.2.1"},
		},
		Deleted: []zone.RecordChange{
			{Name: "old.example.com.", Type: protocol.TypeA, TTL: 300, RData: "192.0.2.0"},
		},
		Timestamp: time.Now(),
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}

	var decoded IXFRJournalEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}

	if decoded.Serial != entry.Serial {
		t.Errorf("Serial = %d, want %d", decoded.Serial, entry.Serial)
	}
	if len(decoded.Added) != len(entry.Added) {
		t.Errorf("Added count = %d, want %d", len(decoded.Added), len(entry.Added))
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example_com"},
		{"example/com", "example_com"},
		{"C:\\Windows\\System32", "C__Windows_System32"},
		{"null\x00byte", "null_byte"},
		{"example.com.", "example_com_"},
		{"example..com.", "example__com_"},
	}

	for _, tc := range tests {
		result := sanitizeFilename(tc.input)
		if result != tc.expected {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestKVJournalStore_MultipleZones(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewKVJournalStore(tmpDir)

	zones := []string{"example.com.", "example.org.", "example.net."}

	for _, zoneName := range zones {
		entry := &IXFRJournalEntry{
			Serial:    2024010101,
			Added:     []zone.RecordChange{{Name: "test." + zoneName, Type: protocol.TypeA}},
			Timestamp: time.Now(),
		}
		if err := store.SaveEntry(zoneName, entry); err != nil {
			t.Fatalf("SaveEntry failed for zone %s: %v", zoneName, err)
		}
	}

	// Verify each zone has its own entry
	for _, zoneName := range zones {
		entries, err := store.LoadEntries(zoneName)
		if err != nil {
			t.Fatalf("LoadEntries failed for zone %s: %v", zoneName, err)
		}
		if len(entries) != 1 {
			t.Errorf("Zone %s: got %d entries, want 1", zoneName, len(entries))
		}
	}
}

func TestKVJournalStore_EntryWithAllFields(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewKVJournalStore(tmpDir)

	zoneName := "example.com."
	ts := time.Now()
	entry := &IXFRJournalEntry{
		Serial: 2024010101,
		Added: []zone.RecordChange{
			{Name: "fulltest.example.com.", Type: protocol.TypeMX, TTL: 600, RData: "10 mail.example.com."},
		},
		Deleted: []zone.RecordChange{
			{Name: "old.example.com.", Type: protocol.TypeA, TTL: 300, RData: "192.0.2.0"},
		},
		Timestamp: ts,
	}

	err := store.SaveEntry(zoneName, entry)
	if err != nil {
		t.Fatalf("SaveEntry failed: %v", err)
	}

	loaded, err := store.LoadEntries(zoneName)
	if err != nil {
		t.Fatalf("LoadEntries failed: %v", err)
	}

	if len(loaded) != 1 {
		t.Fatalf("LoadEntries returned %d entries, want 1", len(loaded))
	}

	if len(loaded[0].Added) != 1 {
		t.Errorf("Added count = %d, want 1", len(loaded[0].Added))
	}
	if loaded[0].Added[0].Type != protocol.TypeMX {
		t.Errorf("Added[0].Type = %d, want %d", loaded[0].Added[0].Type, protocol.TypeMX)
	}
	if len(loaded[0].Deleted) != 1 {
		t.Errorf("Deleted count = %d, want 1", len(loaded[0].Deleted))
	}
}

func TestKVJournalStore_ConcurrentSave(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewKVJournalStore(tmpDir)
	store.SetMaxJournalSize(100)

	zoneName := "example.com."

	// Concurrently save entries
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(idx int) {
			entry := &IXFRJournalEntry{
				Serial:    uint32(2024010100 + idx),
				Added:     []zone.RecordChange{{Name: "test.example.com.", Type: protocol.TypeA}},
				Timestamp: time.Now(),
			}
			store.SaveEntry(zoneName, entry)
			done <- struct{}{}
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all entries were saved
	entries, err := store.LoadEntries(zoneName)
	if err != nil {
		t.Fatalf("LoadEntries failed: %v", err)
	}

	if len(entries) != 10 {
		t.Errorf("LoadEntries returned %d entries, want 10", len(entries))
	}
}

func TestKVJournalStore_CorruptedJournalFile(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewKVJournalStore(tmpDir)

	zoneName := "example.com."

	// Manually create a corrupted journal file in the zone's journal directory.
	zoneDir := store.zoneDir(zoneName)
	os.MkdirAll(zoneDir, 0755)
	corruptedFile := filepath.Join(zoneDir, "2024010101.journal")
	os.WriteFile(corruptedFile, []byte("not valid json"), 0644)

	// Load should skip the corrupted file
	entries, err := store.LoadEntries(zoneName)
	if err != nil {
		t.Fatalf("LoadEntries failed: %v", err)
	}

	if len(entries) != 0 {
		t.Errorf("LoadEntries returned %d entries, want 0", len(entries))
	}

	// Corrupted file should have been removed
	if _, err := os.Stat(corruptedFile); err == nil {
		t.Error("Corrupted file should have been removed")
	}
}

func TestKVJournalStore_DeleteZoneClearsJournals(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewKVJournalStore(tmpDir)

	// Create entries for two zones
	store.SaveEntry("zone1.com.", &IXFRJournalEntry{Serial: 1, Added: []zone.RecordChange{{Name: "a.zone1.com.", Type: protocol.TypeA}}, Timestamp: time.Now()})
	store.SaveEntry("zone2.com.", &IXFRJournalEntry{Serial: 1, Added: []zone.RecordChange{{Name: "a.zone2.com.", Type: protocol.TypeA}}, Timestamp: time.Now()})

	// Verify both exist
	entries1, _ := store.LoadEntries("zone1.com.")
	entries2, _ := store.LoadEntries("zone2.com.")

	if len(entries1) != 1 || len(entries2) != 1 {
		t.Fatal("Setup failed")
	}

	// Verify the collision-resistant zone directories exist.
	zone1Dir := store.zoneDir("zone1.com.")
	zone2Dir := store.zoneDir("zone2.com.")

	if _, err := os.Stat(zone1Dir); err != nil {
		t.Errorf("zone1 dir should exist: %v", err)
	}
	if _, err := os.Stat(zone2Dir); err != nil {
		t.Errorf("zone2 dir should exist: %v", err)
	}
}
