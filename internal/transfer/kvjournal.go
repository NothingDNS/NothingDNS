package transfer

import (
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// KVJournalStore implements JournalStore using a file-based journal.
// Each zone has its own directory under dataDir/ixfr-journals/.
// Each journal entry is stored as a separate file named <serial>.journal.
type KVJournalStore struct {
	dataDir        string
	maxJournalSize int
	mu             sync.RWMutex
}

// NewKVJournalStore creates a new file-based IXFR journal store.
func NewKVJournalStore(dataDir string) *KVJournalStore {
	// Ensure the journals directory exists
	journalDir := filepath.Join(dataDir, "ixfr-journals")
	os.MkdirAll(journalDir, 0755)
	return &KVJournalStore{
		dataDir:        journalDir,
		maxJournalSize: 100,
	}
}

// SetMaxJournalSize sets the maximum number of entries to keep per zone.
func (s *KVJournalStore) SetMaxJournalSize(size int) {
	s.mu.Lock()
	s.maxJournalSize = size
	s.mu.Unlock()
}

// zoneDir returns the directory for a zone's journal files.
func (s *KVJournalStore) zoneDir(zoneName string) string {
	return filepath.Join(s.dataDir, sanitizeFilename(zoneName))
}

// SaveEntry persists a journal entry to disk.
func (s *KVJournalStore) SaveEntry(zoneName string, entry *IXFRJournalEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir := s.zoneDir(zoneName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating zone journal dir: %w", err)
	}

	filename := filepath.Join(dir, fmt.Sprintf("%d.journal", entry.Serial))
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("creating journal file: %w", err)
	}
	defer f.Close()

	enc := gob.NewEncoder(f)
	if err := enc.Encode(entry); err != nil {
		os.Remove(filename)
		return fmt.Errorf("encoding journal entry: %w", err)
	}

	// Trim if needed
	s.trimJournalLocked(zoneName)

	return nil
}

// LoadEntries loads all journal entries for a zone from disk.
func (s *KVJournalStore) LoadEntries(zoneName string) ([]*IXFRJournalEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	dir := s.zoneDir(zoneName)
	entries, err := loadEntriesFromDir(dir)
	if err != nil {
		return nil, err
	}

	// Sort by serial number ascending (chronological order)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Serial < entries[j].Serial
	})

	return entries, nil
}

// Truncate removes old entries keeping only the most recent keepCount entries.
func (s *KVJournalStore) Truncate(zoneName string, keepCount int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.trimJournalLocked(zoneName)
}

// trimJournalLocked removes old journal entries (caller must hold mu).
func (s *KVJournalStore) trimJournalLocked(zoneName string) error {
	dir := s.zoneDir(zoneName)
	entries, err := loadEntriesFromDir(dir)
	if err != nil {
		return nil // No entries to trim
	}

	if len(entries) <= s.maxJournalSize {
		return nil
	}

	// Sort by serial descending to keep newest entries
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Serial > entries[j].Serial
	})

	// Remove entries beyond keepCount
	toRemove := entries[s.maxJournalSize:]
	for _, entry := range toRemove {
		filename := filepath.Join(dir, fmt.Sprintf("%d.journal", entry.Serial))
		os.Remove(filename)
	}

	return nil
}

// loadEntriesFromDir reads all .journal files from a directory.
func loadEntriesFromDir(dir string) ([]*IXFRJournalEntry, error) {
	var entries []*IXFRJournalEntry

	files, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return entries, nil
		}
		return nil, fmt.Errorf("reading journal dir: %w", err)
	}

	for _, f := range files {
		if f.IsDir() || filepath.Ext(f.Name()) != ".journal" {
			continue
		}
		filename := filepath.Join(dir, f.Name())
		file, err := os.Open(filename)
		if err != nil {
			continue // Skip files we can't open
		}
		dec := gob.NewDecoder(file)
		var entry IXFRJournalEntry
		if err := dec.Decode(&entry); err != nil {
			file.Close()
			os.Remove(filename) // Remove corrupt entries
			continue
		}
		file.Close()
		entries = append(entries, &entry)
	}

	return entries, nil
}

// sanitizeFilename converts a zone name to a safe directory name.
func sanitizeFilename(name string) string {
	// Replace characters that are problematic in file paths
	result := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '/' || c == '\\' || c == ':' || c == 0 {
			c = '_'
		}
		result = append(result, c)
	}
	return string(result)
}
