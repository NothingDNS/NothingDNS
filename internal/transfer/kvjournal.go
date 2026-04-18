package transfer

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// KVJournalStore implements JournalStore using a file-based journal.
// Each zone has its own directory under dataDir/ixfr-journals/.
// Each journal entry is stored as a separate file named <serial>.journal.
// VULN-066 fix: replaced gob with JSON+HMAC for on-disk integrity protection.
type KVJournalStore struct {
	dataDir        string
	maxJournalSize int
	mu             sync.RWMutex
	hmacKey        []byte // nil = no integrity protection
}

// NewKVJournalStore creates a new file-based IXFR journal store.
// Pass a 32-byte hmacKey for integrity protection, or nil for legacy mode.
func NewKVJournalStore(dataDir string, hmacKey ...[]byte) *KVJournalStore {
	journalDir := filepath.Join(dataDir, "ixfr-journals")
	os.MkdirAll(journalDir, 0755)
	var key []byte
	if len(hmacKey) > 0 {
		key = hmacKey[0]
	}
	return &KVJournalStore{
		dataDir:        journalDir,
		maxJournalSize: 100,
		hmacKey:        key,
	}
}

// SetMaxJournalSize sets the maximum number of entries to keep per zone.
func (s *KVJournalStore) SetMaxJournalSize(size int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxJournalSize = size
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

	if s.hmacKey != nil {
		if err := s.writeEntry(f, entry); err != nil {
			f.Close()
			os.Remove(filename)
			return fmt.Errorf("write entry: %w", err)
		}
	} else {
		enc := json.NewEncoder(f)
		if err := enc.Encode(entry); err != nil {
			f.Close()
			os.Remove(filename)
			return fmt.Errorf("encoding journal entry: %w", err)
		}
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("close file: %w", err)
	}

	s.trimJournalLocked(zoneName)
	return nil
}

// writeEntry writes a single journal entry in TLV+HMAC format.
func (s *KVJournalStore) writeEntry(f *os.File, entry *IXFRJournalEntry) error {
	payload, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	// Frame: magic(1) + version(2) + payloadLen(4) + payload(n) + hmac(32)
	frameLen := 1 + 2 + 4 + len(payload) + 32
	frame := make([]byte, frameLen)
	frame[0] = 0xDB // magic
	binary.BigEndian.PutUint16(frame[1:3], 1) // version
	binary.BigEndian.PutUint32(frame[3:7], uint32(len(payload)))
	copy(frame[7:], payload)
	hm := hmac.New(sha256.New, s.hmacKey)
	hm.Write(payload)
	copy(frame[7+len(payload):], hm.Sum(nil))

	_, err = f.Write(frame)
	return err
}

// LoadEntries loads all journal entries for a zone from disk.
func (s *KVJournalStore) LoadEntries(zoneName string) ([]*IXFRJournalEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	dir := s.zoneDir(zoneName)
	entries, err := loadEntriesFromDir(dir, s.hmacKey)
	if err != nil {
		return nil, err
	}

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
	entries, err := loadEntriesFromDir(dir, s.hmacKey)
	if err != nil {
		return nil
	}

	if len(entries) <= s.maxJournalSize {
		return nil
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Serial > entries[j].Serial
	})

	toRemove := entries[s.maxJournalSize:]
	for _, entry := range toRemove {
		filename := filepath.Join(dir, fmt.Sprintf("%d.journal", entry.Serial))
		os.Remove(filename)
	}

	return nil
}

// loadEntriesFromDir reads all .journal files from a directory.
func loadEntriesFromDir(dir string, hmacKey []byte) ([]*IXFRJournalEntry, error) {
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
			continue
		}

		var entry IXFRJournalEntry
		func() {
			defer file.Close()
			if hmacKey != nil {
				if err := readEntryHMAC(file, &entry, hmacKey); err != nil {
					os.Remove(filename)
					return
				}
			} else {
				if err := json.NewDecoder(file).Decode(&entry); err != nil {
					os.Remove(filename)
					return
				}
			}
			entries = append(entries, &entry)
		}()
	}

	return entries, nil
}

// readEntryHMAC reads and verifies a TLV+HMAC journal entry.
func readEntryHMAC(f *os.File, entry *IXFRJournalEntry, key []byte) error {
	var hdr [7]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != 0xDB {
		return fmt.Errorf("invalid magic: 0x%x", hdr[0])
	}
	version := binary.BigEndian.Uint16(hdr[1:3])
	if version != 1 {
		return fmt.Errorf("unsupported version: %d", version)
	}
	payloadLen := binary.BigEndian.Uint32(hdr[3:7])

	recordLen := int(payloadLen) + 32
	record := make([]byte, recordLen)
	if _, err := io.ReadFull(f, record); err != nil {
		return err
	}

	storedHMAC := record[payloadLen:]
	payload := record[:payloadLen]

	expectedHMAC := hmac.New(sha256.New, key).Sum(payload)
	if subtle.ConstantTimeCompare(storedHMAC, expectedHMAC) != 1 {
		return fmt.Errorf("integrity check failed")
	}

	return json.Unmarshal(payload, entry)
}

// sanitizeFilename converts a zone name to a safe directory name.
func sanitizeFilename(name string) string {
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
