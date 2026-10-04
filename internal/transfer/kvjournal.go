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
	return newKVJournalStore(dataDir, hmacKey...)
}

// OpenKVJournalStore creates the journal root directory and returns a store.
func OpenKVJournalStore(dataDir string, hmacKey ...[]byte) (*KVJournalStore, error) {
	store := newKVJournalStore(dataDir, hmacKey...)
	if err := os.MkdirAll(store.dataDir, 0700); err != nil {
		return nil, fmt.Errorf("creating IXFR journal dir: %w", err)
	}
	return store, nil
}

func newKVJournalStore(dataDir string, hmacKey ...[]byte) *KVJournalStore {
	journalDir := filepath.Join(dataDir, "ixfr-journals")
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
	if s == nil {
		return
	}
	if size < 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxJournalSize = size
}

// zoneDir returns the directory for a zone's journal files.
func (s *KVJournalStore) zoneDir(zoneName string) string {
	return filepath.Join(s.dataDir, sanitizeFilename(zoneName))
}

// SaveEntry persists a journal entry to disk using the tmp+fsync+rename
// idiom so that a power loss between Write and Close cannot leave a
// half-written file under the canonical name. Each entry is written to a
// sibling temporary file, fsynced, then atomically renamed into place; the
// parent directory is fsynced too so the new dirent is durable.
func (s *KVJournalStore) SaveEntry(zoneName string, entry *IXFRJournalEntry) error {
	if s == nil {
		return fmt.Errorf("journal store is nil")
	}
	if entry == nil {
		return fmt.Errorf("journal entry is nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	dir := s.zoneDir(zoneName)
	// 0700 — journals carry zone contents and (with HMAC enabled) a MAC. Do
	// not expose them to other local users.
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating zone journal dir: %w", err)
	}

	filename := filepath.Join(dir, fmt.Sprintf("%d.journal", entry.Serial))
	base := filepath.Base(filename)

	f, err := os.CreateTemp(dir, "."+base+"-*.tmp")
	if err != nil {
		return fmt.Errorf("creating tmp journal file: %w", err)
	}
	tmpName := f.Name()
	keepTemp := false
	defer func() {
		if !keepTemp {
			os.Remove(tmpName)
		}
	}()

	if s.hmacKey != nil {
		if err := s.writeEntry(f, entry); err != nil {
			f.Close()
			return fmt.Errorf("write entry: %w", err)
		}
	} else {
		enc := json.NewEncoder(f)
		if err := enc.Encode(entry); err != nil {
			f.Close()
			return fmt.Errorf("encoding journal entry: %w", err)
		}
	}

	// fsync the file before rename. Without this, the OS may reorder writes
	// and the rename may publish a name whose contents haven't reached disk.
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("fsync tmp journal: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close tmp journal: %w", err)
	}

	if err := os.Rename(tmpName, filename); err != nil {
		return fmt.Errorf("rename tmp journal: %w", err)
	}
	keepTemp = true

	if err := syncJournalDir(dir); err != nil {
		return err
	}

	if err := s.trimJournalToLocked(zoneName, s.maxJournalSize); err != nil {
		return fmt.Errorf("trim journal: %w", err)
	}
	return nil
}

func syncJournalDir(dir string) (err error) {
	dirFd, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open journal dir: %w", err)
	}
	defer func() {
		if closeErr := dirFd.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close journal dir: %w", closeErr)
		}
	}()

	if err := dirFd.Sync(); err != nil {
		return fmt.Errorf("fsync journal dir: %w", err)
	}
	return nil
}

// writeEntry writes a single journal entry in TLV+HMAC format.
func (s *KVJournalStore) writeEntry(w io.Writer, entry *IXFRJournalEntry) error {
	payload, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	// Frame: magic(1) + version(2) + payloadLen(4) + payload(n) + hmac(32)
	frameLen := 1 + 2 + 4 + len(payload) + 32
	frame := make([]byte, frameLen)
	frame[0] = 0xDB                           // magic
	binary.BigEndian.PutUint16(frame[1:3], 1) // version
	binary.BigEndian.PutUint32(frame[3:7], uint32(len(payload)))
	copy(frame[7:], payload)
	hm := hmac.New(sha256.New, s.hmacKey)
	hm.Write(payload)
	copy(frame[7+len(payload):], hm.Sum(nil))

	return writeJournalFrame(w, frame)
}

func writeJournalFrame(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

// LoadEntries loads all journal entries for a zone from disk.
func (s *KVJournalStore) LoadEntries(zoneName string) ([]*IXFRJournalEntry, error) {
	if s == nil {
		return nil, fmt.Errorf("journal store is nil")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	dir := s.zoneDir(zoneName)
	entries, err := loadEntriesFromDir(dir, s.hmacKey)
	if err != nil {
		return nil, err
	}

	sort.Slice(entries, func(i, j int) bool {
		return serialIsNewer(entries[j].Serial, entries[i].Serial)
	})

	return entries, nil
}

// Truncate removes old entries keeping only the most recent keepCount entries.
func (s *KVJournalStore) Truncate(zoneName string, keepCount int) error {
	if s == nil {
		return fmt.Errorf("journal store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.trimJournalToLocked(zoneName, keepCount)
}

// trimJournalToLocked removes old journal entries, keeping the newest keepCount
// entries. Caller must hold mu.
func (s *KVJournalStore) trimJournalToLocked(zoneName string, keepCount int) error {
	if keepCount < 0 {
		return fmt.Errorf("invalid keepCount: %d", keepCount)
	}

	dir := s.zoneDir(zoneName)
	entries, err := loadEntriesFromDir(dir, s.hmacKey)
	if err != nil {
		return err
	}

	if len(entries) <= keepCount {
		return nil
	}

	sort.Slice(entries, func(i, j int) bool {
		return serialIsNewer(entries[i].Serial, entries[j].Serial)
	})

	toRemove := entries[keepCount:]
	for _, entry := range toRemove {
		filename := filepath.Join(dir, fmt.Sprintf("%d.journal", entry.Serial))
		if err := os.Remove(filename); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove old journal %s: %w", filename, err)
		}
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
			if hmacKey != nil {
				if err := readEntryHMAC(file, &entry, hmacKey); err != nil {
					file.Close()
					os.Remove(filename)
					return
				}
			} else {
				if err := json.NewDecoder(file).Decode(&entry); err != nil {
					file.Close()
					os.Remove(filename)
					return
				}
			}
			file.Close()
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
	// Defence against a corrupt / attacker-controlled file: cap the payload
	// length we will allocate. 16 MiB is well above any plausible journal
	// entry but well below the 4 GiB ceiling of uint32, so a malformed
	// header cannot drive an out-of-memory allocation here.
	const maxJournalPayload = 16 << 20
	if payloadLen > maxJournalPayload {
		return fmt.Errorf("journal payload too large: %d (max %d)", payloadLen, maxJournalPayload)
	}

	recordLen := int(payloadLen) + 32
	record := make([]byte, recordLen)
	if _, err := io.ReadFull(f, record); err != nil {
		return err
	}

	storedHMAC := record[payloadLen:]
	payload := record[:payloadLen]

	hm := hmac.New(sha256.New, key)
	hm.Write(payload)
	expectedHMAC := hm.Sum(nil)
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
		if c == '/' || c == '\\' || c == ':' || c == 0 || c == '.' {
			c = '_'
		}
		result = append(result, c)
	}
	return string(result)
}
