package storage

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/nothingdns/nothingdns/internal/util"
)

// KVStore implements a simple key-value store with ACID transactions.
// This is a simplified implementation that stores data in memory and persists to disk.

// Store constants
const (
	KVMaxKeySize   = 255
	KVMaxValueSize = 4 * 1024 * 1024 // 4MB
	DataFile       = "data.db"
)

// TLV file magic and version for integrity-protected format.
const (
	fileMagic    = 0xDB
	fileVersion  = 1
	hmacLenBytes = 32 // SHA-256 HMAC

	// encryptedFileMagic identifies the AES-256-GCM-encrypted variant
	// of the TLV format used when an aeadKey is configured (L-6).
	// Layout:
	//   byte 0:        0xE0
	//   bytes 1-2:     version (big-endian uint16)
	//   bytes 3-14:    12-byte nonce
	//   bytes 15..end: AES-GCM(plaintext = plain-TLV-without-magic,
	//                          AAD       = magic||version)
	// Plain-TLV-without-magic = version(2) || payloadLen(4) || payload || hmac(32).
	// The GCM tag already authenticates the payload, so the embedded
	// HMAC is redundant under AES-GCM — it is preserved so that
	// disabling encryption later reads back as plain-TLV without
	// format conversion.
	encryptedFileMagic = 0xE0
	aeadNonceLen       = 12

	// maxKVPayload caps untrusted on-disk TLV payload length before
	// allocation. M-1 / L-N1. Package-level so both readTLV and
	// readEncryptedTLV can reference it.
	maxKVPayload     = 64 << 20 // 64 MiB
	maxLegacyGOBFile = 1 << 20  // 1 MiB
)

// Store errors
var (
	ErrKeyTooLarge     = errors.New("key is too large")
	ErrBucketNotFound  = errors.New("bucket not found")
	ErrBucketExists    = errors.New("bucket already exists")
	ErrKVKeyNotFound   = errors.New("key not found")
	ErrTxClosed        = errors.New("transaction is closed")
	ErrTxNotWritable   = errors.New("transaction is not writable")
	ErrDatabaseClosed  = errors.New("database is closed")
	ErrKVValueTooLarge = errors.New("value is too large")
	ErrDataTampered    = errors.New("data file integrity check failed — possible tampering")
)

// KVStore represents the main database
type KVStore struct {
	mu       sync.RWMutex
	path     string
	dataFile string
	opened   bool
	closed   bool
	root     *bucketData
	txid     uint64
	rwtx     *Tx
	// txsMu guards mutations of the txs slice. It exists separately
	// from `mu` because read-only transactions hold s.mu as an RLock
	// while still needing to insert/remove themselves from this slice
	// — multiple concurrent Begin(false) / read-only Commit / Rollback
	// calls would otherwise race on the slice header itself even
	// though each one holds a valid shared-mode store lock.
	txsMu   sync.Mutex
	txs     []*Tx
	stats   StoreStats
	hmacKey []byte // nil means no integrity protection (legacy mode)
	aeadKey []byte // L-6: nil means no at-rest encryption; non-nil = 32-byte AES-256-GCM key
}

// StoreStats contains database statistics
type StoreStats struct {
	TxCount     int64
	OpenTxCount int64
	BucketCount int64
	KeyCount    int64
}

// bucketData represents bucket data stored in memory
type bucketData struct {
	Entries map[string][]byte
	Buckets map[string]*bucketData
}

func newBucketData() *bucketData {
	return &bucketData{
		Entries: make(map[string][]byte),
		Buckets: make(map[string]*bucketData),
	}
}

// KVBucket represents a collection of key-value pairs
type KVBucket struct {
	tx   *Tx
	name string
	data *bucketData
}

// KVCursor represents a bucket cursor for iteration
type KVCursor struct {
	bucket *KVBucket
	keys   []string
	pos    int
}

// Tx represents a database transaction
type Tx struct {
	store          *KVStore
	writable       bool
	closed         bool
	txid           uint64
	commitHandlers []func()
}

// OpenKVStore opens or creates a key-value store.
// An optional hmacKey may be passed as the second argument (must be 32 bytes
// if provided) for integrity protection (SHA-256 HMAC). Without a key the store
// falls back to legacy JSON format on load and saves without HMAC.
// This signature is backward-compatible: existing callers that pass only path
// continue to work.
func OpenKVStore(path string, hmacKey ...[]byte) (*KVStore, error) {
	var key []byte
	if len(hmacKey) > 0 {
		key = hmacKey[0]
	}
	if key != nil && len(key) != 32 {
		return nil, fmt.Errorf("hmac key must be 32 bytes (%d provided)", len(key))
	}
	return openKVStore(path, key, nil)
}

// OpenKVStoreEncrypted opens a KV store with both integrity protection
// (HMAC-SHA256, hmacKey) and at-rest confidentiality (AES-256-GCM,
// aeadKey). Either or both may be nil — nil hmacKey skips the HMAC
// frame, nil aeadKey writes plaintext TLV. Files written without
// aeadKey can still be read with aeadKey set, and vice versa: format
// is determined by the leading magic byte (0xDB plain, 0xE0
// encrypted). L-6: addresses the on-disk confidentiality gap noted
// in SECURITY-REPORT.md.
func OpenKVStoreEncrypted(path string, hmacKey, aeadKey []byte) (*KVStore, error) {
	if hmacKey != nil && len(hmacKey) != 32 {
		return nil, fmt.Errorf("hmac key must be 32 bytes (%d provided)", len(hmacKey))
	}
	if aeadKey != nil && len(aeadKey) != 32 {
		return nil, fmt.Errorf("aead key must be 32 bytes (%d provided)", len(aeadKey))
	}
	return openKVStore(path, hmacKey, aeadKey)
}

func openKVStore(path string, hmacKey, aeadKey []byte) (*KVStore, error) {
	// L-N3: copy keys so Close's zeroize doesn't blow away the
	// caller's slice. Without the copy, the slice header is shared
	// and zeroing the internal "copy" also zeroes whatever the
	// caller still holds (and any future reopen with the same key).
	hmCopy := append([]byte(nil), hmacKey...)
	aeCopy := append([]byte(nil), aeadKey...)
	if len(hmCopy) == 0 {
		hmCopy = nil
	}
	if len(aeCopy) == 0 {
		aeCopy = nil
	}
	store := &KVStore{
		path:     path,
		dataFile: filepath.Join(path, DataFile),
		root: &bucketData{
			Entries: make(map[string][]byte),
			Buckets: make(map[string]*bucketData),
		},
		hmacKey: hmCopy,
		aeadKey: aeCopy,
	}

	// Create directory if needed
	if err := os.MkdirAll(path, 0755); err != nil {
		return nil, err
	}

	// Load existing data if present
	if err := store.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	store.opened = true
	return store, nil
}

// load loads data from disk. It retries briefly if the file is being
// replaced by a concurrent save() (which uses atomic rename).
func (s *KVStore) load() error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		f, err := os.Open(s.dataFile)
		if err == nil {
			defer f.Close()
			return s.readFrom(f)
		}
		if os.IsNotExist(err) {
			lastErr = err
			// Brief wait — a concurrent save() using rename() should complete quickly
			continue
		}
		return err
	}
	return lastErr
}

// readFrom reads and decodes the store data from an open file.
func (s *KVStore) readFrom(f *os.File) error {
	header := make([]byte, 16)
	n, err := f.Read(header)
	if err != nil || n == 0 {
		return fmt.Errorf("cannot read data file header: %w", err)
	}

	// Reset to beginning for actual decoding
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("cannot seek data file: %w", err)
	}

	// JSON files start with '{', TLV files start with fileMagic (0xDB)
	if n > 0 && header[0] == '{' {
		// Legacy JSON format (no HMAC)
		decoder := json.NewDecoder(f)
		return decoder.Decode(&s.root)
	}

	if n > 0 && header[0] == fileMagic {
		// TLV+HMAC format: read HMAC, then payload
		if err := s.readTLV(f); err != nil {
			return fmt.Errorf("tlv read: %w", err)
		}
		return nil
	}

	if n > 0 && header[0] == encryptedFileMagic {
		// L-6: AES-256-GCM-encrypted TLV. Requires the aeadKey.
		if s.aeadKey == nil {
			return fmt.Errorf("data file is AES-GCM encrypted (magic 0xE0) but no aead key configured")
		}
		if err := s.readEncryptedTLV(f); err != nil {
			return fmt.Errorf("encrypted tlv read: %w", err)
		}
		return nil
	}

	// GOB format (legacy) — decode and convert to JSON-compatible structure
	// Only attempted for files without a recognized magic byte.
	if err := s.readGOB(f); err != nil {
		return fmt.Errorf("failed to decode data file (tried JSON, TLV, GOB): %w", err)
	}
	return nil
}

// readTLV reads the TLV+HMAC format: [magic(1) version(2) payloadLen(4) payload(payloadLen) hmac(32)].
func (s *KVStore) readTLV(r io.Reader) error {
	var hdr [7]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != fileMagic {
		return fmt.Errorf("invalid magic: 0x%x", hdr[0])
	}
	version := binary.BigEndian.Uint16(hdr[1:3])
	if version != fileVersion {
		return fmt.Errorf("unsupported TLV version: %d", version)
	}
	payloadLen := binary.BigEndian.Uint32(hdr[3:7])
	// M-1: cap the wire-supplied payload length before allocating.
	// The data file lives on disk and an attacker with write access
	// (container escape, shared mount, restored backup) could plant
	// payloadLen = 0xFFFFFFFF — make([]byte, 4 GiB) instantly OOM-
	// kills the process at startup. maxKVPayload (package-level)
	// matches the WAL cap and is well above any realistic real KV
	// record while keeping the upper bound far below the uint32
	// ceiling.
	if payloadLen > maxKVPayload {
		return fmt.Errorf("kvstore: TLV payload %d exceeds max %d", payloadLen, maxKVPayload)
	}

	// Read payload + HMAC in one read.
	recordLen := int(payloadLen) + hmacLenBytes
	record := make([]byte, recordLen)
	if _, err := io.ReadFull(r, record); err != nil {
		return err
	}

	storedHMAC := record[payloadLen:]
	payload := record[:payloadLen]

	// Verify HMAC if we have a key.
	//
	// hash.Hash.Sum(b) APPENDS the hash state to b and returns the
	// result — it does NOT hash b. The previous call
	//
	//	expectedHMAC := hmac.New(sha256.New, s.hmacKey).Sum(payload)
	//
	// produced (payload || HMAC(key, "")) — payload bytes followed by
	// the HMAC of an EMPTY string. That made expectedHMAC longer than
	// storedHMAC (32 bytes) by exactly len(payload), so
	// subtle.ConstantTimeCompare returned 0 every time (it returns 0
	// immediately on length mismatch), and every TLV+HMAC file
	// rejected as tampered. HMAC mode was completely broken: writeTLV
	// (Write+Sum(nil)) wrote the correct MAC, but readTLV never
	// accepted it.
	if s.hmacKey != nil {
		hm := hmac.New(sha256.New, s.hmacKey)
		hm.Write(payload)
		expectedHMAC := hm.Sum(nil)
		if subtle.ConstantTimeCompare(storedHMAC, expectedHMAC) != 1 {
			return ErrDataTampered
		}
	}

	// Decode JSON payload.
	if err := json.Unmarshal(payload, &s.root); err != nil {
		return fmt.Errorf("json decode: %w", err)
	}
	return nil
}

// readGOB reads legacy GOB format (deprecated — migrations should convert to JSON/TLV).
// SECURITY: Decodes into fixed *bucketData type (not interface{}). The decoder can
// instantiate nested map entries but cannot instantiate arbitrary types since the
// destination type is pinned to the known struct at compile time. We add a post-decode
// sanity check to catch malformed data.
func (s *KVStore) readGOB(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("gob stat: %w", err)
	}
	if info.Size() > maxLegacyGOBFile {
		return fmt.Errorf("gob file %d exceeds max %d", info.Size(), maxLegacyGOBFile)
	}

	// Limit reader to prevent memory exhaustion from large GOB streams.
	lr := io.LimitReader(f, maxLegacyGOBFile)
	if err := gob.NewDecoder(lr).Decode(&s.root); err != nil {
		return fmt.Errorf("gob decode: %w", err)
	}
	if s.root == nil {
		return fmt.Errorf("gob decoded nil root")
	}
	if s.root.Entries == nil {
		s.root.Entries = make(map[string][]byte)
	}
	if s.root.Buckets == nil {
		s.root.Buckets = make(map[string]*bucketData)
	}
	return nil
}

// save saves data to disk atomically using a temp file + rename.
func (s *KVStore) save() error {
	dir := filepath.Dir(s.dataFile)
	tmpFile, err := os.CreateTemp(dir, ".kvstore-save-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Only remove temp file if rename fails; on success the file is now the data file
	renamed := false
	defer func() {
		if !renamed {
			os.Remove(tmpPath)
		}
	}()

	// NEW-H1: dispatch to writeTLV when EITHER protection key is
	// configured. The aead branch lives inside writeTLV, so gating
	// only on hmacKey silently dropped aeadKey-only deployments back
	// to the legacy JSON path — and the startup log still claimed
	// "AES-256-GCM at rest". With this gate, an aead-only config
	// writes through writeTLV (which then encrypts the whole post-
	// magic body); the embedded HMAC computed with a nil key is
	// redundant under AEAD but doesn't harm anything.
	if s.hmacKey != nil || s.aeadKey != nil {
		// Write TLV+HMAC format: [magic(1) version(2) payloadLen(4) payload(n) hmac(32)],
		// optionally wrapped in AES-256-GCM if aeadKey is set.
		if err := s.writeTLV(tmpFile); err != nil {
			tmpFile.Close()
			return fmt.Errorf("write tlv: %w", err)
		}
	} else {
		// Legacy JSON format (no HMAC, no encryption).
		encoder := json.NewEncoder(tmpFile)
		if err := encoder.Encode(s.root); err != nil {
			tmpFile.Close()
			return fmt.Errorf("encode data: %w", err)
		}
	}

	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}

	// Close before rename to release the file handle on Windows
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	// Atomic rename — on Windows this also releases any file locks held by readers
	if err := os.Rename(tmpPath, s.dataFile); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	renamed = true

	if err := syncDataDir(dir); err != nil {
		return err
	}
	return nil
}

func syncDataDir(dir string) (err error) {
	dirFd, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open data dir: %w", err)
	}
	defer func() {
		if closeErr := dirFd.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close data dir: %w", closeErr)
		}
	}()

	if err := dirFd.Sync(); err != nil {
		return fmt.Errorf("fsync data dir: %w", err)
	}
	return nil
}

// writeTLV writes the store in TLV+HMAC format.
func (s *KVStore) writeTLV(w io.Writer) error {
	// Marshal JSON payload.
	payload, err := json.Marshal(s.root)
	if err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}

	// L-N2: refuse to write a payload that the uint32 length field
	// would silently truncate. maxKVPayload (64 MiB) is far below
	// the uint32 ceiling so this is defensive against future buggy
	// callers expanding the cap without re-checking the conversion.
	if len(payload) > maxKVPayload {
		return fmt.Errorf("kvstore: payload %d exceeds max %d", len(payload), maxKVPayload)
	}

	// Frame: magic + version + length + payload + hmac.
	frameLen := 1 + 2 + 4 + len(payload) + hmacLenBytes
	frame := make([]byte, frameLen)
	frame[0] = fileMagic
	binary.BigEndian.PutUint16(frame[1:3], fileVersion)
	binary.BigEndian.PutUint32(frame[3:7], uint32(len(payload)))
	copy(frame[7:7+len(payload)], payload)

	// HMAC is computed over the payload only.
	hm := hmac.New(sha256.New, s.hmacKey)
	hm.Write(payload)
	sum := hm.Sum(nil) // 32 bytes
	copy(frame[7+len(payload):], sum)

	// L-6: encrypt the whole post-magic body if an aead key is set.
	// Layout becomes 0xE0 || version || nonce || GCM(plain-TLV-body,
	// AAD=magic||version) where plain-TLV-body is everything after
	// the magic byte in the unencrypted frame.
	if s.aeadKey != nil {
		gcm, err := newGCM(s.aeadKey)
		if err != nil {
			return err
		}
		nonce := make([]byte, aeadNonceLen)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return fmt.Errorf("aead nonce: %w", err)
		}
		aad := []byte{encryptedFileMagic, 0x00, byte(fileVersion)}
		ct := gcm.Seal(nil, nonce, frame[1:], aad)
		out := make([]byte, 0, 1+2+aeadNonceLen+len(ct))
		out = append(out, encryptedFileMagic)
		out = append(out, aad[1:3]...) // version
		out = append(out, nonce...)
		out = append(out, ct...)
		return util.WriteFull(w, out)
	}

	return util.WriteFull(w, frame)
}

// readEncryptedTLV decrypts an AES-GCM-wrapped TLV frame and feeds
// the plaintext through readTLV via a bytes.Reader. L-6.
func (s *KVStore) readEncryptedTLV(r io.Reader) error {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != encryptedFileMagic {
		return fmt.Errorf("invalid encrypted magic: 0x%x", hdr[0])
	}
	version := binary.BigEndian.Uint16(hdr[1:3])
	if version != fileVersion {
		return fmt.Errorf("unsupported encrypted TLV version: %d", version)
	}
	nonce := make([]byte, aeadNonceLen)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return err
	}
	// L-N1: bound the ciphertext read. The earlier comment claimed
	// "the underlying io.Reader is bounded" but no LimitReader was
	// actually applied — a disk-write attacker (the exact threat
	// model L-6 targets) could plant a multi-GB file starting with
	// 0xE0 and OOM startup before gcm.Open ever runs. Cap matches
	// the inner maxKVPayload plus headroom for the GCM tag + a
	// small fixed overhead.
	const maxEncryptedKVBody = maxKVPayload + 1024 // payload cap + tag + tlv header
	ct, err := io.ReadAll(io.LimitReader(r, maxEncryptedKVBody+1))
	if err != nil {
		return err
	}
	if len(ct) > maxEncryptedKVBody {
		return fmt.Errorf("kvstore: encrypted body %d exceeds max %d", len(ct), maxEncryptedKVBody)
	}
	gcm, err := newGCM(s.aeadKey)
	if err != nil {
		return err
	}
	aad := []byte{encryptedFileMagic, hdr[1], hdr[2]}
	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return fmt.Errorf("aead decrypt: %w", err)
	}
	// pt is the plain-TLV-body (version || payloadLen || payload || hmac).
	// Prepend the plain magic so readTLV parses it as a normal TLV frame.
	plain := make([]byte, 1+len(pt))
	plain[0] = fileMagic
	copy(plain[1:], pt)
	return s.readTLV(bytes.NewReader(plain))
}

// newGCM constructs an AES-256-GCM AEAD from a 32-byte key.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aead key: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aead init: %w", err)
	}
	return gcm, nil
}

// Begin starts a new transaction.
// Read-only transactions acquire a read lock (concurrent with other readers).
// Begin starts a new transaction. Writable transactions take an exclusive
// lock; read-only transactions take a shared lock.
//
// F060 isolation contract: the acquired lock is held open by the returned
// *Tx for its entire lifetime. Tx and KVBucket methods are lock-free under
// the assumption that this lock is still held; Commit() and Rollback()
// release it. The lock-held-during-fn semantics are what View/Update rely
// on for true read/write isolation — without it the previous design let
// concurrent writers observe each other's uncommitted state, which broke
// the project's "ACID" claim.
func (s *KVStore) Begin(writable bool) (*Tx, error) {
	if writable {
		s.mu.Lock()
	} else {
		s.mu.RLock()
	}

	// On any error past this point we must release the lock we just took.
	releaseLockOnError := func() {
		if writable {
			s.mu.Unlock()
		} else {
			s.mu.RUnlock()
		}
	}

	if s.closed {
		releaseLockOnError()
		return nil, ErrDatabaseClosed
	}

	if writable && s.rwtx != nil {
		releaseLockOnError()
		return nil, errors.New("transaction already in progress")
	}

	tx := &Tx{
		store:    s,
		writable: writable,
		txid:     s.txid + 1,
	}

	if writable {
		s.rwtx = tx
		s.txid++
	}

	// Insert under the dedicated txsMu so concurrent Begin(false) calls
	// (each holding only RLock on s.mu) don't race on the slice header.
	s.txsMu.Lock()
	s.txs = append(s.txs, tx)
	s.txsMu.Unlock()
	atomic.AddInt64(&s.stats.TxCount, 1)
	atomic.AddInt64(&s.stats.OpenTxCount, 1)

	return tx, nil
}

// Update executes fn inside a writable transaction. The exclusive lock is
// held for the entire duration of fn, guaranteeing serialisable isolation.
func (s *KVStore) Update(fn func(*Tx) error) error {
	tx, err := s.Begin(true)
	if err != nil {
		return err
	}

	if err := fn(tx); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("rollback failed: %w", rollbackErr))
		}
		return err
	}

	return tx.Commit()
}

// View executes fn inside a read-only transaction. The shared lock is held
// for the entire duration of fn so concurrent writers cannot mutate state
// out from under the reader.
func (s *KVStore) View(fn func(*Tx) error) error {
	tx, err := s.Begin(false)
	if err != nil {
		return err
	}

	err = fn(tx)
	if rollbackErr := tx.Rollback(); rollbackErr != nil {
		return errors.Join(err, fmt.Errorf("rollback failed: %w", rollbackErr))
	}
	return err
}

// Close closes the database and flushes any pending writes.
//
// F060: with Begin holding the store lock for the lifetime of every
// transaction, Close acquires the exclusive lock and therefore blocks
// until all in-flight transactions have called Commit or Rollback (which
// release their lock). We do NOT call Rollback on those transactions
// ourselves — they own their own lock — instead we mark them closed so
// any post-Close call returns ErrTxClosed.
func (s *KVStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	if err := s.save(); err != nil {
		return err
	}

	s.closed = true
	s.rwtx = nil
	for _, tx := range s.txs {
		tx.closed = true
	}

	// L-N3: best-effort key zeroize. Go GC means full eradication is
	// impossible (the runtime may have copied the slice during stack
	// growth or escape analysis), but overwriting the live header
	// shrinks the post-Close window where a memory dump could
	// recover the keys. Defensive, low-cost.
	for i := range s.hmacKey {
		s.hmacKey[i] = 0
	}
	for i := range s.aeadKey {
		s.aeadKey[i] = 0
	}
	s.hmacKey = nil
	s.aeadKey = nil
	return nil
}

// Stats returns database statistics
func (s *KVStore) Stats() StoreStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	bucketCount, keyCount := countBucketData(s.root)
	return StoreStats{
		TxCount:     atomic.LoadInt64(&s.stats.TxCount),
		OpenTxCount: atomic.LoadInt64(&s.stats.OpenTxCount),
		BucketCount: bucketCount,
		KeyCount:    keyCount,
	}
}

func countBucketData(data *bucketData) (bucketCount, keyCount int64) {
	if data == nil {
		return 0, 0
	}
	keyCount += int64(len(data.Entries))
	for _, child := range data.Buckets {
		childBuckets, childKeys := countBucketData(child)
		bucketCount += 1 + childBuckets
		keyCount += childKeys
	}
	return bucketCount, keyCount
}

// Path returns the database path
func (s *KVStore) Path() string {
	return s.path
}

// Tx methods

// Commit commits the transaction.
//
// F060: the store lock is held by the caller (Begin acquired it and did
// not release it). This method performs state mutations under that
// already-held lock, then releases the lock as the final step before
// returning so the transaction lifetime equals the lock lifetime.
func (tx *Tx) Commit() error {
	if tx.closed {
		return ErrTxClosed
	}

	if !tx.writable {
		// Read-only: nothing to save; cleanup + release shared lock.
		tx.closed = true
		tx.store.removeTx(tx)
		atomic.AddInt64(&tx.store.stats.OpenTxCount, -1)
		tx.store.mu.RUnlock()
		return nil
	}

	// Writable: persist first. If the save fails, revert the in-memory state to
	// the last durable version (mirroring Rollback) before releasing the lock —
	// otherwise the mutated-but-unpersisted `root` stays visible to every future
	// transaction and is lost on crash, violating atomicity & durability.
	if err := tx.store.save(); err != nil {
		tx.store.rwtx = nil
		if rerr := tx.store.load(); rerr != nil {
			if os.IsNotExist(rerr) {
				tx.store.root = newBucketData()
			} else {
				util.Warnf("kvstore: failed to reload data after failed commit: %v", rerr)
			}
		}
		tx.closed = true
		tx.store.removeTx(tx)
		atomic.AddInt64(&tx.store.stats.OpenTxCount, -1)
		tx.store.mu.Unlock()
		return err
	}

	tx.store.rwtx = nil
	tx.closed = true
	tx.store.removeTx(tx)
	commitHandlers := append([]func(){}, tx.commitHandlers...)

	atomic.AddInt64(&tx.store.stats.OpenTxCount, -1)
	tx.store.mu.Unlock()

	for _, fn := range commitHandlers {
		fn()
	}

	return nil
}

// Rollback rolls back the transaction and releases the store lock that
// Begin acquired.
//
// Rollback on an already-closed transaction returns ErrTxClosed (pinned by
// TestKVStoreRollbackClosedTransaction): Commit and Rollback each release
// the transaction's store lock exactly once, so a second call must not
// unlock again. Callers using the `defer tx.Rollback()` idiom alongside an
// explicit Commit should therefore ignore the ErrTxClosed return.
func (tx *Tx) Rollback() error {
	if tx.closed {
		return ErrTxClosed
	}

	if !tx.writable {
		// Read-only: cleanup + release shared lock.
		tx.closed = true
		tx.store.removeTx(tx)
		atomic.AddInt64(&tx.store.stats.OpenTxCount, -1)
		tx.store.mu.RUnlock()
		return nil
	}

	// Writable: discard in-memory changes by re-loading from disk under the
	// still-held exclusive lock.
	var rollbackErr error
	tx.store.rwtx = nil
	if err := tx.store.load(); err != nil {
		if os.IsNotExist(err) {
			tx.store.root = newBucketData()
		} else {
			rollbackErr = fmt.Errorf("reload data during rollback: %w", err)
			util.Warnf("kvstore: %v", rollbackErr)
		}
	}

	tx.closed = true
	tx.store.removeTx(tx)
	atomic.AddInt64(&tx.store.stats.OpenTxCount, -1)
	tx.store.mu.Unlock()
	return rollbackErr
}

// removeTx removes a transaction from the store's txs slice to prevent unbounded memory growth.
// Acquires the dedicated txsMu briefly; the store's s.mu may be held in
// either mode by the caller — both are fine since txsMu only protects
// the slice header itself.
func (s *KVStore) removeTx(tx *Tx) {
	s.txsMu.Lock()
	defer s.txsMu.Unlock()
	for i, t := range s.txs {
		if t == tx {
			s.txs = append(s.txs[:i], s.txs[i+1:]...)
			return
		}
	}
}

// Bucket returns a bucket by name. F060: lock-free; the store lock is
// already held by Begin for the lifetime of the transaction.
func (tx *Tx) Bucket(name []byte) *KVBucket {
	key := string(name)
	data, ok := tx.store.root.Buckets[key]
	if !ok {
		return nil
	}

	return &KVBucket{
		tx:   tx,
		name: key,
		data: data,
	}
}

// CreateBucket creates a new bucket. F060: lock-free.
func (tx *Tx) CreateBucket(name []byte) (*KVBucket, error) {
	if tx.closed {
		return nil, ErrTxClosed
	}

	if !tx.writable {
		return nil, ErrTxNotWritable
	}

	key := string(name)
	if _, ok := tx.store.root.Buckets[key]; ok {
		return nil, ErrBucketExists
	}

	data := &bucketData{
		Entries: make(map[string][]byte),
		Buckets: make(map[string]*bucketData),
	}
	tx.store.root.Buckets[key] = data

	return &KVBucket{
		tx:   tx,
		name: key,
		data: data,
	}, nil
}

// CreateBucketIfNotExists creates a bucket if it doesn't exist
func (tx *Tx) CreateBucketIfNotExists(name []byte) (*KVBucket, error) {
	if tx.closed {
		return nil, ErrTxClosed
	}

	if bucket := tx.Bucket(name); bucket != nil {
		return bucket, nil
	}
	return tx.CreateBucket(name)
}

// DeleteBucket deletes a bucket. F060: lock-free.
func (tx *Tx) DeleteBucket(name []byte) error {
	if tx.closed {
		return ErrTxClosed
	}

	if !tx.writable {
		return ErrTxNotWritable
	}

	key := string(name)
	if _, ok := tx.store.root.Buckets[key]; !ok {
		return ErrBucketNotFound
	}

	delete(tx.store.root.Buckets, key)
	return nil
}

// OnCommit registers a commit handler
func (tx *Tx) OnCommit(fn func()) {
	tx.commitHandlers = append(tx.commitHandlers, fn)
}

// KVBucket methods

// Get retrieves a value by key. F060: lock-free.
func (b *KVBucket) Get(key []byte) []byte {
	tx := b.tx
	if tx.closed {
		return nil
	}

	value, ok := b.data.Entries[string(key)]
	if !ok {
		return nil
	}

	// Return a copy
	result := make([]byte, len(value))
	copy(result, value)
	return result
}

// Put stores a key-value pair
func (b *KVBucket) Put(key, value []byte) error {
	if b.tx.closed {
		return ErrTxClosed
	}

	if len(key) == 0 {
		return errors.New("key required")
	}
	if len(key) > KVMaxKeySize {
		return ErrKeyTooLarge
	}
	if len(value) > KVMaxValueSize {
		return ErrKVValueTooLarge
	}

	if !b.tx.writable {
		return ErrTxNotWritable
	}

	// F060: lock-free; Begin holds the exclusive lock.

	// Store copies
	keyCopy := make([]byte, len(key))
	valueCopy := make([]byte, len(value))
	copy(keyCopy, key)
	copy(valueCopy, value)

	b.data.Entries[string(keyCopy)] = valueCopy
	return nil
}

// Delete removes a key. F060: lock-free.
func (b *KVBucket) Delete(key []byte) error {
	if b.tx.closed {
		return ErrTxClosed
	}

	if !b.tx.writable {
		return ErrTxNotWritable
	}

	keyStr := string(key)
	if _, ok := b.data.Entries[keyStr]; !ok {
		return ErrKVKeyNotFound
	}

	delete(b.data.Entries, keyStr)
	return nil
}

// Bucket returns a nested bucket. F060: lock-free.
func (b *KVBucket) Bucket(name []byte) *KVBucket {
	key := string(name)
	data, ok := b.data.Buckets[key]
	if !ok {
		return nil
	}

	return &KVBucket{
		tx:   b.tx,
		name: key,
		data: data,
	}
}

// CreateBucket creates a nested bucket. F060: lock-free.
func (b *KVBucket) CreateBucket(name []byte) (*KVBucket, error) {
	if b.tx.closed {
		return nil, ErrTxClosed
	}

	if !b.tx.writable {
		return nil, ErrTxNotWritable
	}

	key := string(name)
	if _, ok := b.data.Buckets[key]; ok {
		return nil, ErrBucketExists
	}

	data := &bucketData{
		Entries: make(map[string][]byte),
		Buckets: make(map[string]*bucketData),
	}
	b.data.Buckets[key] = data

	return &KVBucket{
		tx:   b.tx,
		name: key,
		data: data,
	}, nil
}

// CreateBucketIfNotExists creates a bucket if it doesn't exist
func (b *KVBucket) CreateBucketIfNotExists(name []byte) (*KVBucket, error) {
	if b.tx.closed {
		return nil, ErrTxClosed
	}

	if child := b.Bucket(name); child != nil {
		return child, nil
	}
	return b.CreateBucket(name)
}

// DeleteBucket deletes a nested bucket. F060: lock-free.
func (b *KVBucket) DeleteBucket(name []byte) error {
	if b.tx.closed {
		return ErrTxClosed
	}

	if !b.tx.writable {
		return ErrTxNotWritable
	}

	key := string(name)
	if _, ok := b.data.Buckets[key]; !ok {
		return ErrBucketNotFound
	}

	delete(b.data.Buckets, key)
	return nil
}

// Cursor returns a cursor for iteration. F060: lock-free.
func (b *KVBucket) Cursor() *KVCursor {
	keys := make([]string, 0, len(b.data.Entries))
	for k := range b.data.Entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	return &KVCursor{
		bucket: b,
		keys:   keys,
		pos:    -1,
	}
}

// ForEach iterates over all key-value pairs
func (b *KVBucket) ForEach(fn func(k, v []byte) error) error {
	c := b.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if err := fn(k, v); err != nil {
			return err
		}
	}
	return nil
}

// Stats returns bucket statistics. F060: lock-free.
func (b *KVBucket) Stats() BucketStats {
	return BucketStats{
		KeyCount: int64(len(b.data.Entries)),
	}
}

// BucketStats contains bucket statistics
type BucketStats struct {
	KeyCount int64
}

// KVCursor methods

// First positions the cursor at the first key
func (c *KVCursor) First() ([]byte, []byte) {
	if len(c.keys) == 0 {
		return nil, nil
	}
	c.pos = 0
	return c.current()
}

// Last positions the cursor at the last key
func (c *KVCursor) Last() ([]byte, []byte) {
	if len(c.keys) == 0 {
		return nil, nil
	}
	c.pos = len(c.keys) - 1
	return c.current()
}

// Next moves to the next key
func (c *KVCursor) Next() ([]byte, []byte) {
	if c.pos >= len(c.keys)-1 {
		return nil, nil
	}
	c.pos++
	return c.current()
}

// Prev moves to the previous key
func (c *KVCursor) Prev() ([]byte, []byte) {
	if c.pos <= 0 {
		return nil, nil
	}
	c.pos--
	return c.current()
}

// Seek positions the cursor at the given key
func (c *KVCursor) Seek(seek []byte) ([]byte, []byte) {
	i := sort.SearchStrings(c.keys, string(seek))
	c.pos = i
	return c.current()
}

func (c *KVCursor) current() ([]byte, []byte) {
	if c.pos < 0 || c.pos >= len(c.keys) {
		return nil, nil
	}
	k := c.keys[c.pos]
	v := c.bucket.data.Entries[k]

	// Return copies
	key := make([]byte, len(k))
	value := make([]byte, len(v))
	copy(key, k)
	copy(value, v)

	return key, value
}
