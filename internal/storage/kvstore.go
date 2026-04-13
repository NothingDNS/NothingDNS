package storage

import (
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
	txs      []*Tx
	stats    StoreStats
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

// OpenKVStore opens or creates a key-value store
func OpenKVStore(path string) (*KVStore, error) {
	store := &KVStore{
		path:     path,
		dataFile: filepath.Join(path, DataFile),
		root: &bucketData{
			Entries: make(map[string][]byte),
			Buckets: make(map[string]*bucketData),
		},
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

	// JSON files start with '{', GOB files start with GOB type encoding
	if n > 0 && header[0] == '{' {
		// JSON format
		decoder := json.NewDecoder(f)
		return decoder.Decode(&s.root)
	}

	// GOB format (legacy) — decode and convert to JSON-compatible structure
	if err := gob.NewDecoder(f).Decode(&s.root); err != nil {
		return fmt.Errorf("failed to decode data file (tried JSON and GOB): %w", err)
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

	encoder := json.NewEncoder(tmpFile)
	if err := encoder.Encode(s.root); err != nil {
		tmpFile.Close()
		return fmt.Errorf("encode data: %w", err)
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

	return nil
}

// Begin starts a new transaction.
// Read-only transactions acquire a read lock (concurrent with other readers).
// Writable transactions acquire a write lock (exclusive).
func (s *KVStore) Begin(writable bool) (*Tx, error) {
	if writable {
		s.mu.Lock()
		defer s.mu.Unlock()
	} else {
		s.mu.RLock()
		defer s.mu.RUnlock()
	}

	if s.closed {
		return nil, ErrDatabaseClosed
	}

	if writable && s.rwtx != nil {
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

	s.txs = append(s.txs, tx)
	atomic.AddInt64(&s.stats.TxCount, 1)
	atomic.AddInt64(&s.stats.OpenTxCount, 1)

	return tx, nil
}

// Update executes a function in a writable transaction
func (s *KVStore) Update(fn func(*Tx) error) error {
	tx, err := s.Begin(true)
	if err != nil {
		return err
	}

	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}

// View executes a function in a read-only transaction.
// The lock is held for the entire duration of fn to ensure consistent reads.
func (s *KVStore) View(fn func(*Tx) error) error {
	tx, err := s.Begin(false)
	if err != nil {
		return err
	}

	// Execute fn while holding the read lock
	err = fn(tx)

	// Rollback explicitly (not deferred) to ensure lock is held until fn completes
	tx.Rollback()

	return err
}

// Close closes the database and flushes any pending writes.
func (s *KVStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true

	if s.rwtx != nil {
		s.rwtx.Rollback()
	}

	for _, tx := range s.txs {
		tx.closed = true
	}

	// Flush any unflushed data before closing
	if err := s.save(); err != nil {
		return err
	}

	return nil
}

// Stats returns database statistics
func (s *KVStore) Stats() StoreStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stats
}

// Path returns the database path
func (s *KVStore) Path() string {
	return s.path
}

// Tx methods

// Commit commits the transaction
func (tx *Tx) Commit() error {
	if tx.closed {
		return ErrTxClosed
	}

	if !tx.writable {
		return ErrTxNotWritable
	}

	tx.store.mu.Lock()
	defer tx.store.mu.Unlock()

	// Save to disk
	if err := tx.store.save(); err != nil {
		return err
	}

	tx.store.rwtx = nil
	tx.closed = true
	tx.store.removeTx(tx)

	for _, fn := range tx.commitHandlers {
		fn()
	}

	atomic.AddInt64(&tx.store.stats.OpenTxCount, -1)
	return nil
}

// Rollback rolls back the transaction.
// For read-only transactions the lock was already released by Begin,
// so this acquires only a read lock to perform cleanup.
// For writable transactions a full write lock is acquired.
func (tx *Tx) Rollback() error {
	if tx.closed {
		return ErrTxClosed
	}

	// Read-only transactions: lock already released by Begin, just clean up.
	if !tx.writable {
		tx.closed = true
		tx.store.removeTx(tx)
		atomic.AddInt64(&tx.store.stats.OpenTxCount, -1)
		return nil
	}

	// Writable transactions: need write lock for state changes.
	tx.store.mu.Lock()
	defer tx.store.mu.Unlock()

	tx.store.rwtx = nil
	// Reload data from disk to discard changes
	if err := tx.store.load(); err != nil {
		util.Warnf("kvstore: failed to reload data during rollback: %v", err)
	}

	tx.closed = true
	tx.store.removeTx(tx)
	atomic.AddInt64(&tx.store.stats.OpenTxCount, -1)
	return nil
}

// removeTx removes a transaction from the store's txs slice to prevent unbounded memory growth.
// Must be called with s.mu held.
func (s *KVStore) removeTx(tx *Tx) {
	for i, t := range s.txs {
		if t == tx {
			s.txs = append(s.txs[:i], s.txs[i+1:]...)
			return
		}
	}
}

// Bucket returns a bucket by name
func (tx *Tx) Bucket(name []byte) *KVBucket {
	tx.store.mu.RLock()
	defer tx.store.mu.RUnlock()

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

// CreateBucket creates a new bucket
func (tx *Tx) CreateBucket(name []byte) (*KVBucket, error) {
	if !tx.writable {
		return nil, ErrTxNotWritable
	}

	tx.store.mu.Lock()
	defer tx.store.mu.Unlock()

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
	if bucket := tx.Bucket(name); bucket != nil {
		return bucket, nil
	}
	return tx.CreateBucket(name)
}

// DeleteBucket deletes a bucket
func (tx *Tx) DeleteBucket(name []byte) error {
	if !tx.writable {
		return ErrTxNotWritable
	}

	tx.store.mu.Lock()
	defer tx.store.mu.Unlock()

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

// Get retrieves a value by key
func (b *KVBucket) Get(key []byte) []byte {
	tx := b.tx
	tx.store.mu.RLock()
	defer tx.store.mu.RUnlock()

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

	b.tx.store.mu.Lock()
	defer b.tx.store.mu.Unlock()

	// Store copies
	keyCopy := make([]byte, len(key))
	valueCopy := make([]byte, len(value))
	copy(keyCopy, key)
	copy(valueCopy, value)

	b.data.Entries[string(keyCopy)] = valueCopy
	return nil
}

// Delete removes a key
func (b *KVBucket) Delete(key []byte) error {
	if !b.tx.writable {
		return ErrTxNotWritable
	}

	b.tx.store.mu.Lock()
	defer b.tx.store.mu.Unlock()

	keyStr := string(key)
	if _, ok := b.data.Entries[keyStr]; !ok {
		return ErrKVKeyNotFound
	}

	delete(b.data.Entries, keyStr)
	return nil
}

// Bucket returns a nested bucket
func (b *KVBucket) Bucket(name []byte) *KVBucket {
	b.tx.store.mu.RLock()
	defer b.tx.store.mu.RUnlock()

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

// CreateBucket creates a nested bucket
func (b *KVBucket) CreateBucket(name []byte) (*KVBucket, error) {
	if !b.tx.writable {
		return nil, ErrTxNotWritable
	}

	b.tx.store.mu.Lock()
	defer b.tx.store.mu.Unlock()

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
	if child := b.Bucket(name); child != nil {
		return child, nil
	}
	return b.CreateBucket(name)
}

// DeleteBucket deletes a nested bucket
func (b *KVBucket) DeleteBucket(name []byte) error {
	if !b.tx.writable {
		return ErrTxNotWritable
	}

	b.tx.store.mu.Lock()
	defer b.tx.store.mu.Unlock()

	key := string(name)
	if _, ok := b.data.Buckets[key]; !ok {
		return ErrBucketNotFound
	}

	delete(b.data.Buckets, key)
	return nil
}

// Cursor returns a cursor for iteration
func (b *KVBucket) Cursor() *KVCursor {
	b.tx.store.mu.RLock()
	defer b.tx.store.mu.RUnlock()

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

// Stats returns bucket statistics
func (b *KVBucket) Stats() BucketStats {
	b.tx.store.mu.RLock()
	defer b.tx.store.mu.RUnlock()

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
	seekStr := string(seek)
	for i, k := range c.keys {
		if k >= seekStr {
			c.pos = i
			return c.current()
		}
	}
	return nil, nil
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
