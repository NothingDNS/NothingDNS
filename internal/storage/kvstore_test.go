package storage

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestKVStore_HMACRoundTrip guards against a regression where readTLV
// computed expectedHMAC via hmac.New(...).Sum(payload), which appended
// the empty-string MAC to the payload bytes instead of hashing the
// payload. ConstantTimeCompare then always saw a length mismatch and
// returned 0, so every TLV+HMAC file was rejected as tampered —
// HMAC mode was effectively broken. This test writes a value with an
// HMAC key, closes, re-opens with the SAME key, and reads back to
// confirm the integrity check accepts genuine data.
func TestKVStore_HMACRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hmac.db")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	store, err := OpenKVStore(path, key)
	if err != nil {
		t.Fatalf("OpenKVStore (write): %v", err)
	}

	if err := store.Update(func(tx *Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("bucket"))
		if err != nil {
			return err
		}
		return b.Put([]byte("key"), []byte("value"))
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	store2, err := OpenKVStore(path, key)
	if err != nil {
		t.Fatalf("OpenKVStore (re-open with correct HMAC key): %v", err)
	}
	defer store2.Close()

	if err := store2.View(func(tx *Tx) error {
		b := tx.Bucket([]byte("bucket"))
		if b == nil {
			return fmt.Errorf("bucket missing")
		}
		got := b.Get([]byte("key"))
		if string(got) != "value" {
			return fmt.Errorf("expected %q, got %q", "value", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("View: %v", err)
	}
}

func TestKVStore_HMACRejectsTrailingBytes_F819(t *testing.T) {
	path := t.TempDir()
	key := bytes.Repeat([]byte{0x5a}, 32)
	store, err := OpenKVStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	f, err := os.OpenFile(filepath.Join(path, DataFile), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0x42}); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if reopened, err := OpenKVStore(path, key); err == nil {
		_ = reopened.Close()
		t.Fatal("OpenKVStore accepted trailing bytes after the HMAC frame")
	}
}

func TestKVStore_WriteTLVCompletesPartialWrites(t *testing.T) {
	hmacKey := make([]byte, 32)
	aeadKey := make([]byte, 32)
	for i := range hmacKey {
		hmacKey[i] = byte(i + 1)
		aeadKey[i] = byte(255 - i)
	}

	tests := []struct {
		name    string
		aeadKey []byte
		read    func(*KVStore, *bytes.Buffer) error
	}{
		{
			name: "plain",
			read: func(store *KVStore, buf *bytes.Buffer) error {
				return store.readTLV(bytes.NewReader(buf.Bytes()))
			},
		},
		{
			name:    "encrypted",
			aeadKey: aeadKey,
			read: func(store *KVStore, buf *bytes.Buffer) error {
				return store.readEncryptedTLV(bytes.NewReader(buf.Bytes()))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := &KVStore{
				root: &bucketData{
					Entries: map[string][]byte{"key": []byte("value")},
					Buckets: map[string]*bucketData{},
				},
				hmacKey: hmacKey,
				aeadKey: tt.aeadKey,
			}
			writer := &chunkedWriter{maxWrite: 3}

			if err := source.writeTLV(writer); err != nil {
				t.Fatalf("writeTLV: %v", err)
			}
			if writer.calls < 2 {
				t.Fatalf("chunked writer should require multiple writes, got %d", writer.calls)
			}

			loaded := &KVStore{hmacKey: hmacKey, aeadKey: tt.aeadKey}
			if err := tt.read(loaded, &writer.buf); err != nil {
				t.Fatalf("read TLV: %v", err)
			}
			got := loaded.root.Entries["key"]
			if string(got) != "value" {
				t.Fatalf("loaded value = %q, want %q", got, "value")
			}
		})
	}
}

func TestKVStoreReadGOBRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.gob")
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(&bucketData{
		Entries: map[string][]byte{"key": []byte("value")},
		Buckets: map[string]*bucketData{},
	}); err != nil {
		t.Fatalf("gob encode: %v", err)
	}
	if buf.Len() > maxLegacyGOBFile {
		t.Fatalf("test fixture gob is unexpectedly large: %d", buf.Len())
	}
	buf.Write(make([]byte, maxLegacyGOBFile-buf.Len()+1))

	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	store := &KVStore{}
	if err := store.readGOB(f); err == nil {
		t.Fatal("readGOB accepted a legacy GOB file larger than the documented cap")
	}
}

// TestReadEncryptedTLV_RejectsOversizedBody regresses
// SECURITY-REPORT-2026-05-23-rescan L-N1. readEncryptedTLV used to
// call io.ReadAll on the raw reader before any size check, so a
// disk-write attacker (the L-6 threat model) could plant a multi-GB
// file starting with 0xE0 and OOM startup before gcm.Open ran. The
// fix wraps the read in io.LimitReader + a post-read sanity check.
func TestReadEncryptedTLV_RejectsOversizedBody(t *testing.T) {
	aead := make([]byte, 32)
	store := &KVStore{aeadKey: aead}

	// Header (magic + version + nonce) is fine; trailing bytes intentionally
	// exceed the cap. We don't need valid ciphertext — the cap check fires
	// before gcm.Open.
	var buf bytes.Buffer
	buf.WriteByte(encryptedFileMagic)
	verBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(verBytes, fileVersion)
	buf.Write(verBytes)
	buf.Write(make([]byte, aeadNonceLen)) // nonce
	// (64 MiB + headroom + 1) of body bytes — guaranteed over the cap.
	body := make([]byte, (64<<20)+1024+1)
	buf.Write(body)

	err := store.readEncryptedTLV(&buf)
	if err == nil {
		t.Fatal("expected error for oversized encrypted body, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds max") {
		t.Errorf("error %q should mention 'exceeds max' (the cap guard message)", err)
	}
}

// TestKVStore_EncryptedAeadOnly_NoPlaintextOnDisk regresses
// SECURITY-REPORT-2026-05-23 NEW-H1. The original L-6 wiring at
// zone_manager.go passes nil hmacKey + aeadKey to OpenKVStoreEncrypted,
// but save()'s dispatch was `if s.hmacKey != nil { writeTLV } else
// { writeJSON }` — so aead-only deployments silently wrote PLAIN
// JSON despite the startup log claiming "AES-256-GCM at rest". The
// earlier TestKVStore_EncryptedRoundTrip passed only because it
// supplied BOTH keys, which doesn't match production wiring shape.
//
// This test pins the production shape: nil hmacKey + aeadKey, write
// a known-secret value, assert the on-disk file starts with the
// encrypted magic 0xE0 and does NOT contain the cleartext value.
func TestKVStore_EncryptedAeadOnly_NoPlaintextOnDisk(t *testing.T) {
	dir := t.TempDir()
	aeadKey := make([]byte, 32)
	for i := range aeadKey {
		aeadKey[i] = byte(7*i + 3)
	}

	const (
		bkt    = "prod-shape-bucket"
		k      = "prod-shape-key"
		secret = "this-must-never-appear-in-the-data-file"
	)

	store, err := OpenKVStoreEncrypted(dir, nil, aeadKey) // production shape
	if err != nil {
		t.Fatalf("OpenKVStoreEncrypted (write, nil hmac): %v", err)
	}
	if err := store.Update(func(tx *Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bkt))
		if err != nil {
			return err
		}
		return b.Put([]byte(k), []byte(secret))
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, DataFile))
	if err != nil {
		t.Fatalf("read on-disk file: %v", err)
	}
	if len(raw) == 0 || raw[0] != 0xE0 {
		t.Errorf("NEW-H1 regression: data file magic = 0x%x, want 0xE0 (encrypted) — save() dispatch silently fell back to plain JSON", raw[0])
	}
	for _, needle := range []string{bkt, k, secret} {
		if bytes.Contains(raw, []byte(needle)) {
			t.Errorf("NEW-H1 regression: on-disk file leaked %q in plaintext", needle)
		}
	}

	// Re-open with the same aead key must recover the value.
	store2, err := OpenKVStoreEncrypted(dir, nil, aeadKey)
	if err != nil {
		t.Fatalf("OpenKVStoreEncrypted (read): %v", err)
	}
	defer store2.Close()
	if err := store2.View(func(tx *Tx) error {
		b := tx.Bucket([]byte(bkt))
		if b == nil {
			return fmt.Errorf("bucket missing")
		}
		got := b.Get([]byte(k))
		if string(got) != secret {
			return fmt.Errorf("got %q, want %q", got, secret)
		}
		return nil
	}); err != nil {
		t.Fatalf("View: %v", err)
	}
}

// TestKVStore_EncryptedRoundTrip regresses SECURITY-REPORT.md L-6.
// When OpenKVStoreEncrypted is configured with a 32-byte aeadKey,
// the on-disk data file must be AES-256-GCM encrypted: a re-open
// with the same key recovers the value, and a hex dump of the file
// must not contain the cleartext bucket / key / value bytes that
// the JSON serializer would otherwise emit verbatim. Plain mode
// (aeadKey nil) and HMAC-only mode keep working unchanged.
func TestKVStore_EncryptedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	hmacKey := make([]byte, 32)
	aeadKey := make([]byte, 32)
	for i := range hmacKey {
		hmacKey[i] = byte(i + 1)
		aeadKey[i] = byte(255 - i)
	}

	const (
		secretBucket = "secret-bucket"
		secretKey    = "the-secret-key"
		secretValue  = "extremely-confidential-payload"
	)

	store, err := OpenKVStoreEncrypted(dir, hmacKey, aeadKey)
	if err != nil {
		t.Fatalf("OpenKVStoreEncrypted (write): %v", err)
	}
	if err := store.Update(func(tx *Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(secretBucket))
		if err != nil {
			return err
		}
		return b.Put([]byte(secretKey), []byte(secretValue))
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// On-disk file must NOT contain the plaintext bucket/key/value.
	raw, err := os.ReadFile(filepath.Join(dir, DataFile))
	if err != nil {
		t.Fatalf("read on-disk file: %v", err)
	}
	if len(raw) == 0 || raw[0] != 0xE0 {
		t.Errorf("L-6 regression: data file magic = 0x%x, want 0xE0 (encrypted)", raw[0])
	}
	for _, needle := range []string{secretBucket, secretKey, secretValue} {
		if bytes.Contains(raw, []byte(needle)) {
			t.Errorf("L-6 regression: on-disk file leaked %q in plaintext", needle)
		}
	}

	// Re-open with the SAME aead key must recover the value.
	store2, err := OpenKVStoreEncrypted(dir, hmacKey, aeadKey)
	if err != nil {
		t.Fatalf("OpenKVStoreEncrypted (re-open): %v", err)
	}
	defer store2.Close()
	if err := store2.View(func(tx *Tx) error {
		b := tx.Bucket([]byte(secretBucket))
		if b == nil {
			return fmt.Errorf("bucket missing")
		}
		got := b.Get([]byte(secretKey))
		if string(got) != secretValue {
			return fmt.Errorf("got %q, want %q", got, secretValue)
		}
		return nil
	}); err != nil {
		t.Fatalf("View: %v", err)
	}

	// Re-open WITHOUT the aead key must refuse to load (clear error,
	// not silent empty store).
	store3, err := OpenKVStore(dir, hmacKey)
	if err == nil {
		_ = store3.Close()
		t.Error("L-6 regression: plain-mode open succeeded on an encrypted file — should have refused with a clear error")
	}
}

// TestReadTLV_RejectsOversizedPayloadLen regresses SECURITY-REPORT.md
// M-1. readTLV used to read a uint32 payloadLen from the data file
// and immediately allocate make([]byte, payloadLen + hmacLenBytes)
// with no upper bound. An attacker with write access to the data
// file — per architecture.md this is an enumerated on-disk attack
// surface (container escape, shared mount, restored backup) — could
// plant payloadLen = 0xFFFFFFFF and OOM-kill the process at startup.
// Same shape as the recently-fixed Raft snapshot OOM (b9f0ed5) and
// raft entry-slice OOM (e9687fe); the cap pattern here mirrors
// kvjournal.go's maxJournalPayload.
func TestReadTLV_RejectsOversizedPayloadLen(t *testing.T) {
	store := &KVStore{}

	// Build a TLV header with payloadLen = 64 MiB + 1 (one byte over
	// the cap). No payload bytes follow — readTLV must error out at
	// the cap check before attempting to allocate.
	var buf bytes.Buffer
	buf.WriteByte(0xDB) // fileMagic
	versionBytes := []byte{0, 0}
	binary.BigEndian.PutUint16(versionBytes, 1) // fileVersion
	buf.Write(versionBytes)
	payloadLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(payloadLenBytes, (64<<20)+1)
	buf.Write(payloadLenBytes)

	err := store.readTLV(&buf)
	if err == nil {
		t.Fatal("expected error for oversized payloadLen, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds max") {
		t.Errorf("error %q should mention 'exceeds max' (the cap guard message)", err)
	}
}

func TestKVStoreOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	if store.Path() != path {
		t.Errorf("Expected path %s, got %s", path, store.Path())
	}

	// Check file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("Database file was not created")
	}
}

func TestKVStoreView(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	err = store.View(func(tx *Tx) error {
		// Read-only transaction
		return nil
	})

	if err != nil {
		t.Fatalf("View failed: %v", err)
	}
}

func TestKVStoreUpdate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	err = store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("test"))
		if err != nil {
			return err
		}

		return bucket.Put([]byte("key"), []byte("value"))
	})

	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
}

func TestKVStorePutGet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	// Put
	err = store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("test"))
		if err != nil {
			return err
		}

		return bucket.Put([]byte("mykey"), []byte("myvalue"))
	})

	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Get
	var value []byte
	err = store.View(func(tx *Tx) error {
		bucket := tx.Bucket([]byte("test"))
		if bucket == nil {
			t.Fatal("Bucket not found")
		}

		value = bucket.Get([]byte("mykey"))
		return nil
	})

	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if string(value) != "myvalue" {
		t.Errorf("Expected 'myvalue', got '%s'", value)
	}
}

func TestKVStoreDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	// Put
	err = store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("test"))
		if err != nil {
			return err
		}

		return bucket.Put([]byte("deletekey"), []byte("deletevalue"))
	})

	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Delete
	err = store.Update(func(tx *Tx) error {
		bucket := tx.Bucket([]byte("test"))
		if bucket == nil {
			t.Fatal("Bucket not found")
		}

		return bucket.Delete([]byte("deletekey"))
	})

	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify deleted
	var value []byte
	err = store.View(func(tx *Tx) error {
		bucket := tx.Bucket([]byte("test"))
		if bucket == nil {
			t.Fatal("Bucket not found")
		}

		value = bucket.Get([]byte("deletekey"))
		return nil
	})

	if err != nil {
		t.Fatalf("View failed: %v", err)
	}

	if value != nil {
		t.Errorf("Expected nil after delete, got '%s'", value)
	}
}

func TestKVStoreNestedBuckets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	// Create nested buckets
	err = store.Update(func(tx *Tx) error {
		parent, err := tx.CreateBucketIfNotExists([]byte("parent"))
		if err != nil {
			return err
		}

		child, err := parent.CreateBucketIfNotExists([]byte("child"))
		if err != nil {
			return err
		}

		return child.Put([]byte("nested_key"), []byte("nested_value"))
	})

	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Read nested
	var value []byte
	err = store.View(func(tx *Tx) error {
		parent := tx.Bucket([]byte("parent"))
		if parent == nil {
			t.Fatal("Parent bucket not found")
		}

		child := parent.Bucket([]byte("child"))
		if child == nil {
			t.Fatal("Child bucket not found")
		}

		value = child.Get([]byte("nested_key"))
		return nil
	})

	if err != nil {
		t.Fatalf("View failed: %v", err)
	}

	if string(value) != "nested_value" {
		t.Errorf("Expected 'nested_value', got '%s'", value)
	}
}

func TestKVStoreRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	// Start transaction and rollback
	tx, err := store.Begin(true)
	if err != nil {
		t.Fatalf("Begin failed: %v", err)
	}

	// Rollback without making any changes
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	// Transaction should be closed
	if !tx.closed {
		t.Error("Expected transaction to be closed")
	}
}

func TestKVStoreRollbackReportsReloadError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	if err := store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("test"))
		if err != nil {
			return err
		}
		return bucket.Put([]byte("key"), []byte("value"))
	}); err != nil {
		t.Fatalf("seed Update failed: %v", err)
	}

	tx, err := store.Begin(true)
	if err != nil {
		t.Fatalf("Begin failed: %v", err)
	}
	bucket, err := tx.CreateBucketIfNotExists([]byte("transient"))
	if err != nil {
		t.Fatalf("CreateBucketIfNotExists: %v", err)
	}
	if err := bucket.Put([]byte("key"), []byte("value")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := os.WriteFile(store.dataFile, []byte("not-a-valid-kv-file"), 0600); err != nil {
		t.Fatalf("corrupt data file: %v", err)
	}

	err = tx.Rollback()
	if err == nil {
		t.Fatal("Rollback should report reload failure")
	}
	if !strings.Contains(err.Error(), "reload data during rollback") {
		t.Fatalf("Rollback error should include reload context, got: %v", err)
	}
}

func TestKVStoreUpdateReportsRollbackFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	if err := store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("test"))
		if err != nil {
			return err
		}
		return bucket.Put([]byte("key"), []byte("value"))
	}); err != nil {
		t.Fatalf("seed Update failed: %v", err)
	}

	callbackErr := errors.New("callback failed")
	err = store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("transient"))
		if err != nil {
			return err
		}
		if err := bucket.Put([]byte("key"), []byte("value")); err != nil {
			return err
		}
		if err := os.WriteFile(store.dataFile, []byte("not-a-valid-kv-file"), 0600); err != nil {
			return err
		}
		return callbackErr
	})
	if !errors.Is(err, callbackErr) {
		t.Fatalf("Update error should include callback error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("Update error should include rollback failure context, got: %v", err)
	}
}

func TestKVStoreKeyTooLarge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	// Try to put a key that's too large
	err = store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("test"))
		if err != nil {
			return err
		}

		largeKey := make([]byte, KVMaxKeySize+1)
		return bucket.Put(largeKey, []byte("value"))
	})

	if err != ErrKeyTooLarge {
		t.Errorf("Expected ErrKeyTooLarge, got %v", err)
	}
}

func TestKVStoreBucketExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	// Create bucket
	err = store.Update(func(tx *Tx) error {
		_, err := tx.CreateBucket([]byte("exists"))
		return err
	})

	if err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	// Try to create again
	err = store.Update(func(tx *Tx) error {
		_, err := tx.CreateBucket([]byte("exists"))
		return err
	})

	if err != ErrBucketExists {
		t.Errorf("Expected ErrBucketExists, got %v", err)
	}
}

func TestKVStoreOnCommit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	called := false

	err = store.Update(func(tx *Tx) error {
		tx.OnCommit(func() {
			called = true
		})

		_, err := tx.CreateBucketIfNotExists([]byte("test"))
		return err
	})

	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	if !called {
		t.Error("OnCommit handler was not called")
	}
}

func TestKVStoreOnCommitRunsAfterUnlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		var handlerErr error
		err := store.Update(func(tx *Tx) error {
			tx.OnCommit(func() {
				handlerErr = store.View(func(viewTx *Tx) error {
					if bucket := viewTx.Bucket([]byte("test")); bucket == nil {
						return ErrBucketNotFound
					}
					return nil
				})
			})

			_, err := tx.CreateBucketIfNotExists([]byte("test"))
			return err
		})
		if err != nil {
			done <- err
			return
		}
		done <- handlerErr
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Update with reentrant OnCommit handler failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnCommit handler blocked while opening a read transaction")
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

func TestKVStoreStats(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	stats := store.Stats()

	if stats.TxCount != 0 {
		t.Errorf("Expected 0 transactions, got %d", stats.TxCount)
	}

	err = store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("test"))
		if err != nil {
			return err
		}
		if err := bucket.Put([]byte("key1"), []byte("value1")); err != nil {
			return err
		}
		if err := bucket.Put([]byte("key2"), []byte("value2")); err != nil {
			return err
		}
		child, err := bucket.CreateBucketIfNotExists([]byte("child"))
		if err != nil {
			return err
		}
		return child.Put([]byte("nested"), []byte("value3"))
	})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	tx, err := store.Begin(false)
	if err != nil {
		t.Fatalf("Begin failed: %v", err)
	}
	stats = store.Stats()
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	if stats.TxCount != 2 {
		t.Errorf("Expected 2 transactions, got %d", stats.TxCount)
	}
	if stats.OpenTxCount != 1 {
		t.Errorf("Expected 1 open transaction, got %d", stats.OpenTxCount)
	}
	if stats.BucketCount != 2 {
		t.Errorf("Expected 2 buckets, got %d", stats.BucketCount)
	}
	if stats.KeyCount != 3 {
		t.Errorf("Expected 3 keys, got %d", stats.KeyCount)
	}
}

func TestKVStoreStatsConcurrentReadOnlyTransactions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	err = store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("test"))
		if err != nil {
			return err
		}
		return bucket.Put([]byte("key"), []byte("value"))
	})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	const goroutines = 8
	const iterations = 100
	start := make(chan struct{})
	errCh := make(chan error, goroutines)
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < iterations; j++ {
				tx, err := store.Begin(false)
				if err != nil {
					errCh <- err
					return
				}
				_ = store.Stats()
				if err := tx.Rollback(); err != nil {
					errCh <- err
					return
				}
			}
		}()
	}

	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent stats transaction failed: %v", err)
		}
	}
}

func TestKVStoreReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	// Create and write
	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}

	err = store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("test"))
		if err != nil {
			return err
		}
		return bucket.Put([]byte("persistent"), []byte("data"))
	})

	if err != nil {
		store.Close()
		t.Fatalf("Update failed: %v", err)
	}

	store.Close()

	// Reopen and read
	store2, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer store2.Close()

	var value []byte
	err = store2.View(func(tx *Tx) error {
		bucket := tx.Bucket([]byte("test"))
		if bucket == nil {
			t.Fatal("Bucket not found after reopen")
		}
		value = bucket.Get([]byte("persistent"))
		return nil
	})

	if err != nil {
		t.Fatalf("View failed: %v", err)
	}

	if string(value) != "data" {
		t.Errorf("Expected 'data', got '%s'", value)
	}
}

func TestKVStoreCloseTwice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}

	// Close once
	if err := store.Close(); err != nil {
		t.Fatalf("First close failed: %v", err)
	}

	// Close again (should be safe)
	if err := store.Close(); err != nil {
		t.Fatalf("Second close failed: %v", err)
	}
}

func TestKVStoreCloseFailureLeavesStoreOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}

	if err := store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("test"))
		if err != nil {
			return err
		}
		return bucket.Put([]byte("key"), []byte("value"))
	}); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	if err := os.RemoveAll(path); err != nil {
		t.Fatalf("RemoveAll failed: %v", err)
	}
	if err := store.Close(); err == nil {
		t.Fatal("Close should fail when the backing directory is missing")
	}
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	err = store.View(func(tx *Tx) error {
		bucket := tx.Bucket([]byte("test"))
		if bucket == nil {
			t.Fatal("expected bucket after failed Close")
		}
		got := bucket.Get([]byte("key"))
		if string(got) != "value" {
			t.Fatalf("value after failed Close = %q, want value", got)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("View after failed Close returned error: %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close after recreating backing directory failed: %v", err)
	}
}

func TestKVStoreTxNotWritable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	// Try to write in read-only transaction
	err = store.View(func(tx *Tx) error {
		_, err := tx.CreateBucket([]byte("test"))
		return err
	})

	if err != ErrTxNotWritable {
		t.Errorf("Expected ErrTxNotWritable, got %v", err)
	}
}

// ========== Additional comprehensive tests ==========

func TestKVStoreBeginOnClosedDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}

	store.Close()

	// Try to begin transaction on closed database
	_, err = store.Begin(true)
	if err != ErrDatabaseClosed {
		t.Errorf("Expected ErrDatabaseClosed, got %v", err)
	}
}

func TestKVStoreConcurrentWriteTransaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	// F060: Begin(true) holds the exclusive lock for the lifetime of the
	// transaction. A concurrent Begin(true) from another goroutine MUST
	// block until the first transaction completes, not race past it. We
	// verify the blocking semantics by attempting a second Begin in a
	// separate goroutine and asserting it only succeeds after the first
	// transaction has been rolled back.
	tx1, err := store.Begin(true)
	if err != nil {
		t.Fatalf("Begin failed: %v", err)
	}

	type res struct {
		tx  *Tx
		err error
	}
	done := make(chan res, 1)
	go func() {
		tx2, err := store.Begin(true)
		done <- res{tx2, err}
	}()

	// The second writer must NOT succeed while tx1 is still open.
	select {
	case r := <-done:
		t.Errorf("second Begin(true) should have blocked on tx1; got tx=%v err=%v", r.tx, r.err)
	case <-time.After(100 * time.Millisecond):
		// expected: still blocked.
	}

	// Releasing tx1 must let the second writer proceed.
	if err := tx1.Rollback(); err != nil {
		t.Fatalf("Rollback tx1: %v", err)
	}
	select {
	case r := <-done:
		if r.err != nil {
			t.Errorf("second Begin(true) failed after tx1 rollback: %v", r.err)
		} else {
			_ = r.tx.Rollback()
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second Begin(true) did not unblock after tx1 rollback")
	}
}

func TestKVStoreCommitReadOnlyTransaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	tx, err := store.Begin(false)
	if err != nil {
		t.Fatalf("Begin failed: %v", err)
	}

	// Commit a read-only transaction — should succeed and clean up properly
	err = tx.Commit()
	if err != nil {
		t.Errorf("Commit of read-only tx should succeed, got %v", err)
	}
}

func TestKVStoreCommitClosedTransaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	tx, err := store.Begin(true)
	if err != nil {
		t.Fatalf("Begin failed: %v", err)
	}

	tx.Rollback()

	// Try to commit a closed transaction
	err = tx.Commit()
	if err != ErrTxClosed {
		t.Errorf("Expected ErrTxClosed, got %v", err)
	}
}

func TestKVStoreRollbackClosedTransaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	tx, err := store.Begin(true)
	if err != nil {
		t.Fatalf("Begin failed: %v", err)
	}

	tx.Rollback()

	// Try to rollback a closed transaction
	err = tx.Rollback()
	if err != ErrTxClosed {
		t.Errorf("Expected ErrTxClosed, got %v", err)
	}
}

func TestKVStoreValueTooLarge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	largeValue := make([]byte, KVMaxValueSize+1)

	err = store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("test"))
		if err != nil {
			return err
		}
		return bucket.Put([]byte("key"), largeValue)
	})

	if err != ErrKVValueTooLarge {
		t.Errorf("Expected ErrKVValueTooLarge, got %v", err)
	}
}

func TestKVStoreEmptyKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	err = store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("test"))
		if err != nil {
			return err
		}
		return bucket.Put([]byte{}, []byte("value"))
	})

	if err == nil {
		t.Error("Expected error for empty key")
	}
}

func TestKVStoreDeleteNonExistentKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	err = store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("test"))
		if err != nil {
			return err
		}
		return bucket.Delete([]byte("nonexistent"))
	})

	if err != ErrKVKeyNotFound {
		t.Errorf("Expected ErrKVKeyNotFound, got %v", err)
	}
}

func TestKVStoreDeleteBucket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	// Create bucket
	err = store.Update(func(tx *Tx) error {
		_, err := tx.CreateBucket([]byte("todelete"))
		return err
	})
	if err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	// Delete bucket
	err = store.Update(func(tx *Tx) error {
		return tx.DeleteBucket([]byte("todelete"))
	})
	if err != nil {
		t.Fatalf("DeleteBucket failed: %v", err)
	}

	// Verify bucket is gone
	_ = store.View(func(tx *Tx) error {
		bucket := tx.Bucket([]byte("todelete"))
		if bucket != nil {
			t.Error("Expected bucket to be deleted")
		}
		return nil
	})
}

func TestKVStoreDeleteNonExistentBucket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	err = store.Update(func(tx *Tx) error {
		return tx.DeleteBucket([]byte("nonexistent"))
	})

	if err != ErrBucketNotFound {
		t.Errorf("Expected ErrBucketNotFound, got %v", err)
	}
}

func TestKVStoreDeleteBucketReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	err = store.View(func(tx *Tx) error {
		return tx.DeleteBucket([]byte("test"))
	})

	if err != ErrTxNotWritable {
		t.Errorf("Expected ErrTxNotWritable, got %v", err)
	}
}

func TestKVStoreNestedBucketOperations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	// Create parent and child bucket
	err = store.Update(func(tx *Tx) error {
		parent, err := tx.CreateBucket([]byte("parent"))
		if err != nil {
			return err
		}

		_, err = parent.CreateBucket([]byte("child"))
		return err
	})
	if err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	// Try to create existing nested bucket
	err = store.Update(func(tx *Tx) error {
		parent := tx.Bucket([]byte("parent"))
		if parent == nil {
			t.Fatal("Parent bucket not found")
		}
		_, err := parent.CreateBucket([]byte("child"))
		return err
	})
	if err != ErrBucketExists {
		t.Errorf("Expected ErrBucketExists, got %v", err)
	}

	// Delete nested bucket
	err = store.Update(func(tx *Tx) error {
		parent := tx.Bucket([]byte("parent"))
		if parent == nil {
			t.Fatal("Parent bucket not found")
		}
		return parent.DeleteBucket([]byte("child"))
	})
	if err != nil {
		t.Fatalf("DeleteBucket failed: %v", err)
	}

	// Verify nested bucket is gone
	_ = store.View(func(tx *Tx) error {
		parent := tx.Bucket([]byte("parent"))
		if parent == nil {
			t.Fatal("Parent bucket not found")
		}
		child := parent.Bucket([]byte("child"))
		if child != nil {
			t.Error("Expected child bucket to be deleted")
		}
		return nil
	})
}

func TestKVStoreDeleteNestedBucketNotFound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	// Create parent bucket
	err = store.Update(func(tx *Tx) error {
		_, err := tx.CreateBucket([]byte("parent"))
		return err
	})
	if err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	// Try to delete non-existent nested bucket
	err = store.Update(func(tx *Tx) error {
		parent := tx.Bucket([]byte("parent"))
		if parent == nil {
			t.Fatal("Parent bucket not found")
		}
		return parent.DeleteBucket([]byte("nonexistent"))
	})

	if err != ErrBucketNotFound {
		t.Errorf("Expected ErrBucketNotFound, got %v", err)
	}
}

func TestKVStoreNestedBucketReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	// Create parent bucket first
	err = store.Update(func(tx *Tx) error {
		_, err := tx.CreateBucket([]byte("parent"))
		return err
	})
	if err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	// Try to create nested bucket in read-only transaction
	err = store.View(func(tx *Tx) error {
		parent := tx.Bucket([]byte("parent"))
		if parent == nil {
			t.Fatal("Parent bucket not found")
		}
		_, err := parent.CreateBucket([]byte("child"))
		return err
	})

	if err != ErrTxNotWritable {
		t.Errorf("Expected ErrTxNotWritable, got %v", err)
	}
}

func TestKVStoreBucketPutReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	// Create bucket first
	err = store.Update(func(tx *Tx) error {
		_, err := tx.CreateBucket([]byte("test"))
		return err
	})
	if err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	// Try to put in read-only transaction
	err = store.View(func(tx *Tx) error {
		bucket := tx.Bucket([]byte("test"))
		if bucket == nil {
			t.Fatal("Bucket not found")
		}
		return bucket.Put([]byte("key"), []byte("value"))
	})

	if err != ErrTxNotWritable {
		t.Errorf("Expected ErrTxNotWritable, got %v", err)
	}
}

func TestKVStoreBucketDeleteReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	// Create bucket with data first
	err = store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucket([]byte("test"))
		if err != nil {
			return err
		}
		return bucket.Put([]byte("key"), []byte("value"))
	})
	if err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	// Try to delete in read-only transaction
	err = store.View(func(tx *Tx) error {
		bucket := tx.Bucket([]byte("test"))
		if bucket == nil {
			t.Fatal("Bucket not found")
		}
		return bucket.Delete([]byte("key"))
	})

	if err != ErrTxNotWritable {
		t.Errorf("Expected ErrTxNotWritable, got %v", err)
	}
}

func TestKVStoreCursorOperations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	// Add some data
	err = store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("test"))
		if err != nil {
			return err
		}
		bucket.Put([]byte("apple"), []byte("fruit1"))
		bucket.Put([]byte("banana"), []byte("fruit2"))
		bucket.Put([]byte("cherry"), []byte("fruit3"))
		bucket.Put([]byte("date"), []byte("fruit4"))
		return nil
	})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Test cursor operations
	_ = store.View(func(tx *Tx) error {
		bucket := tx.Bucket([]byte("test"))
		if bucket == nil {
			t.Fatal("Bucket not found")
		}

		cursor := bucket.Cursor()

		// Test First
		k, v := cursor.First()
		if string(k) != "apple" {
			t.Errorf("Expected first key 'apple', got '%s'", k)
		}
		if string(v) != "fruit1" {
			t.Errorf("Expected first value 'fruit1', got '%s'", v)
		}

		// Test Next
		k, _ = cursor.Next()
		if string(k) != "banana" {
			t.Errorf("Expected next key 'banana', got '%s'", k)
		}

		// Test Last
		k, _ = cursor.Last()
		if string(k) != "date" {
			t.Errorf("Expected last key 'date', got '%s'", k)
		}

		// Test Prev
		k, _ = cursor.Prev()
		if string(k) != "cherry" {
			t.Errorf("Expected prev key 'cherry', got '%s'", k)
		}

		// Test Seek
		k, _ = cursor.Seek([]byte("ch"))
		if string(k) != "cherry" {
			t.Errorf("Expected seek to find 'cherry', got '%s'", k)
		}

		return nil
	})
}

func TestKVStoreCursorEmptyBucket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	// Create empty bucket
	err = store.Update(func(tx *Tx) error {
		_, err := tx.CreateBucket([]byte("empty"))
		return err
	})
	if err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	// Test cursor on empty bucket
	_ = store.View(func(tx *Tx) error {
		bucket := tx.Bucket([]byte("empty"))
		if bucket == nil {
			t.Fatal("Bucket not found")
		}

		cursor := bucket.Cursor()

		k, v := cursor.First()
		if k != nil || v != nil {
			t.Errorf("Expected nil for empty bucket, got k=%v, v=%v", k, v)
		}

		k, v = cursor.Last()
		if k != nil || v != nil {
			t.Errorf("Expected nil for empty bucket, got k=%v, v=%v", k, v)
		}

		k, v = cursor.Next()
		if k != nil || v != nil {
			t.Errorf("Expected nil for empty bucket, got k=%v, v=%v", k, v)
		}

		k, v = cursor.Prev()
		if k != nil || v != nil {
			t.Errorf("Expected nil for empty bucket, got k=%v, v=%v", k, v)
		}

		return nil
	})
}

func TestKVStoreCursorBoundaryConditions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	// Add single entry
	err = store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("test"))
		if err != nil {
			return err
		}
		return bucket.Put([]byte("only"), []byte("one"))
	})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Test cursor boundary conditions
	_ = store.View(func(tx *Tx) error {
		bucket := tx.Bucket([]byte("test"))
		if bucket == nil {
			t.Fatal("Bucket not found")
		}

		cursor := bucket.Cursor()

		// At first, Prev should return nil
		cursor.First()
		k, v := cursor.Prev()
		if k != nil || v != nil {
			t.Errorf("Expected nil at beginning, got k=%v, v=%v", k, v)
		}

		// At last, Next should return nil
		cursor.Last()
		k, v = cursor.Next()
		if k != nil || v != nil {
			t.Errorf("Expected nil at end, got k=%v, v=%v", k, v)
		}

		// Seek beyond all keys
		k, v = cursor.Seek([]byte("zzz"))
		if k != nil || v != nil {
			t.Errorf("Expected nil when seeking beyond all keys, got k=%v, v=%v", k, v)
		}

		return nil
	})
}

func TestKVStoreForEach(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	// Add some data
	err = store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("test"))
		if err != nil {
			return err
		}
		bucket.Put([]byte("a"), []byte("1"))
		bucket.Put([]byte("b"), []byte("2"))
		bucket.Put([]byte("c"), []byte("3"))
		return nil
	})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Test ForEach
	var keys, values []string
	err = store.View(func(tx *Tx) error {
		bucket := tx.Bucket([]byte("test"))
		if bucket == nil {
			t.Fatal("Bucket not found")
		}

		return bucket.ForEach(func(k, v []byte) error {
			keys = append(keys, string(k))
			values = append(values, string(v))
			return nil
		})
	})
	if err != nil {
		t.Fatalf("ForEach failed: %v", err)
	}

	if len(keys) != 3 {
		t.Errorf("Expected 3 keys, got %d", len(keys))
	}
	if len(values) != 3 {
		t.Errorf("Expected 3 values, got %d", len(values))
	}
}

func TestKVStoreForEachError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	// Add some data
	err = store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("test"))
		if err != nil {
			return err
		}
		bucket.Put([]byte("a"), []byte("1"))
		bucket.Put([]byte("b"), []byte("2"))
		return nil
	})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Test ForEach with error
	testErr := errors.New("test error")
	err = store.View(func(tx *Tx) error {
		bucket := tx.Bucket([]byte("test"))
		if bucket == nil {
			t.Fatal("Bucket not found")
		}

		return bucket.ForEach(func(k, v []byte) error {
			if string(k) == "b" {
				return testErr
			}
			return nil
		})
	})

	if err != testErr {
		t.Errorf("Expected testErr, got %v", err)
	}
}

func TestKVStoreBucketStats(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	// Add data
	err = store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("test"))
		if err != nil {
			return err
		}
		bucket.Put([]byte("key1"), []byte("val1"))
		bucket.Put([]byte("key2"), []byte("val2"))
		bucket.Put([]byte("key3"), []byte("val3"))
		return nil
	})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Check stats
	var stats BucketStats
	err = store.View(func(tx *Tx) error {
		bucket := tx.Bucket([]byte("test"))
		if bucket == nil {
			t.Fatal("Bucket not found")
		}
		stats = bucket.Stats()
		return nil
	})
	if err != nil {
		t.Fatalf("View failed: %v", err)
	}

	if stats.KeyCount != 3 {
		t.Errorf("Expected 3 keys, got %d", stats.KeyCount)
	}
}

func TestKVStoreUpdateWithError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	testErr := errors.New("intentional error")

	// Update with error should return the error
	err = store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("test"))
		if err != nil {
			return err
		}
		bucket.Put([]byte("key"), []byte("value"))
		return testErr
	})

	if err != testErr {
		t.Errorf("Expected testErr, got %v", err)
	}

	// Note: The KVStore implementation doesn't fully support rollback for in-memory changes
	// This test verifies that the error is properly returned
}

func TestKVStoreGetOnClosedTransaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	// Create bucket with data
	err = store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("test"))
		if err != nil {
			return err
		}
		return bucket.Put([]byte("key"), []byte("value"))
	})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Get on closed transaction should return nil
	tx, err := store.Begin(false)
	if err != nil {
		t.Fatalf("Begin failed: %v", err)
	}

	bucket := tx.Bucket([]byte("test"))
	tx.Rollback() // Close the transaction

	if bucket == nil {
		return // Bucket is nil, nothing to test
	}

	// Get on closed transaction should return nil
	val := bucket.Get([]byte("key"))
	if val != nil {
		t.Error("Expected nil when getting from closed transaction")
	}
}

func TestKVStoreMultipleOnCommit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	callCount := 0

	err = store.Update(func(tx *Tx) error {
		tx.OnCommit(func() {
			callCount++
		})
		tx.OnCommit(func() {
			callCount++
		})
		tx.OnCommit(func() {
			callCount++
		})

		_, err := tx.CreateBucketIfNotExists([]byte("test"))
		return err
	})

	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	if callCount != 3 {
		t.Errorf("Expected 3 OnCommit calls, got %d", callCount)
	}
}

func TestKVStoreMaxKeySize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	// Key at max size should work
	maxKey := make([]byte, KVMaxKeySize)
	for i := range maxKey {
		maxKey[i] = 'a'
	}

	err = store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("test"))
		if err != nil {
			return err
		}
		return bucket.Put(maxKey, []byte("value"))
	})

	if err != nil {
		t.Errorf("Max size key should work: %v", err)
	}
}

func TestKVStoreMaxValueSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	// Value at max size should work
	maxValue := make([]byte, KVMaxValueSize)
	for i := range maxValue {
		maxValue[i] = 'b'
	}

	err = store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("test"))
		if err != nil {
			return err
		}
		return bucket.Put([]byte("key"), maxValue)
	})

	if err != nil {
		t.Errorf("Max size value should work: %v", err)
	}
}

func TestKVStoreGetNonExistentKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	// Create bucket
	err = store.Update(func(tx *Tx) error {
		_, err := tx.CreateBucket([]byte("test"))
		return err
	})
	if err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	// Get non-existent key
	var value []byte
	err = store.View(func(tx *Tx) error {
		bucket := tx.Bucket([]byte("test"))
		if bucket == nil {
			t.Fatal("Bucket not found")
		}
		value = bucket.Get([]byte("nonexistent"))
		return nil
	})

	if err != nil {
		t.Fatalf("View failed: %v", err)
	}

	if value != nil {
		t.Errorf("Expected nil for non-existent key, got %v", value)
	}
}

func TestKVStoreOpenWithExistingData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	// Create and write data
	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}

	err = store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("test"))
		if err != nil {
			return err
		}
		return bucket.Put([]byte("key"), []byte("value"))
	})

	if err != nil {
		store.Close()
		t.Fatalf("Update failed: %v", err)
	}

	store.Close()

	// Open again and verify data
	store2, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer store2.Close()

	// Add more data
	err = store2.Update(func(tx *Tx) error {
		bucket := tx.Bucket([]byte("test"))
		if bucket == nil {
			t.Fatal("Bucket not found")
		}
		return bucket.Put([]byte("key2"), []byte("value2"))
	})

	if err != nil {
		t.Fatalf("Second update failed: %v", err)
	}

	// Verify both keys exist
	_ = store2.View(func(tx *Tx) error {
		bucket := tx.Bucket([]byte("test"))
		if bucket == nil {
			t.Fatal("Bucket not found")
		}

		v1 := bucket.Get([]byte("key"))
		v2 := bucket.Get([]byte("key2"))

		if string(v1) != "value" {
			t.Errorf("Expected 'value', got '%s'", v1)
		}
		if string(v2) != "value2" {
			t.Errorf("Expected 'value2', got '%s'", v2)
		}

		return nil
	})
}

func TestKVStoreRollbackDiscardsChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	// Write initial data
	err = store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("test"))
		if err != nil {
			return err
		}
		return bucket.Put([]byte("key"), []byte("original"))
	})
	if err != nil {
		t.Fatalf("Initial update failed: %v", err)
	}

	// Start transaction, modify, and rollback
	tx, err := store.Begin(true)
	if err != nil {
		t.Fatalf("Begin failed: %v", err)
	}

	bucket := tx.Bucket([]byte("test"))
	if bucket != nil {
		bucket.Put([]byte("key"), []byte("modified"))
	}

	tx.Rollback()

	// Verify original value
	var value []byte
	err = store.View(func(tx *Tx) error {
		bucket := tx.Bucket([]byte("test"))
		if bucket == nil {
			t.Fatal("Bucket not found")
		}
		value = bucket.Get([]byte("key"))
		return nil
	})

	if err != nil {
		t.Fatalf("View failed: %v", err)
	}

	if string(value) != "original" {
		t.Errorf("Expected 'original' after rollback, got '%s'", value)
	}
}

func TestKVStoreConcurrentGetSet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}
	defer store.Close()

	// Create initial bucket
	err = store.Update(func(tx *Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("test"))
		return err
	})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Run concurrent readers and writers
	const goroutines = 10
	const opsPerGoroutine = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 2) // readers + writers

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				_ = store.View(func(tx *Tx) error {
					bucket := tx.Bucket([]byte("test"))
					if bucket != nil {
						_ = bucket.Get([]byte("key"))
					}
					return nil
				})
			}
		}(i)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				_ = store.Update(func(tx *Tx) error {
					bucket := tx.Bucket([]byte("test"))
					if bucket != nil {
						return bucket.Put([]byte("key"), []byte(fmt.Sprintf("value-%d-%d", idx, j)))
					}
					return nil
				})
			}
		}(i)
	}

	wg.Wait()
}

// TestKVStoreSaveDataIntegrity verifies that save() does not delete the data file
// on successful rename (the bug that was fixed).
func TestKVStoreSaveDataIntegrity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	store, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("OpenKVStore failed: %v", err)
	}

	// Write data
	err = store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("test"))
		if err != nil {
			return err
		}
		return bucket.Put([]byte("key"), []byte("value"))
	})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	store.Close()

	// Reopen and verify data survives
	store2, err := OpenKVStore(path)
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer store2.Close()

	var result []byte
	err = store2.View(func(tx *Tx) error {
		bucket := tx.Bucket([]byte("test"))
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}
		result = bucket.Get([]byte("key"))
		return nil
	})
	if err != nil {
		t.Fatalf("View failed: %v", err)
	}
	if string(result) != "value" {
		t.Errorf("Data lost after save+reopen: got %q, want 'value'", result)
	}
}

func TestSyncDataDir(t *testing.T) {
	if err := syncDataDir(t.TempDir()); err != nil {
		t.Fatalf("syncDataDir on temp dir: %v", err)
	}
}

func TestSyncDataDirInvalidPath(t *testing.T) {
	err := syncDataDir(filepath.Join(t.TempDir(), "missing"))
	if err == nil {
		t.Fatal("expected error for missing data directory")
	}
	if !strings.Contains(err.Error(), "open data dir") {
		t.Fatalf("error = %v, want open data dir context", err)
	}
}

// TestTxCommit_RevertsOnSaveFailure regresses an ACID violation: when a writable
// Commit's save() failed, the mutated-but-unpersisted in-memory state was left
// visible to every future transaction (and lost on crash). A failed commit must
// be atomic — revert to the last durable state, mirroring Rollback.
func TestTxCommit_RevertsOnSaveFailure(t *testing.T) {
	dir := t.TempDir()
	// OpenKVStore takes a DIRECTORY; the data file lives inside it, so a chmod
	// on `dir` is what makes save()'s os.CreateTemp fail.
	store, err := OpenKVStore(dir)
	if err != nil {
		t.Fatalf("OpenKVStore: %v", err)
	}
	defer store.Close()

	// Baseline: persist key "a"=1.
	tx, err := store.Begin(true)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	b, err := tx.CreateBucketIfNotExists([]byte("bkt"))
	if err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	if err := b.Put([]byte("a"), []byte("1")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("baseline commit: %v", err)
	}

	// Make the data dir un-writable so save()'s os.CreateTemp fails.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer os.Chmod(dir, 0o700) // restore so t.TempDir cleanup can remove it

	// Mutate and commit — the save must fail.
	tx2, err := store.Begin(true)
	if err != nil {
		t.Fatalf("Begin 2: %v", err)
	}
	b2, err := tx2.CreateBucketIfNotExists([]byte("bkt"))
	if err != nil {
		t.Fatalf("CreateBucket 2: %v", err)
	}
	if err := b2.Put([]byte("b"), []byte("2")); err != nil {
		t.Fatalf("Put 2: %v", err)
	}
	if err := tx2.Commit(); err == nil {
		t.Fatal("expected commit to fail with a read-only data dir")
	}

	// Restore perms and verify the failed commit was reverted: "b" must be
	// absent (never persisted) and the durable "a" still present.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("restore chmod: %v", err)
	}
	rtx, err := store.Begin(false)
	if err != nil {
		t.Fatalf("Begin read: %v", err)
	}
	defer rtx.Rollback()
	rb := rtx.Bucket([]byte("bkt"))
	if rb == nil {
		t.Fatal("bucket vanished after failed commit")
	}
	if rb.Get([]byte("b")) != nil {
		t.Error("uncommitted key 'b' is visible after a failed commit (ACID violation)")
	}
	if got := rb.Get([]byte("a")); string(got) != "1" {
		t.Errorf("durable key 'a' = %q after failed commit, want \"1\"", got)
	}
}
