package storage

import (
	"path/filepath"
	"testing"
)

// Bucket.Get already treats a transaction-derived handle as invalid after
// Commit or Rollback. A cursor is the same kind of handle and must not expose
// data committed by a later transaction through its stale bucket pointer.
func TestKVCursorStopsAtTransactionBoundary_F900(t *testing.T) {
	store, err := OpenKVStore(filepath.Join(t.TempDir(), "cursor.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if err := store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucket([]byte("items"))
		if err != nil {
			return err
		}
		return bucket.Put([]byte("key"), []byte("before"))
	}); err != nil {
		t.Fatal(err)
	}

	tx, err := store.Begin(false)
	if err != nil {
		t.Fatal(err)
	}
	cursor := tx.Bucket([]byte("items")).Cursor()
	if key, value := cursor.First(); string(key) != "key" || string(value) != "before" {
		t.Fatalf("CONTROL FAILED: cursor returned %q=%q", key, value)
	}
	t.Log("CONTROL OK: cursor reads data while its transaction is open")
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}

	if err := store.Update(func(tx *Tx) error {
		return tx.Bucket([]byte("items")).Put([]byte("key"), []byte("after"))
	}); err != nil {
		t.Fatal(err)
	}

	key, value := cursor.First()
	if key != nil || value != nil {
		t.Log("EXPECTED: a cursor from a closed transaction returns no data")
		t.Logf("ACTUAL: stale cursor returned %q=%q from a later transaction", key, value)
		t.Fatal("PROBLEM CONFIRMED: transaction-derived cursor remained live after rollback")
	}
	t.Log("PROBLEM NOT REPRODUCED: closed transaction invalidated its cursor")
}

func TestKVBucketCannotCreateCursorAfterTransactionCloses_F900(t *testing.T) {
	store, err := OpenKVStore(filepath.Join(t.TempDir(), "cursor-after-close.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Update(func(tx *Tx) error {
		bucket, err := tx.CreateBucket([]byte("items"))
		if err != nil {
			return err
		}
		return bucket.Put([]byte("key"), []byte("value"))
	}); err != nil {
		t.Fatal(err)
	}

	tx, err := store.Begin(false)
	if err != nil {
		t.Fatal(err)
	}
	bucket := tx.Bucket([]byte("items"))
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if key, value := bucket.Cursor().First(); key != nil || value != nil {
		t.Fatalf("FIX NOT VERIFIED: cursor created after commit returned %q=%q", key, value)
	}
	t.Log("FIX VERIFIED: a closed transaction cannot create a live cursor")
}
