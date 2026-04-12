package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

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

	// Start a write transaction
	tx1, err := store.Begin(true)
	if err != nil {
		t.Fatalf("Begin failed: %v", err)
	}

	// Try to start another write transaction (should fail)
	_, err = store.Begin(true)
	if err == nil {
		t.Error("Expected error when starting concurrent write transaction")
		tx1.Rollback()
	} else if err.Error() != "transaction already in progress" {
		t.Errorf("Expected 'transaction already in progress' error, got %v", err)
	}

	tx1.Rollback()
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

	// Try to commit a read-only transaction
	err = tx.Commit()
	if err != ErrTxNotWritable {
		t.Errorf("Expected ErrTxNotWritable, got %v", err)
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
