package storage

import (
	"os"
	"path/filepath"
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
