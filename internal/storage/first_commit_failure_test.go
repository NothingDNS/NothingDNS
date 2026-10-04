package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFirstCommitFailureDiscardsPendingData(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db")
	store, err := OpenKVStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for i := 0; i < 2; i++ {
		tx, err := store.Begin(true)
		if err != nil {
			t.Fatal(err)
		}
		b, err := tx.CreateBucket([]byte("failed"))
		if err != nil {
			t.Fatal(err)
		}
		if err = b.Put([]byte("key"), []byte("pending")); err != nil {
			t.Fatal(err)
		}
		// Removing the still-empty directory forces a pre-write failure without
		// depending on permissions or an existing durable database.
		if err = os.Remove(dir); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(); err == nil {
			t.Fatal("commit unexpectedly succeeded")
		}
		if err = os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err = store.View(func(tx *Tx) error {
			if tx.Bucket([]byte("failed")) != nil {
				t.Error("failed commit left pending bucket visible")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err = store.Update(func(tx *Tx) error { _, err := tx.CreateBucket([]byte("committed")); return err }); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenKVStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err = reopened.View(func(tx *Tx) error {
		if tx.Bucket([]byte("failed")) != nil {
			t.Error("failed write persisted after retry")
		}
		if tx.Bucket([]byte("committed")) == nil {
			t.Error("successful retry not persisted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
