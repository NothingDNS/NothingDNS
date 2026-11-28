package storage

import (
	"errors"
	"path/filepath"
	"testing"
)

// Transaction-derived read handles must stop observing the store once the
// transaction releases its lock. Bucket.Get and Cursor already enforce this
// lifetime; bucket lookup and Stats must enforce the same boundary.
func TestClosedTransactionCannotObserveLaterBucketState_F904(t *testing.T) {
	store, err := OpenKVStore(filepath.Join(t.TempDir(), "closed-reads.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if err := store.Update(func(tx *Tx) error {
		items, err := tx.CreateBucket([]byte("items"))
		if err != nil {
			return err
		}
		if _, err := items.CreateBucket([]byte("existing")); err != nil {
			return err
		}
		return items.Put([]byte("before"), []byte("1"))
	}); err != nil {
		t.Fatal(err)
	}

	tx, err := store.Begin(false)
	if err != nil {
		t.Fatal(err)
	}
	items := tx.Bucket([]byte("items"))
	if items == nil || items.Bucket([]byte("existing")) == nil || items.Stats().KeyCount != 1 {
		t.Fatal("CONTROL FAILED: open transaction could not read its bucket state")
	}
	t.Log("CONTROL OK: bucket lookup and Stats work while the transaction is open")
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}

	if err := store.Update(func(next *Tx) error {
		if _, err := next.CreateBucket([]byte("later-top")); err != nil {
			return err
		}
		liveItems := next.Bucket([]byte("items"))
		if _, err := liveItems.CreateBucket([]byte("later-child")); err != nil {
			return err
		}
		return liveItems.Put([]byte("after"), []byte("2"))
	}); err != nil {
		t.Fatal(err)
	}

	lateTop := tx.Bucket([]byte("later-top"))
	lateChild := items.Bucket([]byte("later-child"))
	stats := items.Stats()
	if lateTop != nil || lateChild != nil || stats.KeyCount != 0 {
		t.Log("EXPECTED: closed transaction returns nil buckets and zero Stats")
		t.Logf("ACTUAL: lateTop=%v lateChild=%v KeyCount=%d", lateTop != nil, lateChild != nil, stats.KeyCount)
		t.Fatal("PROBLEM CONFIRMED: closed transaction observed state committed later")
	}
	t.Log("PROBLEM NOT REPRODUCED: closed transaction reads were invalidated")
}

func TestClosedTransactionReadBoundaries_F904(t *testing.T) {
	store, err := OpenKVStore(filepath.Join(t.TempDir(), "closed-read-boundaries.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if err := store.Update(func(tx *Tx) error {
		parent, err := tx.CreateBucket([]byte("parent"))
		if err != nil {
			return err
		}
		if _, err := parent.CreateBucket([]byte("child")); err != nil {
			return err
		}
		return parent.Put([]byte("key"), []byte("value"))
	}); err != nil {
		t.Fatal(err)
	}

	tx, err := store.Begin(false)
	if err != nil {
		t.Fatal(err)
	}
	parent := tx.Bucket([]byte("parent"))
	if parent == nil || parent.Bucket([]byte("child")) == nil || parent.Stats().KeyCount != 1 {
		t.Fatal("open transaction lost readable bucket state")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	if got := tx.Bucket([]byte("parent")); got != nil {
		t.Fatal("committed transaction still returned a top-level bucket")
	}
	if got := parent.Bucket([]byte("child")); got != nil {
		t.Fatal("bucket handle from committed transaction still returned a child")
	}
	if got := parent.Stats(); got != (BucketStats{}) {
		t.Fatalf("bucket handle from committed transaction returned stats: %+v", got)
	}

	var liveCount int64
	if err := store.View(func(live *Tx) error {
		liveParent := live.Bucket([]byte("parent"))
		if liveParent == nil || liveParent.Bucket([]byte("child")) == nil {
			return errors.New("open transaction could not read nested buckets")
		}
		liveCount = liveParent.Stats().KeyCount
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if liveCount != 1 {
		t.Fatalf("open transaction Stats count = %d, want 1", liveCount)
	}
}
