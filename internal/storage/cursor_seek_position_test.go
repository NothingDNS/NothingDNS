package storage

import "testing"

func TestCursorSeekPastEndUpdatesPosition(t *testing.T) {
	store, err := OpenKVStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err = store.Update(func(tx *Tx) error {
		b, err := tx.CreateBucket([]byte("data"))
		if err != nil {
			return err
		}
		for _, key := range []string{"a", "b", "c"} {
			if err = b.Put([]byte(key), []byte(key)); err != nil {
				return err
			}
		}
		_, err = tx.CreateBucket([]byte("empty"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err = store.View(func(tx *Tx) error {
		c := tx.Bucket([]byte("data")).Cursor()
		c.First()
		if k, _ := c.Seek([]byte("z")); k != nil {
			t.Fatalf("seek past end=%q", k)
		}
		for i := 0; i < 3; i++ {
			if k, _ := c.Next(); k != nil {
				t.Fatalf("next after seek miss=%q", k)
			}
		}
		if k, _ := c.Prev(); string(k) != "c" {
			t.Fatalf("prev from end=%q, want c", k)
		}
		if k, _ := c.Seek(nil); string(k) != "a" {
			t.Fatalf("seek empty=%q, want a", k)
		}
		if k, _ := c.Next(); string(k) != "b" {
			t.Fatalf("next after reset=%q, want b", k)
		}
		if k, _ := c.Seek([]byte("bb")); string(k) != "c" {
			t.Fatalf("seek between keys=%q, want c", k)
		}
		empty := tx.Bucket([]byte("empty")).Cursor()
		if k, _ := empty.Seek([]byte("z")); k != nil {
			t.Fatalf("empty seek=%q", k)
		}
		if k, _ := empty.Next(); k != nil {
			t.Fatalf("empty next=%q", k)
		}
		if k, _ := empty.Prev(); k != nil {
			t.Fatalf("empty prev=%q", k)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
