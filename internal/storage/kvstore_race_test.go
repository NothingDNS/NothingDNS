package storage

import (
	"path/filepath"
	"sync"
	"testing"
)

// TestKVStoreConcurrentReadWriteRace exercises concurrent Read and Write transactions
// against the KVStore under a race detector. No races should be reported.
func TestKVStoreConcurrentReadWriteRace(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	s, err := OpenKVStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	goroutines := 8
	iterations := 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Writers: concurrent Update transactions
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				s.Update(func(tx *Tx) error {
					b, err := tx.CreateBucketIfNotExists([]byte("data"))
					if err != nil {
						return err
					}
					key := []byte(string(rune('a'+id)) + string(rune('0'+i%10)))
					return b.Put(key, []byte("value"))
				})
			}
		}(g)
	}

	// Readers: concurrent View transactions
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				s.View(func(tx *Tx) error {
					b := tx.Bucket([]byte("data"))
					if b != nil {
						_ = b.Get([]byte("key"))
					}
					return nil
				})
			}
		}()
	}

	wg.Wait()
}

// TestKVStoreConcurrentBeginRace exercises concurrent Begin(write=true) calls while
// View transactions are in flight. No races should be reported.
func TestKVStoreConcurrentBeginRace(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	s, err := OpenKVStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	goroutines := 4
	iterations := 30
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Writers: Begin(write=true)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				tx, err := s.Begin(true)
				if err == nil {
					tx.Rollback()
				}
			}
		}()
	}

	// Readers: View
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				s.View(func(tx *Tx) error {
					tx.Bucket([]byte("data"))
					return nil
				})
			}
		}()
	}

	wg.Wait()
}

// TestKVStoreConcurrentStatsRace exercises concurrent Stats() calls while writers
// are modifying the store. No races should be reported.
func TestKVStoreConcurrentStatsRace(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	s, err := OpenKVStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	goroutines := 4
	iterations := 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Writers
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				s.Update(func(tx *Tx) error {
					b, _ := tx.CreateBucketIfNotExists([]byte("data"))
					if b != nil {
						b.Put([]byte("key"), []byte("val"))
					}
					return nil
				})
			}
		}()
	}

	// Stats
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				s.Stats()
				_ = s.Path()
			}
		}()
	}

	wg.Wait()
}
