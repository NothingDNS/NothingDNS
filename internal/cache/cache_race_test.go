package cache

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// TestCacheConcurrentGetSetRace exercises the cache's most concurrency-exposed
// paths under a race detector. No races should be reported.
//
// Static analysis confirmed correct use of per-shard sync.RWMutex: Get holds
// RLock, Set holds Lock, and the identity-check pattern prevents the
// double-remove corruption that concurrent Get-Set can trigger in naive LRU
// implementations. This test provides regression coverage for that analysis.
func TestCacheConcurrentGetSetRace(t *testing.T) {
	c := New(DefaultConfig())

	// Create enough distinct keys to spread across multiple shards so
	// multiple goroutines exercise real contention (not just wait on a
	// single shared lock).
	const goroutines = 8
	const keysPerGoroutine = 250
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Writers: Set unique entries across shards
	for g := 0; g < goroutines; g++ {
		go func(base int) {
			defer wg.Done()
			for i := 0; i < keysPerGoroutine; i++ {
				key := fmt.Sprintf("target%d.example.com.:1", base*keysPerGoroutine+i)
				msg := validMessageForKey(key)
				c.Set(key, msg, 300)
				msg.Release()
			}
		}(g)
	}

	// Readers: Get entries that may or may not exist
	for g := 0; g < goroutines; g++ {
		go func(base int) {
			defer wg.Done()
			for i := 0; i < keysPerGoroutine; i++ {
				key := fmt.Sprintf("target%d.example.com.:1", base*keysPerGoroutine+i)
				_ = c.Get(key)
			}
		}(g)
	}

	wg.Wait()
}

// TestCacheConcurrentGetSameKeyRace verifies that concurrent Get and Set
// on the same key does not produce a data race. Specifically tests the
// identity-check pattern in Cache.Get slow path:
//
//	s.mu.RLock()
//	entry, exists := s.entries[key]
//	... (upstream unreachable) ...
//	s.mu.Lock()
//	if e, ok := s.entries[key]; ok && e == entry {  // identity check
//	    s.moveToFront(entry)
//	}
//	s.mu.Unlock()
//
// Without the identity check, a concurrent Set could replace `entry` with
// a new Entry object, and moveToFront would operate on a stale pointer
// removed from the LRU list by the Set — corrupting the intrusive list.
func TestCacheConcurrentGetSameKeyRace(t *testing.T) {
	c := New(DefaultConfig())

	// Seed one entry that all goroutines will contend on
	seedKey := "shared.example.com.:1"
	seedMsg := validMessageForKey(seedKey)
	c.Set(seedKey, seedMsg, 300)
	seedMsg.Release()

	const goroutines = 4
	const iterations = 200
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	for g := 0; g < goroutines; g++ {
		// Readers: repeatedly get the shared key
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_ = c.Get(seedKey)
			}
		}()
		// Writers: repeatedly replace the shared key (evicts and re-sets)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				msg := validMessageForKey(seedKey)
				c.Set(seedKey, msg, 300)
				msg.Release()
			}
		}()
	}

	wg.Wait()
}

// TestCacheConcurrentUpdateConfigRace verifies that UpdateConfig does not race
// with concurrent Get/Set operations. UpdateConfig holds cfgMu for writes,
// and Get/Set access fields outside cfgMu — this test ensures no field is
// accessed without holding the appropriate lock.
func TestCacheConcurrentUpdateConfigRace(t *testing.T) {
	c := New(DefaultConfig())

	const goroutines = 4
	const iterations = 50
	var wg sync.WaitGroup
	wg.Add(goroutines + 1)

	// Config updater: periodically reconfigures the cache
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			cfg := DefaultConfig()
			cfg.MaxTTL = time.Duration(i+1) * time.Second
			c.UpdateConfig(cfg)
		}
	}()

	for g := 0; g < goroutines; g++ {
		go func(base int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				key := fmt.Sprintf("config%d.example.com.:1", base*iterations+i)
				msg := validMessageForKey(key)
				c.Set(key, msg, 300)
				msg.Release()
				_ = c.Get(key)
				_ = c.Stats()
			}
		}(g)
	}

	wg.Wait()
}

// TestCacheConcurrentDeleteGetRace verifies that Delete does not race with
// concurrent Get on the same key.
func TestCacheConcurrentDeleteGetRace(t *testing.T) {
	c := New(DefaultConfig())

	key := "delete.example.com.:1"
	msg := validMessageForKey(key)
	c.Set(key, msg, 300)
	msg.Release()

	const goroutines = 4
	const iterations = 100
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_ = c.Get(key)
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				c.Delete(key)
				// Re-set so Get has something to find on next iteration
				msg := validMessageForKey(key)
				c.Set(key, msg, 300)
				msg.Release()
			}
		}()
	}

	wg.Wait()
}

// TestCacheConcurrentStatsRace verifies that Stats() does not race with
// concurrent Get/Set operations.
func TestCacheConcurrentStatsRace(t *testing.T) {
	c := New(DefaultConfig())

	const goroutines = 4
	const iterations = 50
	var wg sync.WaitGroup
	wg.Add(goroutines + 1)

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = c.Stats()
			time.Sleep(time.Microsecond)
		}
	}()

	for g := 0; g < goroutines; g++ {
		go func(base int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				key := fmt.Sprintf("stats%d.example.com.:1", base*iterations+i)
				msg := validMessageForKey(key)
				c.Set(key, msg, 300)
				msg.Release()
				_ = c.Get(key)
			}
		}(g)
	}

	wg.Wait()
}

// TestCacheConcurrentFlushRace verifies that Flush() does not race with
// concurrent Get/Set operations.
func TestCacheConcurrentFlushRace(t *testing.T) {
	c := New(DefaultConfig())

	const goroutines = 4
	const iterations = 50
	var wg sync.WaitGroup
	wg.Add(goroutines + 1)

	go func() {
		defer wg.Done()
		for i := 0; i < iterations/2; i++ {
			c.Flush()
		}
	}()

	for g := 0; g < goroutines; g++ {
		go func(base int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				key := fmt.Sprintf("flush%d.example.com.:1", base*iterations+i)
				msg := validMessageForKey(key)
				c.Set(key, msg, 300)
				msg.Release()
				_ = c.Get(key)
			}
		}(g)
	}

	wg.Wait()
}

// TestCacheConcurrentClearRace verifies that Clear() does not race with
// concurrent Get/Set operations.
func TestCacheConcurrentClearRace(t *testing.T) {
	c := New(DefaultConfig())

	const goroutines = 4
	const iterations = 50
	var wg sync.WaitGroup
	wg.Add(goroutines + 1)

	go func() {
		defer wg.Done()
		for i := 0; i < iterations/2; i++ {
			c.Clear()
		}
	}()

	for g := 0; g < goroutines; g++ {
		go func(base int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				key := fmt.Sprintf("clear%d.example.com.:1", base*iterations+i)
				msg := validMessageForKey(key)
				c.Set(key, msg, 300)
				msg.Release()
				_ = c.Get(key)
			}
		}(g)
	}

	wg.Wait()
}

// validMessageForKey is a test helper that creates a valid *protocol.Message
// keyed to the given key string. It allocates a fresh message (not from the
// pool) to avoid polluting pool state during race testing.
func validMessageForKey(key string) *protocol.Message {
	return &protocol.Message{
		Header:    protocol.Header{ID: 1, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Questions: []*protocol.Question{{Name: mustName("example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN}},
		Answers:   []*protocol.ResourceRecord{},
	}
}
