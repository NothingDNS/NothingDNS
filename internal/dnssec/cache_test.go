package dnssec

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestNewValidationCache(t *testing.T) {
	ttl := 5 * time.Minute
	cache := NewValidationCache(ttl)
	if cache == nil {
		t.Fatal("NewValidationCache returned nil")
	}
	if cache.ttl != ttl {
		t.Errorf("ttl = %v, want %v", cache.ttl, ttl)
	}
	if cache.items == nil {
		t.Error("items map is nil")
	}
	if len(cache.items) != 0 {
		t.Errorf("items map not empty, has %d entries", len(cache.items))
	}
}

func TestCacheSetGetBasic(t *testing.T) {
	cache := NewValidationCache(5 * time.Minute)

	// Store a result.
	cache.Set("example.com", 1, ValidationSecure)

	// Retrieve it.
	result, ok := cache.Get("example.com", 1)
	if !ok {
		t.Fatal("Get returned ok=false for existing entry")
	}
	if result != ValidationSecure {
		t.Errorf("result = %v, want %v", result, ValidationSecure)
	}
}

func TestCacheGetNonExistent(t *testing.T) {
	cache := NewValidationCache(5 * time.Minute)

	result, ok := cache.Get("nonexistent.example.com", 1)
	if ok {
		t.Error("Get returned ok=true for non-existent key")
	}
	if result != ValidationIndeterminate {
		t.Errorf("result = %v, want %v", result, ValidationIndeterminate)
	}
}

func TestCacheSetOverwritesExisting(t *testing.T) {
	cache := NewValidationCache(5 * time.Minute)

	cache.Set("example.com", 1, ValidationSecure)
	cache.Set("example.com", 1, ValidationBogus)

	result, ok := cache.Get("example.com", 1)
	if !ok {
		t.Fatal("Get returned ok=false after overwrite")
	}
	if result != ValidationBogus {
		t.Errorf("result = %v, want %v", result, ValidationBogus)
	}
}

func TestCacheDifferentKeysAreIndependent(t *testing.T) {
	cache := NewValidationCache(5 * time.Minute)

	cache.Set("a.example.com", 1, ValidationSecure)
	cache.Set("b.example.com", 1, ValidationInsecure)

	resultA, okA := cache.Get("a.example.com", 1)
	resultB, okB := cache.Get("b.example.com", 1)

	if !okA || !okB {
		t.Fatal("one or both keys not found")
	}
	if resultA != ValidationSecure {
		t.Errorf("a.example.com result = %v, want %v", resultA, ValidationSecure)
	}
	if resultB != ValidationInsecure {
		t.Errorf("b.example.com result = %v, want %v", resultB, ValidationInsecure)
	}
}

func TestCacheSameNameDifferentTypeAreIndependent(t *testing.T) {
	cache := NewValidationCache(5 * time.Minute)

	cache.Set("example.com", 1, ValidationSecure) // Type A
	cache.Set("example.com", 28, ValidationBogus) // Type AAAA

	resultA, okA := cache.Get("example.com", 1)
	resultAAAA, okAAAA := cache.Get("example.com", 28)

	if !okA || !okAAAA {
		t.Fatal("one or both type entries not found")
	}
	if resultA != ValidationSecure {
		t.Errorf("type A result = %v, want %v", resultA, ValidationSecure)
	}
	if resultAAAA != ValidationBogus {
		t.Errorf("type AAAA result = %v, want %v", resultAAAA, ValidationBogus)
	}
}

func TestCacheExpiration(t *testing.T) {
	// Use a very short TTL so entries expire quickly.
	cache := NewValidationCache(50 * time.Millisecond)

	cache.Set("expire.example.com", 1, ValidationSecure)

	// Should be available immediately.
	result, ok := cache.Get("expire.example.com", 1)
	if !ok || result != ValidationSecure {
		t.Fatalf("immediate Get: ok=%v result=%v, want ok=true result=SECURE", ok, result)
	}

	// Wait for TTL to elapse.
	time.Sleep(80 * time.Millisecond)

	result, ok = cache.Get("expire.example.com", 1)
	if ok {
		t.Errorf("Get after expiration: ok=true, want false; result=%v", result)
	}
	if result != ValidationIndeterminate {
		t.Errorf("result after expiration = %v, want %v", result, ValidationIndeterminate)
	}
}

func TestCacheClear(t *testing.T) {
	cache := NewValidationCache(5 * time.Minute)

	cache.Set("a.example.com", 1, ValidationSecure)
	cache.Set("b.example.com", 1, ValidationInsecure)
	cache.Set("c.example.com", 1, ValidationBogus)

	total, _ := cache.Stats()
	if total != 3 {
		t.Fatalf("Stats total before clear = %d, want 3", total)
	}

	cache.Clear()

	total, _ = cache.Stats()
	if total != 0 {
		t.Errorf("Stats total after clear = %d, want 0", total)
	}

	// All entries should be gone.
	for _, name := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		if _, ok := cache.Get(name, 1); ok {
			t.Errorf("Get(%q) returned ok=true after Clear", name)
		}
	}
}

func TestCachePurgeRemovesOnlyExpired(t *testing.T) {
	cache := NewValidationCache(50 * time.Millisecond)

	// Store two entries.
	cache.Set("expired.example.com", 1, ValidationSecure)
	cache.Set("valid.example.com", 1, ValidationInsecure)

	// Manually shorten the TTL of the first entry so it expires.
	cache.mu.Lock()
	key := cacheKey("expired.example.com", 1)
	if entry, ok := cache.items[key]; ok {
		entry.expiresAt = time.Now().Add(-1 * time.Second) // already expired
	}
	cache.mu.Unlock()

	total, expired := cache.Stats()
	if total != 2 {
		t.Fatalf("Stats total = %d, want 2", total)
	}
	if expired != 1 {
		t.Errorf("Stats expired = %d, want 1", expired)
	}

	purged := cache.Purge()
	if purged != 1 {
		t.Errorf("Purge returned %d, want 1", purged)
	}

	total, expired = cache.Stats()
	if total != 1 {
		t.Errorf("Stats total after purge = %d, want 1", total)
	}
	if expired != 0 {
		t.Errorf("Stats expired after purge = %d, want 0", expired)
	}

	// The valid entry should still be retrievable.
	result, ok := cache.Get("valid.example.com", 1)
	if !ok {
		t.Fatal("Get valid.example.com returned ok=false after purge")
	}
	if result != ValidationInsecure {
		t.Errorf("valid.example.com result = %v, want %v", result, ValidationInsecure)
	}

	// The expired entry should be gone.
	_, ok = cache.Get("expired.example.com", 1)
	if ok {
		t.Error("Get expired.example.com returned ok=true after purge")
	}
}

func TestCachePurgeAllExpired(t *testing.T) {
	cache := NewValidationCache(50 * time.Millisecond)

	cache.Set("a.example.com", 1, ValidationSecure)
	cache.Set("b.example.com", 1, ValidationInsecure)

	// Expire both entries.
	cache.mu.Lock()
	for _, entry := range cache.items {
		entry.expiresAt = time.Now().Add(-1 * time.Second)
	}
	cache.mu.Unlock()

	purged := cache.Purge()
	if purged != 2 {
		t.Errorf("Purge returned %d, want 2", purged)
	}

	total, _ := cache.Stats()
	if total != 0 {
		t.Errorf("Stats total after purge = %d, want 0", total)
	}
}

func TestCachePurgeNoneExpired(t *testing.T) {
	cache := NewValidationCache(5 * time.Minute)

	cache.Set("a.example.com", 1, ValidationSecure)

	purged := cache.Purge()
	if purged != 0 {
		t.Errorf("Purge returned %d, want 0 when no entries expired", purged)
	}

	total, _ := cache.Stats()
	if total != 1 {
		t.Errorf("Stats total = %d, want 1", total)
	}
}

func TestCacheStats(t *testing.T) {
	cache := NewValidationCache(50 * time.Millisecond)

	// Empty cache.
	total, expired := cache.Stats()
	if total != 0 || expired != 0 {
		t.Fatalf("empty cache: total=%d expired=%d, want 0 0", total, expired)
	}

	// Add entries.
	cache.Set("a.example.com", 1, ValidationSecure)
	cache.Set("b.example.com", 1, ValidationInsecure)
	cache.Set("c.example.com", 1, ValidationBogus)

	total, expired = cache.Stats()
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
	if expired != 0 {
		t.Errorf("expired = %d, want 0", expired)
	}

	// Expire one entry.
	cache.mu.Lock()
	key := cacheKey("b.example.com", 1)
	if entry, ok := cache.items[key]; ok {
		entry.expiresAt = time.Now().Add(-1 * time.Second)
	}
	cache.mu.Unlock()

	total, expired = cache.Stats()
	if total != 3 {
		t.Errorf("total after expire = %d, want 3", total)
	}
	if expired != 1 {
		t.Errorf("expired after expire = %d, want 1", expired)
	}
}

func TestCacheConcurrentAccess(t *testing.T) {
	cache := NewValidationCache(5 * time.Minute)

	const goroutines = 50
	const opsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines * 3) // writers, readers, and stats callers

	// Concurrent writers.
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				cache.Set("concurrent.example.com", uint16(id), ValidationSecure)
			}
		}(i)
	}

	// Concurrent readers.
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				_, _ = cache.Get("concurrent.example.com", uint16(id))
			}
		}(i)
	}

	// Concurrent stats/purge callers.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				_, _ = cache.Stats()
			}
		}()
	}

	wg.Wait()

	// After all goroutines complete, each unique key should still be readable.
	total, _ := cache.Stats()
	if total != goroutines {
		t.Errorf("total entries after concurrent writes = %d, want %d", total, goroutines)
	}
}

func TestCacheConcurrentMixed(t *testing.T) {
	cache := NewValidationCache(5 * time.Minute)

	const writers = 20
	const readers = 20

	var wg sync.WaitGroup
	wg.Add(writers + readers)

	// Writers inserting different domains.
	for i := 0; i < writers; i++ {
		go func(id int) {
			defer wg.Done()
			name := "domain" + string(rune('0'+id%10)) + ".example.com"
			for j := 0; j < 200; j++ {
				cache.Set(name, 1, ValidationResult(id%4))
			}
		}(i)
	}

	// Readers querying those domains.
	for i := 0; i < readers; i++ {
		go func(id int) {
			defer wg.Done()
			name := "domain" + string(rune('0'+id%10)) + ".example.com"
			for j := 0; j < 200; j++ {
				result, ok := cache.Get(name, 1)
				if ok && result < 0 || result > ValidationIndeterminate {
					t.Errorf("unexpected result value %d", result)
				}
			}
		}(i)
	}

	wg.Wait()
}

// ---------------------------------------------------------------------------
// RRSIGCache tests
// ---------------------------------------------------------------------------

func TestNewRRSIGCache(t *testing.T) {
	cache := NewRRSIGCache(5 * time.Minute)
	if cache == nil {
		t.Fatal("NewRRSIGCache returned nil")
	}
	if cache.ttl != 5*time.Minute {
		t.Errorf("Expected TTL 5m, got %v", cache.ttl)
	}
	if cache.items == nil {
		t.Error("items map should be initialized")
	}
}

func TestRRSIGCache_SetGet(t *testing.T) {
	cache := NewRRSIGCache(5 * time.Minute)

	rrsig := &protocol.ResourceRecord{
		Name:  &protocol.Name{Labels: []string{"example", "com"}, FQDN: true},
		Type:  protocol.TypeRRSIG,
		Class: protocol.ClassIN,
		TTL:   300,
	}

	data := []byte("example RRset data for signing")

	// Set
	cache.SetRRSIG("example.com.", protocol.TypeA, data, rrsig)

	// Get with matching data should return the RRSIG
	dataHash := sha256.Sum256(data)
	got, ok := cache.GetRRSIG("example.com.", protocol.TypeA, dataHash)
	if !ok {
		t.Fatal("GetRRSIG should find the cached RRSIG")
	}
	if got != rrsig {
		t.Error("GetRRSIG should return the same RRSIG pointer")
	}
}

func TestRRSIGCache_GetMiss(t *testing.T) {
	cache := NewRRSIGCache(5 * time.Minute)

	var hash [32]byte
	_, ok := cache.GetRRSIG("example.com.", protocol.TypeA, hash)
	if ok {
		t.Error("GetRRSIG should return false for empty cache")
	}
}

func TestRRSIGCache_GetExpired(t *testing.T) {
	cache := NewRRSIGCache(1 * time.Millisecond)

	rrsig := &protocol.ResourceRecord{
		Name:  &protocol.Name{Labels: []string{"example", "com"}, FQDN: true},
		Type:  protocol.TypeRRSIG,
		Class: protocol.ClassIN,
	}

	data := []byte("data")
	cache.SetRRSIG("example.com.", protocol.TypeA, data, rrsig)

	// Wait for expiry
	time.Sleep(10 * time.Millisecond)

	dataHash := sha256.Sum256(data)
	_, ok := cache.GetRRSIG("example.com.", protocol.TypeA, dataHash)
	if ok {
		t.Error("GetRRSIG should not return expired entries")
	}
}

func TestRRSIGCache_ClearRRSIG(t *testing.T) {
	cache := NewRRSIGCache(5 * time.Minute)

	rrsig := &protocol.ResourceRecord{
		Name:  &protocol.Name{Labels: []string{"example", "com"}, FQDN: true},
		Type:  protocol.TypeRRSIG,
		Class: protocol.ClassIN,
	}

	cache.SetRRSIG("example.com.", protocol.TypeA, []byte("data"), rrsig)
	cache.ClearRRSIG()

	dataHash := sha256.Sum256([]byte("data"))
	_, ok := cache.GetRRSIG("example.com.", protocol.TypeA, dataHash)
	if ok {
		t.Error("GetRRSIG should return false after ClearRRSIG")
	}
}

func TestRRSIGCache_DifferentData(t *testing.T) {
	cache := NewRRSIGCache(5 * time.Minute)

	rrsig1 := &protocol.ResourceRecord{
		Name:  &protocol.Name{Labels: []string{"example", "com"}, FQDN: true},
		Type:  protocol.TypeRRSIG,
		Class: protocol.ClassIN,
		TTL:   300,
	}
	rrsig2 := &protocol.ResourceRecord{
		Name:  &protocol.Name{Labels: []string{"example", "com"}, FQDN: true},
		Type:  protocol.TypeRRSIG,
		Class: protocol.ClassIN,
		TTL:   600,
	}

	data1 := []byte("data version 1")
	data2 := []byte("data version 2")

	cache.SetRRSIG("example.com.", protocol.TypeA, data1, rrsig1)
	cache.SetRRSIG("example.com.", protocol.TypeA, data2, rrsig2)

	// Get first
	hash1 := sha256.Sum256(data1)
	got1, ok := cache.GetRRSIG("example.com.", protocol.TypeA, hash1)
	if !ok || got1 != rrsig1 {
		t.Error("Should get rrsig1 for data1")
	}

	// Get second
	hash2 := sha256.Sum256(data2)
	got2, ok := cache.GetRRSIG("example.com.", protocol.TypeA, hash2)
	if !ok || got2 != rrsig2 {
		t.Error("Should get rrsig2 for data2")
	}
}

func TestRRSIGCache_LazyEviction(t *testing.T) {
	cache := NewRRSIGCache(1 * time.Millisecond)

	// Fill cache beyond threshold
	for i := 0; i < 5001; i++ {
		data := []byte(fmt.Sprintf("data-%d", i))
		cache.SetRRSIG("example.com.", protocol.TypeA, data, &protocol.ResourceRecord{})
	}

	// Wait for all to expire
	time.Sleep(10 * time.Millisecond)

	// Adding one more should trigger lazy eviction
	cache.SetRRSIG("example.com.", protocol.TypeA, []byte("trigger-eviction"), &protocol.ResourceRecord{})

	// Cache should have been partially cleaned
	if len(cache.items) > 5000 {
		t.Errorf("Cache should have been evicted, but has %d items", len(cache.items))
	}
}
