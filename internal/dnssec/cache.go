package dnssec

import (
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// ValidationCache caches DNSSEC validation results to reduce repeated
// cryptographic operations.
type ValidationCache struct {
	mu    sync.RWMutex
	items map[string]*cacheEntry
	ttl   time.Duration
}

// cacheEntry holds a cached validation result.
type cacheEntry struct {
	result    ValidationResult
	expiresAt time.Time
}

// NewValidationCache creates a new validation cache with the given TTL.
func NewValidationCache(ttl time.Duration) *ValidationCache {
	return &ValidationCache{
		items: make(map[string]*cacheEntry),
		ttl:   ttl,
	}
}

// cacheKey builds a cache key from name and query type.
func cacheKey(name string, qtype uint16) string {
	return protocol.TypeString(qtype) + "/" + name
}

// Get retrieves a cached validation result.
func (c *ValidationCache) Get(name string, qtype uint16) (ValidationResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := cacheKey(name, qtype)
	entry, ok := c.items[key]
	if !ok {
		return ValidationIndeterminate, false
	}

	if time.Now().After(entry.expiresAt) {
		delete(c.items, key)
		return ValidationIndeterminate, false
	}

	return entry.result, true
}

// Set stores a validation result.
func (c *ValidationCache) Set(name string, qtype uint16, result ValidationResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Lazy eviction: purge expired entries when cache exceeds threshold
	if len(c.items) > 10000 {
		now := time.Now()
		for key, entry := range c.items {
			if now.After(entry.expiresAt) {
				delete(c.items, key)
			}
		}
	}

	c.items[cacheKey(name, qtype)] = &cacheEntry{
		result:    result,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// Clear removes all entries from the cache.
func (c *ValidationCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[string]*cacheEntry)
}

// Stats returns cache statistics.
func (c *ValidationCache) Stats() (total, expired int) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()
	total = len(c.items)
	for _, entry := range c.items {
		if now.After(entry.expiresAt) {
			expired++
		}
	}
	return
}

// Purge removes expired entries from the cache.
func (c *ValidationCache) Purge() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var purged int
	for key, entry := range c.items {
		if now.After(entry.expiresAt) {
			delete(c.items, key)
			purged++
		}
	}
	return purged
}
