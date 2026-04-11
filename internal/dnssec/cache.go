package dnssec

import (
	"crypto/sha256"
	"fmt"
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

// rrsigCacheEntry holds a cached RRSIG for an RRset.
type rrsigCacheEntry struct {
	rrsig    *protocol.ResourceRecord
	dataHash [32]byte // SHA-256 hash of the signed data
	expiresAt time.Time
}

// RRSIGCache caches signed RRsets to avoid re-signing.
type RRSIGCache struct {
	mu    sync.RWMutex
	items map[string]*rrsigCacheEntry
	ttl   time.Duration
}

// NewValidationCache creates a new validation cache with the given TTL.
func NewValidationCache(ttl time.Duration) *ValidationCache {
	return &ValidationCache{
		items: make(map[string]*cacheEntry),
		ttl:   ttl,
	}
}

// NewRRSIGCache creates a new RRSIG cache with the given TTL.
func NewRRSIGCache(ttl time.Duration) *RRSIGCache {
	return &RRSIGCache{
		items: make(map[string]*rrsigCacheEntry),
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

// rrsigCacheKey builds a cache key for RRSIG cache.
func rrsigCacheKey(zone string, qtype uint16, dataHash [32]byte) string {
	return fmt.Sprintf("%s/%s/%x", zone, protocol.TypeString(qtype), dataHash)
}

// GetRRSIG retrieves a cached RRSIG for the given zone, type, and data hash.
func (c *RRSIGCache) GetRRSIG(zone string, qtype uint16, dataHash [32]byte) (*protocol.ResourceRecord, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := rrsigCacheKey(zone, qtype, dataHash)
	entry, ok := c.items[key]
	if !ok {
		return nil, false
	}

	if time.Now().After(entry.expiresAt) {
		delete(c.items, key)
		return nil, false
	}

	return entry.rrsig, true
}

// SetRRSIG stores an RRSIG in the cache.
func (c *RRSIGCache) SetRRSIG(zone string, qtype uint16, data []byte, rrsig *protocol.ResourceRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Lazy eviction: purge expired entries when cache exceeds threshold
	if len(c.items) > 5000 {
		now := time.Now()
		for key, entry := range c.items {
			if now.After(entry.expiresAt) {
				delete(c.items, key)
			}
		}
	}

	dataHash := sha256.Sum256(data)
	c.items[rrsigCacheKey(zone, qtype, dataHash)] = &rrsigCacheEntry{
		rrsig:    rrsig,
		dataHash: dataHash,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// ClearRRSIG removes all entries from the RRSIG cache.
func (c *RRSIGCache) ClearRRSIG() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[string]*rrsigCacheEntry)
}
