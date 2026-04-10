package cache

import (
	"container/list"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// Entry represents a cached DNS response.
type Entry struct {
	// Query key
	Key string

	// Response message
	Message *protocol.Message

	// Response code (for negative caching)
	RCode uint8

	// TTL information
	TTL        uint32    // Original TTL from record
	ExpireTime time.Time // When this entry expires

	// Prefetch tracking
	CanPrefetch bool      // Whether this entry can be prefetched
	PrefetchDue time.Time // When prefetch should occur

	// Entry type
	IsNegative bool // True for NXDOMAIN/NODATA entries
	IsStale    bool // True when serving a stale entry (RFC 8767)

	// Access tracking for LRU
	element *list.Element // Position in LRU list
}

// IsExpired returns true if the entry has expired.
func (e *Entry) IsExpired(now time.Time) bool {
	return now.After(e.ExpireTime)
}

// ShouldPrefetch returns true if prefetch is due for this entry.
func (e *Entry) ShouldPrefetch(now time.Time) bool {
	if !e.CanPrefetch || e.IsNegative {
		return false
	}
	return now.After(e.PrefetchDue)
}

// RemainingTTL returns the remaining TTL for this entry in seconds.
func (e *Entry) RemainingTTL(now time.Time) uint32 {
	if e.IsExpired(now) {
		return 0
	}
	remaining := e.ExpireTime.Sub(now)
	if remaining < 0 {
		return 0
	}
	return uint32(remaining.Seconds())
}

// Stats tracks cache statistics.
type Stats struct {
	Hits        uint64
	Misses      uint64
	Evictions   uint64
	Expirations uint64
	StaleServed uint64
	Size        int
	Capacity    int
}

// HitRate returns the cache hit rate as a percentage.
func (s *Stats) HitRate() float64 {
	total := s.Hits + s.Misses
	if total == 0 {
		return 0
	}
	return float64(s.Hits) / float64(total) * 100
}

// HitRatio returns the cache hit ratio (alias for HitRate).
func (s *Stats) HitRatio() float64 {
	return s.HitRate()
}

// Cache is a thread-safe DNS cache with LRU eviction.
type Cache struct {
	// Configuration
	capacity          int
	minTTL            time.Duration
	maxTTL            time.Duration
	defaultTTL        time.Duration
	negativeTTL       time.Duration
	prefetchEnabled   bool
	prefetchThreshold time.Duration

	// Serve-stale (RFC 8767) configuration
	serveStale     bool
	staleGrace     time.Duration // How long past expiry to serve stale entries
	staleServed    uint64        // Count of stale entries served

	// Storage
	mu      sync.RWMutex
	entries map[string]*Entry
	lruList *list.List // Front = most recently used, Back = least recently used

	// Statistics
	stats Stats

	// Prefetch callback
	prefetchFunc func(key string, qtype uint16)

	// Invalidation callback for cluster sync
	invalidateFunc func(key string)
}

// Config holds cache configuration.
type Config struct {
	Capacity          int
	MinTTL            time.Duration
	MaxTTL            time.Duration
	DefaultTTL        time.Duration
	NegativeTTL       time.Duration
	PrefetchEnabled   bool
	PrefetchThreshold time.Duration
	ServeStale        bool          // RFC 8767: serve stale entries when upstream fails
	StaleGrace        time.Duration // How long past expiry to keep stale entries
}

// DefaultConfig returns the default cache configuration.
func DefaultConfig() Config {
	return Config{
		Capacity:          10000,
		MinTTL:            5 * time.Second,
		MaxTTL:            24 * time.Hour,
		DefaultTTL:        5 * time.Minute,
		NegativeTTL:       60 * time.Second,
		PrefetchEnabled:   false,
		PrefetchThreshold: 60 * time.Second,
		ServeStale:        false,
		StaleGrace:        24 * time.Hour, // RFC 8767 recommends at least 1-3 days
	}
}

// New creates a new DNS cache with the given configuration.
func New(config Config) *Cache {
	return &Cache{
		capacity:          config.Capacity,
		minTTL:            config.MinTTL,
		maxTTL:            config.MaxTTL,
		defaultTTL:        config.DefaultTTL,
		negativeTTL:       config.NegativeTTL,
		prefetchEnabled:   config.PrefetchEnabled,
		prefetchThreshold: config.PrefetchThreshold,
		serveStale:        config.ServeStale,
		staleGrace:        config.StaleGrace,
		entries:           make(map[string]*Entry, config.Capacity),
		lruList:           list.New(),
		stats:             Stats{Capacity: config.Capacity},
	}
}

// MakeKey creates a cache key from query name and type.
// Uses strings.Builder instead of fmt.Sprintf for efficiency.
func MakeKey(name string, qtype uint16) string {
	var b strings.Builder
	b.Grow(len(name) + 1 + 10) // name + ":" + max uint16 digits
	b.WriteString(name)
	b.WriteByte(':')
	b.WriteString(strconv.FormatUint(uint64(qtype), 10))
	return b.String()
}

// Get retrieves an entry from the cache.
// Returns nil if not found or expired.
// When serve-stale is enabled, expired entries are kept in the cache
// but not returned by Get — use GetStale to retrieve them.
func (c *Cache) Get(key string) *Entry {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.entries[key]
	if !exists {
		c.stats.Misses++
		return nil
	}

	now := time.Now()
	if entry.IsExpired(now) {
		if c.serveStale {
			// Keep the entry for stale serving but don't return it
			// from a normal Get — the caller should use GetStale
			// after upstream failure.
			staleDeadline := entry.ExpireTime.Add(c.staleGrace)
			if now.After(staleDeadline) {
				// Past stale grace period — truly remove it
				c.removeEntry(entry)
			}
		} else {
			c.removeEntry(entry)
		}
		c.stats.Expirations++
		c.stats.Misses++
		return nil
	}

	// Move to front (most recently used)
	c.lruList.MoveToFront(entry.element)
	c.stats.Hits++

	return entry
}

// GetStale retrieves a stale (expired but within grace period) cache entry.
// Per RFC 8767, stale entries should only be served when the upstream is
// unavailable. Returns nil if no stale entry exists or serve-stale is disabled.
// The returned entry has IsStale=true and TTL set to 30s (RFC 8767 §4).
func (c *Cache) GetStale(key string) *Entry {
	if !c.serveStale {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.entries[key]
	if !exists {
		return nil
	}

	now := time.Now()
	if !entry.IsExpired(now) {
		// Not expired — normal Get should be used
		return nil
	}

	// Check if within stale grace period
	staleDeadline := entry.ExpireTime.Add(c.staleGrace)
	if now.After(staleDeadline) {
		// Past stale grace — remove it
		c.removeEntry(entry)
		return nil
	}

	// Serve the stale entry with a short TTL (RFC 8767 §4 recommends 30s)
	c.lruList.MoveToFront(entry.element)
	c.staleServed++

	staleEntry := &Entry{
		Key:        entry.Key,
		Message:    entry.Message,
		RCode:      entry.RCode,
		TTL:        30, // RFC 8767: stale TTL
		ExpireTime: entry.ExpireTime,
		IsNegative: entry.IsNegative,
		IsStale:    true,
	}
	return staleEntry
}

// StaleServed returns the count of stale entries served.
func (c *Cache) StaleServed() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.staleServed
}

// Set adds or updates an entry in the cache.
func (c *Cache) Set(key string, msg *protocol.Message, ttl uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.setInternal(key, msg, ttl, false)
}

// SetNegative adds a negative cache entry (NXDOMAIN or NODATA).
func (c *Cache) SetNegative(key string, rcode uint8) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Apply min/max TTL constraints to negative TTL
	ttl := c.negativeTTL
	if ttl < c.minTTL {
		ttl = c.minTTL
	}
	if ttl > c.maxTTL {
		ttl = c.maxTTL
	}

	expireTime := time.Now().Add(ttl)

	entry := &Entry{
		Key:        key,
		RCode:      rcode,
		ExpireTime: expireTime,
		IsNegative: true,
	}

	c.addEntry(key, entry)
}

// setInternal adds or updates an entry with the given TTL.
func (c *Cache) setInternal(key string, msg *protocol.Message, ttl uint32, isPrefetch bool) {
	// Apply min/max TTL constraints
	duration := time.Duration(ttl) * time.Second
	if duration < c.minTTL {
		duration = c.minTTL
	}
	if duration > c.maxTTL {
		duration = c.maxTTL
	}

	now := time.Now()
	expireTime := now.Add(duration)

	// Calculate prefetch time if enabled
	var prefetchDue time.Time
	canPrefetch := c.prefetchEnabled && !isPrefetch
	if canPrefetch {
		prefetchOffset := c.prefetchThreshold
		if duration > prefetchOffset {
			prefetchDue = expireTime.Add(-prefetchOffset)
		} else {
			canPrefetch = false
		}
	}

	entry := &Entry{
		Key:         key,
		Message:     msg,
		TTL:         ttl,
		ExpireTime:  expireTime,
		CanPrefetch: canPrefetch,
		PrefetchDue: prefetchDue,
		IsNegative:  false,
	}

	c.addEntry(key, entry)
}

// addEntry adds an entry to the cache, handling eviction if needed.
func (c *Cache) addEntry(key string, entry *Entry) {
	// Check if key already exists
	if oldEntry, exists := c.entries[key]; exists {
		// Remove old entry from LRU list
		c.lruList.Remove(oldEntry.element)
	}

	// Evict oldest entries if at capacity
	for len(c.entries) >= c.capacity {
		c.evictOldest()
	}

	// Add to map and LRU list
	element := c.lruList.PushFront(entry)
	entry.element = element
	c.entries[key] = entry
	c.stats.Size = len(c.entries)
}

// removeEntry removes an entry from the cache.
func (c *Cache) removeEntry(entry *Entry) {
	c.lruList.Remove(entry.element)
	delete(c.entries, entry.Key)
	c.stats.Size = len(c.entries)
}

// evictOldest removes the least recently used entry.
func (c *Cache) evictOldest() {
	element := c.lruList.Back()
	if element == nil {
		return
	}

	entry := element.Value.(*Entry)
	c.removeEntry(entry)
	c.stats.Evictions++
}

// EvictPercent removes approximately percent of entries from the cache,
// starting with the least recently used entries.
func (c *Cache) EvictPercent(percent int) {
	if percent <= 0 || percent > 100 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	count := len(c.entries) * percent / 100
	if count == 0 && len(c.entries) > 0 {
		count = 1 // Always evict at least one if cache has entries
	}

	for i := 0; i < count; i++ {
		element := c.lruList.Back()
		if element == nil {
			break
		}
		entry := element.Value.(*Entry)
		c.removeEntry(entry)
		c.stats.Evictions++
	}
}

// SetInvalidateFunc sets the callback function for cache invalidation.
func (c *Cache) SetInvalidateFunc(fn func(key string)) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.invalidateFunc = fn
}

// Delete removes an entry from the cache.
func (c *Cache) Delete(key string) {
	var notify bool
	var fn func(string)
	c.mu.Lock()
	if entry, exists := c.entries[key]; exists {
		c.removeEntry(entry)
		notify = true
	}
	fn = c.invalidateFunc
	c.mu.Unlock()

	// Notify outside lock to prevent deadlock
	if notify && fn != nil {
		fn(key)
	}
}

// Clear removes all entries from the cache.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*Entry, c.capacity)
	c.lruList.Init()
	c.stats.Size = 0
}

// Flush is an alias for Clear.
func (c *Cache) Flush() {
	c.Clear()
}

// DeleteLocal removes an entry without triggering invalidation callback.
// Used when receiving invalidation from cluster to avoid broadcast loops.
func (c *Cache) DeleteLocal(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, exists := c.entries[key]; exists {
		c.removeEntry(entry)
	}
}

// Invalidate removes an entry and broadcasts invalidation to cluster.
func (c *Cache) Invalidate(key string) {
	c.Delete(key)
}

// InvalidatePattern removes entries matching a pattern and broadcasts invalidations.
// Pattern uses prefix matching (e.g., "example.com" matches "www.example.com:A")
func (c *Cache) InvalidatePattern(pattern string) []string {
	c.mu.Lock()

	var invalidated []string
	for key := range c.entries {
		// Extract domain from key (format: "domain:type")
		domain, _ := ExtractQueryInfo(key)
		if strings.Contains(domain, pattern) || strings.HasSuffix(domain, pattern) {
			if entry, exists := c.entries[key]; exists {
				c.removeEntry(entry)
				invalidated = append(invalidated, key)
			}
		}
	}
	fn := c.invalidateFunc
	c.mu.Unlock()

	// Notify invalidation callback outside lock to prevent deadlock
	if fn != nil {
		for _, key := range invalidated {
			fn(key)
		}
	}
	return invalidated
}

// Stats returns a copy of the current cache statistics.
func (c *Cache) Stats() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	s := c.stats
	s.StaleServed = c.staleServed
	return s
}

// Size returns the current number of entries in the cache.
func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.entries)
}

// GetPrefetchable returns entries that are due for prefetching.
func (c *Cache) GetPrefetchable() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()
	var keys []string

	for _, entry := range c.entries {
		if entry.ShouldPrefetch(now) {
			// Extract query type from key for prefetch callback
			keys = append(keys, entry.Key)
		}
	}

	return keys
}

// SetPrefetchFunc sets the callback function for prefetching.
func (c *Cache) SetPrefetchFunc(fn func(key string, qtype uint16)) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.prefetchFunc = fn
}

// OnPrefetchComplete marks a prefetch as complete and resets the prefetch flag.
func (c *Cache) OnPrefetchComplete(key string, msg *protocol.Message, ttl uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Update with new TTL but mark as prefetch to avoid infinite prefetch loop
	c.setInternal(key, msg, ttl, true)
}

// ExtractQueryInfo extracts the query name and type from a cache key.
// Returns empty values if the key format is unexpected.
func ExtractQueryInfo(key string) (string, uint16) {
	// Find the last colon separator
	for i := len(key) - 1; i >= 0; i-- {
		if key[i] == ':' {
			name := key[:i]
			typeStr := key[i+1:]
			var qtype uint16
			// Try to parse the type number
			if _, err := fmt.Sscanf(typeStr, "%d", &qtype); err != nil {
				return "", 0
			}
			return name, qtype
		}
	}
	return "", 0
}

// CacheEntryJSON is a JSON-serializable cache entry for persistence.
type CacheEntryJSON struct {
	Key        string    `json:"key"`
	WireBytes  []byte    `json:"wire"`
	TTL        uint32    `json:"ttl"`
	RCode      uint8     `json:"rcode"`
	IsNegative bool      `json:"negative"`
	ExpireTime time.Time `json:"expire_time"`
}

// Save returns a serializable snapshot of all non-negative cache entries.
// Negative entries are excluded because they have very short TTLs and
// add little value on restart. Only entries that have not yet expired are included.
func (c *Cache) Save() []CacheEntryJSON {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()
	var entries []CacheEntryJSON

	for _, entry := range c.entries {
		// Skip expired entries
		if entry.IsExpired(now) {
			continue
		}
		// Skip negative entries (short TTL, low value on restart)
		if entry.IsNegative {
			continue
		}
		// Skip entries without a message (shouldn't happen)
		if entry.Message == nil {
			continue
		}

		// Pack message to wire format
		buf := make([]byte, entry.Message.WireLength())
		n, err := entry.Message.Pack(buf)
		if err != nil {
			continue // Skip entries that can't be packed
		}

		entries = append(entries, CacheEntryJSON{
			Key:        entry.Key,
			WireBytes:  buf[:n],
			TTL:        entry.TTL,
			RCode:      entry.RCode,
			IsNegative: entry.IsNegative,
			ExpireTime: entry.ExpireTime,
		})
	}

	return entries
}

// Load restores cache entries from a previously saved snapshot.
// Only non-expired entries are restored. Entries that have already
// expired are skipped. The cache is not cleared before loading.
func (c *Cache) Load(entries []CacheEntryJSON) (restored int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for _, e := range entries {
		// Skip expired entries
		if e.ExpireTime.Before(now) {
			continue
		}

		// Unpack the wire-format message
		msg, err := protocol.UnpackMessage(e.WireBytes)
		if err != nil {
			continue
		}

		// Calculate remaining TTL
		remainingTTL := uint32(e.ExpireTime.Sub(now).Seconds())
		if remainingTTL == 0 {
			continue
		}

		// Use setInternal to add without triggering callbacks
		c.setInternal(e.Key, msg, remainingTTL, false)
		restored++
	}

	return restored
}
