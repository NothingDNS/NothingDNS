package memory

import (
	"github.com/nothingdns/nothingdns/internal/cache"
)

// CacheEvictor implements the Evictor interface using the DNS cache.
type CacheEvictor struct {
	cache *cache.Cache
}

// NewCacheEvictor creates an evictor backed by the DNS cache.
func NewCacheEvictor(c *cache.Cache) *CacheEvictor {
	return &CacheEvictor{cache: c}
}

// Evict removes cached entries. For LRU caches without a partial-evict API,
// we clear the entire cache to free memory quickly.
func (e *CacheEvictor) Evict(_ int) {
	if e.cache != nil {
		e.cache.Clear()
	}
}

// Clear removes all cache entries.
func (e *CacheEvictor) Clear() {
	if e.cache != nil {
		e.cache.Clear()
	}
}
