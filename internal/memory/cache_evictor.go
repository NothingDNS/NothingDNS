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

// Evict removes approximately percent of entries from the cache,
// starting with the least recently used entries.
func (e *CacheEvictor) Evict(percent int) {
	if e.cache != nil {
		e.cache.EvictPercent(percent)
	}
}

// Clear removes all cache entries.
func (e *CacheEvictor) Clear() {
	if e.cache != nil {
		e.cache.Clear()
	}
}
