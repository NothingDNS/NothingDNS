package api

import (
	"github.com/nothingdns/nothingdns/internal/cache"
)

// CacheService is the single source of truth for cache-related business
// logic, kept separate from the HTTP handler layer and ensuring consistent
// response types.
type CacheService struct {
	cache *cache.Cache
}

// NewCacheService creates a CacheService backed by the given *cache.Cache.
// If cache is nil, all methods return zero values / nil errors gracefully.
func NewCacheService(cache *cache.Cache) *CacheService {
	return &CacheService{cache: cache}
}

// GetStats returns current cache statistics in a transport-agnostic format.
func (s *CacheService) GetStats() *CacheStatsResponse {
	if s == nil || s.cache == nil {
		return &CacheStatsResponse{}
	}
	stats := s.cache.Stats()
	return &CacheStatsResponse{
		Size:     stats.Size,
		Capacity: stats.Capacity,
		Hits:     stats.Hits,
		Misses:   stats.Misses,
		HitRatio: stats.HitRatio(),
	}
}

// Flush purges all entries from the cache.
func (s *CacheService) Flush() error {
	if s == nil || s.cache == nil {
		return nil
	}
	s.cache.Flush()
	return nil
}

// FlushName purges the entries of one name (every type) and returns how many
// were removed.
func (s *CacheService) FlushName(name string) int {
	if s == nil || s.cache == nil {
		return 0
	}
	return len(s.cache.InvalidateName(name))
}

// Available reports whether the underlying cache is present.
func (s *CacheService) Available() bool {
	return s != nil && s.cache != nil
}

// Cache returns the underlying *cache.Cache. Use with caution.
func (s *CacheService) Cache() *cache.Cache {
	return s.cache
}
