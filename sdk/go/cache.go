package nothingdns

import (
	"context"
)

// CacheService handles the DNS response cache (the /api/v1/cache endpoints).
type CacheService struct {
	t *Transport
}

// Stats returns cache size, capacity, hit/miss counters and hit ratio. It
// requires the operator role or higher.
func (s *CacheService) Stats(ctx context.Context) (*CacheStats, error) {
	var out CacheStats
	if err := s.t.doJSON(ctx, "GET", "/api/v1/cache/stats", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Flush drops every cached entry. It requires the admin role. Call it right
// after a bulk zone change so clients see new data immediately. It returns
// the server's confirmation message.
func (s *CacheService) Flush(ctx context.Context) (string, error) {
	return s.t.doMessage(ctx, "POST", "/api/v1/cache/flush", nil, nil)
}
