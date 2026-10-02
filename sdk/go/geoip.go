package nothingdns

import (
	"context"
)

// GeoIPService handles GeoDNS statistics (the /api/v1/geoip endpoints).
type GeoIPService struct {
	t *Transport
}

// Stats returns GeoDNS statistics, including whether the MaxMind database is
// loaded. It requires the operator role or higher.
func (s *GeoIPService) Stats(ctx context.Context) (*GeoIPStats, error) {
	var out GeoIPStats
	if err := s.t.doJSON(ctx, "GET", "/api/v1/geoip/stats", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
