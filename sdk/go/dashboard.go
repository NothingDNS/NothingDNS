package nothingdns

import (
	"context"
)

// DashboardService handles dashboard counters and live query events (the
// /api/dashboard endpoints). Unlike the rest of the API, these endpoints use
// camelCase field names on the wire.
type DashboardService struct {
	t *Transport
}

// Stats returns the dashboard counter block. It requires the operator role or
// higher.
func (s *DashboardService) Stats(ctx context.Context) (*DashboardStats, error) {
	var out DashboardStats
	if err := s.t.doJSON(ctx, "GET", "/api/dashboard/stats", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Queries returns the last 100 query events. It requires the operator role or
// higher.
//
// Event fields are camelCase (ClientIP, QueryType, …) — this endpoint differs
// from the rest of the API, which is snake_case.
func (s *DashboardService) Queries(ctx context.Context) ([]QueryEvent, error) {
	var out []QueryEvent
	if err := s.t.doJSON(ctx, "GET", "/api/dashboard/queries", nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Zones returns the dashboard zone summary. It requires the operator role or
// higher.
func (s *DashboardService) Zones(ctx context.Context) ([]Zone, error) {
	var out []Zone
	if err := s.t.doJSON(ctx, "GET", "/api/dashboard/zones", nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}
