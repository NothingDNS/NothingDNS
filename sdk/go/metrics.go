package nothingdns

import (
	"context"
)

// MetricsService handles the query log, top domains and the metrics history
// ring buffer (the /api/v1/queries, /api/v1/topdomains and
// /api/v1/metrics/history endpoints).
type MetricsService struct {
	t *Transport
}

// QueryLogOptions tunes Metrics.QueryLog. Every field is optional; a zero
// value is omitted so the server applies its default.
type QueryLogOptions struct {
	// Offset is the index of the first row to return.
	Offset int
	// Limit is the page size.
	Limit int
	// Q is a substring filter matched against the queried domain.
	Q string
}

// QueryLog returns one page of the query log. It requires the operator role or
// higher.
//
// opts optionally carries the offset, limit and a "q" substring filter. Pass
// nil to use the server defaults.
func (s *MetricsService) QueryLog(ctx context.Context, opts *QueryLogOptions) (*QueryLogPage, error) {
	query := map[string]any{}
	if opts != nil {
		if opts.Offset != 0 {
			query["offset"] = opts.Offset
		}
		if opts.Limit != 0 {
			query["limit"] = opts.Limit
		}
		if opts.Q != "" {
			query["q"] = opts.Q
		}
	}
	var out QueryLogPage
	if err := s.t.doJSON(ctx, "GET", "/api/v1/queries", query, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// TopDomains returns the most-queried domains. It requires the operator role
// or higher. limit caps the number of entries; pass 0 to use the server
// default.
func (s *MetricsService) TopDomains(ctx context.Context, limit int) (*TopDomains, error) {
	query := map[string]any{}
	if limit != 0 {
		query["limit"] = limit
	}
	var out TopDomains
	if err := s.t.doJSON(ctx, "GET", "/api/v1/topdomains", query, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// History returns the recent metrics ring buffer. It requires the operator
// role or higher.
//
// The series are parallel arrays: Queries[i] was recorded at Timestamps[i].
func (s *MetricsService) History(ctx context.Context) (*MetricsHistory, error) {
	var out MetricsHistory
	if err := s.t.doJSON(ctx, "GET", "/api/v1/metrics/history", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
