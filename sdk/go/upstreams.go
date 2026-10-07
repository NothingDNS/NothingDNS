package nothingdns

import (
	"context"
)

// UpstreamsService handles the upstream resolver pool (the
// /api/v1/upstreams endpoints).
type UpstreamsService struct {
	t *Transport
}

// changeUpstreamRequest is the JSON body of PUT /api/v1/upstreams.
type changeUpstreamRequest struct {
	Action string `json:"action"`
	Server string `json:"server"`
}

// List returns upstream health and counters. It requires the operator role or
// higher.
//
// The result carries pool-wide per-upstream counters (Upstreams) and the
// configured servers with latency and health (Servers).
func (s *UpstreamsService) List(ctx context.Context) (*Upstreams, error) {
	var out Upstreams
	if err := s.t.doJSON(ctx, "GET", "/api/v1/upstreams", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Add adds one upstream server at runtime. It requires the admin role. server
// is an address in "host:port" form, e.g. "9.9.9.9:53". It returns the
// server's confirmation message.
//
// It fails with an *ErrAPIError carrying status 409 when the server is already
// in the pool, and 400 (see IsBadRequest) when server has no valid port or is
// a private address.
func (s *UpstreamsService) Add(ctx context.Context, server string) (string, error) {
	return s.change(ctx, "add", server)
}

// Remove removes one upstream server at runtime. It requires the admin role.
// It returns the server's confirmation message. Removing the last server is
// refused with 400 (see IsBadRequest).
func (s *UpstreamsService) Remove(ctx context.Context, server string) (string, error) {
	return s.change(ctx, "remove", server)
}

func (s *UpstreamsService) change(ctx context.Context, action, server string) (string, error) {
	return s.t.doMessage(ctx, "PUT", "/api/v1/upstreams", nil, changeUpstreamRequest{Action: action, Server: server})
}
