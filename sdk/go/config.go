package nothingdns

import (
	"context"
	"fmt"
	"strings"
)

// LogLevels are the log levels accepted by Config.SetLogging.
var LogLevels = []string{"debug", "info", "warn", "warning", "error", "fatal"}

// IsValidLogLevel reports whether level is a level accepted by
// Config.SetLogging.
func IsValidLogLevel(level string) bool {
	for _, l := range LogLevels {
		if l == level {
			return true
		}
	}
	return false
}

// ConfigService handles configuration inspection and the runtime tunables
// (the /api/v1/config endpoints).
//
// Runtime changes are persisted to runtime_overrides.json in the data
// directory and re-applied over the YAML section on every config reload, so
// they survive a restart. Every setter requires the admin role.
type ConfigService struct {
	t *Transport
}

// RRLOptions tunes the per-client response-rate limiter. Every field is
// optional; a nil field is omitted so the setting keeps its current value,
// making this a partial update rather than a replacement.
type RRLOptions struct {
	// Enabled turns the limiter on or off.
	Enabled *bool
	// Rate is the sustained queries per second allowed per client.
	Rate *float64
	// Burst is the token-bucket burst size.
	Burst *int
	// MaxBuckets is the maximum number of client buckets tracked.
	MaxBuckets *int
}

// CacheConfigOptions tunes the response cache at runtime. Every field is
// optional; a nil field keeps its current value (partial update).
type CacheConfigOptions struct {
	// Enabled turns the cache on or off.
	Enabled *bool
	// Size is the maximum number of cached entries.
	Size *int
	// DefaultTTL is the default TTL for cached answers, in seconds.
	DefaultTTL *int
	// MaxTTL is the maximum TTL the cache will honour, in seconds.
	MaxTTL *int
	// MinTTL is the minimum TTL the cache will honour, in seconds.
	MinTTL *int
	// NegativeTTL is the TTL for cached negative answers, in seconds.
	NegativeTTL *int
	// Prefetch enables prefetching of popular entries.
	Prefetch *bool
	// PrefetchThreshold is the access count that triggers a prefetch.
	PrefetchThreshold *int
	// ServeStale enables serving stale answers while revalidating (RFC
	// 8767).
	ServeStale *bool
	// StaleGraceSecs is how long a stale answer may be served, in seconds.
	StaleGraceSecs *int
}

// ResolutionOptions tunes iterative resolution at runtime. Every field is
// optional; a nil field keeps its current value (partial update).
type ResolutionOptions struct {
	// Recursive resolves recursively for clients that are allowed to.
	Recursive *bool
	// AuthoritativeOnly answers only from local zones and refuses
	// everything else.
	AuthoritativeOnly *bool
	// MaxDepth is the maximum CNAME/answer chain depth.
	MaxDepth *int
	// Timeout is the resolver timeout as a duration string, e.g. "2s".
	Timeout *string
	// EDNS0BufferSize is the EDNS0 buffer size advertised to clients.
	EDNS0BufferSize *int
	// QNAMEMinimization sends minimal (label-count) QNAME queries upstream.
	QNAMEMinimization *bool
	// Use0x20 randomises QNAME letter case to defeat cache poisoning.
	Use0x20 *bool
}

// loggingRequest is the JSON body of PUT /api/v1/config/logging.
type loggingRequest struct {
	Level string `json:"level"`
}

// toggleRequest is the JSON body of the PUT /api/v1/config/{dns64,cookie}
// endpoints.
type toggleRequest struct {
	Enabled bool `json:"enabled"`
}

// rrlRequest is the JSON body of PUT /api/v1/config/rrl.
type rrlRequest struct {
	Enabled    *bool    `json:"enabled,omitempty"`
	Rate       *float64 `json:"rate,omitempty"`
	Burst      *int     `json:"burst,omitempty"`
	MaxBuckets *int     `json:"max_buckets,omitempty"`
}

// cacheConfigRequest is the JSON body of PUT /api/v1/config/cache.
type cacheConfigRequest struct {
	Enabled           *bool `json:"enabled,omitempty"`
	Size              *int  `json:"size,omitempty"`
	DefaultTTL        *int  `json:"default_ttl,omitempty"`
	MaxTTL            *int  `json:"max_ttl,omitempty"`
	MinTTL            *int  `json:"min_ttl,omitempty"`
	NegativeTTL       *int  `json:"negative_ttl,omitempty"`
	Prefetch          *bool `json:"prefetch,omitempty"`
	PrefetchThreshold *int  `json:"prefetch_threshold,omitempty"`
	ServeStale        *bool `json:"serve_stale,omitempty"`
	StaleGraceSecs    *int  `json:"stale_grace_secs,omitempty"`
}

// resolutionRequest is the JSON body of PUT /api/v1/config/resolution.
type resolutionRequest struct {
	Recursive         *bool   `json:"recursive,omitempty"`
	AuthoritativeOnly *bool   `json:"authoritative_only,omitempty"`
	MaxDepth          *int    `json:"max_depth,omitempty"`
	Timeout           *string `json:"timeout,omitempty"`
	EDNS0BufferSize   *int    `json:"edns0_buffer_size,omitempty"`
	QNAMEMinimization *bool   `json:"qname_minimization,omitempty"`
	Use0x20           *bool   `json:"use_0x20,omitempty"`
}

// Get returns the effective configuration with secrets redacted. It requires
// the operator role or higher. The result is the merged config as nested
// maps; the server replaces secrets with a redaction marker.
func (s *ConfigService) Get(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := s.t.doJSON(ctx, "GET", "/api/v1/config", nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Reload re-reads the YAML config file without dropping the listener. It
// requires the admin role. It returns the server's confirmation message.
func (s *ConfigService) Reload(ctx context.Context) (string, error) {
	return s.t.doMessage(ctx, "POST", "/api/v1/config/reload", nil, nil)
}

// SetLogging changes the log level at runtime. It requires the admin role.
// level is one of "debug", "info", "warn", "warning", "error", "fatal".
//
// It fails with an *ErrValidationError for an unknown level.
func (s *ConfigService) SetLogging(ctx context.Context, level string) (string, error) {
	if !IsValidLogLevel(level) {
		return "", &ErrValidationError{Message: fmt.Sprintf("level must be one of %s", strings.Join(LogLevels, ", "))}
	}
	return s.t.doMessage(ctx, "PUT", "/api/v1/config/logging", nil, loggingRequest{Level: level})
}

// SetRRL tunes the per-client response-rate limiter at runtime. It requires
// the admin role. Every field of opts is optional; omitted fields keep their
// current value.
func (s *ConfigService) SetRRL(ctx context.Context, opts *RRLOptions) (string, error) {
	var body rrlRequest
	if opts != nil {
		body.Enabled = opts.Enabled
		body.Rate = opts.Rate
		body.Burst = opts.Burst
		body.MaxBuckets = opts.MaxBuckets
	}
	return s.t.doMessage(ctx, "PUT", "/api/v1/config/rrl", nil, body)
}

// SetCache tunes the response cache at runtime. It requires the admin role.
// Every field of opts is optional; omitted fields keep their current value, so
// this is a partial update rather than a replacement.
func (s *ConfigService) SetCache(ctx context.Context, opts *CacheConfigOptions) (string, error) {
	var body cacheConfigRequest
	if opts != nil {
		body.Enabled = opts.Enabled
		body.Size = opts.Size
		body.DefaultTTL = opts.DefaultTTL
		body.MaxTTL = opts.MaxTTL
		body.MinTTL = opts.MinTTL
		body.NegativeTTL = opts.NegativeTTL
		body.Prefetch = opts.Prefetch
		body.PrefetchThreshold = opts.PrefetchThreshold
		body.ServeStale = opts.ServeStale
		body.StaleGraceSecs = opts.StaleGraceSecs
	}
	return s.t.doMessage(ctx, "PUT", "/api/v1/config/cache", nil, body)
}

// SetResolution tunes iterative resolution at runtime. It requires the admin
// role. Every field of opts is optional; omitted fields keep their current
// value.
func (s *ConfigService) SetResolution(ctx context.Context, opts *ResolutionOptions) (string, error) {
	var body resolutionRequest
	if opts != nil {
		body.Recursive = opts.Recursive
		body.AuthoritativeOnly = opts.AuthoritativeOnly
		body.MaxDepth = opts.MaxDepth
		body.Timeout = opts.Timeout
		body.EDNS0BufferSize = opts.EDNS0BufferSize
		body.QNAMEMinimization = opts.QNAMEMinimization
		body.Use0x20 = opts.Use0x20
	}
	return s.t.doMessage(ctx, "PUT", "/api/v1/config/resolution", nil, body)
}

// SetDNS64 enables or disables DNS64 synthesis for NAT64 networks
// (RFC 6147). It requires the admin role.
func (s *ConfigService) SetDNS64(ctx context.Context, enabled bool) (string, error) {
	return s.t.doMessage(ctx, "PUT", "/api/v1/config/dns64", nil, toggleRequest{Enabled: enabled})
}

// SetCookie enables or disables DNS Cookies (RFC 7873). It requires the admin
// role.
func (s *ConfigService) SetCookie(ctx context.Context, enabled bool) (string, error) {
	return s.t.doMessage(ctx, "PUT", "/api/v1/config/cookie", nil, toggleRequest{Enabled: enabled})
}
