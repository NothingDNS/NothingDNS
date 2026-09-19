package config

// Runtime overrides: the settings the dashboard/API can change on a running
// server WITHOUT a restart, persisted so they survive one.
//
// The file plays the same role for tunables that access_policy.json plays for
// the ACL and the recursion allow list: it is written by API mutations and
// re-applied on top of the YAML config at every load (startup and SIGHUP), so
// an operator's dashboard change is not silently reverted by the next reload.
// Only keys present in the file win over YAML; everything else keeps coming
// from the config file.
//
// Deliberately NOT covered: anything whose new value has to be validated
// against the filesystem or a listening socket before it can be trusted
// (resolution.root_hints, bind addresses, TLS files, zone paths). Those still
// require a config-file edit so -validate-config can reject them up front.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// maxRuntimeOverridesFileSize caps the override file read. The file only ever
// holds a handful of scalars plus the upstream server list.
const maxRuntimeOverridesFileSize = 64 * 1024

// runtimeOverridesFileName is the file name inside storage.data_dir.
const runtimeOverridesFileName = "runtime_overrides.json"

// RuntimeOverrides holds the persisted no-restart settings. Every section and
// every field is a pointer: nil means "not overridden, use the YAML value".
type RuntimeOverrides struct {
	Logging    *LoggingOverride    `json:"logging,omitempty"`
	RRL        *RRLOverride        `json:"rrl,omitempty"`
	Cache      *CacheOverride      `json:"cache,omitempty"`
	Resolution *ResolutionOverride `json:"resolution,omitempty"`
	DNS64      *DNS64Override      `json:"dns64,omitempty"`
	Cookie     *CookieOverride     `json:"cookie,omitempty"`

	// UpstreamServers replaces upstream.servers wholesale when set (the API
	// adds and removes one server at a time, but the resulting list is what
	// has to survive a restart — a stored delta would drift from the pool).
	UpstreamServers *[]string `json:"upstream_servers,omitempty"`
}

// LoggingOverride overrides logging.level.
type LoggingOverride struct {
	Level *string `json:"level,omitempty"`
}

// RRLOverride overrides the rrl section.
type RRLOverride struct {
	Enabled *bool `json:"enabled,omitempty"`
	// Rate is float-valued to match the live rate limiter (and the API), which
	// accepts fractional queries-per-second. rrl.rate in the config file is an
	// integer, so a fractional rate truncates when it is applied to Config.
	Rate       *float64 `json:"rate,omitempty"`
	Burst      *int     `json:"burst,omitempty"`
	MaxBuckets *int     `json:"max_buckets,omitempty"`
}

// CacheOverride overrides the cache section. The TTL fields are seconds, like
// the config file and the API body (not time.Duration).
type CacheOverride struct {
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

// ResolutionOverride overrides the resolution section. root_hints is absent on
// purpose: a file path needs start-up validation, so it stays YAML-only.
type ResolutionOverride struct {
	Recursive         *bool   `json:"recursive,omitempty"`
	AuthoritativeOnly *bool   `json:"authoritative_only,omitempty"`
	MaxDepth          *int    `json:"max_depth,omitempty"`
	Timeout           *string `json:"timeout,omitempty"`
	EDNS0BufferSize   *int    `json:"edns0_buffer_size,omitempty"`
	QnameMinimization *bool   `json:"qname_minimization,omitempty"`
	Use0x20           *bool   `json:"use_0x20,omitempty"`
}

// DNS64Override overrides dns64.enabled. The prefix stays YAML-only: changing
// it needs a new synthesizer, which is built at start-up.
type DNS64Override struct {
	Enabled *bool `json:"enabled,omitempty"`
}

// CookieOverride overrides cookie.enabled.
type CookieOverride struct {
	Enabled *bool `json:"enabled,omitempty"`
}

// RuntimeOverridesFile returns the override file path inside dataDir, or ""
// when no data dir is configured (overrides then apply live but are not
// persisted, mirroring the access policy).
func RuntimeOverridesFile(dataDir string) string {
	if dataDir == "" {
		return ""
	}
	return filepath.Join(dataDir, runtimeOverridesFileName)
}

// LoadRuntimeOverrides reads the override file. A missing file (or an empty
// path) is not an error: it returns nil, nil.
func LoadRuntimeOverrides(path string) (*RuntimeOverrides, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxRuntimeOverridesFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxRuntimeOverridesFileSize {
		return nil, fmt.Errorf("runtime overrides file %s exceeds %d bytes", path, maxRuntimeOverridesFileSize)
	}
	var o RuntimeOverrides
	if err := json.Unmarshal(data, &o); err != nil {
		return nil, fmt.Errorf("parsing runtime overrides file %s: %w", path, err)
	}
	return &o, nil
}

// SaveRuntimeOverrides atomically writes the overrides with owner-only
// permissions (temp file + rename), like SaveAccessPolicy.
func SaveRuntimeOverrides(path string, o *RuntimeOverrides) error {
	if path == "" {
		return fmt.Errorf("no runtime overrides file configured (set storage.data_dir)")
	}
	if o == nil {
		o = &RuntimeOverrides{}
	}
	data, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".runtime_overrides-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// ApplyRuntimeOverrides mutates cfg in place for every field the overrides
// set. Nil sections and nil fields are left alone, so the YAML value stands.
func ApplyRuntimeOverrides(cfg *Config, o *RuntimeOverrides) {
	if cfg == nil || o == nil {
		return
	}

	if l := o.Logging; l != nil {
		assignString(&cfg.Logging.Level, l.Level)
	}

	if r := o.RRL; r != nil {
		assignBool(&cfg.RRL.Enabled, r.Enabled)
		if r.Rate != nil {
			cfg.RRL.Rate = int(*r.Rate)
		}
		assignInt(&cfg.RRL.Burst, r.Burst)
		assignInt(&cfg.RRL.MaxBuckets, r.MaxBuckets)
	}

	if c := o.Cache; c != nil {
		assignInt(&cfg.Cache.Size, c.Size)
		assignInt(&cfg.Cache.DefaultTTL, c.DefaultTTL)
		assignInt(&cfg.Cache.MaxTTL, c.MaxTTL)
		assignInt(&cfg.Cache.MinTTL, c.MinTTL)
		assignInt(&cfg.Cache.NegativeTTL, c.NegativeTTL)
		assignBool(&cfg.Cache.Prefetch, c.Prefetch)
		assignInt(&cfg.Cache.PrefetchThreshold, c.PrefetchThreshold)
		assignBool(&cfg.Cache.ServeStale, c.ServeStale)
		assignInt(&cfg.Cache.StaleGraceSecs, c.StaleGraceSecs)
	}

	if res := o.Resolution; res != nil {
		assignBool(&cfg.Resolution.Recursive, res.Recursive)
		assignBool(&cfg.Resolution.AuthoritativeOnly, res.AuthoritativeOnly)
		assignInt(&cfg.Resolution.MaxDepth, res.MaxDepth)
		assignString(&cfg.Resolution.Timeout, res.Timeout)
		assignInt(&cfg.Resolution.EDNS0BufferSize, res.EDNS0BufferSize)
		assignBool(&cfg.Resolution.QnameMinimization, res.QnameMinimization)
		assignBool(&cfg.Resolution.Use0x20, res.Use0x20)
	}

	if d := o.DNS64; d != nil {
		assignBool(&cfg.DNS64.Enabled, d.Enabled)
	}

	if ck := o.Cookie; ck != nil {
		assignBool(&cfg.Cookie.Enabled, ck.Enabled)
	}

	if o.UpstreamServers != nil {
		cfg.Upstream.Servers = copyStrings(*o.UpstreamServers)
	}
}

// MergeRuntimeOverridePatch deep-merges patch over existing and returns the
// result to persist. Neither argument is mutated: every value is copied, so
// the caller can keep using the patch it built for the live apply.
func MergeRuntimeOverridePatch(existing, patch *RuntimeOverrides) *RuntimeOverrides {
	if existing == nil {
		existing = &RuntimeOverrides{}
	}
	if patch == nil {
		patch = &RuntimeOverrides{}
	}

	merged := &RuntimeOverrides{}

	if existing.Logging != nil || patch.Logging != nil {
		e, p := orEmpty(existing.Logging), orEmpty(patch.Logging)
		merged.Logging = &LoggingOverride{Level: mergePtr(e.Level, p.Level)}
	}

	if existing.RRL != nil || patch.RRL != nil {
		e, p := orEmpty(existing.RRL), orEmpty(patch.RRL)
		merged.RRL = &RRLOverride{
			Enabled:    mergePtr(e.Enabled, p.Enabled),
			Rate:       mergePtr(e.Rate, p.Rate),
			Burst:      mergePtr(e.Burst, p.Burst),
			MaxBuckets: mergePtr(e.MaxBuckets, p.MaxBuckets),
		}
	}

	if existing.Cache != nil || patch.Cache != nil {
		e, p := orEmpty(existing.Cache), orEmpty(patch.Cache)
		merged.Cache = &CacheOverride{
			Size:              mergePtr(e.Size, p.Size),
			DefaultTTL:        mergePtr(e.DefaultTTL, p.DefaultTTL),
			MaxTTL:            mergePtr(e.MaxTTL, p.MaxTTL),
			MinTTL:            mergePtr(e.MinTTL, p.MinTTL),
			NegativeTTL:       mergePtr(e.NegativeTTL, p.NegativeTTL),
			Prefetch:          mergePtr(e.Prefetch, p.Prefetch),
			PrefetchThreshold: mergePtr(e.PrefetchThreshold, p.PrefetchThreshold),
			ServeStale:        mergePtr(e.ServeStale, p.ServeStale),
			StaleGraceSecs:    mergePtr(e.StaleGraceSecs, p.StaleGraceSecs),
		}
	}

	if existing.Resolution != nil || patch.Resolution != nil {
		e, p := orEmpty(existing.Resolution), orEmpty(patch.Resolution)
		merged.Resolution = &ResolutionOverride{
			Recursive:         mergePtr(e.Recursive, p.Recursive),
			AuthoritativeOnly: mergePtr(e.AuthoritativeOnly, p.AuthoritativeOnly),
			MaxDepth:          mergePtr(e.MaxDepth, p.MaxDepth),
			Timeout:           mergePtr(e.Timeout, p.Timeout),
			EDNS0BufferSize:   mergePtr(e.EDNS0BufferSize, p.EDNS0BufferSize),
			QnameMinimization: mergePtr(e.QnameMinimization, p.QnameMinimization),
			Use0x20:           mergePtr(e.Use0x20, p.Use0x20),
		}
	}

	if existing.DNS64 != nil || patch.DNS64 != nil {
		e, p := orEmpty(existing.DNS64), orEmpty(patch.DNS64)
		merged.DNS64 = &DNS64Override{Enabled: mergePtr(e.Enabled, p.Enabled)}
	}

	if existing.Cookie != nil || patch.Cookie != nil {
		e, p := orEmpty(existing.Cookie), orEmpty(patch.Cookie)
		merged.Cookie = &CookieOverride{Enabled: mergePtr(e.Enabled, p.Enabled)}
	}

	switch {
	case patch.UpstreamServers != nil:
		servers := copyStrings(*patch.UpstreamServers)
		merged.UpstreamServers = &servers
	case existing.UpstreamServers != nil:
		servers := copyStrings(*existing.UpstreamServers)
		merged.UpstreamServers = &servers
	}

	return merged
}

// orEmpty returns p, or a zero-valued section when p is nil, so the merge can
// read fields off both sides unconditionally.
func orEmpty[T any](p *T) *T {
	if p != nil {
		return p
	}
	return new(T)
}

// mergePtr returns a copy of patch when it is set, else a copy of existing.
func mergePtr[T any](existing, patch *T) *T {
	src := existing
	if patch != nil {
		src = patch
	}
	if src == nil {
		return nil
	}
	v := *src
	return &v
}

func assignString(dst *string, src *string) {
	if src != nil {
		*dst = *src
	}
}

func assignInt(dst *int, src *int) {
	if src != nil {
		*dst = *src
	}
}

func assignBool(dst *bool, src *bool) {
	if src != nil {
		*dst = *src
	}
}

func copyStrings(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	return out
}
