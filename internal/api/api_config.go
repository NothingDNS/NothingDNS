package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

func (s *Server) handleConfigReload(w http.ResponseWriter, r *http.Request) {
	if s.requireMethod(w, r, http.MethodPost) {
		return
	}
	// Config reload can swap zones, TLS certs, ACL, upstreams, blocklists.
	// Admin-only (VULN-009).
	if s.requireAdmin(w, r) {
		return
	}

	if s.reloadFunc == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Reload not available")
		return
	}

	if err := s.reloadFunc(); err != nil {
		s.writeError(w, http.StatusInternalServerError, sanitizeError(err, "Failed to reload config"))
		return
	}

	s.writeJSON(w, http.StatusOK, &MessageResponse{
		Message: "Configuration reloaded",
	})
}

// handleConfigGet returns the current server configuration with sensitive fields redacted.
func (s *Server) handleConfigGet(w http.ResponseWriter, r *http.Request) {
	if s.requireMethod(w, r, http.MethodGet) {
		return
	}
	if s.requireOperator(w, r) {
		return
	}

	s.runtimeMu.RLock()
	configGetter := s.configGetter
	s.runtimeMu.RUnlock()
	if configGetter == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Config not available")
		return
	}

	cfg := configGetter()
	if cfg == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Config not available")
		return
	}

	// Marshal full config to a map so we can redact sensitive fields while
	// preserving the PascalCase keys the frontend expects (Go's default encoder).
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to serialize config")
		return
	}
	var publicCfg map[string]any
	if err := json.Unmarshal(cfgJSON, &publicCfg); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to serialize config")
		return
	}
	publicCfg["Version"] = util.Version
	// PUT /api/v1/config/logging changes the level at runtime only; report the
	// level in effect, not the one in the config file, or the dashboard shows
	// a stale value and cannot switch back to it.
	if logging, ok := publicCfg["Logging"].(map[string]any); ok {
		logging["Level"] = strings.ToLower(util.GetDefaultLogger().Level().String())
	}

	// Redact sensitive fields. These structs carry only yaml tags (no json
	// tags), so they serialize under their Go field names — redact by those.
	// NOTE: this is an allowlist-by-omission; whenever a secret field is added
	// to a config struct it MUST be added here too (regression: TestConfigGet_RedactsSecrets).
	if server, ok := publicCfg["Server"].(map[string]any); ok {
		if httpCfg, ok := server["HTTP"].(map[string]any); ok {
			httpCfg["AuthToken"] = ""
			httpCfg["AuthSecret"] = ""
			// Configured user plaintext passwords. Zeroed at startup in main.go,
			// but a SIGHUP reload re-loads them, so redact at the boundary too.
			if users, ok := httpCfg["Users"].([]any); ok {
				for _, u := range users {
					if user, ok := u.(map[string]any); ok {
						user["Password"] = ""
					}
				}
			}
		}
	}
	if cluster, ok := publicCfg["Cluster"].(map[string]any); ok {
		cluster["EncryptionKey"] = ""         // gossip AES-256-GCM key
		cluster["SnapshotEncryptionKey"] = "" // Raft snapshot at-rest key
	}
	if storage, ok := publicCfg["Storage"].(map[string]any); ok {
		storage["EncryptionKey"] = "" // KV data-file at-rest key
	}
	if metrics, ok := publicCfg["Metrics"].(map[string]any); ok {
		metrics["AuthToken"] = "" // Prometheus endpoint bearer token
	}
	if dnssecCfg, ok := publicCfg["DNSSEC"].(map[string]any); ok {
		if signing, ok := dnssecCfg["Signing"].(map[string]any); ok {
			if keys, ok := signing["Keys"].([]any); ok {
				for _, k := range keys {
					if key, ok := k.(map[string]any); ok {
						key["PrivateKey"] = ""
					}
				}
			}
		}
	}
	if slaveZones, ok := publicCfg["SlaveZones"].([]any); ok {
		for _, sz := range slaveZones {
			if zone, ok := sz.(map[string]any); ok {
				zone["TSIGSecret"] = ""
			}
		}
	}

	s.writeJSON(w, http.StatusOK, publicCfg)
}

// handleClusterStatus returns cluster status.
func (s *Server) handleConfigLogging(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	// Setting log level to FATAL silences the audit trail; admin-only (VULN-009).
	if s.requireAdmin(w, r) {
		return
	}

	var req struct {
		Level string `json:"level"`
	}
	// VULN-071: use MaxBytesReader to prevent unbounded body reading on config PUT
	if !s.decode(w, r, &req) {
		return
	}

	var level util.LogLevel
	switch strings.ToLower(req.Level) {
	case "debug":
		level = util.DEBUG
	case "info":
		level = util.INFO
	case "warn", "warning":
		level = util.WARN
	case "error":
		level = util.ERROR
	case "fatal":
		level = util.FATAL
	default:
		s.writeError(w, http.StatusBadRequest, "Invalid log level")
		return
	}

	util.GetDefaultLogger().SetLevel(level)
	s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "Logging level updated"})
}

// handleConfigRRL updates the runtime response rate limiting configuration.
func (s *Server) handleConfigRRL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	// Disabling rate limiting turns the server into an open amplifier;
	// admin-only (VULN-009).
	if s.requireAdmin(w, r) {
		return
	}

	s.runtimeMu.RLock()
	rateLimiter := s.rateLimiter
	s.runtimeMu.RUnlock()
	if rateLimiter == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Rate limiter not available")
		return
	}

	// Pointer fields let us distinguish "omitted" from "set to zero
	// value". The previous \`Enabled bool\` declaration meant a PUT
	// of \`{"rate": 100}\` (intending only to tweak the rate) was
	// indistinguishable from \`{"enabled": false, "rate": 100}\` —
	// the former silently disabled rate limiting because Go's JSON
	// unmarshal zeroes missing fields. \`SetEnabled\` only runs
	// when the JSON actually carries the key.
	var req struct {
		Enabled *bool    `json:"enabled"`
		Rate    *float64 `json:"rate"`
		Burst   *int     `json:"burst"`
	}
	// VULN-071: use MaxBytesReader to prevent unbounded body reading on config PUT
	if !s.decode(w, r, &req) {
		return
	}

	if req.Enabled != nil {
		rateLimiter.SetEnabled(*req.Enabled)
	}
	if req.Rate != nil && *req.Rate > 0 {
		rateLimiter.SetRate(*req.Rate)
	}
	if req.Burst != nil && *req.Burst > 0 {
		rateLimiter.SetBurst(*req.Burst)
	}

	s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "RRL configuration updated"})
}

// handleConfigCache updates the runtime cache configuration.
func (s *Server) handleConfigCache(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	// Cache sizing, TTL, prefetch, and stale-serving changes directly affect
	// resolver availability and memory pressure; keep runtime mutation admin-only.
	if s.requireAdmin(w, r) {
		return
	}

	if s.cache == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Cache not available")
		return
	}

	// Pointer fields enable patch-semantics: only apply what the
	// caller actually set. The previous \`bool\`/\`int\` fields treated
	// omitted JSON keys as zero values and \`UpdateConfig\` then
	// replaced every cache parameter with those zeros — a PUT of
	// \`{"size": 100000}\` (intending to bump capacity) would have
	// also disabled serve-stale, set every TTL to zero, and turned
	// prefetch off in one shot.
	var req struct {
		Enabled           *bool `json:"enabled"`
		Size              *int  `json:"size"`
		DefaultTTL        *int  `json:"default_ttl"`
		MaxTTL            *int  `json:"max_ttl"`
		MinTTL            *int  `json:"min_ttl"`
		NegativeTTL       *int  `json:"negative_ttl"`
		Prefetch          *bool `json:"prefetch"`
		PrefetchThreshold *int  `json:"prefetch_threshold"`
		ServeStale        *bool `json:"serve_stale"`
		StaleGraceSecs    *int  `json:"stale_grace_secs"`
	}
	// VULN-071: use MaxBytesReader to prevent unbounded body reading on config PUT
	if !s.decode(w, r, &req) {
		return
	}

	// Merge over the existing config so omitted fields keep their
	// current values.
	cfg := s.cache.GetConfig()
	if req.Size != nil {
		if *req.Size < 1 {
			s.writeError(w, http.StatusBadRequest, "size must be at least 1")
			return
		}
		cfg.Capacity = *req.Size
	}
	// Seconds-valued fields share identical validate-and-assign logic;
	// table order preserves which field's error is reported first.
	for _, f := range []struct {
		name string
		src  *int
		dst  *time.Duration
	}{
		{"min_ttl", req.MinTTL, &cfg.MinTTL},
		{"max_ttl", req.MaxTTL, &cfg.MaxTTL},
		{"default_ttl", req.DefaultTTL, &cfg.DefaultTTL},
		{"negative_ttl", req.NegativeTTL, &cfg.NegativeTTL},
		{"prefetch_threshold", req.PrefetchThreshold, &cfg.PrefetchThreshold},
		{"stale_grace_secs", req.StaleGraceSecs, &cfg.StaleGrace},
	} {
		if f.src == nil {
			continue
		}
		d, err := cacheConfigSeconds(f.name, *f.src)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		*f.dst = d
	}
	if req.Prefetch != nil {
		cfg.PrefetchEnabled = *req.Prefetch
	}
	if req.ServeStale != nil {
		cfg.ServeStale = *req.ServeStale
	}
	// The cache's on/off lifecycle is owned by the manager and fixed at
	// startup — it cannot be toggled at runtime. Reaching this handler means
	// the cache IS enabled (guarded above), so a request to DISABLE it can't
	// be honored: reject it with a clear 400 instead of returning 200 while
	// silently ignoring the change (an operator footgun). Sending the current
	// value (enabled=true) is accepted as a no-op.
	if req.Enabled != nil && !*req.Enabled {
		s.writeError(w, http.StatusBadRequest, "cache cannot be disabled at runtime; set cache.enabled=false in the config file and reload")
		return
	}

	s.cache.UpdateConfig(cfg)

	s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "Cache configuration updated"})
}

func cacheConfigSeconds(field string, seconds int) (time.Duration, error) {
	if seconds < 0 {
		return 0, fmt.Errorf("%s cannot be negative", field)
	}
	const maxDurationSeconds = int64(1<<63-1) / int64(time.Second)
	if int64(seconds) > maxDurationSeconds {
		return 0, fmt.Errorf("%s is too large", field)
	}
	return time.Duration(seconds) * time.Second, nil
}

// handleGeoDNSStats returns GeoDNS engine statistics.
