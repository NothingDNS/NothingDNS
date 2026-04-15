package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/util"
)

func (s *Server) handleConfigReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.requireOperator(w, r) {
		return
	}

	if s.reloadFunc == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Reload not available")
		return
	}

	if err := s.reloadFunc(); err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to reload config: %v", err))
		return
	}

	s.writeJSON(w, http.StatusOK, &MessageResponse{
		Message: "Configuration reloaded",
	})
}

// handleConfigGet returns the current server configuration with sensitive fields redacted.
func (s *Server) handleConfigGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.requireOperator(w, r) {
		return
	}

	if s.configGetter == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Config not available")
		return
	}

	cfg := s.configGetter()
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

	// Redact sensitive fields
	if server, ok := publicCfg["Server"].(map[string]any); ok {
		if httpCfg, ok := server["HTTP"].(map[string]any); ok {
			httpCfg["AuthToken"] = ""
		}
	}
	if cluster, ok := publicCfg["Cluster"].(map[string]any); ok {
		cluster["EncryptionKey"] = ""
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
	if s.requireOperator(w, r) {
		return
	}

	var req struct {
		Level string `json:"level"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON")
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
	if s.requireOperator(w, r) {
		return
	}

	if s.rateLimiter == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Rate limiter not available")
		return
	}

	var req struct {
		Enabled bool    `json:"enabled"`
		Rate    float64 `json:"rate"`
		Burst   int     `json:"burst"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	s.rateLimiter.SetEnabled(req.Enabled)
	if req.Rate > 0 {
		s.rateLimiter.SetRate(req.Rate)
	}
	if req.Burst > 0 {
		s.rateLimiter.SetBurst(req.Burst)
	}

	s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "RRL configuration updated"})
}

// handleConfigCache updates the runtime cache configuration.
func (s *Server) handleConfigCache(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.requireOperator(w, r) {
		return
	}

	if s.cache == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Cache not available")
		return
	}

	var req struct {
		Enabled           bool `json:"enabled"`
		Size              int  `json:"size"`
		DefaultTTL        int  `json:"default_ttl"`
		MaxTTL            int  `json:"max_ttl"`
		MinTTL            int  `json:"min_ttl"`
		NegativeTTL       int  `json:"negative_ttl"`
		Prefetch          bool `json:"prefetch"`
		PrefetchThreshold int  `json:"prefetch_threshold"`
		ServeStale        bool `json:"serve_stale"`
		StaleGraceSecs    int  `json:"stale_grace_secs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	// Build cache config from request
	cfg := cache.Config{
		Capacity:          req.Size,
		MinTTL:            time.Duration(req.MinTTL) * time.Second,
		MaxTTL:            time.Duration(req.MaxTTL) * time.Second,
		DefaultTTL:        time.Duration(req.DefaultTTL) * time.Second,
		NegativeTTL:       time.Duration(req.NegativeTTL) * time.Second,
		PrefetchEnabled:   req.Prefetch,
		PrefetchThreshold: time.Duration(req.PrefetchThreshold) * time.Second,
		ServeStale:        req.ServeStale,
		StaleGrace:        time.Duration(req.StaleGraceSecs) * time.Second,
	}

	s.cache.UpdateConfig(cfg)

	s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "Cache configuration updated"})
}

// handleGeoDNSStats returns GeoDNS engine statistics.
