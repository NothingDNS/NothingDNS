package api

// Runtime configuration mutations that need no restart. Each handler applies
// the change to the live component AND records it in the runtime overrides
// file, so the next start or SIGHUP re-applies it on top of the YAML config
// instead of silently reverting to the config-file value.

import (
	"net/http"
	"time"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/util"
)

// persistAndApplyOverrides merges patch into the runtime overrides file and
// applies it to the live config. Callers must have already applied the change
// to the runtime component itself (rate limiter, cache, synthesizer, …); this
// only handles the two config-shaped copies of the setting.
//
// With no overrides file (storage.data_dir unset) the change still applies
// live and the call succeeds — same contract as an ACL update without an
// access policy file.
func (s *Server) persistAndApplyOverrides(patch *config.RuntimeOverrides) error {
	if patch == nil {
		return nil
	}

	s.overridesMu.Lock()
	defer s.overridesMu.Unlock()

	s.runtimeMu.RLock()
	file := s.overridesFile
	configGetter := s.configGetter
	s.runtimeMu.RUnlock()

	if file != "" {
		existing, err := config.LoadRuntimeOverrides(file)
		if err != nil {
			// Refuse to silently discard whatever the file holds by
			// overwriting it with only this patch: the operator has to see
			// the corrupt file, and the caller reports the failure.
			return err
		}
		if err := config.SaveRuntimeOverrides(file, config.MergeRuntimeOverridePatch(existing, patch)); err != nil {
			return err
		}
	}

	// Keep the in-memory config in step so GET /api/v1/config reports what is
	// actually in effect, and a later reload of unrelated sections does not
	// read a stale value. Writes are serialized by overridesMu.
	if configGetter != nil {
		if cfg := configGetter(); cfg != nil {
			config.ApplyRuntimeOverrides(cfg, patch)
		}
	}
	return nil
}

// currentConfig returns the live config, or nil when no getter is registered.
func (s *Server) currentConfig() *config.Config {
	s.runtimeMu.RLock()
	getter := s.configGetter
	s.runtimeMu.RUnlock()
	if getter == nil {
		return nil
	}
	return getter()
}

// handleConfigResolution updates the resolution settings that can change
// without a restart.
//
// authoritative_only takes effect on the very next query (the pipeline reads it
// per request). The resolver-construction fields (recursive, max_depth,
// timeout, edns0_buffer_size, qname_minimization, use_0x20) are read when the
// iterative resolver is built, so they take effect on the next reload or
// restart — persisting them is what makes that reload keep the new value.
// resolution.root_hints is deliberately not settable here: a file path must be
// validated at startup.
//
// Endpoint path: PUT /api/v1/config/resolution
func (s *Server) handleConfigResolution(w http.ResponseWriter, r *http.Request) {
	if s.requireMethod(w, r, http.MethodPut) {
		return
	}
	// Turning recursion on (or authoritative_only off) opens forwarding paths
	// to every client the ACL admits — admin-only (VULN-009).
	if s.requireAdmin(w, r) {
		return
	}

	// Pointer fields give patch semantics: an omitted key keeps its current
	// value instead of being reset to Go's zero value.
	var req struct {
		Recursive         *bool   `json:"recursive"`
		AuthoritativeOnly *bool   `json:"authoritative_only"`
		MaxDepth          *int    `json:"max_depth"`
		Timeout           *string `json:"timeout"`
		EDNS0BufferSize   *int    `json:"edns0_buffer_size"`
		QnameMinimization *bool   `json:"qname_minimization"`
		Use0x20           *bool   `json:"use_0x20"`
	}
	if !s.decode(w, r, &req) {
		return
	}

	if req.MaxDepth != nil && *req.MaxDepth < 0 {
		s.writeError(w, http.StatusBadRequest, "max_depth cannot be negative")
		return
	}
	if req.EDNS0BufferSize != nil && (*req.EDNS0BufferSize < 0 || *req.EDNS0BufferSize > 65535) {
		s.writeError(w, http.StatusBadRequest, "edns0_buffer_size must be between 0 and 65535")
		return
	}
	if req.Timeout != nil {
		if _, err := time.ParseDuration(*req.Timeout); err != nil {
			s.writeError(w, http.StatusBadRequest, "timeout must be a duration (e.g. 5s)")
			return
		}
	}
	patch := &config.RuntimeOverrides{Resolution: &config.ResolutionOverride{
		Recursive:         req.Recursive,
		AuthoritativeOnly: req.AuthoritativeOnly,
		MaxDepth:          req.MaxDepth,
		Timeout:           req.Timeout,
		EDNS0BufferSize:   req.EDNS0BufferSize,
		QnameMinimization: req.QnameMinimization,
		Use0x20:           req.Use0x20,
	}}
	if err := s.persistAndApplyOverrides(patch); err != nil {
		util.Warnf("api: failed to persist resolution overrides: %v", err)
		s.writeError(w, http.StatusInternalServerError, sanitizeError(err, "Failed to save runtime overrides"))
		return
	}

	s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "Resolution configuration updated"})
}

// handleConfigDNS64 toggles DNS64/NAT64 synthesis (RFC 6147) at runtime.
// The prefix itself stays config-file-only: changing it needs a new
// synthesizer, which is built at startup.
//
// Endpoint path: PUT /api/v1/config/dns64
func (s *Server) handleConfigDNS64(w http.ResponseWriter, r *http.Request) {
	if s.requireMethod(w, r, http.MethodPut) {
		return
	}
	// Synthesis rewrites AAAA answers for every client — admin-only.
	if s.requireAdmin(w, r) {
		return
	}

	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	if req.Enabled == nil {
		s.writeError(w, http.StatusBadRequest, "enabled is required")
		return
	}

	s.runtimeMu.RLock()
	synth := s.dns64Synth
	s.runtimeMu.RUnlock()
	previous := false
	if synth == nil {
		if *req.Enabled {
			s.writeError(w, http.StatusBadRequest, "dns64 not configured at startup; set dns64 in the config file and reload")
			return
		}
		// Already off and nothing to turn off: still record the intent so a
		// later config file that enables DNS64 does not resurrect it.
	} else {
		previous = synth.IsEnabled()
		synth.SetEnabled(*req.Enabled)
	}

	patch := &config.RuntimeOverrides{DNS64: &config.DNS64Override{Enabled: req.Enabled}}
	if err := s.persistAndApplyOverrides(patch); err != nil {
		// Leave the running server matching what is persisted.
		synth.SetEnabled(previous)
		util.Warnf("api: failed to persist dns64 override: %v", err)
		s.writeError(w, http.StatusInternalServerError, sanitizeError(err, "Failed to save runtime overrides"))
		return
	}

	s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "DNS64 configuration updated"})
}

// handleConfigCookie toggles DNS Cookies (RFC 7873) at runtime. Enabling
// creates a cookie jar on the DNS handler; disabling drops it, so clients stop
// being challenged.
//
// Endpoint path: PUT /api/v1/config/cookie
func (s *Server) handleConfigCookie(w http.ResponseWriter, r *http.Request) {
	if s.requireMethod(w, r, http.MethodPut) {
		return
	}
	// Cookies are an off-path spoofing defence; disabling them weakens every
	// client's protection — admin-only.
	if s.requireAdmin(w, r) {
		return
	}

	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	if req.Enabled == nil {
		s.writeError(w, http.StatusBadRequest, "enabled is required")
		return
	}

	s.runtimeMu.RLock()
	setCookieEnabled := s.setCookieEnabled
	s.runtimeMu.RUnlock()
	if setCookieEnabled == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Cookie control not available")
		return
	}
	previous := false
	if cfg := s.currentConfig(); cfg != nil {
		previous = cfg.Cookie.Enabled
	}
	if err := setCookieEnabled(*req.Enabled); err != nil {
		s.writeError(w, http.StatusInternalServerError, sanitizeError(err, "Failed to update DNS cookies"))
		return
	}

	patch := &config.RuntimeOverrides{Cookie: &config.CookieOverride{Enabled: req.Enabled}}
	if err := s.persistAndApplyOverrides(patch); err != nil {
		// Leave the running server matching what is persisted.
		if rbErr := setCookieEnabled(previous); rbErr != nil {
			util.Warnf("api: failed to restore DNS cookie state after a persist failure: %v", rbErr)
		}
		util.Warnf("api: failed to persist cookie override: %v", err)
		s.writeError(w, http.StatusInternalServerError, sanitizeError(err, "Failed to save runtime overrides"))
		return
	}

	s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "DNS cookie configuration updated"})
}
