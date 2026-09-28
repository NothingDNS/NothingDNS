package api

import (
	"fmt"
	"net/http"
	"strings"
)

func (s *Server) handleBlocklists(w http.ResponseWriter, r *http.Request) {
	if s.requireMethod(w, r, http.MethodGet, http.MethodPost) {
		return
	}
	if s.requireOperator(w, r) {
		return
	}
	if r.Method == http.MethodPost {
		// URL-based blocklist sources trigger an outbound HTTP fetch, giving
		// the caller cross-site request primitives even with the allowlist
		// (cf. VULN-004); and file-based sources can read arbitrary process-
		// visible paths. Admin-only (VULN-009).
		if s.requireAdmin(w, r) {
			return
		}
	}

	s.runtimeMu.RLock()
	blocklistService := s.blocklistService
	s.runtimeMu.RUnlock()
	if blocklistService == nil || !blocklistService.Available() {
		if r.Method == http.MethodPost {
			s.writeError(w, http.StatusServiceUnavailable, "Blocklist not available")
			return
		}
		s.writeJSON(w, http.StatusOK, &BlocklistResponse{
			Enabled:    false,
			TotalRules: 0,
			FilesCount: 0,
			URLsCount:  0,
		})
		return
	}

	switch r.Method {
	case http.MethodGet:
		stats := blocklistService.GetStats()
		s.writeJSON(w, http.StatusOK, stats)
	case http.MethodPost:
		var req BlocklistAddRequest
		if !s.decode(w, r, &req) {
			return
		}
		if req.File != "" {
			if err := blocklistService.AddFile(req.File); err != nil {
				s.writeError(w, http.StatusBadRequest, sanitizeError(err, "Failed to load blocklist file"))
				return
			}
			s.writeJSON(w, http.StatusCreated, &MessageResponse{Message: "Blocklist file added"})
		} else if req.URL != "" {
			if err := blocklistService.AddURL(req.URL); err != nil {
				s.writeError(w, http.StatusBadRequest, sanitizeError(err, "Failed to load blocklist from URL"))
				return
			}
			s.writeJSON(w, http.StatusCreated, &MessageResponse{Message: "Blocklist URL added: " + req.URL})
		} else {
			s.writeError(w, http.StatusBadRequest, "file or url is required")
		}
	}
}

// handleBlocklistActions handles toggle and file-based removal.
func (s *Server) handleBlocklistActions(w http.ResponseWriter, r *http.Request) {
	if s.requireOperator(w, r) {
		return
	}
	s.runtimeMu.RLock()
	blocklistService := s.blocklistService
	s.runtimeMu.RUnlock()
	if blocklistService == nil || !blocklistService.Available() {
		s.writeError(w, http.StatusServiceUnavailable, "Blocklist not available")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/blocklists/")

	// Toggle: /api/v1/blocklists/toggle
	if path == "toggle" {
		if r.Method != http.MethodPost {
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		// Flipping the global blocklist off undoes all domain filtering.
		// Admin-only (VULN-009).
		if s.requireAdmin(w, r) {
			return
		}
		// Toggle() atomically flips the enabled state and returns the
		// resulting value. Replaces the TOCTOU Stats()+SetEnabled
		// pattern that could silently lose one of two simultaneous
		// toggle clicks and report the wrong state back to the operator.
		nowEnabled := blocklistService.Toggle()
		s.writeJSON(w, http.StatusOK, &MessageResponse{
			Message: fmt.Sprintf("Blocklist %s", map[bool]string{true: "enabled", false: "disabled"}[nowEnabled]),
		})
		return
	}

	// List sources: GET /api/v1/blocklists/sources
	if path == "sources" && r.Method == http.MethodGet {
		sources := blocklistService.GetSources()
		s.writeJSON(w, http.StatusOK, sources)
		return
	}

	// Toggle source: POST /api/v1/blocklists/{id}/toggle
	if strings.HasSuffix(path, "/toggle") {
		if r.Method != http.MethodPost {
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		if s.requireAdmin(w, r) {
			return
		}
		// r.URL.Path is already percent-decoded by net/http, and a source ID
		// (a file path or a full URL) is a path, not a query string. Decoding
		// it a second time with url.QueryUnescape is wrong twice over: the
		// query decoder rewrites a literal '+' into a space, so any source
		// whose ID contains one — a base64 token or a space-encoded query
		// parameter in a blocklist URL — could be added through the API but
		// never removed or toggled again. Use the decoded path as-is.
		id := strings.TrimSuffix(path, "/toggle")
		enabled, err := blocklistService.ToggleSource(id)
		if err != nil {
			s.writeError(w, http.StatusNotFound, "Source not found")
			return
		}
		state := map[bool]string{true: "enabled", false: "disabled"}[enabled]
		s.writeJSON(w, http.StatusOK, &MessageResponse{Message: fmt.Sprintf("Source %s", state)})
		return
	}

	// Delete by file path: /api/v1/blocklists/{filepath}
	if r.Method == http.MethodDelete {
		if s.requireAdmin(w, r) {
			return
		}
		// r.URL.Path is already decoded by net/http and the source ID is a
		// path, so it is used as-is — see the note on the toggle branch above
		// for why a second url.QueryUnescape is wrong here.
		if err := blocklistService.RemoveSource(path); err != nil {
			s.writeError(w, http.StatusBadRequest, sanitizeError(err, "Failed to remove blocklist source"))
			return
		}
		s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "Blocklist source removed"})
		return
	}

	s.writeError(w, http.StatusNotFound, "Not found")
}

// handleUpstreams returns upstream server status.
