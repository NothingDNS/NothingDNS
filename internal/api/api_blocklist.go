package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func (s *Server) handleBlocklists(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.requireOperator(w, r) {
		return
	}

	if s.blocklist == nil {
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
		stats := s.blocklist.Stats()
		s.writeJSON(w, http.StatusOK, &BlocklistResponse{
			Enabled:    stats.Enabled,
			TotalRules: stats.TotalBlocks,
			FilesCount: stats.Files,
			URLsCount:  stats.URLs,
		})
	case http.MethodPost:
		if s.requireOperator(w, r) {
			return
		}
		var req BlocklistAddRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}
		if req.File != "" {
			if err := s.blocklist.AddFile(req.File); err != nil {
				s.writeError(w, http.StatusBadRequest, sanitizeError(err, "Failed to load blocklist file"))
				return
			}
			s.writeJSON(w, http.StatusCreated, &MessageResponse{Message: "Blocklist file added"})
		} else if req.URL != "" {
			if err := s.blocklist.AddURL(req.URL); err != nil {
				s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Failed to load blocklist from URL: %v", err))
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
	if s.blocklist == nil {
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
		if s.requireOperator(w, r) {
			return
		}
		stats := s.blocklist.Stats()
		s.blocklist.SetEnabled(!stats.Enabled)
		s.writeJSON(w, http.StatusOK, &MessageResponse{
			Message: fmt.Sprintf("Blocklist %s", map[bool]string{true: "enabled", false: "disabled"}[!stats.Enabled]),
		})
		return
	}

	// List sources: GET /api/v1/blocklists/sources
	if path == "sources" && r.Method == http.MethodGet {
		sources := s.blocklist.GetSources()
		s.writeJSON(w, http.StatusOK, sources)
		return
	}

	// Toggle source: POST /api/v1/blocklists/{id}/toggle
	if strings.HasSuffix(path, "/toggle") {
		if r.Method != http.MethodPost {
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		if s.requireOperator(w, r) {
			return
		}
		id := strings.TrimSuffix(path, "/toggle")
		decodedID, err := url.QueryUnescape(id)
		if err != nil {
			decodedID = id
		}
		enabled, err := s.blocklist.ToggleSource(decodedID)
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
		if s.requireOperator(w, r) {
			return
		}
		// URL-decode the path to handle encoded slashes
		decodedPath, err := url.QueryUnescape(path)
		if err != nil {
			decodedPath = path
		}
		if err := s.blocklist.RemoveSource(decodedPath); err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Failed to remove blocklist source: %v", err))
			return
		}
		s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "Blocklist source removed"})
		return
	}

	s.writeError(w, http.StatusNotFound, "Not found")
}

// handleUpstreams returns upstream server status.
