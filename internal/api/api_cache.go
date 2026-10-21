package api

import (
	"fmt"
	"net/http"
)

func (s *Server) handleCacheStats(w http.ResponseWriter, r *http.Request) {
	if s.requireMethod(w, r, http.MethodGet) {
		return
	}
	if s.requireOperator(w, r) {
		return
	}

	if !s.cacheService.Available() {
		s.writeError(w, http.StatusServiceUnavailable, "Cache not available")
		return
	}

	stats := s.cacheService.GetStats()
	s.writeJSON(w, http.StatusOK, stats)
}

// handleCacheFlush flushes the cache.
func (s *Server) handleCacheFlush(w http.ResponseWriter, r *http.Request) {
	if s.requireMethod(w, r, http.MethodPost) {
		return
	}
	if s.requireAdmin(w, r) {
		return
	}

	if !s.cacheService.Available() {
		s.writeError(w, http.StatusServiceUnavailable, "Cache not available")
		return
	}

	// ?name= flushes the entries of that one name; without it the whole cache
	// is cleared.
	if name := r.URL.Query().Get("name"); name != "" {
		n := s.cacheService.FlushName(name)
		s.writeJSON(w, http.StatusOK, &MessageResponse{
			Message: fmt.Sprintf("Flushed %d cache entries for %s", n, name),
		})
		return
	}

	if err := s.cacheService.Flush(); err != nil {
		// Route the internal error through sanitizeError so file paths /
		// panic details never leak to the client (consistent with the rest
		// of the API); fall back to a generic message otherwise.
		s.writeError(w, http.StatusInternalServerError, sanitizeError(err, "Cache flush failed"))
		return
	}
	s.writeJSON(w, http.StatusOK, &MessageResponse{
		Message: "Cache flushed",
	})
}

// handleConfigReload reloads configuration.
