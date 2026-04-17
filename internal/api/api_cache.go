package api

import (
	"net/http"
)

func (s *Server) handleCacheStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
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

	stats := s.cache.Stats()
	s.writeJSON(w, http.StatusOK, &CacheStatsResponse{
		Size:     stats.Size,
		Capacity: stats.Capacity,
		Hits:     stats.Hits,
		Misses:   stats.Misses,
		HitRatio: stats.HitRatio(),
	})
}

// handleCacheFlush flushes the cache.
func (s *Server) handleCacheFlush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.requireAdmin(w, r) {
		return
	}

	if s.cache == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Cache not available")
		return
	}

	s.cache.Flush()
	s.writeJSON(w, http.StatusOK, &MessageResponse{
		Message: "Cache flushed",
	})
}

// handleConfigReload reloads configuration.
