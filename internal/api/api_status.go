package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

func (s *Server) handleSPA(spaHandler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Unknown API paths are errors, not dashboard routes: answering them
		// with index.html and 200 made typos such as /api/v1/users look like
		// successful calls to API clients.
		if r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") {
			s.writeError(w, http.StatusNotFound, "Not found")
			return
		}
		spaHandler.ServeHTTP(w, r)
	}
}

// handleDashboardStats returns stats formatted for the web dashboard.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	resp := &StatusResponse{
		Status:    "running",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Version:   util.Version,
	}

	// Operational detail (cache statistics and cluster topology) is operator-level
	// data — the sibling endpoints that expose it (e.g. /api/v1/cache/stats,
	// /api/v1/cluster/*) all require operator. Viewers get only the basic running
	// status; operators and above get the full picture. (V10)
	if s.hasOperatorRole(r) {
		if s.cache != nil {
			stats := s.cache.Stats()
			resp.Cache = &CacheInfo{
				Size:     stats.Size,
				Capacity: stats.Capacity,
				Hits:     stats.Hits,
				Misses:   stats.Misses,
				HitRatio: stats.HitRatio(),
			}
		}

		if s.cluster != nil {
			clusterStats := s.cluster.Stats()
			resp.Cluster = ClusterInfo{
				Enabled:    true,
				NodeID:     clusterStats.NodeID,
				NodeCount:  clusterStats.NodeCount,
				AliveCount: clusterStats.AliveCount,
				Healthy:    clusterStats.IsHealthy,
			}
		} else {
			resp.Cluster = ClusterInfo{Enabled: false}
		}
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// handleZones handles GET (list zones) and POST (create zone).
