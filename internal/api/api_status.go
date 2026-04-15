package api

import (
	"net/http"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

func (s *Server) handleSPA(spaHandler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

	s.writeJSON(w, http.StatusOK, resp)
}

// handleZones handles GET (list zones) and POST (create zone).
