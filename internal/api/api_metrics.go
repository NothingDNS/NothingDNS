package api

import (
	"net/http"
	"strconv"
	"time"
)

func (s *Server) handleDashboardStats(w http.ResponseWriter, r *http.Request) {
	if s.requireOperator(w, r) {
		return
	}
	resp := &DashboardStatsResponse{}

	if s.cache != nil {
		cs := s.cache.Stats()
		resp.QueriesTotal = cs.Hits + cs.Misses
		total := float64(cs.Hits + cs.Misses)
		if total > 0 {
			resp.CacheHitRate = float64(cs.Hits) / total * 100
		}
	}

	if s.zoneManager != nil {
		resp.ZoneCount = s.zoneManager.Count()
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// handleDashboardQueries returns query events for the dashboard.
func (s *Server) handleDashboardQueries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.requireOperator(w, r) {
		return
	}

	if s.dashboardServer == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Dashboard not available")
		return
	}

	stats := s.dashboardServer.GetStats()
	queries, _ := stats.GetRecentQueries(0, 100)
	s.writeJSON(w, http.StatusOK, queries)
}

// handleDashboardZones returns zone list for the dashboard.
func (s *Server) handleDashboardZones(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.requireOperator(w, r) {
		return
	}

	if s.dashboardServer == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Dashboard not available")
		return
	}

	// Proxy to dashboard server's handleZones
	s.dashboardServer.ServeHTTP(w, r)
}

// handleQueryLog returns a paginated query log.
func (s *Server) handleQueryLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.requireOperator(w, r) {
		return
	}

	if s.dashboardServer == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Dashboard not available")
		return
	}

	offset := 0
	limit := 100
	if o := r.URL.Query().Get("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil && v >= 0 {
			offset = v
		}
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 500 {
			limit = v
		}
	}

	stats := s.dashboardServer.GetStats()
	queries, total := stats.GetRecentQueries(offset, limit)

	entries := make([]QueryLogEntry, 0, len(queries))
	for _, q := range queries {
		entries = append(entries, QueryLogEntry{
			Timestamp:    q.Timestamp.UTC().Format(time.RFC3339),
			ClientIP:     q.ClientIP,
			Domain:       q.Domain,
			QueryType:    q.QueryType,
			ResponseCode: q.ResponseCode,
			Duration:     q.Duration,
			Cached:       q.Cached,
			Blocked:      q.Blocked,
			Protocol:     q.Protocol,
		})
	}

	s.writeJSON(w, http.StatusOK, &QueryLogResponse{
		Queries: entries,
		Total:   total,
		Offset:  offset,
		Limit:   limit,
	})
}

// handleTopDomains returns the top N most-queried domains.
func (s *Server) handleTopDomains(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.requireOperator(w, r) {
		return
	}

	if s.dashboardServer == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Dashboard not available")
		return
	}

	limit := 10
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 100 {
			limit = v
		}
	}

	stats := s.dashboardServer.GetStats()
	domains := stats.GetTopDomains(limit)

	s.writeJSON(w, http.StatusOK, &TopDomainsResponse{
		Domains: domains,
		Limit:   limit,
	})
}

// handleMetricsHistory returns metrics history from the ring buffer.
func (s *Server) handleMetricsHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.requireOperator(w, r) {
		return
	}

	if s.metrics == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Metrics not available")
		return
	}

	history := s.metrics.GetHistory()
	s.writeJSON(w, http.StatusOK, history)
}

// handleDNSSECStatus returns DNSSEC validation status.
