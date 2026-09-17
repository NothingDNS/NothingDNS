package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/dashboard"
	"github.com/nothingdns/nothingdns/internal/util"
)

func (s *Server) handleDashboardStats(w http.ResponseWriter, r *http.Request) {
	// L-N6: method gate, mirroring the sibling handleDashboardQueries
	// / handleDashboardZones handlers in this file. The L-11 fix
	// gated the dashboard package's stats endpoint; this API-package
	// sibling was missed in that sweep.
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.requireOperator(w, r) {
		return
	}
	resp := &DashboardStatsResponse{}

	// Real server-wide counters (uptime, total/blocked queries, query rate,
	// upstream latency) come from the metrics collector. Previously these
	// fields were never set, so the dashboard showed permanent zeros.
	s.runtimeMu.RLock()
	metricsCollector := s.metrics
	s.runtimeMu.RUnlock()
	if metricsCollector != nil {
		snap := metricsCollector.Snapshot()
		resp.Uptime = int(snap.UptimeSeconds)
		resp.QueriesTotal = snap.QueriesTotal
		resp.QueriesPerSec = snap.QueriesPerSec
		resp.BlockedQueries = snap.BlockedQueries
		resp.UpstreamLatency = snap.AvgUpstreamLatency
	}

	if s.cache != nil {
		cs := s.cache.Stats()
		// Fall back to cache hits+misses for the total only when metrics are
		// disabled, so the card is never blank.
		if resp.QueriesTotal == 0 {
			resp.QueriesTotal = cs.Hits + cs.Misses
		}
		total := float64(cs.Hits + cs.Misses)
		if total > 0 {
			resp.CacheHitRate = float64(cs.Hits) / total * 100
		}
	}

	if s.zoneManager != nil {
		resp.ZoneCount = s.zoneManager.Count()
	}

	// Distinct DNS query clients seen in a rolling window — the dashboard
	// server owns this (it receives every query event with the client IP).
	s.runtimeMu.RLock()
	dashboardServer := s.dashboardServer
	s.runtimeMu.RUnlock()
	if dashboardServer != nil {
		resp.ActiveClients = dashboardServer.GetStats().ActiveClients
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

	s.runtimeMu.RLock()
	dashboardServer := s.dashboardServer
	s.runtimeMu.RUnlock()
	if dashboardServer == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Dashboard not available")
		return
	}

	stats := dashboardServer.GetStats()
	queries, _ := stats.GetRecentQueries(0, 100)
	// Redact client IPs for non-admins, like /api/v1/queries (LOW-010).
	if !hasRole(r.Context(), nil, auth.RoleAdmin) {
		queries = dashboard.RedactQueryEvents(queries)
	}
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

	s.runtimeMu.RLock()
	dashboardServer := s.dashboardServer
	s.runtimeMu.RUnlock()
	if dashboardServer == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Dashboard not available")
		return
	}

	// Proxy to dashboard server's handleZones
	dashboardServer.ServeHTTP(w, r)
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

	s.runtimeMu.RLock()
	dashboardServer := s.dashboardServer
	s.runtimeMu.RUnlock()
	if dashboardServer == nil {
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

	// Optional case-insensitive domain substring filter, applied server-side
	// across the full query log (not just the current page).
	filter := strings.TrimSpace(r.URL.Query().Get("q"))
	const maxFilterLen = 253 // max DNS name length
	if len(filter) > maxFilterLen {
		filter = filter[:maxFilterLen]
	}

	stats := dashboardServer.GetStats()
	queries, total := stats.GetRecentQueriesFiltered(offset, limit, filter)

	// Redact client IPs for non-admin operators (LOW-010)
	isAdmin := hasRole(r.Context(), nil, auth.RoleAdmin)

	entries := make([]QueryLogEntry, 0, len(queries))
	for _, q := range queries {
		if q == nil {
			continue
		}
		clientIP := q.ClientIP
		if !isAdmin {
			clientIP = redactIP(clientIP)
		}
		entries = append(entries, QueryLogEntry{
			Timestamp:    q.Timestamp.UTC().Format(time.RFC3339),
			ClientIP:     clientIP,
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

// redactIP masks the last octet/group of an IP address to reduce PII exposure.
func redactIP(ip string) string {
	return util.RedactIP(ip)
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

	s.runtimeMu.RLock()
	dashboardServer := s.dashboardServer
	s.runtimeMu.RUnlock()
	if dashboardServer == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Dashboard not available")
		return
	}

	limit := 10
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 100 {
			limit = v
		}
	}

	stats := dashboardServer.GetStats()
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

	s.runtimeMu.RLock()
	metricsCollector := s.metrics
	s.runtimeMu.RUnlock()
	if metricsCollector == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Metrics not available")
		return
	}

	history := metricsCollector.GetHistory()
	s.writeJSON(w, http.StatusOK, history)
}

// handleDNSSECStatus returns DNSSEC validation status.
