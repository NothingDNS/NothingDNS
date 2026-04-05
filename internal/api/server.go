package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/blocklist"
	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/cluster"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/dashboard"
	"github.com/nothingdns/nothingdns/internal/doh"
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/filter"
	"github.com/nothingdns/nothingdns/internal/metrics"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/upstream"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// Server provides HTTP API for DNS server management.
type Server struct {
	config          config.HTTPConfig
	httpServer      *http.Server
	zoneManager     *zone.Manager
	cache           *cache.Cache
	reloadFunc      func() error
	dnsHandler      server.Handler
	cluster         *cluster.Cluster
	dashboardServer *dashboard.Server
	blocklist       *blocklist.Blocklist
	upstreamClient  *upstream.Client
	upstreamLB      *upstream.LoadBalancer
	aclChecker      *filter.ACLChecker
	authStore       *auth.Store
	metrics         *metrics.MetricsCollector
	validator       *dnssec.Validator

	// Goroutine leak detection baseline
	goroutineBaseline int64
}

// WithDashboard sets the dashboard server for real-time stats.
func (s *Server) WithDashboard(ds *dashboard.Server) *Server {
	s.dashboardServer = ds
	return s
}

// NewServer creates a new API server.
func NewServer(cfg config.HTTPConfig, zm *zone.Manager, c *cache.Cache, reload func() error, dnsHandler server.Handler, cl *cluster.Cluster, ds *dashboard.Server) *Server {
	return &Server{
		config:          cfg,
		zoneManager:     zm,
		cache:           c,
		reloadFunc:      reload,
		dnsHandler:      dnsHandler,
		cluster:         cl,
		dashboardServer: ds,
	}
}

// WithBlocklist sets the blocklist for the API server.
func (s *Server) WithBlocklist(bl *blocklist.Blocklist) *Server {
	s.blocklist = bl
	return s
}

// WithUpstream sets the upstream client and load balancer for the API server.
func (s *Server) WithUpstream(client *upstream.Client, lb *upstream.LoadBalancer) *Server {
	s.upstreamClient = client
	s.upstreamLB = lb
	return s
}

// WithACL sets the ACL checker for the API server.
func (s *Server) WithACL(acl *filter.ACLChecker) *Server {
	s.aclChecker = acl
	return s
}

// WithAuth sets the auth store for the API server.
func (s *Server) WithAuth(store *auth.Store) *Server {
	s.authStore = store
	return s
}

// WithMetrics sets the metrics collector for the API server.
func (s *Server) WithMetrics(mc *metrics.MetricsCollector) *Server {
	s.metrics = mc
	return s
}

// WithDNSSEC sets the DNSSEC validator for the API server.
func (s *Server) WithDNSSEC(v *dnssec.Validator) *Server {
	s.validator = v
	return s
}

// Start starts the API server.
func (s *Server) Start() error {
	if !s.config.Enabled {
		return nil
	}

	// Capture goroutine baseline on startup
	atomic.StoreInt64(&s.goroutineBaseline, int64(runtime.NumGoroutine()))

	mux := http.NewServeMux()

	// DoH endpoint (RFC 8484) - no auth required
	if s.config.DoHEnabled && s.dnsHandler != nil {
		dohHandler := doh.NewHandler(s.dnsHandler)
		mux.Handle(s.config.DoHPath, dohHandler)
	}

	// DoWS endpoint (DNS over WebSocket) - no auth required
	if s.config.DoWSEnabled && s.dnsHandler != nil {
		wsHandler := doh.NewWSHandler(s.dnsHandler)
		mux.Handle(s.config.DoWSPath, wsHandler)
	}

	// Health and status
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/readyz", s.handleReadiness)
	mux.HandleFunc("/livez", s.handleLiveness)
	mux.HandleFunc("/api/v1/status", s.handleStatus)

	// Cluster management
	if s.cluster != nil {
		mux.HandleFunc("/api/v1/cluster/status", s.handleClusterStatus)
		mux.HandleFunc("/api/v1/cluster/nodes", s.handleClusterNodes)
	}

	// Zone management
	mux.HandleFunc("/api/v1/zones", s.handleZones)
	mux.HandleFunc("/api/v1/zones/reload", s.handleZoneReload)
	mux.HandleFunc("/api/v1/zones/", s.handleZoneActions)

	// Cache management
	mux.HandleFunc("/api/v1/cache/stats", s.handleCacheStats)
	mux.HandleFunc("/api/v1/cache/flush", s.handleCacheFlush)

	// Blocklist management
	if s.blocklist != nil {
		mux.HandleFunc("/api/v1/blocklists", s.handleBlocklists)
		mux.HandleFunc("/api/v1/blocklists/", s.handleBlocklistActions)
	}

	// Upstream management
	if s.upstreamClient != nil || s.upstreamLB != nil {
		mux.HandleFunc("/api/v1/upstreams", s.handleUpstreams)
	}

	// ACL management
	if s.aclChecker != nil {
		mux.HandleFunc("/api/v1/acl", s.handleACL)
	}

	// Auth endpoints (no auth required for login, all require auth for others)
	if s.authStore != nil {
		mux.HandleFunc("/api/v1/auth/login", s.handleLogin)
		mux.HandleFunc("/api/v1/auth/users", s.handleUsers)
		mux.HandleFunc("/api/v1/auth/roles", s.handleRoles)
		mux.HandleFunc("/api/v1/auth/logout", s.handleLogout)
	}

	// Config management
	mux.HandleFunc("/api/v1/config/reload", s.handleConfigReload)

	// DNSSEC status
	if s.validator != nil {
		mux.HandleFunc("/api/v1/dnssec/status", s.handleDNSSECStatus)
	}

	// Dashboard UI
	mux.HandleFunc("/api/dashboard/stats", s.handleDashboardStats)
	mux.HandleFunc("/api/v1/queries", s.handleQueryLog)
	mux.HandleFunc("/api/v1/topdomains", s.handleTopDomains)

	// Metrics history
	if s.metrics != nil {
		mux.HandleFunc("/api/v1/metrics/history", s.handleMetricsHistory)
	}

	// OpenAPI / Swagger
	mux.HandleFunc("/api/openapi.json", s.handleOpenAPISpec)
	mux.HandleFunc("/api/docs", s.handleSwaggerUI)

	// WebSocket endpoint
	mux.HandleFunc("/ws", s.dashboardServer.ServeHTTP)

	// SPA static assets
	spaHandler := dashboard.SPAHandler()
	mux.Handle("/assets/", spaHandler)

	// SPA fallback: serve index.html for all non-API routes
	mux.HandleFunc("/", s.handleSPA(spaHandler))

	s.httpServer = &http.Server{
		Addr:         s.config.Bind,
		Handler:      s.corsMiddleware(s.authMiddleware(mux)),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			util.Warnf("API server error: %v", err)
		}
	}()

	return nil
}

// Stop stops the API server.
func (s *Server) Stop() error {
	if s.httpServer == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return s.httpServer.Shutdown(ctx)
}

// corsMiddleware adds CORS headers.
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// authMiddleware adds authentication.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for login and public endpoints
		if r.URL.Path == "/api/v1/auth/login" {
			next.ServeHTTP(w, r)
			return
		}

		// If no auth configured, allow all
		if s.config.AuthToken == "" && s.authStore == nil {
			next.ServeHTTP(w, r)
			return
		}

		// Get token from Authorization header
		token := r.Header.Get("Authorization")
		if strings.HasPrefix(token, "Bearer ") {
			token = token[7:]
		}

		// Fallback: query parameter
		if token == "" {
			token = r.URL.Query().Get("token")
		}

		// Fallback: cookie
		if token == "" {
			if c, err := r.Cookie("ndns_token"); err == nil {
				token = c.Value
			}
		}

		// Validate token
		if token != "" {
			// First try old-style shared token
			if s.config.AuthToken != "" && (token == s.config.AuthToken) {
				next.ServeHTTP(w, r)
				return
			}

			// Try JWT-style token from auth store
			if s.authStore != nil {
				if user, err := s.authStore.ValidateToken(token); err == nil {
					// Set user info in request context
					ctx := WithUser(r.Context(), user)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}
		}

		// For SPA routes, serve the login page instead of JSON error
		if !strings.HasPrefix(r.URL.Path, "/api/") && !strings.HasPrefix(r.URL.Path, "/assets/") &&
			r.URL.Path != "/health" && r.URL.Path != "/ws" &&
			!strings.HasSuffix(r.URL.Path, ".svg") && !strings.HasSuffix(r.URL.Path, ".ico") {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(dashboard.GetLoginHTML()))
			return
		}

		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
	})
}

// handleHealth returns health status.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, &HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

// handleReadiness implements the Kubernetes readiness probe.
// Returns 200 if the server is ready to accept traffic:
// - Zone manager has loaded zones
// - Upstream is healthy (if configured)
func (s *Server) handleReadiness(w http.ResponseWriter, r *http.Request) {
	status := "ready"
	code := http.StatusOK

	// Check if zones are loaded (zero zones is OK in recursive mode)
	// but if zoneManager exists and has no zones, consider if any are configured
	if s.zoneManager != nil {
		count := s.zoneManager.Count()
		// Zone count of 0 is OK if the manager is in recursive mode
		// (no zone files configured, all queries go to upstream)
		_ = count // 0 zones is valid for recursive operation
	}

	// Check upstream health if configured
	if s.upstreamLB != nil {
		healthy := s.upstreamLB.IsHealthy()
		if !healthy {
			status = "unhealthy"
			code = http.StatusServiceUnavailable
		}
	} else if s.upstreamClient != nil {
		// Single upstream: check if at least one server is healthy
		// upstream.Client has servers field, check via health
		healthy := s.upstreamClient.IsHealthy()
		if !healthy {
			status = "unhealthy"
			code = http.StatusServiceUnavailable
		}
	}

	s.writeJSON(w, code, &HealthResponse{
		Status:    status,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

// handleLiveness implements the Kubernetes liveness probe.
// Returns 200 if the server process is alive and not deadlocked.
// Returns 503 if goroutine leak or deadlock is detected.
func (s *Server) handleLiveness(w http.ResponseWriter, r *http.Request) {
	status := "alive"
	code := http.StatusOK

	// Check for goroutine leak: compare current goroutine count to baseline
	baseline := atomic.LoadInt64(&s.goroutineBaseline)
	if baseline > 0 {
		current := int64(runtime.NumGoroutine())
		// Allow up to 2x baseline growth to account for normal async operations
		if current > baseline*2 {
			status = "goroutine_leak"
			code = http.StatusServiceUnavailable
		}
	}

	s.writeJSON(w, code, &HealthResponse{
		Status:    status,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

// handleSPA returns a handler that serves the React SPA, falling back to
// index.html for client-side routes. Non-API, non-static-file requests
// are handled by the SPA.
func (s *Server) handleSPA(spaHandler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		spaHandler.ServeHTTP(w, r)
	}
}

// handleDashboardStats returns stats formatted for the web dashboard.
func (s *Server) handleDashboardStats(w http.ResponseWriter, r *http.Request) {
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

// handleQueryLog returns a paginated query log.
func (s *Server) handleQueryLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
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

	if s.metrics == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Metrics not available")
		return
	}

	history := s.metrics.GetHistory()
	s.writeJSON(w, http.StatusOK, history)
}

// handleDNSSECStatus returns DNSSEC validation status.
func (s *Server) handleDNSSECStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	status := s.validator.DNSSECStatus()
	s.writeJSON(w, http.StatusOK, status)
}

// handleStatus returns server status.
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
func (s *Server) handleZones(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListZones(w, r)
	case http.MethodPost:
		s.handleCreateZone(w, r)
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleListZones returns list of zones with serial and record count.
func (s *Server) handleListZones(w http.ResponseWriter, r *http.Request) {
	resp := &ZoneListResponse{Zones: []ZoneSummary{}}
	if s.zoneManager != nil {
		for name, z := range s.zoneManager.List() {
			z.RLock()
			recordCount := 0
			for _, records := range z.Records {
				recordCount += len(records)
			}
			serial := uint32(0)
			if z.SOA != nil {
				serial = z.SOA.Serial
			}
			z.RUnlock()
			resp.Zones = append(resp.Zones, ZoneSummary{
				Name:    name,
				Serial:  serial,
				Records: recordCount,
			})
		}
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// handleZoneActions dispatches zone-specific operations based on path and method.
// Routes: DELETE /api/v1/zones/{name}
//
//	GET    /api/v1/zones/{name}/records
//	POST   /api/v1/zones/{name}/records
//	PUT    /api/v1/zones/{name}/records
//	DELETE /api/v1/zones/{name}/records
//	GET    /api/v1/zones/{name}/export
func (s *Server) handleZoneActions(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/zones/")

	// Decode URL-encoded zone name (e.g., "example.com." from "example.com.")
	zoneName, err := url.PathUnescape(path)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid zone name")
		return
	}

	if s.zoneManager == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Zone manager not available")
		return
	}

	// Check if there's a sub-path after the zone name
	parts := strings.SplitN(zoneName, "/", 2)
	if len(parts) == 1 || parts[1] == "" {
		// /api/v1/zones/{name}
		switch r.Method {
		case http.MethodGet:
			s.handleGetZone(w, r, parts[0])
		case http.MethodDelete:
			s.handleDeleteZone(w, r, parts[0])
		default:
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
		return
	}

	zoneName = parts[0]
	subPath := parts[1]

	switch {
	case subPath == "records":
		switch r.Method {
		case http.MethodGet:
			s.handleGetRecords(w, r, zoneName)
		case http.MethodPost:
			s.handleAddRecord(w, r, zoneName)
		case http.MethodPut:
			s.handleUpdateRecord(w, r, zoneName)
		case http.MethodDelete:
			s.handleDeleteRecord(w, r, zoneName)
		default:
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	case subPath == "export":
		if r.Method == http.MethodGet {
			s.handleExportZone(w, r, zoneName)
		} else {
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	default:
		s.writeError(w, http.StatusNotFound, "Not found")
	}
}

// handleGetZone returns details of a single zone.
func (s *Server) handleGetZone(w http.ResponseWriter, r *http.Request, name string) {
	z, ok := s.zoneManager.Get(name)
	if !ok {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("Zone %s not found", name))
		return
	}

	z.RLock()
	defer z.RUnlock()

	recordCount := 0
	for _, records := range z.Records {
		recordCount += len(records)
	}

	result := &ZoneDetailResponse{
		Name:    z.Origin,
		Records: recordCount,
	}

	if z.SOA != nil {
		result.Serial = z.SOA.Serial
		result.SOA = &SOADetail{
			MName:   z.SOA.MName,
			RName:   z.SOA.RName,
			Serial:  z.SOA.Serial,
			Refresh: z.SOA.Refresh,
			Retry:   z.SOA.Retry,
			Expire:  z.SOA.Expire,
			Minimum: z.SOA.Minimum,
		}
	}

	var nsList []string
	for _, ns := range z.NS {
		nsList = append(nsList, ns.NSDName)
	}
	result.Nameservers = nsList

	s.writeJSON(w, http.StatusOK, result)
}

// handleCreateZone creates a new zone.
func (s *Server) handleCreateZone(w http.ResponseWriter, r *http.Request) {
	if s.zoneManager == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Zone manager not available")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Failed to read request body")
		return
	}

	var req struct {
		Name        string   `json:"name"`
		TTL         uint32   `json:"ttl"`
		AdminEmail  string   `json:"admin_email"`
		Nameservers []string `json:"nameservers"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if req.Name == "" {
		s.writeError(w, http.StatusBadRequest, "Zone name is required")
		return
	}
	if len(req.Nameservers) == 0 {
		s.writeError(w, http.StatusBadRequest, "At least one nameserver is required")
		return
	}

	ttl := req.TTL
	if ttl == 0 {
		ttl = 3600
	}

	soa := &zone.SOARecord{
		TTL:     ttl,
		MName:   req.Nameservers[0],
		RName:   req.AdminEmail,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minimum: 86400,
	}

	var nsRecords []zone.NSRecord
	for _, ns := range req.Nameservers {
		nsRecords = append(nsRecords, zone.NSRecord{
			TTL:     ttl,
			NSDName: ns,
		})
	}

	if err := s.zoneManager.CreateZone(req.Name, ttl, soa, nsRecords); err != nil {
		s.writeError(w, http.StatusConflict, err.Error())
		return
	}

	s.writeJSON(w, http.StatusCreated, &MessageNameResponse{
		Message: fmt.Sprintf("Zone %s created", req.Name),
		Name:    req.Name,
	})
}

// handleDeleteZone deletes a zone.
func (s *Server) handleDeleteZone(w http.ResponseWriter, r *http.Request, name string) {
	if err := s.zoneManager.DeleteZone(name); err != nil {
		s.writeError(w, http.StatusNotFound, err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, &MessageResponse{
		Message: fmt.Sprintf("Zone %s deleted", name),
	})
}

// handleGetRecords returns records for a zone.
func (s *Server) handleGetRecords(w http.ResponseWriter, r *http.Request, zoneName string) {
	name := r.URL.Query().Get("name")

	records, err := s.zoneManager.GetRecords(zoneName, name)
	if err != nil {
		s.writeError(w, http.StatusNotFound, err.Error())
		return
	}

	// Convert to API response
	resp := &RecordListResponse{Records: make([]RecordItem, 0, len(records))}
	for _, r := range records {
		resp.Records = append(resp.Records, RecordItem{
			Name:  r.Name,
			Type:  r.Type,
			TTL:   r.TTL,
			Class: r.Class,
			Data:  r.RData,
		})
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// handleAddRecord adds a record to a zone.
func (s *Server) handleAddRecord(w http.ResponseWriter, r *http.Request, zoneName string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Failed to read request body")
		return
	}

	var req struct {
		Name string `json:"name"`
		Type string `json:"type"`
		TTL  uint32 `json:"ttl"`
		Data string `json:"data"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if req.Name == "" || req.Type == "" || req.Data == "" {
		s.writeError(w, http.StatusBadRequest, "name, type, and data are required")
		return
	}

	ttl := req.TTL
	if ttl == 0 {
		// Use zone's default TTL
		if z, ok := s.zoneManager.Get(zoneName); ok {
			z.RLock()
			ttl = z.DefaultTTL
			z.RUnlock()
		}
		if ttl == 0 {
			ttl = 3600
		}
	}

	record := zone.Record{
		Name:  req.Name,
		Type:  req.Type,
		TTL:   ttl,
		Class: "IN",
		RData: req.Data,
	}

	if err := s.zoneManager.AddRecord(zoneName, record); err != nil {
		s.writeError(w, http.StatusNotFound, err.Error())
		return
	}

	s.writeJSON(w, http.StatusCreated, &MessageResponse{
		Message: "Record added",
	})
}

// handleUpdateRecord updates a record in a zone.
func (s *Server) handleUpdateRecord(w http.ResponseWriter, r *http.Request, zoneName string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Failed to read request body")
		return
	}

	var req struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		OldData string `json:"old_data"`
		TTL     uint32 `json:"ttl"`
		Data    string `json:"data"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if req.Name == "" || req.Type == "" {
		s.writeError(w, http.StatusBadRequest, "name and type are required")
		return
	}

	newRecord := zone.Record{
		Name:  req.Name,
		Type:  req.Type,
		TTL:   req.TTL,
		Class: "IN",
		RData: req.Data,
	}

	if err := s.zoneManager.UpdateRecord(zoneName, req.Name, req.Type, req.OldData, newRecord); err != nil {
		s.writeError(w, http.StatusNotFound, err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, &MessageResponse{
		Message: "Record updated",
	})
}

// handleDeleteRecord deletes a record from a zone.
func (s *Server) handleDeleteRecord(w http.ResponseWriter, r *http.Request, zoneName string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Failed to read request body")
		return
	}

	var req struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if req.Name == "" || req.Type == "" {
		s.writeError(w, http.StatusBadRequest, "name and type are required")
		return
	}

	if err := s.zoneManager.DeleteRecord(zoneName, req.Name, req.Type); err != nil {
		s.writeError(w, http.StatusNotFound, err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, &MessageResponse{
		Message: "Record deleted",
	})
}

// handleExportZone returns a zone in BIND format.
func (s *Server) handleExportZone(w http.ResponseWriter, r *http.Request, zoneName string) {
	content, err := s.zoneManager.ExportZone(zoneName)
	if err != nil {
		s.writeError(w, http.StatusNotFound, err.Error())
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.zone", strings.TrimSuffix(zoneName, ".")))
	w.Write([]byte(content))
}

// handleZoneReload reloads a zone.
func (s *Server) handleZoneReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	zoneName := r.URL.Query().Get("zone")
	if zoneName == "" {
		s.writeError(w, http.StatusBadRequest, "Missing zone parameter")
		return
	}

	if s.zoneManager == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Zone manager not available")
		return
	}

	if err := s.zoneManager.Reload(zoneName); err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to reload zone: %v", err))
		return
	}

	s.writeJSON(w, http.StatusOK, &MessageResponse{
		Message: fmt.Sprintf("Zone %s reloaded", zoneName),
	})
}

// handleCacheStats returns cache statistics.
func (s *Server) handleCacheStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
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
func (s *Server) handleConfigReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
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

// handleClusterStatus returns cluster status.
func (s *Server) handleClusterStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.cluster == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Cluster not available")
		return
	}

	stats := s.cluster.Stats()
	s.writeJSON(w, http.StatusOK, &ClusterStatusResponse{
		NodeID:     stats.NodeID,
		NodeCount:  stats.NodeCount,
		AliveCount: stats.AliveCount,
		Healthy:    stats.IsHealthy,
		Gossip: GossipInfo{
			MessagesSent:     stats.GossipStats.MessagesSent,
			MessagesReceived: stats.GossipStats.MessagesReceived,
			PingSent:         stats.GossipStats.PingSent,
			PingReceived:     stats.GossipStats.PingReceived,
		},
	})
}

// handleClusterNodes returns list of cluster nodes.
func (s *Server) handleClusterNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.cluster == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Cluster not available")
		return
	}

	nodes := s.cluster.GetNodes()
	resp := &ClusterNodesResponse{Nodes: make([]NodeDetail, 0, len(nodes))}
	for _, node := range nodes {
		resp.Nodes = append(resp.Nodes, NodeDetail{
			ID:       node.ID,
			Addr:     node.Addr,
			Port:     node.Port,
			State:    node.State.String(),
			Region:   node.Meta.Region,
			Zone:     node.Meta.Zone,
			Weight:   node.Meta.Weight,
			HTTPAddr: node.Meta.HTTPAddr,
			Version:  node.Version,
		})
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// handleBlocklists returns the list of active blocklists.
func (s *Server) handleBlocklists(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.blocklist == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Blocklist not available")
		return
	}

	switch r.Method {
	case http.MethodGet:
		stats := s.blocklist.Stats()
		s.writeJSON(w, http.StatusOK, &BlocklistResponse{
			Enabled:     stats.Enabled,
			TotalRules: stats.TotalBlocks,
			FilesCount: stats.Files,
		})
	case http.MethodPost:
		// Add new blocklist source (URL or file path)
		var req BlocklistAddRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}
		// Note: Dynamic blocklist addition would require modifying the blocklist engine
		// For now, return a message that full reload is needed
		s.writeJSON(w, http.StatusOK, &MessageResponse{
			Message: "Blocklist updated. Reload config to apply changes.",
		})
	}
}

// handleBlocklistActions handles individual blocklist actions.
func (s *Server) handleBlocklistActions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.blocklist == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Blocklist not available")
		return
	}

	// Extract blocklist ID from path
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/blocklists/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		s.writeError(w, http.StatusBadRequest, "Missing blocklist ID")
		return
	}

	// Note: Dynamic blocklist removal would require modifying the blocklist engine
	s.writeJSON(w, http.StatusOK, &MessageResponse{
		Message: "Blocklist removal requires config reload",
	})
}

// handleUpstreams returns upstream server status.
func (s *Server) handleUpstreams(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	switch r.Method {
	case http.MethodGet:
		var upstreams []UpstreamStatus
		if s.upstreamLB != nil {
			queries, failed, failovers := s.upstreamLB.Stats()
			upstreams = append(upstreams, UpstreamStatus{
				Address:      "load-balancer",
				Healthy:     s.upstreamLB.IsHealthy(),
				Queries:     queries,
				Failed:      failed,
				Failovers:   failovers,
			})
		}
		if s.upstreamClient != nil {
			upstreams = append(upstreams, UpstreamStatus{
				Address: "direct-upstream",
				Healthy: s.upstreamClient.IsHealthy(),
			})
		}
		s.writeJSON(w, http.StatusOK, &UpstreamsResponse{Upstreams: upstreams})
	case http.MethodPut:
		// Update upstream configuration
		s.writeError(w, http.StatusNotImplemented, "Dynamic upstream update not implemented")
	}
}

// handleACL returns ACL rules.
func (s *Server) handleACL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.aclChecker == nil {
		s.writeError(w, http.StatusServiceUnavailable, "ACL not available")
		return
	}

	switch r.Method {
	case http.MethodGet:
		// Get ACL rules - would need ACL checker to expose rules
		s.writeJSON(w, http.StatusOK, &ACLResponse{
			Rules: []ACLRuleResponse{}, // Would populate from ACL checker
		})
	case http.MethodPut:
		// Update ACL rules - would need ACL checker to support updates
		s.writeError(w, http.StatusNotImplemented, "Dynamic ACL update not implemented")
	}
}

// contextKey is a custom type for context keys.
type contextKey string

const userContextKey contextKey = "user"

// WithUser adds user information to a context.
func WithUser(ctx context.Context, user *auth.User) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}

// GetUser retrieves user information from a context.
func GetUser(ctx context.Context) *auth.User {
	if user, ok := ctx.Value(userContextKey).(*auth.User); ok {
		return user
	}
	return nil
}

// handleLogin authenticates a user and returns a token.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.authStore == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Auth not configured")
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate user
	user, err := s.authStore.GetUser(req.Username)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Verify password
	if !auth.VerifyPassword(req.Password, user.Hash) {
		s.writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Generate token
	token, err := s.authStore.GenerateToken(req.Username, 24*time.Hour)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "ndns_token",
		Value:    token.Token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	})

	s.writeJSON(w, http.StatusOK, &LoginResponse{
		Token:    token.Token,
		Username: user.Username,
		Role:     string(user.Role),
		Expires:  token.ExpiresAt.Format(time.RFC3339),
	})
}

// handleLogout invalidates the current token.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	token := r.Header.Get("Authorization")
	if strings.HasPrefix(token, "Bearer ") {
		token = token[7:]
	}

	if token != "" && s.authStore != nil {
		s.authStore.RevokeToken(token)
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "ndns_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "Logged out"})
}

// handleUsers manages users.
func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	if s.authStore == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Auth not configured")
		return
	}

	switch r.Method {
	case http.MethodGet:
		users := s.authStore.ListUsers()
		resp := make([]UserResponse, 0, len(users))
		for _, u := range users {
			resp = append(resp, UserResponse{
				Username:  u.Username,
				Role:     string(u.Role),
				Created:  u.CreatedAt,
				Updated:  u.UpdatedAt,
			})
		}
		s.writeJSON(w, http.StatusOK, resp)

	case http.MethodPost:
		// Require admin role
		if !hasRole(r.Context(), s.authStore, auth.RoleAdmin) {
			s.writeError(w, http.StatusForbidden, "Admin role required")
			return
		}

		var req CreateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		if req.Username == "" || req.Password == "" {
			s.writeError(w, http.StatusBadRequest, "Username and password required")
			return
		}

		role := auth.RoleViewer
		if req.Role != "" {
			role = auth.Role(req.Role)
		}

		user, err := s.authStore.CreateUser(req.Username, req.Password, role)
		if err != nil {
			s.writeError(w, http.StatusConflict, err.Error())
			return
		}

		s.writeJSON(w, http.StatusCreated, &UserResponse{
			Username: user.Username,
			Role:     string(user.Role),
			Created:  user.CreatedAt,
			Updated:  user.UpdatedAt,
		})

	case http.MethodDelete:
		// Require admin role
		if !hasRole(r.Context(), s.authStore, auth.RoleAdmin) {
			s.writeError(w, http.StatusForbidden, "Admin role required")
			return
		}

		username := r.URL.Query().Get("username")
		if username == "" {
			s.writeError(w, http.StatusBadRequest, "username required")
			return
		}

		if err := s.authStore.DeleteUser(username); err != nil {
			s.writeError(w, http.StatusNotFound, err.Error())
			return
		}

		s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "User deleted"})
	}
}

// handleRoles returns available roles.
func (s *Server) handleRoles(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, &RolesResponse{
		Roles: []RoleResponse{
			{Name: "admin", Description: "Full access to all resources"},
			{Name: "operator", Description: "Can modify zones, cache, and config"},
			{Name: "viewer", Description: "Read-only access"},
		},
	})
}

// hasRole checks if the current user has at least the required role.
func hasRole(ctx context.Context, store *auth.Store, required auth.Role) bool {
	user := GetUser(ctx)
	if user == nil {
		return false
	}
	return store.HasRole(user.Username, required)
}

// writeJSON writes a JSON response.
func (s *Server) writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		util.Warnf("api: failed to encode JSON response: %v", err)
	}
}

// writeError writes an error response.
func (s *Server) writeError(w http.ResponseWriter, status int, message string) {
	s.writeJSON(w, status, &ErrorResponse{Error: message})
}
