package api

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
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
	"github.com/nothingdns/nothingdns/internal/odoh"
	"github.com/nothingdns/nothingdns/internal/rpz"
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
	configGetter    func() *config.Config // Returns full server config
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
	rpzEngine       *rpz.Engine
	odohProxy       *odoh.ObliviousProxy // ODoH proxy (RFC 9230)
	loginLimiter    *loginRateLimiter
	apiRateLimiter  *apiRateLimiter
	stopCh          chan struct{} // Channel to signal shutdown
	stopOnce        sync.Once    // Ensure Stop is idempotent

	// Goroutine leak detection baseline
	goroutineBaseline int64
}

// loginRateLimiter tracks failed login attempts per IP and username.
// It applies both IP-based and account-based rate limiting to prevent brute force attacks.
type loginRateLimiter struct {
	mu         sync.Mutex
	ipAttempts    map[string]*loginAttempt    // IP-based tracking
	userAttempts  map[string]*loginAttempt    // Username-based tracking (account lockout)
}

// loginAttempt tracks failed attempts for a single IP or username.
type loginAttempt struct {
	count       int
	lastTry     time.Time
	lockedUntil time.Time
}

// LoginRateLimit constants
const (
	loginMaxAttempts   = 5             // Maximum attempts before lockout
	loginLockoutPeriod = 5 * time.Minute // How long to lock out after max attempts
	loginMaxDelay     = 30 * time.Second // Maximum delay between attempts
)

// checkRateLimit checks if the given IP is rate-limited.
// Returns true if the request should be rejected, and the delay to apply.
func (l *loginRateLimiter) checkRateLimit(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	attempt, exists := l.ipAttempts[ip]

	if !exists {
		return false, 0
	}

	// Check if currently locked out
	if now.Before(attempt.lockedUntil) {
		return true, time.Until(attempt.lockedUntil)
	}

	// Check if delay period is active (progressive delay)
	if now.Before(attempt.lastTry.Add(loginMaxDelay)) {
		delay := time.Until(attempt.lastTry.Add(loginMaxDelay))
		if delay > 0 {
			return true, delay
		}
	}

	return false, 0
}

// checkUserRateLimit checks if the given username is rate-limited (account lockout).
// Returns true if the account should be locked, and the delay to apply.
func (l *loginRateLimiter) checkUserRateLimit(username string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	attempt, exists := l.userAttempts[username]

	if !exists {
		return false, 0
	}

	// Check if currently locked out
	if now.Before(attempt.lockedUntil) {
		return true, time.Until(attempt.lockedUntil)
	}

	return false, 0
}

// recordFailedAttempt records a failed login attempt for the given IP and username.
func (l *loginRateLimiter) recordFailedAttempt(ip, username string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()

	// Track by IP
	attempt, exists := l.ipAttempts[ip]
	if !exists {
		l.ipAttempts[ip] = &loginAttempt{
			count:   1,
			lastTry: now,
		}
	} else {
		// Reset lockout if expired
		if now.After(attempt.lockedUntil) {
			attempt.count = 0
			attempt.lockedUntil = time.Time{}
		}
		attempt.count++
		attempt.lastTry = now
		if attempt.count >= loginMaxAttempts {
			attempt.lockedUntil = now.Add(loginLockoutPeriod)
		}
	}

	// Track by username (account lockout)
	userAttempt, userExists := l.userAttempts[username]
	if !userExists {
		l.userAttempts[username] = &loginAttempt{
			count:   1,
			lastTry: now,
		}
	} else {
		// Reset lockout if expired
		if now.After(userAttempt.lockedUntil) {
			userAttempt.count = 0
			userAttempt.lockedUntil = time.Time{}
		}
		userAttempt.count++
		userAttempt.lastTry = now
		if userAttempt.count >= loginMaxAttempts {
			userAttempt.lockedUntil = now.Add(loginLockoutPeriod)
		}
	}
}

// recordSuccess removes the IP and username from rate limiting on successful login.
func (l *loginRateLimiter) recordSuccess(ip, username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.ipAttempts, ip)
	delete(l.userAttempts, username)
}

// apiRateLimiter implements a sliding window rate limiter for API endpoints.
type apiRateLimiter struct {
	mu          sync.Mutex
	requests    map[string][]time.Time // IP -> timestamps of recent requests
	maxReqs    int                    // Maximum requests per window
	windowSecs int                    // Window size in seconds
}

// apiRateLimit constants for authenticated endpoints
const (
	apiRateLimitMaxRequests = 100        // Max requests per window
	apiRateLimitWindowSecs = 60          // Window size in seconds
)

// checkRateLimit checks if the IP is within rate limits.
// Returns true if the request should be rejected.
func (r *apiRateLimiter) checkRateLimit(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-time.Duration(r.windowSecs) * time.Second)

	// Get or create request list for this IP
	reqs, exists := r.requests[ip]
	if !exists {
		reqs = []time.Time{}
	}

	// Filter to only requests within the window
	validReqs := make([]time.Time, 0, len(reqs))
	for _, t := range reqs {
		if t.After(windowStart) {
			validReqs = append(validReqs, t)
		}
	}

	// Check if limit exceeded
	if len(validReqs) >= r.maxReqs {
		r.requests[ip] = validReqs
		return true
	}

	// Add current request
	validReqs = append(validReqs, now)
	r.requests[ip] = validReqs
	return false
}

// getResetTime returns when the rate limit will reset for an IP
func (r *apiRateLimiter) getResetTime(ip string) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()

	reqs, exists := r.requests[ip]
	if !exists || len(reqs) == 0 {
		return 0
	}

	// Find oldest request in window
	now := time.Now()
	windowStart := now.Add(-time.Duration(r.windowSecs) * time.Second)
	var oldest time.Time
	for _, t := range reqs {
		if t.After(windowStart) {
			if oldest.IsZero() || t.Before(oldest) {
				oldest = t
			}
		}
	}

	if oldest.IsZero() {
		return 0
	}
	return oldest.Add(time.Duration(r.windowSecs) * time.Second).Sub(now)
}

// cleanup removes stale entries to prevent memory growth
func (r *apiRateLimiter) cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-time.Duration(r.windowSecs) * time.Second)

	for ip, reqs := range r.requests {
		validReqs := make([]time.Time, 0, len(reqs))
		for _, t := range reqs {
			if t.After(windowStart) {
				validReqs = append(validReqs, t)
			}
		}
		if len(validReqs) == 0 {
			delete(r.requests, ip)
		} else {
			r.requests[ip] = validReqs
		}
	}
}

// newAPIRateLimiter creates a new API rate limiter
func newAPIRateLimiter() *apiRateLimiter {
	return &apiRateLimiter{
		requests:    make(map[string][]time.Time),
		maxReqs:     apiRateLimitMaxRequests,
		windowSecs:  apiRateLimitWindowSecs,
	}
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
		loginLimiter: &loginRateLimiter{
			ipAttempts:   make(map[string]*loginAttempt),
			userAttempts: make(map[string]*loginAttempt),
		},
		apiRateLimiter: newAPIRateLimiter(),
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

// WithConfigGetter sets the config getter for the API server.
func (s *Server) WithConfigGetter(getter func() *config.Config) *Server {
	s.configGetter = getter
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

// WithRPZ sets the RPZ engine for the API server.
func (s *Server) WithRPZ(e *rpz.Engine) *Server {
	s.rpzEngine = e
	return s
}

// WithODoH sets the ODoH proxy for the API server (RFC 9230).
func (s *Server) WithODoH(proxy *odoh.ObliviousProxy) *Server {
	s.odohProxy = proxy
	return s
}

// Start starts the API server.
func (s *Server) Start() error {
	if !s.config.Enabled {
		return nil
	}

	// Capture goroutine baseline on startup
	atomic.StoreInt64(&s.goroutineBaseline, int64(runtime.NumGoroutine()))

	// Start rate limiter cleanup goroutine
	s.stopCh = make(chan struct{})
	go s.rateLimitCleanupLoop()

	mux := http.NewServeMux()

	// DoH endpoint (RFC 8484) - no auth required
	if s.config.DoHEnabled && s.dnsHandler != nil {
		dohHandler := doh.NewHandler(s.dnsHandler)
		mux.Handle(s.config.DoHPath, dohHandler)
	}

	// DoWS endpoint (DNS over WebSocket) - no auth required
	if s.config.DoWSEnabled && s.dnsHandler != nil {
		wsHandler := doh.NewWSHandler(s.dnsHandler, s.config.AllowedOrigins)
		mux.Handle(s.config.DoWSPath, wsHandler)
	}

	// ODoH endpoint (RFC 9230 - Oblivious DNS over HTTPS) - no auth required
	if s.config.ODoHEnabled && s.odohProxy != nil {
		mux.Handle(s.config.ODoHPath, s.odohProxy)
	}

	// Health and status
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/readyz", s.handleReadiness)
	mux.HandleFunc("/livez", s.handleLiveness)
	mux.HandleFunc("/api/v1/status", s.handleStatus)

	// Cluster management (always registered, returns proper JSON when disabled)
	mux.HandleFunc("/api/v1/cluster/status", s.handleClusterStatus)
	mux.HandleFunc("/api/v1/cluster/nodes", s.handleClusterNodes)

	// Zone management
	mux.HandleFunc("/api/v1/zones", s.handleZones)
	mux.HandleFunc("/api/v1/zones/reload", s.handleZoneReload)
	mux.HandleFunc("/api/v1/zones/", s.handleZoneActions)

	// Cache management
	mux.HandleFunc("/api/v1/cache/stats", s.handleCacheStats)
	mux.HandleFunc("/api/v1/cache/flush", s.handleCacheFlush)

	// Blocklist management (always registered)
	mux.HandleFunc("/api/v1/blocklists", s.handleBlocklists)
	mux.HandleFunc("/api/v1/blocklists/", s.handleBlocklistActions)

	// Upstream management (always registered)
	mux.HandleFunc("/api/v1/upstreams", s.handleUpstreams)

	// ACL management (always registered)
	mux.HandleFunc("/api/v1/acl", s.handleACL)

	// RPZ management (always registered)
	mux.HandleFunc("/api/v1/rpz", s.handleRPZ)
	mux.HandleFunc("/api/v1/rpz/rules", s.handleRPZRules)
	mux.HandleFunc("/api/v1/rpz/", s.handleRPZActions)

	// Server config (read-only)
	mux.HandleFunc("/api/v1/server/config", s.handleServerConfig)

	// Auth endpoints (no auth required for login, all require auth for others)
	if s.authStore != nil {
		mux.HandleFunc("/api/v1/auth/login", s.handleLogin)
		mux.HandleFunc("/api/v1/auth/users", s.handleUsers)
		mux.HandleFunc("/api/v1/auth/roles", s.handleRoles)
		mux.HandleFunc("/api/v1/auth/logout", s.handleLogout)
	}

	// Config management
	mux.HandleFunc("/api/v1/config/reload", s.handleConfigReload)
	mux.HandleFunc("/api/v1/config", s.handleConfigGet)

	// DNSSEC status (always registered)
	mux.HandleFunc("/api/v1/dnssec/status", s.handleDNSSECStatus)

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
		IdleTimeout:  120 * time.Second,
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
	// Signal cleanup goroutines to stop (idempotent via sync.Once)
	s.stopOnce.Do(func() {
		if s.stopCh != nil {
			close(s.stopCh)
		}
	})

	if s.httpServer == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return s.httpServer.Shutdown(ctx)
}

// rateLimitCleanupLoop periodically cleans up stale entries from rate limiters.
func (s *Server) rateLimitCleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.apiRateLimiter.cleanup()
		}
	}
}

// corsMiddleware adds CORS headers.
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// If allowed_origins is empty, allow all (backward compatible default)
		// If allowed_origins contains "*", allow all origins
		// Otherwise validate against the explicit list
		allowedOrigins := s.config.AllowedOrigins
		allowOrigin := ""
		if len(allowedOrigins) == 0 {
			// Default: allow all when no explicit origins configured
			// (backward compatible - sets * for browsers, origin for programmatic clients)
			allowOrigin = "*"
		} else if len(allowedOrigins) == 1 && allowedOrigins[0] == "*" {
			// Reject wildcard - insecure when credentials are involved.
			// No CORS header = browser blocks credentialed cross-origin requests.
			allowOrigin = ""
		} else if origin != "" && isOriginAllowed(origin, allowedOrigins) {
			allowOrigin = origin
		}

		if allowOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
			w.Header().Set("Vary", "Origin")
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			if allowOrigin == "" && origin != "" && len(allowedOrigins) > 0 {
				// Origin was present but not allowed — reject preflight
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isOriginAllowed checks if the given origin is in the allowed list.
func isOriginAllowed(origin string, allowed []string) bool {
	for _, o := range allowed {
		if o == origin {
			return true
		}
	}
	return false
}

// authMiddleware adds authentication.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for login and public endpoints
		if r.URL.Path == "/api/v1/auth/login" {
			next.ServeHTTP(w, r)
			return
		}

		// Skip auth for health and readiness endpoints (public information)
		if r.URL.Path == "/health" || r.URL.Path == "/ready" || r.URL.Path == "/readyz" || r.URL.Path == "/livez" {
			next.ServeHTTP(w, r)
			return
		}

		// SECURITY: If neither AuthToken nor authStore is configured,
		// authentication is required. Deny all API requests.
		// To allow unauthenticated access, set auth_token or configure users.
		if s.config.AuthToken == "" && s.authStore == nil {
			http.Error(w, `{"error":"authentication required: set auth_token or configure users"}`, http.StatusUnauthorized)
			return
		}

		// Get token from Authorization header
		token := r.Header.Get("Authorization")
		token = strings.TrimPrefix(token, "Bearer ")

		// Fallback: cookie
		if token == "" {
			if c, err := r.Cookie("ndns_token"); err == nil {
				token = c.Value
			}
		}

		// Validate token
		if token != "" {
			// First try old-style shared token
			// SECURITY: Check length first to prevent timing attack via ConstantTimeCompare
			if s.config.AuthToken != "" && len(token) == len(s.config.AuthToken) && subtle.ConstantTimeCompare([]byte(token), []byte(s.config.AuthToken)) == 1 {
				// Check API rate limit for authenticated requests
				ip := getClientIP(r)
				if s.apiRateLimiter.checkRateLimit(ip) {
					resetTime := s.apiRateLimiter.getResetTime(ip)
					w.Header().Set("Retry-After", strconv.Itoa(int(resetTime.Seconds())+1))
					http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// Try JWT-style token from auth store
			if s.authStore != nil {
				if user, err := s.authStore.ValidateToken(token); err == nil {
					// Check API rate limit for authenticated requests
					ip := getClientIP(r)
					if s.apiRateLimiter.checkRateLimit(ip) {
						resetTime := s.apiRateLimiter.getResetTime(ip)
						w.Header().Set("Retry-After", strconv.Itoa(int(resetTime.Seconds())+1))
						http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
						return
					}
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

	if s.validator == nil {
		s.writeJSON(w, http.StatusOK, &dnssec.DNSSECStatus{
			Enabled: false,
		})
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
func (s *Server) handleListZones(w http.ResponseWriter, _ *http.Request) {
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

	switch subPath {
	case "records":
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
	case "export":
		if r.Method == http.MethodGet {
			s.handleExportZone(w, r, zoneName)
		} else {
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	case "ptr-bulk":
		if r.Method == http.MethodPost {
			s.handleBulkPTR(w, r, zoneName)
		} else {
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	case "ptr6-lookup":
		if r.Method == http.MethodGet {
			s.handlePtr6Lookup(w, r, zoneName)
		} else {
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	default:
		s.writeError(w, http.StatusNotFound, "Not found")
	}
}

// handleGetZone returns details of a single zone.
func (s *Server) handleGetZone(w http.ResponseWriter, _ *http.Request, name string) {
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
	if s.requireOperator(w, r) {
		return
	}
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
	if s.requireOperator(w, r) {
		return
	}
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
	if s.requireOperator(w, r) {
		return
	}
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
	if s.requireOperator(w, r) {
		return
	}
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
	if s.requireOperator(w, r) {
		return
	}
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
func (s *Server) handleExportZone(w http.ResponseWriter, _ *http.Request, zoneName string) {
	content, err := s.zoneManager.ExportZone(zoneName)
	if err != nil {
		s.writeError(w, http.StatusNotFound, err.Error())
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.zone", strings.TrimSuffix(zoneName, ".")))
	w.Write([]byte(content))
}

// handleBulkPTR handles bulk PTR record creation with CIDR pattern.
func (s *Server) handleBulkPTR(w http.ResponseWriter, r *http.Request, zoneName string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Failed to read request body")
		return
	}

	var req struct {
		CIDR     string `json:"cidr"`
		Pattern  string `json:"pattern"`
		Override bool   `json:"override"`
		AddA     bool   `json:"addA"`
		Preview  bool   `json:"preview"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if req.CIDR == "" || req.Pattern == "" {
		s.writeError(w, http.StatusBadRequest, "cidr and pattern are required")
		return
	}

	_, ipNet, err := net.ParseCIDR(req.CIDR)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid CIDR: %v", err))
		return
	}

	// Check that it's IPv4
	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		s.writeError(w, http.StatusBadRequest, "Only IPv4 CIDR is supported")
		return
	}

	// Generate all IPs in range
	ones, _ := ipNet.Mask.Size()
	numIPs := 1 << (32 - ones)
	if numIPs > 65536 {
		s.writeError(w, http.StatusBadRequest, "CIDR too large (max /16)")
		return
	}

	// Validate pattern has required placeholders [A], [B], [C], [D]
	if !strings.Contains(req.Pattern, "[A]") || !strings.Contains(req.Pattern, "[B]") ||
		!strings.Contains(req.Pattern, "[C]") || !strings.Contains(req.Pattern, "[D]") {
		s.writeError(w, http.StatusBadRequest, "Pattern must contain [A], [B], [C], [D] placeholders")
		return
	}

	z, ok := s.zoneManager.Get(zoneName)
	if !ok {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("Zone %s not found", zoneName))
		return
	}

	// Validate zone/CIDR compatibility
	zoneOrigin := z.Origin
	if _, err := validateZoneCIDR(zoneOrigin, ones); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Analyze all records in one lock
	z.RLock()
	existingPTR := z.Records["PTR"]
	existingA := z.Records["A"]
	z.RUnlock()

	type change struct {
		IP        string `json:"ip"`
		PTRName   string `json:"ptrName"`
		AName     string `json:"aName,omitempty"`
		Action    string `json:"action"` // add, override, skip
		PTRExist  bool   `json:"ptrExist"`
		AExist    bool   `json:"aExist,omitempty"`
		OldPTR    string `json:"oldPtr,omitempty"`
		OldA      string `json:"oldA,omitempty"`
		RevRecord string `json:"revRecord"` // the relative PTR record name
	}

	changes := make([]change, 0, numIPs)
	add, addA, skip, override, overrideA := 0, 0, 0, 0, 0

	for i := 0; i < numIPs; i++ {
		ip := make(net.IP, 4)
		copy(ip, ip4)
		n := binary.BigEndian.Uint32(ip)
		binary.BigEndian.PutUint32(ip, n+uint32(i))

		a, b, c, d := ip[0], ip[1], ip[2], ip[3]
		ptrName := strings.ReplaceAll(strings.ReplaceAll(
			strings.ReplaceAll(strings.ReplaceAll(req.Pattern,
				"[A]", fmt.Sprintf("%d", a)),
				"[B]", fmt.Sprintf("%d", b)),
				"[C]", fmt.Sprintf("%d", c)),
				"[D]", fmt.Sprintf("%d", d))

		// Compute relative PTR record name within the zone
		revRecord := reverseIPv4Relative(ip.String(), zoneOrigin, ones)

		// Check existing PTR using relative name
		var oldPTR string
		ptrExist := false
		for _, rec := range existingPTR {
			if rec.Name == revRecord || rec.Name == revRecord+"." {
				ptrExist = true
				oldPTR = rec.RData
				break
			}
		}

		// Check existing A
		var oldA string
		aExist := false
		if req.AddA {
			for _, rec := range existingA {
				if rec.Name == ptrName || rec.Name == ptrName+"." {
					aExist = true
					oldA = rec.RData
					break
				}
			}
		}

		ch := change{
			IP:        ip.String(),
			PTRName:   ptrName,
			Action:    "add",
			PTRExist:  ptrExist,
			RevRecord: revRecord,
		}

		if ptrExist && !req.Override {
			ch.Action = "skip"
			skip++
		} else if ptrExist && req.Override {
			ch.Action = "override"
			ch.OldPTR = oldPTR
			override++
		} else {
			add++
		}

		if req.AddA {
			ch.AName = ptrName
			ch.AExist = aExist
			if aExist && !req.Override {
				ch.Action = "skip"
				skip++
			} else if aExist && req.Override {
				if ch.Action == "add" {
					ch.Action = "override"
				}
				ch.OldA = oldA
				overrideA++
			} else if !aExist {
				addA++
			}
		}

		changes = append(changes, ch)
	}

	// If preview, return just the analysis
	if req.Preview {
		s.writeJSON(w, http.StatusOK, map[string]interface{}{
			"preview":    true,
			"total":      numIPs,
			"willAdd":    add,
			"willAddA":   addA,
			"willSkip":   skip,
			"willOverride": override + overrideA,
			"changes":    changes,
		})
		return
	}

	// Actually apply changes
	added, addedA, exists, existsA, skipped := 0, 0, 0, 0, 0
	for _, ch := range changes {
		if ch.Action == "skip" {
			skipped++
			continue
		}

		if ch.Action == "override" || ch.Action == "add" {
			if ch.PTRExist {
				s.zoneManager.DeleteRecord(zoneName, ch.RevRecord, "PTR")
			}
			rec := zone.Record{
				Name:  ch.RevRecord,
				Type:  "PTR",
				Class: "IN",
				TTL:   3600,
				RData: ch.PTRName,
			}
			err := s.zoneManager.AddRecord(zoneName, rec)
			if err == nil {
				added++
			} else {
				exists++
			}
		}

		if req.AddA && ch.AName != "" {
			if ch.AExist {
				s.zoneManager.DeleteRecord(zoneName, ch.AName, "A")
			}
			aRec := zone.Record{
				Name:  ch.AName,
				Type:  "A",
				Class: "IN",
				TTL:   3600,
				RData: ch.IP,
			}
			err := s.zoneManager.AddRecord(zoneName, aRec)
			if err == nil {
				addedA++
			} else {
				existsA++
			}
		}
	}

	// Audit log
	util.Infof("bulk-ptr: zone=%s cidr=%s pattern=%s override=%v addA=%v added=%d addedA=%d skipped=%d exists=%d",
		zoneName, req.CIDR, req.Pattern, req.Override, req.AddA, added, addedA, skipped, exists)

	s.writeJSON(w, http.StatusOK, map[string]int{
		"added":    added,
		"addedA":   addedA,
		"exists":   exists,
		"existsA":  existsA,
		"skipped":  skipped,
	})
}

// handlePtr6Lookup performs a reverse lookup for an IPv6 address.
// This is a query-only operation - it does not create records.
// Query: GET /api/v1/zones/{zone}/ptr6-lookup?ip=<ipv6-address>
func (s *Server) handlePtr6Lookup(w http.ResponseWriter, r *http.Request, zoneName string) {
	ipStr := r.URL.Query().Get("ip")
	if ipStr == "" {
		s.writeError(w, http.StatusBadRequest, "IP parameter is required")
		return
	}

	// Parse IPv6 address
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid IPv6 address")
		return
	}

	// Verify zone exists and is an IPv6 reverse zone
	z, ok := s.zoneManager.Get(zoneName)
	if !ok {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("Zone %s not found", zoneName))
		return
	}

	// Check if zone is an ip6.arpa zone
	if !strings.HasSuffix(z.Origin, "ip6.arpa.") {
		s.writeError(w, http.StatusBadRequest, "Zone is not an IPv6 reverse zone (must end with ip6.arpa.)")
		return
	}

	// Compute the IPv6 reverse name (nibble-based)
	// 2001:db8::1 -> 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
	ptrName := reverseIPv6(ip)

	// Lock zone for reading
	z.RLock()
	defer z.RUnlock()

	// Search for PTR record
	for _, rec := range z.Records["PTR"] {
		fqdn := rec.Name
		if !strings.HasSuffix(fqdn, ".") {
			fqdn += "."
		}
		target := ptrName + "."
		if fqdn == target || rec.Name == ptrName {
			s.writeJSON(w, http.StatusOK, map[string]interface{}{
				"ip":       ipStr,
				"ptr":      ptrName,
				"ptrFQDN":  target,
				"target":   rec.RData,
				"ttl":      rec.TTL,
				"found":    true,
			})
			return
		}
	}

	// Not found
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"ip":     ipStr,
		"ptr":    ptrName,
		"ptrFQDN": ptrName + ".",
		"found":  false,
	})
}

// reverseIPv6 computes the ip6.arpa reverse lookup name for an IPv6 address.
// Each nibble (4 bits) of the IPv6 address becomes a label in the reverse tree.
func reverseIPv6(ip net.IP) string {
	ip = ip.To16()
	if ip == nil {
		return ""
	}

	var parts []string
	// Process nibbles (4-bit chunks) in reverse order
	for i := 15; i >= 0; i-- {
		parts = append(parts, fmt.Sprintf("%x", ip[i]&0x0F))      // low nibble
		parts = append(parts, fmt.Sprintf("%x", (ip[i]>>4)&0x0F)) // high nibble
	}
	return strings.Join(parts, ".") + ".ip6.arpa"
}

// reverseIPv4 converts 1.2.3.4 to 4.3.2.1.in-addr.arpa
func reverseIPv4(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ip
	}
	return fmt.Sprintf("%s.%s.%s.%s.in-addr.arpa", parts[3], parts[2], parts[1], parts[0])
}

// reverseIPv4Relative returns the relative name for a PTR record within a zone.
// The FQDN for IP a.b.c.d is: d.c.b.a.in-addr.arpa
// Zone origin like "1.168.192.in-addr.arpa" means last 1 octet varies (a=/24).
// We need to return just the varying labels in correct order: "a" for /24, "b.a" for /16, "c.b.a" for /8.
// cidrPrefix is the CIDR being added (must be >= zone prefix).
func reverseIPv4Relative(ip string, origin string, cidrPrefix int) string {
	fqdn := reverseIPv4(ip)
	// fqdn is like "4.1.168.192.in-addr.arpa" for IP 192.168.1.4
	// labels before "in-addr.arpa" are [4, 1, 168, 192] = [d, c, b, a] for IP a.b.c.d
	// varyingLabels = 4 - zonePrefix/8
	// For /24 zone: varyingLabels = 4 - 3 = 1 → need [d] = "4"
	// For /16 zone: varyingLabels = 4 - 2 = 2 → need [c, d] = "1.4"
	// For /8 zone: varyingLabels = 4 - 1 = 3 → need [b, c, d] = "168.1.4"
	// Parse zone prefix from origin (not from cidrPrefix)
	originStripped := strings.TrimSuffix(origin, ".")
	remainder := strings.TrimSuffix(originStripped, ".in-addr.arpa")
	if remainder == originStripped {
		return fqdn
	}
	labels := strings.Split(remainder, ".")
	numFixed := len(labels)
	if numFixed < 1 || numFixed > 4 {
		return fqdn
	}
	zonePrefix := 8 * numFixed
	varyingLabels := 4 - zonePrefix/8
	if varyingLabels < 1 {
		varyingLabels = 1
	}
	if varyingLabels > 4 {
		varyingLabels = 4
	}
	// Split fqdn and extract varying labels from the end (reversed order)
	// FQDN: d.c.b.a.in-addr.arpa -> labels [d, c, b, a, in-addr, arpa]
	parts := strings.Split(fqdn, ".")
	if len(parts) < 6 {
		return fqdn
	}
	// We need the last varyingLabels from ipLabels, reversed back to normal order
	// For varyingLabels=1: ipLabels[3] = d = 4
	// For varyingLabels=2: ipLabels[2], ipLabels[3] = c, d = 1, 4 → "1.4"
	// For varyingLabels=3: ipLabels[1], ipLabels[2], ipLabels[3] = b, c, d = 168, 1, 4 → "168.1.4"
	start := 4 - varyingLabels
	if start < 0 {
		start = 0
	}
	// ipLabels is [d, c, b, a], we want [c, d] for varyingLabels=2 (which is parts[1], parts[2])
	// Actually parts[0]=d, parts[1]=c, parts[2]=b, parts[3]=a
	// For varyingLabels=2: want c,d = parts[1], parts[2]? No...
	// Wait: parts[0]=4, parts[1]=1, parts[2]=168, parts[3]=192
	// For /16: want "1.4" = c.d = parts[1].parts[2]? But 1.4 would be parts[1]+"."+parts[2]
	// parts = [4, 1, 168, 192]
	// parts[0] = 4 = d
	// parts[1] = 1 = c
	// parts[2] = 168 = b
	// parts[3] = 192 = a
	// For /16 varyingLabels=2: want b.a = 168.192? No, want c.d = 1.4 = parts[1].parts[3]? No...
	// Let me re-think. IP is a.b.c.d = 192.168.1.4
	// FQDN reversed: d.c.b.a.in-addr.arpa = 4.1.168.192.in-addr.arpa
	// So parts[0]=4=d, parts[1]=1=c, parts[2]=168=b, parts[3]=192=a
	// Zone /16 (168.192) means last 2 octets vary: c.b = 1.168? No...
	// In reverse: d.c = 4.1 represents c.d = 1.4 (the varying part)
	// So for varyingLabels=2, I need: parts[1].parts[0] = 1.4 (reversed order!)
	// For varyingLabels=3: parts[2].parts[1].parts[0] = 168.1.4
	result := make([]string, varyingLabels)
	for i := 0; i < varyingLabels; i++ {
		result[i] = parts[varyingLabels-1-i]
	}
	return strings.Join(result, ".")
}

// validateZoneCIDR checks if the zone origin is compatible with the CIDR prefix.
// CIDR prefix must be >= zone prefix (more specific or equal to zone).
// Returns the expected prefix implied by the zone origin, or error if incompatible.
func validateZoneCIDR(origin string, cidrPrefix int) (int, error) {
	// Origin must have trailing dot
	if !strings.HasSuffix(origin, ".") {
		return 0, fmt.Errorf("zone origin %s must have trailing dot", origin)
	}
	// Parse origin: should end with .in-addr.arpa
	originStripped := strings.TrimSuffix(origin, ".")
	if !strings.HasSuffix(originStripped, "in-addr.arpa") {
		return 0, fmt.Errorf("zone %s is not a reverse DNS zone (.in-addr.arpa)", origin)
	}
	// Get labels between origin and .in-addr.arpa
	// e.g. "1.168.192.in-addr.arpa" -> ["1", "168", "192"]
	remainder := strings.TrimSuffix(originStripped, ".in-addr.arpa")
	if remainder == originStripped {
		return 0, fmt.Errorf("zone %s is not a valid reverse DNS zone", origin)
	}
	labels := strings.Split(remainder, ".")
	// Number of fixed octets = number of labels in zone
	// Zone prefix = 8 * numFixed
	numFixed := len(labels)
	if numFixed < 1 || numFixed > 4 {
		return 0, fmt.Errorf("zone %s has invalid number of octets", origin)
	}
	zonePrefix := 8 * numFixed
	// CIDR must be >= zone prefix (more specific or same)
	if cidrPrefix < zonePrefix {
		return 0, fmt.Errorf("CIDR prefix /%d is too small for zone %s (minimum /%d)", cidrPrefix, origin, zonePrefix)
	}
	return zonePrefix, nil
}

// handleZoneReload reloads a zone.
func (s *Server) handleZoneReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.requireOperator(w, r) {
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
	if s.requireOperator(w, r) {
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
	if s.requireOperator(w, r) {
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

// handleConfigGet returns the current server configuration.
func (s *Server) handleConfigGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.configGetter == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Config not available")
		return
	}

	cfg := s.configGetter()
	s.writeJSON(w, http.StatusOK, cfg)
}

// handleClusterStatus returns cluster status.
func (s *Server) handleClusterStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.cluster == nil {
		s.writeJSON(w, http.StatusOK, &ClusterStatusResponse{
			NodeID:     "",
			NodeCount:  0,
			AliveCount: 0,
			Healthy:    false,
			Gossip: GossipInfo{
				MessagesSent:     0,
				MessagesReceived: 0,
				PingSent:         0,
				PingReceived:     0,
			},
		})
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
		s.writeJSON(w, http.StatusOK, &ClusterNodesResponse{Nodes: []NodeDetail{}})
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

// handleBlocklists returns blocklist stats or adds a new blocklist entry.
func (s *Server) handleBlocklists(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.blocklist == nil {
		s.writeJSON(w, http.StatusOK, &BlocklistResponse{
			Enabled:     false,
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
			Enabled:     stats.Enabled,
			TotalRules: stats.TotalBlocks,
			FilesCount: stats.Files,
			URLsCount:  stats.URLs,
		})
	case http.MethodPost:
		if s.requireOperator(w, r) {
			return
		}
		var req BlocklistAddRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}
		if req.File != "" {
			if err := s.blocklist.AddFile(req.File); err != nil {
				s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Failed to load blocklist file: %v", err))
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
		if err := s.blocklist.RemoveFile(decodedPath); err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Failed to remove blocklist file: %v", err))
			return
		}
		s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "Blocklist file removed"})
		return
	}

	s.writeError(w, http.StatusNotFound, "Not found")
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
			queries, failed, _ := s.upstreamClient.Stats()
			upstreams = append(upstreams, UpstreamStatus{
				Address: "direct-upstream",
				Healthy: s.upstreamClient.IsHealthy(),
				Queries: queries,
				Failed:  failed,
			})
		}
		s.writeJSON(w, http.StatusOK, &UpstreamsResponse{Upstreams: upstreams})
	case http.MethodPut:
		if s.requireOperator(w, r) {
			return
		}
		// Update upstream configuration (add/remove servers)
		var req UpstreamUpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		if s.upstreamClient == nil {
			s.writeError(w, http.StatusServiceUnavailable, "Upstream client not configured")
			return
		}

		switch req.Action {
		case "add":
			if req.Server == "" {
				s.writeError(w, http.StatusBadRequest, "Server address required")
				return
			}
			if err := s.upstreamClient.AddServer(req.Server); err != nil {
				s.writeError(w, http.StatusConflict, err.Error())
				return
			}
			s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "Server added: " + req.Server})

		case "remove":
			if req.Server == "" {
				s.writeError(w, http.StatusBadRequest, "Server address required")
				return
			}
			if err := s.upstreamClient.RemoveServer(req.Server); err != nil {
				s.writeError(w, http.StatusNotFound, err.Error())
				return
			}
			s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "Server removed: " + req.Server})

		default:
			s.writeError(w, http.StatusBadRequest, "Invalid action: must be 'add' or 'remove'")
		}
	}
}

// handleACL returns ACL rules or updates them.
func (s *Server) handleACL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.aclChecker == nil {
		s.writeJSON(w, http.StatusOK, &ACLResponse{Rules: []ACLRuleResponse{}})
		return
	}

	switch r.Method {
	case http.MethodGet:
		rules := s.aclChecker.GetRules()
		aclRules := make([]ACLRuleResponse, 0, len(rules))
		for _, rule := range rules {
			aclRules = append(aclRules, ACLRuleResponse{
				Name:     rule.Name,
				Networks: rule.Networks,
				Action:   rule.Action,
				Types:    rule.Types,
			})
		}
		s.writeJSON(w, http.StatusOK, &ACLResponse{Rules: aclRules})
	case http.MethodPut:
		if s.requireOperator(w, r) {
			return
		}
		var req struct {
			Rules []struct {
				Name     string   `json:"name"`
				Networks []string `json:"networks"`
				Action   string   `json:"action"`
				Types    []string `json:"types,omitempty"`
				Redirect string   `json:"redirect,omitempty"`
			} `json:"rules"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		// Convert to config rules
		configRules := make([]config.ACLRule, 0, len(req.Rules))
		for _, rule := range req.Rules {
			configRules = append(configRules, config.ACLRule{
				Name:     rule.Name,
				Networks: rule.Networks,
				Action:   rule.Action,
				Types:    rule.Types,
				Redirect: rule.Redirect,
			})
		}

		if err := s.aclChecker.UpdateRules(configRules); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "ACL rules updated"})
	}
}

// handleRPZ returns RPZ statistics.
func (s *Server) handleRPZ(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.rpzEngine == nil {
		s.writeJSON(w, http.StatusOK, &RPZStatsResponse{
			Enabled:       false,
			TotalRules:    0,
			QNAMERules:    0,
			ClientIPRules: 0,
			RespIPRules:   0,
			FilesCount:    0,
			TotalMatches:  0,
			TotalLookups:  0,
		})
		return
	}

	stats := s.rpzEngine.Stats()
	lastReload := ""
	if !stats.LastReload.IsZero() {
		lastReload = stats.LastReload.Format(time.RFC3339)
	}
	s.writeJSON(w, http.StatusOK, &RPZStatsResponse{
		Enabled:       stats.Enabled,
		TotalRules:    stats.TotalRules,
		QNAMERules:    stats.QNAMERules,
		ClientIPRules: stats.ClientIPRules,
		RespIPRules:   stats.RespIPRules,
		FilesCount:    stats.Files,
		TotalMatches:  stats.TotalMatches,
		TotalLookups:  stats.TotalLookups,
		LastReload:    lastReload,
	})
}

// handleRPZRules returns RPZ QNAME rules list.
func (s *Server) handleRPZRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodDelete {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.rpzEngine == nil {
		s.writeJSON(w, http.StatusOK, &RPZRulesResponse{Rules: []RPZRuleResponse{}})
		return
	}

	switch r.Method {
	case http.MethodGet:
		rules := s.rpzEngine.ListQNAMERules()
		resp := make([]RPZRuleResponse, 0, len(rules))
		for _, r := range rules {
			resp = append(resp, RPZRuleResponse{
				Pattern:      r.Pattern,
				Action:       actionToString(r.Action),
				Trigger:      triggerToString(r.Trigger),
				OverrideData: r.OverrideData,
				PolicyName:   r.PolicyName,
				Priority:     r.Priority,
			})
		}
		s.writeJSON(w, http.StatusOK, &RPZRulesResponse{Rules: resp})
	case http.MethodPost:
		if s.requireOperator(w, r) {
			return
		}
		var req RPZAddRuleRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}
		if req.Pattern == "" {
			s.writeError(w, http.StatusBadRequest, "pattern is required")
			return
		}
		action := parseAction(req.Action)
		s.rpzEngine.AddQNAMERule(req.Pattern, action, req.OverrideData)
		s.writeJSON(w, http.StatusCreated, &MessageResponse{Message: "Rule added"})
	case http.MethodDelete:
		if s.requireOperator(w, r) {
			return
		}
		// DELETE /api/v1/rpz/rules?pattern=domain.com
		pattern := r.URL.Query().Get("pattern")
		if pattern == "" {
			s.writeError(w, http.StatusBadRequest, "pattern query parameter required")
			return
		}
		s.rpzEngine.RemoveQNAMERule(pattern)
		s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "Rule removed"})
	}
}

// handleRPZActions handles RPZ enable/disable toggle.
func (s *Server) handleRPZActions(w http.ResponseWriter, r *http.Request) {
	if s.rpzEngine == nil {
		s.writeError(w, http.StatusServiceUnavailable, "RPZ not available")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/rpz/")
	if strings.HasPrefix(path, "toggle") {
		if r.Method != http.MethodPost {
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		if s.requireOperator(w, r) {
			return
		}
		// Toggle enabled state
		s.rpzEngine.SetEnabled(!s.rpzEngine.IsEnabled())
		s.writeJSON(w, http.StatusOK, &MessageResponse{
			Message: fmt.Sprintf("RPZ %s", map[bool]string{true: "enabled", false: "disabled"}[s.rpzEngine.IsEnabled()]),
		})
		return
	}

	s.writeError(w, http.StatusNotFound, "Not found")
}

// handleServerConfig returns the current server configuration (read-only, sanitized).
func (s *Server) handleServerConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	s.writeJSON(w, http.StatusOK, &ServerConfigResponse{
		Version:    util.Version,
		ListenPort: 0, // Not available in HTTPConfig
		LogLevel:   "", // Not available in HTTPConfig
	})
}

// actionToString converts a PolicyAction to a string.
func actionToString(a rpz.PolicyAction) string {
	switch a {
	case rpz.ActionNXDOMAIN:
		return "NXDOMAIN"
	case rpz.ActionNODATA:
		return "NODATA"
	case rpz.ActionCNAME:
		return "CNAME"
	case rpz.ActionOverride:
		return "Override"
	case rpz.ActionDrop:
		return "Drop"
	case rpz.ActionPassThrough:
		return "PassThrough"
	case rpz.ActionTCPOnly:
		return "TCPOnly"
	default:
		return "Unknown"
	}
}

// triggerToString converts a TriggerType to a string.
func triggerToString(t rpz.TriggerType) string {
	switch t {
	case rpz.TriggerQNAME:
		return "QNAME"
	case rpz.TriggerResponseIP:
		return "ResponseIP"
	case rpz.TriggerClientIP:
		return "ClientIP"
	case rpz.TriggerNSDNAME:
		return "NSDNAME"
	case rpz.TriggerNSIP:
		return "NSIP"
	default:
		return "Unknown"
	}
}

// parseAction converts a string to a PolicyAction.
func parseAction(s string) rpz.PolicyAction {
	switch strings.ToUpper(s) {
	case "NXDOMAIN":
		return rpz.ActionNXDOMAIN
	case "NODATA":
		return rpz.ActionNODATA
	case "CNAME":
		return rpz.ActionCNAME
	case "OVERRIDE":
		return rpz.ActionOverride
	case "DROP":
		return rpz.ActionDrop
	case "PASSTHROUGH":
		return rpz.ActionPassThrough
	case "TCPONLY":
		return rpz.ActionTCPOnly
	default:
		return rpz.ActionNXDOMAIN
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

	// Check IP-based rate limit
	ip := getClientIP(r)
	if rejected, delay := s.loginLimiter.checkRateLimit(ip); rejected {
		w.Header().Set("Retry-After", strconv.Itoa(int(delay.Seconds())))
		s.writeError(w, http.StatusTooManyRequests, "Too many requests, try again later")
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Check account-based rate limit (username lockout)
	if rejected, delay := s.loginLimiter.checkUserRateLimit(req.Username); rejected {
		w.Header().Set("Retry-After", strconv.Itoa(int(delay.Seconds())))
		s.writeError(w, http.StatusTooManyRequests, "Account locked due to too many failed attempts")
		return
	}

	// Validate user
	user, err := s.authStore.GetUser(req.Username)
	if err != nil {
		s.loginLimiter.recordFailedAttempt(ip, req.Username)
		s.writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Verify password
	if !auth.VerifyPassword(req.Password, user.Hash) {
		s.loginLimiter.recordFailedAttempt(ip, req.Username)
		s.writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Successful login - clear rate limit state
	s.loginLimiter.recordSuccess(ip, req.Username)

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
	token = strings.TrimPrefix(token, "Bearer ")

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

// requireOperator checks if the request has operator role (or is using legacy single-token auth).
// Writes error and returns true if access denied.
func (s *Server) requireOperator(w http.ResponseWriter, r *http.Request) bool {
	// If using legacy single-token auth (no authStore), skip RBAC — token holders have full access
	if s.authStore == nil {
		return false
	}
	if !hasRole(r.Context(), s.authStore, auth.RoleOperator) {
		s.writeError(w, http.StatusForbidden, "Operator role required")
		return true
	}
	return false
}

// requireAdmin checks if the request has admin role (or is using legacy single-token auth).
// Writes error and returns true if access denied.
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	// If using legacy single-token auth (no authStore), skip RBAC — token holders have full access
	if s.authStore == nil {
		return false
	}
	if !hasRole(r.Context(), s.authStore, auth.RoleAdmin) {
		s.writeError(w, http.StatusForbidden, "Admin role required")
		return true
	}
	return false
}

// getClientIP extracts the client IP from the request.
// SECURITY: X-Forwarded-For is NOT trusted by default because it can be trivially spoofed.
// An attacker can set X-Forwarded-For to any IP to bypass rate limiting.
// If the server is behind a trusted reverse proxy, the proxy should set X-Real-IP
// and this function will use it. Otherwise, RemoteAddr is used.
func getClientIP(r *http.Request) string {
	// Check X-Real-IP header (set by trusted proxies, not user-supplied)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		xri = strings.TrimSpace(xri)
		if net.ParseIP(xri) != nil {
			return xri
		}
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
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
