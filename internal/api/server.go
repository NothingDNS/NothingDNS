package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
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
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/doh"
	"github.com/nothingdns/nothingdns/internal/filter"
	"github.com/nothingdns/nothingdns/internal/geodns"
	"github.com/nothingdns/nothingdns/internal/metrics"
	"github.com/nothingdns/nothingdns/internal/odoh"
	"github.com/nothingdns/nothingdns/internal/otel"
	"github.com/nothingdns/nothingdns/internal/rpz"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/transfer"
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
	zoneSigners     map[string]*dnssec.Signer // zone name → signer
	zoneSignersMu   sync.RWMutex
	rpzEngine       *rpz.Engine
	geoEngine       *geodns.Engine
	slaveManager    *transfer.SlaveManager
	rateLimiter     *filter.RateLimiter
	odohProxy       *odoh.ObliviousProxy  // ODoH proxy (RFC 9230)
	odohTarget      *odoh.ObliviousTarget // ODoH target resolver (RFC 9230)
	loginLimiter    *loginRateLimiter
	apiRateLimiter  *apiRateLimiter
	tracer          *otel.Tracer // OpenTelemetry tracing
	stopCh          chan struct{} // Channel to signal shutdown
	stopOnce        sync.Once     // Ensure Stop is idempotent
	bootstrapMu     sync.Mutex    // Serialize bootstrap to prevent TOCTOU race

	// Goroutine leak detection baseline
	goroutineBaseline int64
}

// loginRateLimiter tracks failed login attempts per IP and username.
// It applies both IP-based and account-based rate limiting to prevent brute force attacks.
type loginRateLimiter struct {
	mu           sync.Mutex
	ipAttempts   map[string]*loginAttempt // IP-based tracking
	userAttempts map[string]*loginAttempt // Username-based tracking (account lockout)
}

// loginAttempt tracks failed attempts for a single IP or username.
type loginAttempt struct {
	count       int
	lastTry     time.Time
	lockedUntil time.Time
}

// LoginRateLimit constants
const (
	loginMaxAttempts    = 5                // Maximum attempts before lockout
	loginLockoutPeriod  = 5 * time.Minute  // How long to lock out after max attempts
	loginMaxDelay       = 30 * time.Second // Maximum delay between attempts
	loginMaxIPEntries   = 50000            // Maximum tracked IPs to prevent unbounded memory growth
	loginMaxUserEntries = 10000            // Maximum tracked usernames
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
		// Enforce max entries to prevent unbounded memory growth
		if len(l.ipAttempts) >= loginMaxIPEntries {
			var oldestIP string
			var oldestTime time.Time
			for k, v := range l.ipAttempts {
				if oldestIP == "" || v.lastTry.Before(oldestTime) {
					oldestIP = k
					oldestTime = v.lastTry
				}
			}
			delete(l.ipAttempts, oldestIP)
		}
		l.ipAttempts[ip] = &loginAttempt{
			count:   1,
			lastTry: now,
		}
	} else {
		// Reset lockout if expired (only check non-zero lockedUntil)
		if !attempt.lockedUntil.IsZero() && now.After(attempt.lockedUntil) {
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
		// Enforce max entries to prevent unbounded memory growth
		if len(l.userAttempts) >= loginMaxUserEntries {
			var oldestUser string
			var oldestTime time.Time
			for k, v := range l.userAttempts {
				if oldestUser == "" || v.lastTry.Before(oldestTime) {
					oldestUser = k
					oldestTime = v.lastTry
				}
			}
			delete(l.userAttempts, oldestUser)
		}
		l.userAttempts[username] = &loginAttempt{
			count:   1,
			lastTry: now,
		}
	} else {
		// Reset lockout if expired (only check non-zero lockedUntil)
		if !userAttempt.lockedUntil.IsZero() && now.After(userAttempt.lockedUntil) {
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

// cleanup removes stale lockout entries to prevent memory growth.
// Called periodically by the API server's cleanup goroutine.
func (l *loginRateLimiter) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()

	// Clean up expired IP attempts
	for ip, attempt := range l.ipAttempts {
		// Remove if lockout expired and no active delay
		if now.After(attempt.lockedUntil) && now.After(attempt.lastTry.Add(loginMaxDelay)) {
			delete(l.ipAttempts, ip)
		}
	}

	// Clean up expired user attempts
	for username, attempt := range l.userAttempts {
		// Remove if lockout expired
		if now.After(attempt.lockedUntil) {
			delete(l.userAttempts, username)
		}
	}
}

// apiRateLimiter implements a sliding window rate limiter for API endpoints.
type apiRateLimiter struct {
	mu         sync.Mutex
	requests   map[string][]time.Time // IP -> timestamps of recent requests
	maxReqs    int                    // Maximum requests per window
	windowSecs int                    // Window size in seconds
}

// apiRateLimit constants for authenticated endpoints
const (
	apiRateLimitMaxRequests  = 100   // Max requests per window
	apiRateLimitWindowSecs   = 60    // Window size in seconds
	apiRateLimitMaxEntries   = 50000 // Max tracked IPs to prevent unbounded memory growth
)

// maxBodyBytes is the maximum size for request bodies to prevent OOM attacks.
const maxBodyBytes = 64 * 1024 // 64KB

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
		// Enforce max entries to prevent unbounded memory growth
		if len(r.requests) >= apiRateLimitMaxEntries {
			var oldestIP string
			var oldestTime time.Time
			for k, v := range r.requests {
				if len(v) > 0 && (oldestIP == "" || v[0].Before(oldestTime)) {
					oldestIP = k
					oldestTime = v[0]
				}
			}
			delete(r.requests, oldestIP)
		}
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
		requests:   make(map[string][]time.Time),
		maxReqs:    apiRateLimitMaxRequests,
		windowSecs: apiRateLimitWindowSecs,
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

// WithZoneSigners sets the DNSSEC zone signers for the API server.
func (s *Server) WithZoneSigners(m map[string]*dnssec.Signer) *Server {
	s.zoneSignersMu.Lock()
	s.zoneSigners = m
	s.zoneSignersMu.Unlock()
	return s
}

// WithRPZ sets the RPZ engine for the API server.
func (s *Server) WithRPZ(e *rpz.Engine) *Server {
	s.rpzEngine = e
	return s
}

// WithGeoDNS sets the GeoDNS engine for the API server.
func (s *Server) WithGeoDNS(e *geodns.Engine) *Server {
	s.geoEngine = e
	return s
}

// WithSlaveManager sets the slave zone manager for the API server.
func (s *Server) WithSlaveManager(sm *transfer.SlaveManager) *Server {
	s.slaveManager = sm
	return s
}

// WithRateLimiter sets the DNS rate limiter for the API server.
func (s *Server) WithRateLimiter(rl *filter.RateLimiter) *Server {
	s.rateLimiter = rl
	return s
}

// WithODoH sets the ODoH proxy for the API server (RFC 9230).
func (s *Server) WithODoH(proxy *odoh.ObliviousProxy) *Server {
	s.odohProxy = proxy
	return s
}

// WithODoHTarget sets the ODoH target resolver for the API server (RFC 9230).
func (s *Server) WithODoHTarget(target *odoh.ObliviousTarget) *Server {
	s.odohTarget = target
	return s
}

// WithTracer sets the OpenTelemetry tracer for API request spans.
func (s *Server) WithTracer(t *otel.Tracer) *Server {
	s.tracer = t
	return s
}

// Start starts the API server.
func (s *Server) Start() error {
	if !s.config.Enabled {
		return nil
	}

	// Capture goroutine baseline on startup. This is a preliminary baseline;
	// a proper baseline is captured later via SetGoroutineBaseline() after
	// all servers (DNS, cluster, etc.) are running.
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
	if s.config.ODoHEnabled {
		if s.odohTarget != nil {
			mux.Handle(s.config.ODoHPath, s.odohTarget)
			mux.HandleFunc("/.well-known/odoh-config", s.handleODoHConfig)
		} else if s.odohProxy != nil {
			mux.Handle(s.config.ODoHPath, s.odohProxy)
		}
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

	// GeoIP / GeoDNS stats
	mux.HandleFunc("/api/v1/geoip/stats", s.handleGeoDNSStats)

	// Zone transfers (slave zones)
	mux.HandleFunc("/api/v1/zones/transfers", s.handleSlaveZones)

	// Server config (read-only)
	mux.HandleFunc("/api/v1/server/config", s.handleServerConfig)

	// Auth endpoints (no auth required for login, bootstrap requires no auth when no users exist)
	if s.authStore != nil {
		mux.HandleFunc("/api/v1/auth/login", s.handleLogin)
		mux.HandleFunc("/api/v1/auth/bootstrap", s.handleBootstrap)
		mux.HandleFunc("/api/v1/auth/users", s.handleUsers)
		mux.HandleFunc("/api/v1/auth/roles", s.handleRoles)
		mux.HandleFunc("/api/v1/auth/logout", s.handleLogout)
	}

	// Config management
	mux.HandleFunc("/api/v1/config/reload", s.handleConfigReload)
	mux.HandleFunc("/api/v1/config", s.handleConfigGet)
	mux.HandleFunc("/api/v1/config/logging", s.handleConfigLogging)
	mux.HandleFunc("/api/v1/config/rrl", s.handleConfigRRL)
	mux.HandleFunc("/api/v1/config/cache", s.handleConfigCache)

	// DNSSEC status (always registered)
	mux.HandleFunc("/api/v1/dnssec/status", s.handleDNSSECStatus)
	mux.HandleFunc("/api/v1/dnssec/keys", s.handleDNSSECKeys)

	// Dashboard UI
	mux.HandleFunc("/api/dashboard/stats", s.handleDashboardStats)
	mux.HandleFunc("/api/dashboard/queries", s.handleDashboardQueries)
	mux.HandleFunc("/api/dashboard/zones", s.handleDashboardZones)
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

	var handler http.Handler = mux
	if s.tracer != nil {
		handler = otel.Middleware(s.tracer)(handler)
	}
	handler = securityHeadersMiddleware(s.corsMiddleware(s.authMiddleware(handler)))

	s.httpServer = &http.Server{
		Addr:              s.config.Bind,
		Handler:           handler,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		// Use TLS if cert and key files are configured
		if s.config.TLSCertFile != "" && s.config.TLSKeyFile != "" {
			util.Infof("API server starting with TLS on %s", s.config.Bind)
			if err := s.httpServer.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				util.Warnf("API server TLS error: %v", err)
			}
		} else {
			// Warn if DoH is enabled without TLS
			if s.config.DoHEnabled {
				util.Warnf("DoH is enabled but TLS is not configured - queries will be sent over plaintext HTTP")
			}
			// Warn loudly if auth is enabled without TLS - tokens transmitted in clear
			if s.authStore != nil {
				util.Warnf("AUTHENTICATION IS ENABLED BUT TLS IS NOT CONFIGURED - auth tokens will be transmitted over plaintext HTTP. This is a security risk.")
			}
			if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				util.Warnf("API server error: %v", err)
			}
		}
	}()

	return nil
}

// SetGoroutineBaseline captures the current goroutine count as the baseline.
// Call this after all servers (DNS, cluster, etc.) have started their worker goroutines
// for accurate leak detection.
func (s *Server) SetGoroutineBaseline() {
	atomic.StoreInt64(&s.goroutineBaseline, int64(runtime.NumGoroutine()))
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
			s.loginLimiter.cleanup()
		}
	}
}

// securityHeadersMiddleware adds security headers to all responses.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		// Explicit CSP directives — default-src alone leaves base-uri,
		// form-action, frame-ancestors, and object-src unrestricted (VULN-016).
		// style-src keeps unsafe-inline for Radix UI inline styles; script-src
		// stays strict. connect-src permits WebSocket to the same origin.
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; "+
				"font-src 'self' data:; "+
				"connect-src 'self';"+
				"frame-ancestors 'none'; "+
				"object-src 'none'; "+
				"base-uri 'self'; "+
				"form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

// corsMiddleware adds CORS headers.
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// If allowed_origins is empty, allow same-origin requests only
		// (cross-origin requests receive no CORS allow header).
		// If allowed_origins contains "*", allow all origins.
		// Otherwise validate against the explicit list.
		allowedOrigins := s.config.AllowedOrigins
		allowOrigin := ""
		allowAllOrigins := false
		for _, allowed := range allowedOrigins {
			if allowed == "*" {
				allowAllOrigins = true
				break
			}
		}
		if allowAllOrigins {
			allowOrigin = "*"
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
			if allowOrigin == "" && origin != "" {
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
		if r.URL.Path == "/api/v1/auth/login" || r.URL.Path == "/api/v1/auth/bootstrap" {
			next.ServeHTTP(w, r)
			return
		}

		// Skip auth for health and readiness endpoints (public information)
		if r.URL.Path == "/health" || r.URL.Path == "/ready" || r.URL.Path == "/readyz" || r.URL.Path == "/livez" {
			next.ServeHTTP(w, r)
			return
		}

		// Skip auth for static assets (React SPA) — let spaHandler serve them
		if strings.HasPrefix(r.URL.Path, "/assets/") ||
			r.URL.Path == "/favicon.svg" || r.URL.Path == "/favicon.ico" {
			next.ServeHTTP(w, r)
			return
		}

		// VULN-044: Skip auth for DNS-over-HTTPS family endpoints. These are
		// DNS resolution paths, not admin API; clients (browsers, stub
		// resolvers) never send a Bearer token for a DoH query, so running
		// them through auth returns 401 to every legitimate user the moment
		// auth_token or the authStore is configured.
		if s.config.DoHEnabled && s.config.DoHPath != "" && r.URL.Path == s.config.DoHPath {
			next.ServeHTTP(w, r)
			return
		}
		if s.config.DoWSEnabled && s.config.DoWSPath != "" && r.URL.Path == s.config.DoWSPath {
			next.ServeHTTP(w, r)
			return
		}
		if s.config.ODoHEnabled {
			if s.config.ODoHPath != "" && r.URL.Path == s.config.ODoHPath {
				next.ServeHTTP(w, r)
				return
			}
			if r.URL.Path == "/.well-known/odoh-config" {
				next.ServeHTTP(w, r)
				return
			}
		}

		// VULN-055: Apply the API rate limit to every /api/ request BEFORE
		// any auth decision, so unauthenticated scans and failed-auth
		// brute-force attempts also consume budget. Previously the limiter
		// only fired inside the successful-auth branches, which left the
		// login/credential-stuffing surface unthrottled.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			ip := getClientIP(r)
			if s.apiRateLimiter.checkRateLimit(ip) {
				resetTime := s.apiRateLimiter.getResetTime(ip)
				w.Header().Set("Retry-After", strconv.Itoa(int(resetTime.Seconds())+1))
				http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}
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

		// Fallback: cookie. Only accepted for safe methods — CSRF prevention.
		// State-changing requests (POST/PUT/PATCH/DELETE) must use Authorization.
		if token == "" && isSafeMethod(r.Method) {
			if c, err := r.Cookie("ndns_token"); err == nil {
				token = c.Value
			}
		}

		// Validate token
		if token != "" {
			// First try old-style shared token (auth_token)
			// SECURITY: Check length first to prevent timing attack via ConstantTimeCompare
			legacyToken := s.config.AuthToken
			if legacyToken != "" && len(token) == len(legacyToken) && subtle.ConstantTimeCompare([]byte(token), []byte(legacyToken)) == 1 {
				// Legacy token binds to config.AuthTokenRole (default viewer).
				// Previously this silently synthesized admin regardless of intent.
				ctx := WithUser(r.Context(), legacyTokenUser(s.config.AuthTokenRole))
				next.ServeHTTP(w, r.WithContext(ctx))
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

		// For SPA routes, serve the React SPA instead of the old login HTML
		// The React app handles authentication internally
		if !strings.HasPrefix(r.URL.Path, "/api/") && !strings.HasPrefix(r.URL.Path, "/assets/") &&
			r.URL.Path != "/health" && r.URL.Path != "/ws" &&
			!strings.HasSuffix(r.URL.Path, ".svg") && !strings.HasSuffix(r.URL.Path, ".ico") {
			indexHTML, err := fs.ReadFile(dashboard.DistFS, "index.html")
			if err != nil {
				// Fallback to old login HTML if React SPA not available
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Write([]byte(dashboard.GetLoginHTML()))
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(indexHTML)
			return
		}

		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
	})
}
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
// roleOrder maps a role to its privilege height. Kept local to avoid coupling
// the api package to internal auth.Store lookup when the request context
// carries a synthesized legacy-token user whose username is not in the store.
var roleOrder = map[auth.Role]int{
	auth.RoleViewer:   1,
	auth.RoleOperator: 2,
	auth.RoleAdmin:    3,
}

// legacyTokenUsername is the synthetic username assigned to requests
// authenticated via the legacy shared `auth_token`. Chosen to be distinct
// from any realistic real username so audit logs and rate-limit keys separate
// legacy-token traffic from real user traffic.
const legacyTokenUsername = "__legacy_auth_token__"

// legacyTokenUser returns the synthetic user bound to the legacy auth_token.
// The role is taken from config.AuthTokenRole (default "viewer"); unknown or
// empty values fail closed to viewer. Previously the legacy path unconditionally
// synthesized admin, which collapsed RBAC to a single shared secret (VULN-003).
func legacyTokenUser(configuredRole string) *auth.User {
	role := auth.RoleViewer
	switch strings.ToLower(strings.TrimSpace(configuredRole)) {
	case string(auth.RoleAdmin):
		role = auth.RoleAdmin
	case string(auth.RoleOperator):
		role = auth.RoleOperator
	case string(auth.RoleViewer), "":
		role = auth.RoleViewer
	}
	return &auth.User{Username: legacyTokenUsername, Role: role}
}

// isSafeMethod reports whether the HTTP method is read-only (no server state
// change). Cookie-based auth is only accepted on safe methods to prevent CSRF
// via cross-site POST/PUT/DELETE; state-changing requests must use
// Authorization: Bearer.
func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

// hasRole checks whether the request user has at least the required role.
// Trusts user.Role as attached to the context by the auth middleware rather
// than re-looking up the store, so synthesized users (e.g. legacy-token users
// whose username is not in the store) are handled correctly.
func hasRole(ctx context.Context, _ *auth.Store, required auth.Role) bool {
	user := GetUser(ctx)
	if user == nil {
		return false
	}
	return roleOrder[user.Role] >= roleOrder[required]
}

// requireOperator checks if the request has operator role.
// Writes error and returns true if access denied.
func (s *Server) requireOperator(w http.ResponseWriter, r *http.Request) bool {
	if s.authStore == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Auth not configured")
		return true
	}
	if !hasRole(r.Context(), s.authStore, auth.RoleOperator) {
		s.writeError(w, http.StatusForbidden, "Operator role required")
		return true
	}
	return false
}

// requireAdmin checks if the request has admin role.
// Destructive infra operations (ACL rewrite, upstream swap, RPZ rewrite,
// blocklist URL-add, config reload, cluster admin) must gate through this
// rather than requireOperator to prevent operator-role overreach (VULN-009).
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.authStore == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Auth not configured")
		return true
	}
	if !hasRole(r.Context(), s.authStore, auth.RoleAdmin) {
		s.writeError(w, http.StatusForbidden, "Admin role required")
		return true
	}
	return false
}

// getClientIP extracts the client IP from the request.
// SECURITY: X-Forwarded-For is NOT trusted because it can be trivially spoofed.
// X-Real-IP is only trusted when explicitly configured via TrustedProxies to
// prevent remote attackers from bypassing rate limiting or IP-based auth checks.
func getClientIP(r *http.Request) string {
	// Fall back to RemoteAddr — the only source that cannot be spoofed by clients.
	// X-Real-IP should only be trusted when behind a known reverse proxy.
	// To enable X-Real-IP, the proxy must be explicitly configured as trusted.
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

// sanitizeError converts an internal error to a safe client-facing message.
// Use this instead of err.Error() in API responses to prevent information leakage.
func sanitizeError(err error, fallback string) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	// Strip file paths and internal details — only allow simple descriptive messages
	if strings.Contains(msg, "/") || strings.Contains(msg, "panic") {
		return fallback
	}
	return msg
}
