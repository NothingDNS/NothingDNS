// Package dashboard provides a web dashboard for NothingDNS
package dashboard

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/websocket"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// Server implements the web dashboard server
type Server struct {
	mu             sync.RWMutex
	clients        map[*Client]struct{}
	broadcastChan  chan *QueryEvent
	stopOnce       sync.Once // guards Stop() against second-call panic on broadcastChan
	stats          *DashboardStats
	enabled        bool
	wg             sync.WaitGroup
	allowedOrigins []string // Allowed CORS origins for WebSocket
	authStore      *auth.Store
	authToken      string // Legacy token-only auth fallback
	authTokenRole  string // Role bound to authToken (default viewer)
	zoneManager    *zone.Manager
}

// secureCompare performs constant-time comparison to prevent timing attacks
func secureCompare(a, b string) bool {
	aDigest := sha256.Sum256([]byte(a))
	bDigest := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(aDigest[:], bDigest[:]) == 1
}

// MaxWebSocketClients is the maximum number of concurrent WebSocket connections.
const MaxWebSocketClients = 1000

// Client represents a connected WebSocket client
type Client struct {
	conn      WebSocketConn
	send      chan []byte
	closeSend sync.Once
	closed    chan struct{} // Used to signal write loop to exit
	// redactIPs is true for non-admin viewers: streamed events carry a
	// masked client IP, matching the query log API (LOW-010).
	redactIPs bool
}

// RedactQueryEvents returns copies of events with client IPs masked. The
// input events are shared with the stats ring buffer and are not modified.
func RedactQueryEvents(events []*QueryEvent) []*QueryEvent {
	out := make([]*QueryEvent, len(events))
	for i, e := range events {
		if e == nil {
			continue
		}
		cp := *e
		cp.ClientIP = util.RedactIP(cp.ClientIP)
		out[i] = &cp
	}
	return out
}

// WebSocketConn interface for WebSocket connections
type WebSocketConn interface {
	ReadMessage() (messageType int, p []byte, err error)
	WriteMessage(messageType int, data []byte) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	Close() error
}

// QueryEvent represents a DNS query event for streaming
type QueryEvent struct {
	Timestamp    time.Time `json:"timestamp"`
	ClientIP     string    `json:"clientIp"`
	CountryCode  string    `json:"countryCode"`
	Domain       string    `json:"domain"`
	QueryType    string    `json:"queryType"`
	ResponseCode string    `json:"responseCode"`
	Duration     int64     `json:"duration"`
	Cached       bool      `json:"cached"`
	Blocked      bool      `json:"blocked"`
	Protocol     string    `json:"protocol"`
}

// DashboardStats represents dashboard statistics
type DashboardStats struct {
	mu              sync.RWMutex
	Uptime          time.Time     `json:"uptime"`
	QueriesTotal    int64         `json:"queriesTotal"`
	QueriesPerSec   float64       `json:"queriesPerSec"`
	CacheHitRate    float64       `json:"cacheHitRate"`
	BlockedQueries  int64         `json:"blockedQueries"`
	ActiveClients   int           `json:"activeClients"`
	ZoneCount       int           `json:"zoneCount"`
	UpstreamLatency time.Duration `json:"upstreamLatency"`
	RecentQueries   []*QueryEvent `json:"recentQueries"`
	// recentClients maps a querying client IP to the unix-second timestamp it
	// was last seen, so ActiveClients reports distinct DNS clients in a rolling
	// window (NOT the number of dashboard WebSocket viewers, which is what it
	// used to conflate). Guarded by mu.
	recentClients map[string]int64
}

// activeClientWindow is how long a client IP counts toward ActiveClients after
// its last query.
const activeClientWindow = 5 * time.Minute

// GetRecentQueries returns a paginated copy of recent queries.
func (ds *DashboardStats) GetRecentQueries(offset, limit int) ([]*QueryEvent, int) {
	if offset < 0 || limit <= 0 {
		return nil, 0
	}

	ds.mu.RLock()
	defer ds.mu.RUnlock()

	total := len(ds.RecentQueries)
	if total == 0 {
		return nil, 0
	}
	end := offset + limit
	if end > total {
		end = total
	}
	if offset >= total {
		return nil, 0
	}
	return cloneQueryEvents(ds.RecentQueries[offset:end]), total
}

func cloneQueryEvents(events []*QueryEvent) []*QueryEvent {
	if len(events) == 0 {
		return nil
	}
	clones := make([]*QueryEvent, len(events))
	for i, event := range events {
		if event == nil {
			continue
		}
		eventCopy := *event
		clones[i] = &eventCopy
	}
	return clones
}

// GetRecentQueriesFiltered returns recent queries whose domain contains the
// (case-insensitive) substring `filter`, paginated by offset/limit. When
// `filter` is empty it behaves like GetRecentQueries. `total` is the count
// AFTER filtering, so the caller paginates over the whole filtered set rather
// than only the current page (the previous client-side filter searched just
// the 50 visible rows, hiding matches on other pages).
func (ds *DashboardStats) GetRecentQueriesFiltered(offset, limit int, filter string) ([]*QueryEvent, int) {
	if filter == "" {
		return ds.GetRecentQueries(offset, limit)
	}
	if offset < 0 || limit <= 0 {
		return nil, 0
	}

	ds.mu.RLock()
	defer ds.mu.RUnlock()

	needle := strings.ToLower(filter)
	matched := make([]*QueryEvent, 0)
	for _, q := range ds.RecentQueries {
		if q != nil && strings.Contains(strings.ToLower(q.Domain), needle) {
			matched = append(matched, q)
		}
	}

	total := len(matched)
	if offset >= total {
		return nil, total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return cloneQueryEvents(matched[offset:end]), total
}

// TopDomainsEntry represents a domain with its query count.
type TopDomainsEntry struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

// GetTopDomains returns the top N most-queried domains.
func (ds *DashboardStats) GetTopDomains(limit int) []TopDomainsEntry {
	if limit <= 0 {
		return nil
	}

	ds.mu.RLock()
	defer ds.mu.RUnlock()

	if len(ds.RecentQueries) == 0 {
		return nil
	}

	countByDomain := make(map[string]int)
	for _, q := range ds.RecentQueries {
		if q == nil {
			continue
		}
		countByDomain[q.Domain]++
	}
	if len(countByDomain) == 0 {
		return nil
	}

	type domainCount struct {
		domain string
		count  int
	}
	var sorted []domainCount
	for domain, count := range countByDomain {
		sorted = append(sorted, domainCount{domain, count})
	}

	// Sort by count descending
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].count > sorted[i].count {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	if limit > len(sorted) {
		limit = len(sorted)
	}
	result := make([]TopDomainsEntry, limit)
	for i := 0; i < limit; i++ {
		result[i] = TopDomainsEntry{
			Domain: sorted[i].domain,
			Count:  sorted[i].count,
		}
	}
	return result
}

// NewServer creates a new dashboard server
func NewServer() *Server {
	s := &Server{
		clients:       make(map[*Client]struct{}),
		broadcastChan: make(chan *QueryEvent, 1000),
		stats: &DashboardStats{
			Uptime:        time.Now(),
			RecentQueries: make([]*QueryEvent, 0, 100),
		},
		enabled: true,
	}

	s.wg.Add(1)
	go s.broadcastLoop()

	return s
}

// SetZoneManager sets the zone manager for the dashboard server.
func (s *Server) SetZoneManager(zm *zone.Manager) {
	s.mu.Lock()
	s.zoneManager = zm
	s.mu.Unlock()
}

// SetAllowedOrigins sets the allowed CORS origins for WebSocket connections.
func (s *Server) SetAllowedOrigins(origins []string) {
	s.mu.Lock()
	s.allowedOrigins = cloneStrings(origins)
	s.mu.Unlock()
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string(nil), values...)
}

// SetAuthStore sets the auth store for WebSocket authentication.
func (s *Server) SetAuthStore(store *auth.Store) {
	s.mu.Lock()
	s.authStore = store
	s.mu.Unlock()
}

// SetAuthTokenRole sets the role bound to the legacy token (server.http.
// auth_token_role); only "admin" sees unmasked client IPs.
func (s *Server) SetAuthTokenRole(role string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authTokenRole = role
}

// SetAuthToken sets the legacy token for token-only authentication fallback.
func (s *Server) SetAuthToken(token string) {
	s.mu.Lock()
	s.authToken = token
	s.mu.Unlock()
}

// authenticateRequest checks for a valid auth token in the request.
// Returns true if auth is not configured (permissive), or if a valid token
// is present. Writes a 401 only when auth IS configured but token is missing/invalid.
func (s *Server) authenticateRequest(w http.ResponseWriter, r *http.Request) bool {
	ok, _ := s.authenticateRequestRole(w, r)
	return ok
}

// authenticateRequestRole is authenticateRequest that also reports whether
// the caller is an admin (and may see unmasked client IPs).
func (s *Server) authenticateRequestRole(w http.ResponseWriter, r *http.Request) (ok, admin bool) {
	s.mu.RLock()
	authStore := s.authStore
	authToken := s.authToken
	authTokenRole := s.authTokenRole
	s.mu.RUnlock()

	// No auth configured — allow all requests (legacy permissive behavior)
	if authToken == "" && authStore == nil {
		return true, true
	}

	token := r.Header.Get("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")
	if token == "" {
		if c, err := r.Cookie("ndns_token"); err == nil {
			token = c.Value
		}
	}

	if token == "" {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return false, false
	}

	if authToken != "" && secureCompare(token, authToken) {
		return true, isAdminRole(authTokenRole)
	}
	if authStore != nil {
		if user, err := authStore.ValidateToken(token); err == nil {
			return true, user.Role == auth.RoleAdmin
		}
	}
	http.Error(w, "invalid token", http.StatusUnauthorized)
	return false, false
}

func isAdminRole(role string) bool {
	return strings.EqualFold(strings.TrimSpace(role), string(auth.RoleAdmin))
}

// ServeHTTP handles HTTP requests
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch path {
	case "/api/dashboard/stats":
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		if s.authenticateRequest(w, r) {
			s.handleStats(w, r)
		}
	case "/api/dashboard/queries":
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		if ok, admin := s.authenticateRequestRole(w, r); ok {
			s.handleQueryStream(w, r, admin)
		}
	case "/api/dashboard/zones":
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		if s.authenticateRequest(w, r) {
			s.handleZones(w, r)
		}
	case "/ws":
		s.handleWebSocket(w, r)
	default:
		http.NotFound(w, r)
	}
}

// requireMethod returns true if the request matches one of the
// allowed methods. Otherwise it writes 405 with an Allow header and
// returns false. L-11: the dashboard's data endpoints previously
// accepted any verb. They're read-only today (POST/PUT/DELETE just
// invoked the read handler) so it wasn't an exploit, but the
// missing check was a defense-in-depth regression risk — anyone
// adding a state-mutating side effect to handleStats / handleZones /
// handleQueryStream would silently expose it to verbs that bypass
// the cookie-CSRF defense the main API uses.
func requireMethod(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	for _, m := range allowed {
		if r.Method == m {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	return false
}

// handleStats handles stats API requests
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	s.stats.mu.RLock()
	defer s.stats.mu.RUnlock()

	resp := &StatsAPIResponse{
		Uptime:          nonNegativeSecondsSince(s.stats.Uptime, time.Now()),
		QueriesTotal:    s.stats.QueriesTotal,
		QueriesPerSec:   s.stats.QueriesPerSec,
		CacheHitRate:    s.stats.CacheHitRate,
		BlockedQueries:  s.stats.BlockedQueries,
		ActiveClients:   s.stats.ActiveClients,
		ZoneCount:       s.stats.ZoneCount,
		UpstreamLatency: s.stats.UpstreamLatency.Milliseconds(),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		util.Warnf("dashboard: failed to encode stats: %v", err)
	}
}

func nonNegativeSecondsSince(start, now time.Time) float64 {
	if now.Before(start) {
		return 0
	}
	return now.Sub(start).Seconds()
}

// handleQueryStream handles query stream requests
func (s *Server) handleQueryStream(w http.ResponseWriter, r *http.Request, admin bool) {
	s.stats.mu.RLock()
	queries := make([]*QueryEvent, len(s.stats.RecentQueries))
	copy(queries, s.stats.RecentQueries)
	s.stats.mu.RUnlock()
	if !admin {
		queries = RedactQueryEvents(queries)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(queries); err != nil {
		util.Warnf("dashboard: failed to encode queries: %v", err)
	}
}

// handleZones handles zone list requests
func (s *Server) handleZones(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	zm := s.zoneManager
	s.mu.RUnlock()

	zones := []ZoneAPIEntry{}

	if zm != nil {
		for name, z := range zm.List() {
			serial := int64(0)
			if z.SOA != nil {
				serial = int64(z.SOA.Serial)
			}
			zones = append(zones, ZoneAPIEntry{
				Name:    name,
				Records: len(z.Records),
				Serial:  int(serial),
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(zones); err != nil {
		util.Warnf("dashboard: failed to encode zones: %v", err)
	}
}

// handleWebSocket handles WebSocket connections
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")
	if token == "" {
		if c, err := r.Cookie("ndns_token"); err == nil {
			token = c.Value
		}
	}
	// Note: Query parameter token fallback has been removed for security.
	// Browsers automatically send cookies with WebSocket upgrade requests.

	// Validate authentication
	s.mu.RLock()
	authStore := s.authStore
	authToken := s.authToken
	authTokenRole := s.authTokenRole
	s.mu.RUnlock()

	if token == "" {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}

	// Validate token: check legacy token first, then JWT (matches auth middleware behavior)
	valid, admin := false, false
	if authToken != "" && secureCompare(token, authToken) {
		valid, admin = true, isAdminRole(authTokenRole)
	}
	if !valid && authStore != nil {
		if user, err := authStore.ValidateToken(token); err == nil {
			valid, admin = true, user.Role == auth.RoleAdmin
		}
	}
	if !valid {
		util.Warnf("dashboard: websocket auth failed: invalid token")
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	// Snapshot allowedOrigins under the lock so a concurrent
	// SetAllowedOrigins can't race on the slice header. The
	// websocket.Handshake variadic call must not see a torn slice
	// during reslicing.
	s.mu.RLock()
	origins := cloneStrings(s.allowedOrigins)
	s.mu.RUnlock()

	conn, err := websocket.Handshake(w, r, origins...)
	if err != nil {
		util.Warnf("dashboard: websocket handshake failed: %v", err)
		return
	}
	// Per-connection rate limit so a single authenticated client cannot
	// hold a server goroutine at line-rate (VULN-018). 100 msg/s matches
	// the primitive's documented sizing.
	conn.SetRateLimit(100, time.Second)

	client := &Client{
		conn:      conn,
		send:      make(chan []byte, 256),
		closed:    make(chan struct{}),
		redactIPs: !admin,
	}

	s.AddClient(client)
	s.ClientLoop(client)
}

// RecordQuery records a query event and broadcasts it
func (s *Server) RecordQuery(event *QueryEvent) {
	if event == nil {
		return
	}
	eventCopy := *event
	storedEvent := &eventCopy

	// Update stats
	s.stats.mu.Lock()
	s.stats.QueriesTotal++
	s.stats.RecentQueries = append(s.stats.RecentQueries, storedEvent)

	// Keep only last 100 queries
	if len(s.stats.RecentQueries) > 100 {
		s.stats.RecentQueries = s.stats.RecentQueries[1:]
	}

	// Track distinct client IPs in a rolling window for ActiveClients.
	if event.ClientIP != "" {
		if s.stats.recentClients == nil {
			s.stats.recentClients = make(map[string]int64)
		}
		now := time.Now().Unix()
		s.stats.recentClients[event.ClientIP] = now
		cutoff := now - int64(activeClientWindow.Seconds())
		for ip, seen := range s.stats.recentClients {
			if seen < cutoff {
				delete(s.stats.recentClients, ip)
			}
		}
		s.stats.ActiveClients = len(s.stats.recentClients)
	}
	s.stats.mu.Unlock()

	// Broadcast to connected clients
	select {
	case s.broadcastChan <- storedEvent:
	default:
		// Channel full, drop event
	}
}

// UpdateStats updates dashboard statistics
func (s *Server) UpdateStats(stats UpdateStatsRequest) {
	s.stats.mu.Lock()
	defer s.stats.mu.Unlock()

	if stats.QueriesPerSec > 0 {
		s.stats.QueriesPerSec = stats.QueriesPerSec
	}
	if stats.CacheHitRate > 0 {
		s.stats.CacheHitRate = stats.CacheHitRate
	}
	if stats.ZoneCount > 0 {
		s.stats.ZoneCount = stats.ZoneCount
	}
	if stats.UpstreamLatency > 0 {
		s.stats.UpstreamLatency = stats.UpstreamLatency
	}
}

// UpdateStatsRequest represents a stats update request
type UpdateStatsRequest struct {
	QueriesPerSec   float64       `json:"queriesPerSec"`
	CacheHitRate    float64       `json:"cacheHitRate"`
	ZoneCount       int           `json:"zoneCount"`
	UpstreamLatency time.Duration `json:"upstreamLatency"`
}

// AddClient adds a WebSocket client if the connection limit hasn't been reached.
func (s *Server) AddClient(client *Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.clients) >= MaxWebSocketClients {
		util.Warnf("dashboard: WebSocket connection limit reached (%d)", MaxWebSocketClients)
		return
	}
	s.clients[client] = struct{}{}
	// Note: ActiveClients tracks distinct DNS query clients (see RecordQuery),
	// NOT the number of dashboard WebSocket viewers — the two were previously
	// conflated here.
}

// RemoveClient removes a WebSocket client
func (s *Server) RemoveClient(client *Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clients, client)
}

// broadcastLoop broadcasts events to all connected clients
func (s *Server) broadcastLoop() {
	defer s.wg.Done()
	for event := range s.broadcastChan {
		data, err := json.Marshal(&BroadcastMessage{
			Type:  "query",
			Event: event,
		})
		if err != nil {
			continue
		}
		var redacted []byte // marshalled on first use

		s.mu.RLock()
		for client := range s.clients {
			payload := data
			if client.redactIPs {
				if redacted == nil {
					redacted, err = json.Marshal(&BroadcastMessage{
						Type:  "query",
						Event: RedactQueryEvents([]*QueryEvent{event})[0],
					})
					if err != nil {
						break
					}
				}
				payload = redacted
			}
			select {
			case client.send <- payload:
			default:
				// Client channel full, skip
			}
		}
		s.mu.RUnlock()
	}
}

// ClientLoop handles a client's read/write loops
//
// Defer order matters. broadcastLoop reads s.clients under s.mu.RLock
// and uses a non-blocking
//
//	select { case client.send <- data: default: }
//
// to fan out events. If we close(client.send) while the client is
// still in s.clients, an in-flight broadcastLoop iteration that
// already passed the RLock'd map read can panic with
// "send on closed channel" on its next iteration over this client —
// the default branch only protects against a full buffer, not a
// closed channel. RemoveClient takes s.mu.Lock and so naturally
// serializes against broadcastLoop's RLock; once it returns, no
// future broadcastLoop iteration can see this client, and the send
// channel is safe to close.
//
// Order is therefore: signal write loop, drop from broadcast set,
// then close the send channel and finally the conn.
func (s *Server) ClientLoop(client *Client) {
	defer func() {
		close(client.closed) // Signal write loop to exit
		s.RemoveClient(client)
		client.closeSend.Do(func() { close(client.send) })
		if err := closeClientConn(client); err != nil {
			util.Warnf("dashboard: failed to close WebSocket client: %v", err)
		}
	}()

	// Write loop
	go func() {
		for {
			select {
			case data := <-client.send:
				// Set write deadline to prevent blocking on slow clients
				if err := client.conn.SetWriteDeadline(time.Now().Add(time.Minute)); err != nil {
					return
				}
				if err := client.conn.WriteMessage(1, data); err != nil {
					return
				}
			case <-client.closed:
				return
			}
		}
	}()

	// Read loop with idle timeout to detect slow/dead clients
	for {
		// Set read deadline to prevent slow-client DoS (2 minute idle timeout)
		if err := client.conn.SetReadDeadline(time.Now().Add(2 * time.Minute)); err != nil {
			return
		}
		_, _, err := client.conn.ReadMessage()
		if err != nil {
			return
		}
	}
}

// Stop stops the dashboard server. Idempotent — a second call is
// a no-op rather than the close-of-closed-channel panic the bare
// close(s.broadcastChan) would produce.
func (s *Server) Stop() {
	closed := false
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.enabled = false
		if s.broadcastChan != nil {
			close(s.broadcastChan)
		}
		for client := range s.clients {
			if err := closeClientConn(client); err != nil {
				util.Warnf("dashboard: failed to close WebSocket client: %v", err)
			}
		}
		s.clients = make(map[*Client]struct{})
		s.mu.Unlock()
		closed = true
	})
	if !closed {
		return
	}

	// Wait for broadcastLoop to finish
	s.wg.Wait()
}

func closeClientConn(client *Client) error {
	if client == nil || client.conn == nil {
		return nil
	}
	return client.conn.Close()
}

// StatsAPIResponse is the JSON response for GET /api/dashboard/stats.
type StatsAPIResponse struct {
	Uptime          float64 `json:"uptime"`
	QueriesTotal    int64   `json:"queriesTotal"`
	QueriesPerSec   float64 `json:"queriesPerSec"`
	CacheHitRate    float64 `json:"cacheHitRate"`
	BlockedQueries  int64   `json:"blockedQueries"`
	ActiveClients   int     `json:"activeClients"`
	ZoneCount       int     `json:"zoneCount"`
	UpstreamLatency int64   `json:"upstreamLatency"`
}

// ZoneAPIEntry represents a zone in the zones list API response.
type ZoneAPIEntry struct {
	Name    string `json:"name"`
	Records int    `json:"records"`
	Serial  int    `json:"serial"`
}

// BroadcastMessage is the JSON WebSocket broadcast envelope.
type BroadcastMessage struct {
	Type  string      `json:"type"`
	Event *QueryEvent `json:"event"`
}

// GetStats returns current dashboard statistics
func (s *Server) GetStats() *DashboardStats {
	s.stats.mu.RLock()
	defer s.stats.mu.RUnlock()

	recentQueries := make([]*QueryEvent, len(s.stats.RecentQueries))
	for i, query := range s.stats.RecentQueries {
		if query == nil {
			continue
		}
		queryCopy := *query
		recentQueries[i] = &queryCopy
	}

	return &DashboardStats{
		Uptime:          s.stats.Uptime,
		QueriesTotal:    s.stats.QueriesTotal,
		QueriesPerSec:   s.stats.QueriesPerSec,
		CacheHitRate:    s.stats.CacheHitRate,
		BlockedQueries:  s.stats.BlockedQueries,
		ActiveClients:   s.stats.ActiveClients,
		ZoneCount:       s.stats.ZoneCount,
		UpstreamLatency: s.stats.UpstreamLatency,
		RecentQueries:   recentQueries,
	}
}
