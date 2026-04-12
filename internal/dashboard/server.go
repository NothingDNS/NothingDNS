// Package dashboard provides a web dashboard for NothingDNS
package dashboard

import (
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
	mu              sync.RWMutex
	clients         map[*Client]struct{}
	broadcastChan   chan *QueryEvent
	stats           *DashboardStats
	enabled         bool
	wg              sync.WaitGroup
	allowedOrigins  []string // Allowed CORS origins for WebSocket
	authStore       *auth.Store
	authToken       string    // Legacy token-only auth fallback
	zoneManager     *zone.Manager
}

// secureCompare performs constant-time comparison to prevent timing attacks
func secureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// MaxWebSocketClients is the maximum number of concurrent WebSocket connections.
const MaxWebSocketClients = 1000

// Client represents a connected WebSocket client
type Client struct {
	conn      WebSocketConn
	send      chan []byte
	closeSend sync.Once
	closed    chan struct{} // Used to signal write loop to exit
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
}

// GetRecentQueries returns a paginated copy of recent queries.
func (ds *DashboardStats) GetRecentQueries(offset, limit int) ([]*QueryEvent, int) {
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
	queries := make([]*QueryEvent, end-offset)
	copy(queries, ds.RecentQueries[offset:end])
	return queries, total
}

// TopDomainsEntry represents a domain with its query count.
type TopDomainsEntry struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

// GetTopDomains returns the top N most-queried domains.
func (ds *DashboardStats) GetTopDomains(limit int) []TopDomainsEntry {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	if len(ds.RecentQueries) == 0 {
		return nil
	}

	countByDomain := make(map[string]int)
	for _, q := range ds.RecentQueries {
		countByDomain[q.Domain]++
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
	s.allowedOrigins = origins
	s.mu.Unlock()
}

// SetAuthStore sets the auth store for WebSocket authentication.
func (s *Server) SetAuthStore(store *auth.Store) {
	s.mu.Lock()
	s.authStore = store
	s.mu.Unlock()
}

// SetAuthToken sets the legacy token for token-only authentication fallback.
func (s *Server) SetAuthToken(token string) {
	s.mu.Lock()
	s.authToken = token
	s.mu.Unlock()
}

// ServeHTTP handles HTTP requests
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch path {
	case "/api/dashboard/stats":
		s.handleStats(w, r)
	case "/api/dashboard/queries":
		s.handleQueryStream(w, r)
	case "/api/dashboard/zones":
		s.handleZones(w, r)
	case "/ws":
		s.handleWebSocket(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handleStats handles stats API requests
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	s.stats.mu.RLock()
	defer s.stats.mu.RUnlock()

	resp := &StatsAPIResponse{
		Uptime:          time.Since(s.stats.Uptime).Seconds(),
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

// handleQueryStream handles query stream requests
func (s *Server) handleQueryStream(w http.ResponseWriter, r *http.Request) {
	s.stats.mu.RLock()
	queries := make([]*QueryEvent, len(s.stats.RecentQueries))
	copy(queries, s.stats.RecentQueries)
	s.stats.mu.RUnlock()

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
	// Also accept token from query parameter (for WebSocket auth)
	if token == "" {
		token = r.URL.Query().Get("token")
	}

	// Validate authentication
	s.mu.RLock()
	authStore := s.authStore
	authToken := s.authToken
	s.mu.RUnlock()

	if token == "" {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}

	// Validate against auth store if available, otherwise use legacy token
	if authStore != nil {
		if _, err := authStore.ValidateToken(token); err != nil {
			// Log without exposing internal error details to client
			util.Warnf("dashboard: websocket auth failed: token validation error")
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
	} else if authToken != "" {
		// Legacy token-only mode: constant-time comparison
		if !secureCompare(token, authToken) {
			util.Warnf("dashboard: websocket auth failed: invalid legacy token")
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
	} else {
		// SECURITY: deny if neither auth store nor legacy token configured (fail closed)
		http.Error(w, "authentication required: auth not configured", http.StatusUnauthorized)
		return
	}

	conn, err := websocket.Handshake(w, r, s.allowedOrigins...)
	if err != nil {
		util.Warnf("dashboard: websocket handshake failed: %v", err)
		return
	}

	client := &Client{
		conn:   conn,
		send:   make(chan []byte, 256),
		closed: make(chan struct{}),
	}

	s.AddClient(client)
	s.ClientLoop(client)
}

// RecordQuery records a query event and broadcasts it
func (s *Server) RecordQuery(event *QueryEvent) {
	// Update stats
	s.stats.mu.Lock()
	s.stats.QueriesTotal++
	s.stats.RecentQueries = append(s.stats.RecentQueries, event)

	// Keep only last 100 queries
	if len(s.stats.RecentQueries) > 100 {
		s.stats.RecentQueries = s.stats.RecentQueries[1:]
	}
	s.stats.mu.Unlock()

	// Broadcast to connected clients
	select {
	case s.broadcastChan <- event:
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
	s.stats.mu.Lock()
	s.stats.ActiveClients = len(s.clients)
	s.stats.mu.Unlock()
}

// RemoveClient removes a WebSocket client
func (s *Server) RemoveClient(client *Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clients, client)
	s.stats.mu.Lock()
	s.stats.ActiveClients = len(s.clients)
	s.stats.mu.Unlock()
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

		s.mu.RLock()
		for client := range s.clients {
			select {
			case client.send <- data:
			default:
				// Client channel full, skip
			}
		}
		s.mu.RUnlock()
	}
}

// ClientLoop handles a client's read/write loops
func (s *Server) ClientLoop(client *Client) {
	defer func() {
		close(client.closed) // Signal write loop to exit
		client.closeSend.Do(func() { close(client.send) })
		s.RemoveClient(client)
		client.conn.Close()
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

// Stop stops the dashboard server
func (s *Server) Stop() {
	s.mu.Lock()

	s.enabled = false

	if s.broadcastChan != nil {
		close(s.broadcastChan)
	}

	// Close all clients
	for client := range s.clients {
		if client.conn != nil {
			client.conn.Close()
		}
	}
	s.clients = make(map[*Client]struct{})
	s.mu.Unlock()

	// Wait for broadcastLoop to finish
	s.wg.Wait()
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
	return s.stats
}
