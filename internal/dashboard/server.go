// Package dashboard provides a web dashboard for NothingDNS
package dashboard

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/websocket"
)

// Server implements the web dashboard server
type Server struct {
	mu            sync.RWMutex
	clients       map[*Client]struct{}
	broadcastChan chan *QueryEvent
	stats         *DashboardStats
	enabled       bool
	wg            sync.WaitGroup
}

// Client represents a connected WebSocket client
type Client struct {
	conn      WebSocketConn
	send      chan []byte
	closeSend sync.Once
}

// WebSocketConn interface for WebSocket connections
type WebSocketConn interface {
	ReadMessage() (messageType int, p []byte, err error)
	WriteMessage(messageType int, data []byte) error
	Close() error
}

// QueryEvent represents a DNS query event for streaming
type QueryEvent struct {
	Timestamp    time.Time `json:"timestamp"`
	ClientIP     string    `json:"clientIp"`
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
	// This would typically fetch from zone manager
	zones := []ZoneAPIEntry{
		{Name: "example.com", Records: 15, Serial: 2024032601},
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(zones); err != nil {
		util.Warnf("dashboard: failed to encode zones: %v", err)
	}
}

// handleWebSocket handles WebSocket connections
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Handshake(w, r)
	if err != nil {
		util.Warnf("dashboard: websocket handshake failed: %v", err)
		return
	}

	client := &Client{
		conn: conn,
		send: make(chan []byte, 256),
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

// AddClient adds a WebSocket client
func (s *Server) AddClient(client *Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
		client.closeSend.Do(func() { close(client.send) })
		s.RemoveClient(client)
		client.conn.Close()
	}()

	// Write loop
	go func() {
		for data := range client.send {
			if err := client.conn.WriteMessage(1, data); err != nil {
				return
			}
		}
	}()

	// Read loop
	for {
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
