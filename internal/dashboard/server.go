// Package dashboard provides a web dashboard for NothingDNS
package dashboard

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

// Server implements the web dashboard server
type Server struct {
	mu            sync.RWMutex
	clients       map[*Client]struct{}
	broadcastChan chan *QueryEvent
	stats         *DashboardStats
	enabled       bool
	staticHandler http.Handler
	wg            sync.WaitGroup
}

// Client represents a connected WebSocket client
type Client struct {
	conn        WebSocketConn
	send        chan []byte
	subscribe   chan struct{}
	unsubscribe chan struct{}
	closeSend   sync.Once
}

// WebSocketConn interface for WebSocket connections
type WebSocketConn interface {
	ReadMessage() (messageType int, p []byte, err error)
	WriteMessage(messageType int, data []byte) error
	Close() error
}

// QueryEvent represents a DNS query event for streaming
type QueryEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	ClientIP    string    `json:"clientIp"`
	Domain      string    `json:"domain"`
	QueryType   string    `json:"queryType"`
	ResponseCode string   `json:"responseCode"`
	Duration    int64     `json:"duration"`
	Cached      bool      `json:"cached"`
	Blocked     bool      `json:"blocked"`
	Protocol    string    `json:"protocol"`
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

// SetStaticHandler sets the static file handler
func (s *Server) SetStaticHandler(handler http.Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.staticHandler = handler
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
		// Serve static files
		if s.staticHandler != nil {
			s.staticHandler.ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
	}
}

// handleStats handles stats API requests
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	s.stats.mu.RLock()
	defer s.stats.mu.RUnlock()

	stats := map[string]interface{}{
		"uptime":          time.Since(s.stats.Uptime).Seconds(),
		"queriesTotal":    s.stats.QueriesTotal,
		"queriesPerSec":   s.stats.QueriesPerSec,
		"cacheHitRate":    s.stats.CacheHitRate,
		"blockedQueries":  s.stats.BlockedQueries,
		"activeClients":   s.stats.ActiveClients,
		"zoneCount":       s.stats.ZoneCount,
		"upstreamLatency": s.stats.UpstreamLatency.Milliseconds(),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		log.Printf("dashboard: failed to encode stats: %v", err)
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
		log.Printf("dashboard: failed to encode queries: %v", err)
	}
}

// handleZones handles zone list requests
func (s *Server) handleZones(w http.ResponseWriter, r *http.Request) {
	// This would typically fetch from zone manager
	zones := []map[string]interface{}{
		{"name": "example.com", "records": 15, "serial": 2024032601},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(zones); err != nil {
		log.Printf("dashboard: failed to encode zones: %v", err)
	}
}

// handleWebSocket handles WebSocket connections
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// WebSocket upgrade would be handled by gorilla/websocket or similar
	// This is a placeholder that returns method not allowed
	w.WriteHeader(http.StatusMethodNotAllowed)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"error": "WebSocket upgrade required",
	}); err != nil {
		log.Printf("dashboard: failed to encode websocket error: %v", err)
	}
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
		data, err := json.Marshal(map[string]interface{}{
			"type":  "query",
			"event": event,
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

// GetStats returns current dashboard statistics
func (s *Server) GetStats() *DashboardStats {
	return s.stats
}
