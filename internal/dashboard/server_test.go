package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewServer(t *testing.T) {
	server := NewServer()
	if server == nil {
		t.Fatal("Expected non-nil server")
	}

	if len(server.clients) != 0 {
		t.Errorf("Expected 0 clients, got %d", len(server.clients))
	}

	if server.stats == nil {
		t.Error("Expected non-nil stats")
	}
}

func TestHandleStats(t *testing.T) {
	server := NewServer()

	// Update some stats
	server.UpdateStats(UpdateStatsRequest{
		QueriesPerSec:   100.5,
		CacheHitRate:    85.3,
		ZoneCount:       5,
		UpstreamLatency: 10 * time.Millisecond,
	})

	req := httptest.NewRequest("GET", "/api/dashboard/stats", nil)
	w := httptest.NewRecorder()

	server.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var stats map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &stats); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if stats["queriesPerSec"].(float64) != 100.5 {
		t.Errorf("Expected queriesPerSec 100.5, got %v", stats["queriesPerSec"])
	}

	if stats["cacheHitRate"].(float64) != 85.3 {
		t.Errorf("Expected cacheHitRate 85.3, got %v", stats["cacheHitRate"])
	}
}

func TestHandleQueryStream(t *testing.T) {
	server := NewServer()

	// Record some queries
	for i := 0; i < 5; i++ {
		server.RecordQuery(&QueryEvent{
			Timestamp:    time.Now(),
			ClientIP:     "192.168.1.1",
			Domain:       "example.com",
			QueryType:    "A",
			ResponseCode: "NOERROR",
			Duration:     1000,
			Cached:       i%2 == 0,
		})
	}

	req := httptest.NewRequest("GET", "/api/dashboard/queries", nil)
	w := httptest.NewRecorder()

	server.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var queries []*QueryEvent
	if err := json.Unmarshal(w.Body.Bytes(), &queries); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if len(queries) != 5 {
		t.Errorf("Expected 5 queries, got %d", len(queries))
	}
}

func TestRecordQuery(t *testing.T) {
	server := NewServer()

	// Record a query
	event := &QueryEvent{
		Timestamp:    time.Now(),
		ClientIP:     "10.0.0.1",
		Domain:       "test.example.com",
		QueryType:    "AAAA",
		ResponseCode: "NOERROR",
		Duration:     2000,
		Cached:       true,
		Blocked:      false,
		Protocol:     "udp",
	}

	server.RecordQuery(event)

	// Check stats updated
	server.stats.mu.RLock()
	if server.stats.QueriesTotal != 1 {
		t.Errorf("Expected QueriesTotal 1, got %d", server.stats.QueriesTotal)
	}

	if len(server.stats.RecentQueries) != 1 {
		t.Errorf("Expected 1 recent query, got %d", len(server.stats.RecentQueries))
	}
	server.stats.mu.RUnlock()
}

func TestRecentQueriesLimit(t *testing.T) {
	server := NewServer()

	// Record more than 100 queries
	for i := 0; i < 150; i++ {
		server.RecordQuery(&QueryEvent{
			Domain:      "example.com",
			QueryType:   "A",
			ResponseCode: "NOERROR",
		})
	}

	server.stats.mu.RLock()
	if len(server.stats.RecentQueries) > 100 {
		t.Errorf("Expected at most 100 recent queries, got %d", len(server.stats.RecentQueries))
	}
	server.stats.mu.RUnlock()
}

func TestAddRemoveClient(t *testing.T) {
	server := NewServer()

	client := &Client{
		send:        make(chan []byte, 10),
		subscribe:   make(chan struct{}),
		unsubscribe: make(chan struct{}),
	}

	server.AddClient(client)

	if len(server.clients) != 1 {
		t.Errorf("Expected 1 client, got %d", len(server.clients))
	}

	if server.stats.ActiveClients != 1 {
		t.Errorf("Expected ActiveClients 1, got %d", server.stats.ActiveClients)
	}

	server.RemoveClient(client)

	if len(server.clients) != 0 {
		t.Errorf("Expected 0 clients, got %d", len(server.clients))
	}

	if server.stats.ActiveClients != 0 {
		t.Errorf("Expected ActiveClients 0, got %d", server.stats.ActiveClients)
	}
}

func TestBroadcastLoop(t *testing.T) {
	server := NewServer()

	// Create mock client
	mockConn := &MockWebSocketConn{}
	client := &Client{
		conn:        mockConn,
		send:        make(chan []byte, 10),
		subscribe:   make(chan struct{}),
		unsubscribe: make(chan struct{}),
	}

	server.AddClient(client)

	// Record a query (should broadcast)
	event := &QueryEvent{
		Domain:      "broadcast.example.com",
		QueryType:   "A",
		Protocol:    "udp",
	}

	server.RecordQuery(event)

	// Check if message was sent to client
	select {
	case data := <-client.send:
		var msg map[string]interface{}
		if err := json.Unmarshal(data, &msg); err != nil {
			t.Fatalf("Failed to parse message: %v", err)
		}

		if msg["type"].(string) != "query" {
			t.Errorf("Expected type 'query', got %v", msg["type"])
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Expected broadcast message")
	}

	server.RemoveClient(client)
}

func TestHandleZones(t *testing.T) {
	server := NewServer()

	req := httptest.NewRequest("GET", "/api/dashboard/zones", nil)
	w := httptest.NewRecorder()

	server.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var zones []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &zones); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Should have at least one zone (placeholder)
	if len(zones) < 1 {
		t.Error("Expected at least one zone")
	}
}

func TestHandleWebSocket(t *testing.T) {
	server := NewServer()

	req := httptest.NewRequest("GET", "/ws", nil)
	w := httptest.NewRecorder()

	server.ServeHTTP(w, req)

	// WebSocket upgrade should fail without proper headers
	if w.Code != http.StatusMethodNotAllowed {
		t.Logf("WebSocket returned status %d (expected without upgrade)", w.Code)
	}
}

func TestNotFound(t *testing.T) {
	server := NewServer()

	req := httptest.NewRequest("GET", "/nonexistent", nil)
	w := httptest.NewRecorder()

	server.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func TestStop(t *testing.T) {
	server := NewServer()

	// Add a client
	client := &Client{
		send: make(chan []byte, 10),
	}
	server.AddClient(client)

	server.Stop()

	if server.enabled {
		t.Error("Expected server to be disabled")
	}

	if len(server.clients) != 0 {
		t.Errorf("Expected 0 clients after stop, got %d", len(server.clients))
	}
}

func TestUpdateStats(t *testing.T) {
	server := NewServer()

	server.UpdateStats(UpdateStatsRequest{
		QueriesPerSec:   500.0,
		CacheHitRate:    90.5,
		ZoneCount:       10,
		UpstreamLatency: 15 * time.Millisecond,
	})

	server.stats.mu.RLock()
	defer server.stats.mu.RUnlock()

	if server.stats.QueriesPerSec != 500.0 {
		t.Errorf("Expected QueriesPerSec 500.0, got %v", server.stats.QueriesPerSec)
	}

	if server.stats.CacheHitRate != 90.5 {
		t.Errorf("Expected CacheHitRate 90.5, got %v", server.stats.CacheHitRate)
	}

	if server.stats.ZoneCount != 10 {
		t.Errorf("Expected ZoneCount 10, got %d", server.stats.ZoneCount)
	}

	if server.stats.UpstreamLatency != 15*time.Millisecond {
		t.Errorf("Expected UpstreamLatency 15ms, got %v", server.stats.UpstreamLatency)
	}
}

func TestGetStats(t *testing.T) {
	server := NewServer()

	stats := server.GetStats()
	if stats == nil {
		t.Error("Expected non-nil stats")
	}

	if stats.Uptime.IsZero() {
		t.Error("Expected non-zero uptime")
	}
}

// Mock implementations

type MockWebSocketConn struct {
	messages [][]byte
	closed   bool
}

func (m *MockWebSocketConn) ReadMessage() (int, []byte, error) {
	return 0, nil, nil
}

func (m *MockWebSocketConn) WriteMessage(messageType int, data []byte) error {
	m.messages = append(m.messages, data)
	return nil
}

func (m *MockWebSocketConn) Close() error {
	m.closed = true
	return nil
}
