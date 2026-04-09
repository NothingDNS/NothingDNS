package dashboard

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
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
			Domain:       "example.com",
			QueryType:    "A",
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
		send: make(chan []byte, 10),
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
		conn: mockConn,
		send: make(chan []byte, 10),
	}

	server.AddClient(client)

	// Record a query (should broadcast)
	event := &QueryEvent{
		Domain:    "broadcast.example.com",
		QueryType: "A",
		Protocol:  "udp",
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

	var zones []ZoneAPIEntry
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
	mu       sync.Mutex
	readErr  atomic.Bool
}

func (m *MockWebSocketConn) ReadMessage() (int, []byte, error) {
	if m.readErr.Load() {
		return 0, nil, errors.New("read error")
	}
	return 0, nil, nil
}

func (m *MockWebSocketConn) WriteMessage(messageType int, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, data)
	return nil
}

func (m *MockWebSocketConn) SetWriteDeadline(time.Time) error { return nil }
func (m *MockWebSocketConn) SetReadDeadline(time.Time) error { return nil }

func (m *MockWebSocketConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// Test ClientLoop with read error
func TestClientLoop_ReadError(t *testing.T) {
	server := NewServer()

	mockConn := &ErrorMockWebSocketConn{}
	mockConn.readErr.Store(true)
	client := &Client{
		conn:   mockConn,
		send:   make(chan []byte, 10),
		closed: make(chan struct{}),
	}

	server.AddClient(client)

	// ClientLoop should exit when ReadMessage returns error
	done := make(chan struct{})
	go func() {
		server.ClientLoop(client)
		close(done)
	}()

	// Wait for client loop to finish
	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Error("ClientLoop did not exit on read error")
	}

	// Client should be removed
	server.mu.RLock()
	if len(server.clients) != 0 {
		t.Errorf("Expected 0 clients after ClientLoop exit, got %d", len(server.clients))
	}
	server.mu.RUnlock()

	// Connection should be closed
	if !mockConn.closed {
		t.Error("Expected connection to be closed")
	}
}

// Test ClientLoop with write error
func TestClientLoop_WriteError(t *testing.T) {
	server := NewServer()

	mockConn := &ErrorMockWebSocketConn{}
	mockConn.writeErr.Store(true)
	client := &Client{
		conn:   mockConn,
		send:   make(chan []byte, 10),
		closed: make(chan struct{}),
	}

	server.AddClient(client)

	done := make(chan struct{})
	go func() {
		server.ClientLoop(client)
		close(done)
	}()

	// Send a message to trigger write
	event := &QueryEvent{Domain: "test.example.com"}
	server.RecordQuery(event)

	// Give time for the write goroutine to fail
	time.Sleep(50 * time.Millisecond)

	// The write goroutine exits but read loop is still running
	// Trigger read error to complete the cleanup
	mockConn.mu.Lock()
	mockConn.readErr.Store(true)
	mockConn.mu.Unlock()

	// Wait for client loop to finish
	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Error("ClientLoop did not exit")
	}
}

// Test ClientLoop with successful write
func TestClientLoop_SuccessfulWrite(t *testing.T) {
	server := NewServer()

	mockConn := &MockWebSocketConn{}
	client := &Client{
		conn:   mockConn,
		send:   make(chan []byte, 10),
		closed: make(chan struct{}),
	}

	server.AddClient(client)

	done := make(chan struct{})
	go func() {
		server.ClientLoop(client)
		close(done)
	}()

	// Send a message to trigger write
	event := &QueryEvent{Domain: "test.example.com"}
	server.RecordQuery(event)

	// Give time for write to process
	time.Sleep(50 * time.Millisecond)

	// Verify message was written
	mockConn.mu.Lock()
	if len(mockConn.messages) == 0 {
		t.Error("Expected message to be written")
	}
	mockConn.mu.Unlock()

	// Close the send channel to stop the write loop
	client.closeSend.Do(func() { close(client.send) })

	// Trigger read error to exit
	mockConn.readErr.Store(true)

	// Wait for client loop to finish
	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Error("ClientLoop did not exit")
	}
}

// ErrorMockWebSocketConn is a mock that can return errors
type ErrorMockWebSocketConn struct {
	messages [][]byte
	closed   bool
	readErr  atomic.Bool
	writeErr atomic.Bool
	mu       sync.Mutex
}

func (m *ErrorMockWebSocketConn) ReadMessage() (int, []byte, error) {
	if m.readErr.Load() {
		return 0, nil, errors.New("read error")
	}
	return 0, nil, nil
}

func (m *ErrorMockWebSocketConn) WriteMessage(messageType int, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.writeErr.Load() {
		return errors.New("write error")
	}
	m.messages = append(m.messages, data)
	return nil
}

func (m *ErrorMockWebSocketConn) SetWriteDeadline(time.Time) error { return nil }
func (m *ErrorMockWebSocketConn) SetReadDeadline(time.Time) error { return nil }

func (m *ErrorMockWebSocketConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// Test Stop is idempotent when called after broadcastChan is drained
func TestStop_AfterDrain(t *testing.T) {
	server := NewServer()

	// Add a client
	client := &Client{
		conn: &MockWebSocketConn{},
		send: make(chan []byte, 10),
	}
	server.AddClient(client)

	// Stop should work correctly
	server.Stop()

	if server.enabled {
		t.Error("Expected server to be disabled")
	}

	if len(server.clients) != 0 {
		t.Errorf("Expected 0 clients after stop, got %d", len(server.clients))
	}
}

// Test Stop with clients that have nil connections
func TestStop_NilClientConnections(t *testing.T) {
	server := NewServer()

	// Add client with nil connection
	client := &Client{
		conn: nil,
		send: make(chan []byte, 10),
	}
	server.AddClient(client)

	// Should not panic
	server.Stop()

	if len(server.clients) != 0 {
		t.Errorf("Expected 0 clients after stop, got %d", len(server.clients))
	}
}

// Test broadcastLoop when channel is full (drop event)
func TestBroadcastLoop_ChannelFull(t *testing.T) {
	server := NewServer()
	defer server.Stop()

	// Create client with small buffer
	client := &Client{
		conn: &MockWebSocketConn{},
		send: make(chan []byte, 1), // Small buffer
	}
	server.AddClient(client)

	// Record many queries quickly to fill the channel
	for i := 0; i < 50; i++ {
		event := &QueryEvent{
			Domain:    "test.example.com",
			QueryType: "A",
		}
		server.RecordQuery(event)
	}

	// Give time for broadcast loop to process
	time.Sleep(100 * time.Millisecond)

	// Should not block or panic - events may be dropped when channel is full
	// This tests the "default" case in the broadcast loop select
}

// Test broadcastLoop with no clients
func TestBroadcastLoop_NoClients(t *testing.T) {
	server := NewServer()
	defer server.Stop()

	// Record a query without any clients
	event := &QueryEvent{
		Domain:    "test.example.com",
		QueryType: "A",
	}
	server.RecordQuery(event)

	// Should not panic or block
	time.Sleep(50 * time.Millisecond)
}

// Test RecordQuery broadcastChan full
func TestRecordQuery_BroadcastChanFull(t *testing.T) {
	server := NewServer()
	defer server.Stop()

	// Create server with very small broadcast channel
	// Fill the channel first
	for i := 0; i < 1001; i++ {
		select {
		case server.broadcastChan <- &QueryEvent{Domain: "fill.example.com"}:
		default:
		}
	}

	// Now record a query - should not block even when channel is full
	event := &QueryEvent{
		Domain:    "test.example.com",
		QueryType: "A",
	}
	server.RecordQuery(event)

	// Should complete without blocking
}

// Test UpdateStats with zero values (should not update)
func TestUpdateStats_ZeroValues(t *testing.T) {
	server := NewServer()

	// Set initial values
	server.UpdateStats(UpdateStatsRequest{
		QueriesPerSec:   100.0,
		CacheHitRate:    50.0,
		ZoneCount:       5,
		UpstreamLatency: 10 * time.Millisecond,
	})

	// Try to update with zero values - should not change
	server.UpdateStats(UpdateStatsRequest{
		QueriesPerSec:   0,
		CacheHitRate:    0,
		ZoneCount:       0,
		UpstreamLatency: 0,
	})

	server.stats.mu.RLock()
	if server.stats.QueriesPerSec != 100.0 {
		t.Errorf("Expected QueriesPerSec to remain 100.0, got %v", server.stats.QueriesPerSec)
	}
	if server.stats.CacheHitRate != 50.0 {
		t.Errorf("Expected CacheHitRate to remain 50.0, got %v", server.stats.CacheHitRate)
	}
	if server.stats.ZoneCount != 5 {
		t.Errorf("Expected ZoneCount to remain 5, got %d", server.stats.ZoneCount)
	}
	if server.stats.UpstreamLatency != 10*time.Millisecond {
		t.Errorf("Expected UpstreamLatency to remain 10ms, got %v", server.stats.UpstreamLatency)
	}
	server.stats.mu.RUnlock()
}

// Test RemoveClient that doesn't exist
func TestRemoveClient_NonExistent(t *testing.T) {
	server := NewServer()

	client := &Client{
		send: make(chan []byte, 10),
	}

	// Remove client that was never added - should not panic
	server.RemoveClient(client)

	if len(server.clients) != 0 {
		t.Errorf("Expected 0 clients, got %d", len(server.clients))
	}
}

// Test AddClient multiple times
func TestAddClient_MultipleTimes(t *testing.T) {
	server := NewServer()

	client := &Client{
		send: make(chan []byte, 10),
	}

	// Add same client multiple times
	server.AddClient(client)
	server.AddClient(client)
	server.AddClient(client)

	// Map should only have one entry (though the client is the same key)
	server.mu.RLock()
	count := len(server.clients)
	server.mu.RUnlock()

	if count != 1 {
		t.Errorf("Expected 1 client, got %d", count)
	}
}

// Test Concurrent client operations
func TestClient_ConcurrentOperations(t *testing.T) {
	server := NewServer()
	defer server.Stop()

	var wg sync.WaitGroup

	// Concurrently add and remove clients
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			client := &Client{
				conn: &MockWebSocketConn{},
				send: make(chan []byte, 10),
			}
			server.AddClient(client)
			time.Sleep(time.Microsecond * time.Duration(id%10))
			server.RemoveClient(client)
		}(i)
	}

	wg.Wait()

	server.mu.RLock()
	if len(server.clients) != 0 {
		t.Errorf("Expected 0 clients after concurrent operations, got %d", len(server.clients))
	}
	server.mu.RUnlock()
}

// Test ServeHTTP all routes
func TestServeHTTP_AllRoutes(t *testing.T) {
	server := NewServer()
	defer server.Stop()

	tests := []struct {
		path       string
		expectCode int
	}{
		{"/api/dashboard/stats", http.StatusOK},
		{"/api/dashboard/queries", http.StatusOK},
		{"/api/dashboard/zones", http.StatusOK},
		{"/ws", http.StatusUnauthorized}, // Auth required - returns 401 when no auth store configured
		{"/unknown", http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()
			server.ServeHTTP(w, req)

			if w.Code != tt.expectCode {
				t.Errorf("Path %s: expected status %d, got %d", tt.path, tt.expectCode, w.Code)
			}
		})
	}
}

// Test handleStats response content type
func TestHandleStats_ContentType(t *testing.T) {
	server := NewServer()
	defer server.Stop()

	req := httptest.NewRequest("GET", "/api/dashboard/stats", nil)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got %s", ct)
	}
}

// Test handleQueryStream response content type
func TestHandleQueryStream_ContentType(t *testing.T) {
	server := NewServer()
	defer server.Stop()

	req := httptest.NewRequest("GET", "/api/dashboard/queries", nil)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got %s", ct)
	}
}

// Test handleZones response content type
func TestHandleZones_ContentType(t *testing.T) {
	server := NewServer()
	defer server.Stop()

	req := httptest.NewRequest("GET", "/api/dashboard/zones", nil)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got %s", ct)
	}
}

// Test QueryEvent JSON serialization
func TestQueryEvent_JSONSerialization(t *testing.T) {
	event := &QueryEvent{
		Timestamp:    time.Now(),
		ClientIP:     "192.168.1.1",
		Domain:       "example.com",
		QueryType:    "AAAA",
		ResponseCode: "NOERROR",
		Duration:     1500,
		Cached:       true,
		Blocked:      false,
		Protocol:     "udp",
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Failed to marshal QueryEvent: %v", err)
	}

	var decoded QueryEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal QueryEvent: %v", err)
	}

	if decoded.ClientIP != event.ClientIP {
		t.Errorf("Expected ClientIP %s, got %s", event.ClientIP, decoded.ClientIP)
	}
	if decoded.Domain != event.Domain {
		t.Errorf("Expected Domain %s, got %s", event.Domain, decoded.Domain)
	}
	if decoded.QueryType != event.QueryType {
		t.Errorf("Expected QueryType %s, got %s", event.QueryType, decoded.QueryType)
	}
	if decoded.Protocol != event.Protocol {
		t.Errorf("Expected Protocol %s, got %s", event.Protocol, decoded.Protocol)
	}
}

// Test DashboardStats JSON serialization
func TestDashboardStats_JSONSerialization(t *testing.T) {
	stats := &DashboardStats{
		Uptime:          time.Now(),
		QueriesTotal:    1000,
		QueriesPerSec:   50.5,
		CacheHitRate:    85.3,
		BlockedQueries:  25,
		ActiveClients:   10,
		ZoneCount:       5,
		UpstreamLatency: 15 * time.Millisecond,
		RecentQueries:   []*QueryEvent{},
	}

	data, err := json.Marshal(stats)
	if err != nil {
		t.Fatalf("Failed to marshal DashboardStats: %v", err)
	}

	var decoded DashboardStats
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal DashboardStats: %v", err)
	}

	if decoded.QueriesTotal != stats.QueriesTotal {
		t.Errorf("Expected QueriesTotal %d, got %d", stats.QueriesTotal, decoded.QueriesTotal)
	}
	if decoded.QueriesPerSec != stats.QueriesPerSec {
		t.Errorf("Expected QueriesPerSec %f, got %f", stats.QueriesPerSec, decoded.QueriesPerSec)
	}
}

// Test multiple servers
func TestMultipleServers(t *testing.T) {
	server1 := NewServer()
	server2 := NewServer()

	defer server1.Stop()
	defer server2.Stop()

	// Each server should be independent
	server1.UpdateStats(UpdateStatsRequest{
		QueriesPerSec: 100.0,
	})

	server2.UpdateStats(UpdateStatsRequest{
		QueriesPerSec: 200.0,
	})

	if server1.stats.QueriesPerSec != 100.0 {
		t.Errorf("Server1: Expected QueriesPerSec 100.0, got %v", server1.stats.QueriesPerSec)
	}

	if server2.stats.QueriesPerSec != 200.0 {
		t.Errorf("Server2: Expected QueriesPerSec 200.0, got %v", server2.stats.QueriesPerSec)
	}
}

// Test broadcast message format
func TestBroadcast_MessageFormat(t *testing.T) {
	server := NewServer()
	defer server.Stop()

	mockConn := &MockWebSocketConn{}
	client := &Client{
		conn: mockConn,
		send: make(chan []byte, 10),
	}
	server.AddClient(client)

	event := &QueryEvent{
		Domain:    "test.example.com",
		QueryType: "A",
		Protocol:  "udp",
		Cached:    true,
		Blocked:   false,
	}

	server.RecordQuery(event)

	// Wait for broadcast
	select {
	case data := <-client.send:
		var msg map[string]interface{}
		if err := json.Unmarshal(data, &msg); err != nil {
			t.Fatalf("Failed to parse message: %v", err)
		}

		if msg["type"] != "query" {
			t.Errorf("Expected type 'query', got %v", msg["type"])
		}

		eventMap, ok := msg["event"].(map[string]interface{})
		if !ok {
			t.Fatal("Expected event to be a map")
		}

		if eventMap["domain"] != "test.example.com" {
			t.Errorf("Expected domain 'test.example.com', got %v", eventMap["domain"])
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Expected broadcast message")
	}
}

// Test RecentQueries order
func TestRecentQueries_Order(t *testing.T) {
	server := NewServer()
	defer server.Stop()

	// Record queries in order
	for i := 0; i < 5; i++ {
		server.RecordQuery(&QueryEvent{
			Domain:    "test" + string(rune('0'+i)) + ".example.com",
			QueryType: "A",
		})
	}

	server.stats.mu.RLock()
	queries := server.stats.RecentQueries
	server.stats.mu.RUnlock()

	// First query should be for test0.example.com
	if len(queries) != 5 {
		t.Fatalf("Expected 5 queries, got %d", len(queries))
	}

	// Queries should be in order they were recorded
	if queries[0].Domain != "test0.example.com" {
		t.Errorf("Expected first query domain 'test0.example.com', got %s", queries[0].Domain)
	}
}

// Test ClientLoop closed send channel
func TestClientLoop_ClosedSendChannel(t *testing.T) {
	server := NewServer()

	mockConn := &BlockingMockWebSocketConn{
		readChan: make(chan struct{}),
	}
	client := &Client{
		conn:   mockConn,
		send:   make(chan []byte, 10),
		closed: make(chan struct{}),
	}

	server.AddClient(client)

	done := make(chan struct{})
	go func() {
		server.ClientLoop(client)
		close(done)
	}()

	// Close the send channel to stop the write loop
	client.closeSend.Do(func() { close(client.send) })

	// Close the readChan to trigger ReadMessage return
	close(mockConn.readChan)

	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Error("ClientLoop did not exit")
	}
}

// BlockingMockWebSocketConn blocks on ReadMessage until readChan is closed
type BlockingMockWebSocketConn struct {
	messages [][]byte
	closed   bool
	readChan chan struct{}
	mu       sync.Mutex
}

func (m *BlockingMockWebSocketConn) ReadMessage() (int, []byte, error) {
	<-m.readChan // Block until readChan is closed
	return 0, nil, errors.New("connection closed")
}

func (m *BlockingMockWebSocketConn) WriteMessage(messageType int, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, data)
	return nil
}

func (m *BlockingMockWebSocketConn) SetWriteDeadline(time.Time) error { return nil }
func (m *BlockingMockWebSocketConn) SetReadDeadline(time.Time) error { return nil }

func (m *BlockingMockWebSocketConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// DashboardStats method tests

func TestGetRecentQueries_Empty(t *testing.T) {
	ds := &DashboardStats{
		RecentQueries: nil,
	}
	queries, total := ds.GetRecentQueries(0, 10)
	if queries != nil {
		t.Error("Expected nil for empty queries")
	}
	if total != 0 {
		t.Errorf("Total = %d, want 0", total)
	}
}

func TestGetRecentQueries_WithData(t *testing.T) {
	ds := &DashboardStats{
		RecentQueries: []*QueryEvent{
			{Domain: "a.com", QueryType: "A"},
			{Domain: "b.com", QueryType: "A"},
			{Domain: "c.com", QueryType: "A"},
		},
	}
	queries, total := ds.GetRecentQueries(0, 2)
	if len(queries) != 2 {
		t.Errorf("Queries len = %d, want 2", len(queries))
	}
	if total != 3 {
		t.Errorf("Total = %d, want 3", total)
	}
}

func TestGetRecentQueries_OffsetBeyond(t *testing.T) {
	ds := &DashboardStats{
		RecentQueries: []*QueryEvent{
			{Domain: "a.com", QueryType: "A"},
		},
	}
	queries, total := ds.GetRecentQueries(10, 5)
	if queries != nil {
		t.Error("Expected nil for offset beyond data")
	}
	if total != 0 {
		// When offset >= total, returns 0 per implementation
		t.Errorf("Total = %d, want 0", total)
	}
}

func TestGetTopDomains_Empty(t *testing.T) {
	ds := &DashboardStats{
		RecentQueries: nil,
	}
	result := ds.GetTopDomains(10)
	if result != nil {
		t.Error("Expected nil for empty queries")
	}
}

func TestGetTopDomains_WithData(t *testing.T) {
	ds := &DashboardStats{
		RecentQueries: []*QueryEvent{
			{Domain: "a.com", QueryType: "A"},
			{Domain: "a.com", QueryType: "A"},
			{Domain: "b.com", QueryType: "A"},
			{Domain: "c.com", QueryType: "A"},
			{Domain: "c.com", QueryType: "A"},
			{Domain: "c.com", QueryType: "A"},
		},
	}
	result := ds.GetTopDomains(3)

	// Should return top 3 domains sorted by count
	if len(result) != 3 {
		t.Errorf("Result len = %d, want 3", len(result))
	}
	// c.com has 3 queries, should be first
	if result[0].Domain != "c.com" {
		t.Errorf("Top domain = %q, want c.com", result[0].Domain)
	}
	if result[0].Count != 3 {
		t.Errorf("Top count = %d, want 3", result[0].Count)
	}
}

func TestGetTopDomains_LimitLessThanData(t *testing.T) {
	ds := &DashboardStats{
		RecentQueries: []*QueryEvent{
			{Domain: "a.com", QueryType: "A"},
			{Domain: "b.com", QueryType: "A"},
			{Domain: "c.com", QueryType: "A"},
		},
	}
	result := ds.GetTopDomains(1)

	if len(result) != 1 {
		t.Errorf("Result len = %d, want 1", len(result))
	}
}
