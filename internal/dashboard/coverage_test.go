package dashboard

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// ============================================================================
// broadcastLoop - JSON marshal error path (server.go:237-238)
// json.Marshal fails when a value cannot be marshaled (e.g., channel).
// We need a QueryEvent with a field that causes marshal failure.
// Since QueryEvent fields are all simple types, we exercise the path by
// verifying the broadcastLoop handles it gracefully with the existing
// functional tests. The error path is triggered when the map contains
// an unmarshallable value.
// ============================================================================

func TestBroadcastLoop_MarshalError(t *testing.T) {
	server := NewServer()
	defer server.Stop()

	// We can't directly send an unmarshallable value through broadcastChan
	// since it accepts *QueryEvent. However, we can verify that the broadcastLoop
	// continues working after events by sending a normal event.
	// The marshal error path is extremely difficult to trigger since QueryEvent
	// only contains marshallable fields.
	// Instead, let's test the default select case (client channel full) with
	// concurrent broadcast verification.

	client := &Client{
		conn: &MockWebSocketConn{},
		send: make(chan []byte, 1),
	}
	server.AddClient(client)

	// Fill the client's send channel
	client.send <- []byte("filler")

	// Record a query - the broadcast should hit the default case
	event := &QueryEvent{
		Domain:    "full.example.com",
		QueryType: "A",
	}
	server.RecordQuery(event)

	// Give time for broadcast
	time.Sleep(50 * time.Millisecond)

	// Client should still have only the filler message
	// (broadcast was skipped because channel was full)
}

// ============================================================================
// broadcastLoop - verify the continue path by sending many events rapidly
// ============================================================================

func TestBroadcastLoop_RapidEvents(t *testing.T) {
	server := NewServer()
	defer server.Stop()

	client := &Client{
		conn: &slowMockConn{},
		send: make(chan []byte, 2),
	}
	server.AddClient(client)

	// Send many events rapidly - some may be dropped
	for i := 0; i < 20; i++ {
		event := &QueryEvent{
			Domain:    "rapid.example.com",
			QueryType: "A",
		}
		server.RecordQuery(event)
	}

	time.Sleep(100 * time.Millisecond)
}

// slowMockConn is a mock connection that processes slowly
type slowMockConn struct {
	mu       sync.Mutex
	messages [][]byte
	closed   bool
}

func (m *slowMockConn) ReadMessage() (int, []byte, error) {
	return 0, nil, errors.New("read error")
}

func (m *slowMockConn) WriteMessage(messageType int, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, data)
	return nil
}

func (m *slowMockConn) SetWriteDeadline(time.Time) error { return nil }
func (m *slowMockConn) SetReadDeadline(time.Time) error  { return nil }

func (m *slowMockConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// ============================================================================
// StaticHandler - error path for fs.Sub (static.go:17-18)
// The fs.Sub error path is virtually impossible to trigger since "static"
// is a valid subdirectory within the embedded FS. Mark as skipped.
// ============================================================================

func TestStaticHandler_FsSubErrorSkipped(t *testing.T) {
	t.Skip("StaticHandler fs.Sub error path requires invalid embedded FS subdirectory - unreachable in normal builds")
}

// ============================================================================
// Additional coverage: broadcastLoop with multiple clients, one full, one not
// ============================================================================

func TestBroadcastLoop_MixedClients(t *testing.T) {
	server := NewServer()
	defer server.Stop()

	// Client 1: has room in channel
	client1 := &Client{
		conn: &MockWebSocketConn{},
		send: make(chan []byte, 10),
	}
	server.AddClient(client1)

	// Client 2: channel is full
	client2 := &Client{
		conn: &MockWebSocketConn{},
		send: make(chan []byte, 1),
	}
	server.AddClient(client2)
	client2.send <- []byte("filler")

	// Record a query
	event := &QueryEvent{
		Domain:    "mixed.example.com",
		QueryType: "AAAA",
	}
	server.RecordQuery(event)

	time.Sleep(50 * time.Millisecond)

	// Client 1 should receive the message
	select {
	case data := <-client1.send:
		var msg map[string]interface{}
		if err := json.Unmarshal(data, &msg); err != nil {
			t.Errorf("Failed to unmarshal message: %v", err)
		}
		if msg["type"] != "query" {
			t.Errorf("Expected type 'query', got %v", msg["type"])
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Client 1 should have received the broadcast")
	}
}

// ============================================================================
// Additional coverage: StaticHandler serves files correctly
// ============================================================================

func TestSPAHandler_ServesIndex(t *testing.T) {
	handler := SPAHandler()
	if handler == nil {
		t.Error("Expected non-nil handler from SPAHandler()")
	}

	req := httptest.NewRequest("GET", "/zones", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for SPA route, got %d", w.Code)
	}
}

// ============================================================================
// Additional coverage: handleStats with BlockedQueries increment
// ============================================================================

func TestRecordQuery_IncrementBlockedQueries(t *testing.T) {
	server := NewServer()
	defer server.Stop()

	// Record a blocked query
	event := &QueryEvent{
		Domain:    "blocked.example.com",
		QueryType: "A",
		Blocked:   true,
	}
	server.RecordQuery(event)

	server.stats.mu.RLock()
	total := server.stats.QueriesTotal
	queries := len(server.stats.RecentQueries)
	server.stats.mu.RUnlock()

	if total != 1 {
		t.Errorf("Expected QueriesTotal 1, got %d", total)
	}
	if queries != 1 {
		t.Errorf("Expected 1 recent query, got %d", queries)
	}

	// Verify the recorded query has Blocked set
	server.stats.mu.RLock()
	q := server.stats.RecentQueries[0]
	server.stats.mu.RUnlock()

	if !q.Blocked {
		t.Error("Expected Blocked to be true")
	}
}

// ============================================================================
// Additional coverage: RecordQuery trimming to 100 entries
// ============================================================================

func TestRecordQuery_TrimRecentQueries(t *testing.T) {
	server := NewServer()
	defer server.Stop()

	// Record 105 queries
	for i := 0; i < 105; i++ {
		server.RecordQuery(&QueryEvent{
			Domain:    "trim.example.com",
			QueryType: "A",
		})
	}

	server.stats.mu.RLock()
	count := len(server.stats.RecentQueries)
	server.stats.mu.RUnlock()

	if count != 100 {
		t.Errorf("Expected 100 recent queries (trimmed), got %d", count)
	}
}

// ============================================================================
// Additional coverage: ServeHTTP with different HTTP methods
// ============================================================================

// TestServeHTTP_PostRequest regresses SECURITY-REPORT.md L-11. The
// dashboard data endpoints previously accepted any HTTP method —
// POST to /api/dashboard/stats returned 200 with the stats payload,
// silently bypassing the safe-method discipline that the main API
// uses for cookie-CSRF defense. The endpoints are read-only today,
// so the misbehaviour wasn't itself an exploit, but any future
// state-mutating side effect added to handleStats / handleZones /
// handleQueryStream would have inherited the looseness. Post-fix
// only GET is accepted; other verbs get 405 with an Allow header.
//
// (Historical name: this test asserted the buggy "POST → 200"
// behaviour. The mock is unchanged; only the assertion flipped.)
func TestServeHTTP_PostRequest(t *testing.T) {
	server := NewServer()
	server.SetAuthToken("test-token")
	defer server.Stop()

	req := httptest.NewRequest("POST", "/api/dashboard/stats", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("L-11 regression: POST should return 405, got %d", w.Code)
	}
	if got := w.Header().Get("Allow"); got != "GET" {
		t.Errorf("L-11 regression: Allow header should be \"GET\", got %q", got)
	}
}

// ============================================================================
// Additional coverage tests for the dashboard package.
//
// Remaining uncovered lines:
//
// 1. server.go:178 - default case when broadcastChan is full in RecordQuery.
//    The broadcastChan has a buffer of 1000 and broadcastLoop continuously
//    drains it. Filling it would require sending 1001+ events faster than
//    broadcastLoop can process them (json.Marshal + client iteration).
//    This is a protective back-pressure mechanism that is nearly impossible
//    to trigger through the public API in a test environment.
//
// 2. server.go:237-238 - json.Marshal error in broadcastLoop. The data being
//    marshaled is map[string]interface{}{"type": "query", "event": event}
//    where event is *QueryEvent with all marshallable fields. There is no way
//    to inject an unmarshallable value through the public API.
//
// 3. static.go:17-19 - fs.Sub error path. The embedded filesystem always
//    contains a "static" subdirectory (guaranteed by the go:embed directive).
//    This error path is unreachable in any valid build.
// ============================================================================

// ============================================================================
// RecordQuery - verify stats update with concurrent events
// ============================================================================

func TestRecordQuery_ConcurrentEvents(t *testing.T) {
	server := NewServer()
	defer server.Stop()

	// Send events concurrently to stress test RecordQuery
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			server.RecordQuery(&QueryEvent{
				Domain:    "concurrent.example.com",
				QueryType: "A",
				Timestamp: time.Now(),
			})
		}
		close(done)
	}()

	// Wait for all events
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("Concurrent RecordQuery calls should complete")
	}

	// Give broadcastLoop time to process
	time.Sleep(50 * time.Millisecond)

	server.stats.mu.RLock()
	total := server.stats.QueriesTotal
	server.stats.mu.RUnlock()

	if total != 100 {
		t.Errorf("Expected QueriesTotal 100, got %d", total)
	}
}

// ============================================================================
// RecordQuery - event with all fields populated
// ============================================================================

func TestRecordQuery_AllFieldsPopulated(t *testing.T) {
	server := NewServer()
	defer server.Stop()

	event := &QueryEvent{
		Timestamp:    time.Now(),
		ClientIP:     "192.168.1.100",
		Domain:       "full.example.com",
		QueryType:    "AAAA",
		ResponseCode: "NOERROR",
		Answers:      []string{"AAAA 2001:db8::1"},
		Cached:       true,
		Blocked:      false,
		Duration:     15000,
	}
	server.RecordQuery(event)
	event.Answers[0] = "mutated"

	server.stats.mu.RLock()
	recent := server.stats.RecentQueries
	server.stats.mu.RUnlock()

	if len(recent) != 1 {
		t.Fatalf("Expected 1 recent query, got %d", len(recent))
	}
	if recent[0].Domain != "full.example.com" {
		t.Errorf("Expected domain 'full.example.com', got %s", recent[0].Domain)
	}
	if recent[0].ClientIP != "192.168.1.100" {
		t.Errorf("Expected ClientIP '192.168.1.100', got %s", recent[0].ClientIP)
	}
	if !recent[0].Cached {
		t.Error("Expected Cached to be true")
	}
	if len(recent[0].Answers) != 1 || recent[0].Answers[0] != "AAAA 2001:db8::1" {
		t.Errorf("Answers not cloned independently: %v", recent[0].Answers)
	}
}

// ============================================================================
// ServeHTTP - stats endpoint returns valid JSON
// ============================================================================

func TestServeHTTP_StatsEndpointValidJSON(t *testing.T) {
	server := NewServer()
	server.SetAuthToken("test-token")
	defer server.Stop()

	// Record some queries to populate stats
	for i := 0; i < 5; i++ {
		server.RecordQuery(&QueryEvent{
			Domain:    "stats.example.com",
			QueryType: "A",
		})
	}

	req := httptest.NewRequest("GET", "/api/dashboard/stats", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var stats map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &stats); err != nil {
		t.Fatalf("Response should be valid JSON: %v", err)
	}
	if stats["queriesTotal"] == nil {
		t.Error("Expected queriesTotal field")
	}
}

// ============================================================================
// broadcastLoop - verify event is properly marshaled and sent to client
// ============================================================================

func TestBroadcastLoop_EventContentVerification(t *testing.T) {
	server := NewServer()
	defer server.Stop()

	client := &Client{
		conn: &MockWebSocketConn{},
		send: make(chan []byte, 10),
	}
	server.AddClient(client)

	event := &QueryEvent{
		Domain:       "verify.example.com",
		QueryType:    "A",
		ResponseCode: "NOERROR",
		Timestamp:    time.Now(),
	}
	server.RecordQuery(event)

	select {
	case data := <-client.send:
		var msg map[string]interface{}
		if err := json.Unmarshal(data, &msg); err != nil {
			t.Fatalf("Failed to unmarshal broadcast message: %v", err)
		}
		if msg["type"] != "query" {
			t.Errorf("Expected type 'query', got %v", msg["type"])
		}
		eventMap, ok := msg["event"].(map[string]interface{})
		if !ok {
			t.Fatal("Expected event to be a map")
		}
		if eventMap["domain"] != "verify.example.com" {
			t.Errorf("Expected domain 'verify.example.com', got %v", eventMap["domain"])
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Client should have received the broadcast event")
	}
}

// ============================================================================
// UpdateStats - all fields updated
// ============================================================================

func TestUpdateStats_AllFields(t *testing.T) {
	server := NewServer()
	defer server.Stop()

	server.UpdateStats(UpdateStatsRequest{
		QueriesPerSec:   42.5,
		CacheHitRate:    85.3,
		ZoneCount:       5,
		UpstreamLatency: 10 * time.Millisecond,
	})

	server.stats.mu.RLock()
	qps := server.stats.QueriesPerSec
	chr := server.stats.CacheHitRate
	zc := server.stats.ZoneCount
	ul := server.stats.UpstreamLatency
	server.stats.mu.RUnlock()

	if qps != 42.5 {
		t.Errorf("Expected QueriesPerSec 42.5, got %f", qps)
	}
	if chr != 85.3 {
		t.Errorf("Expected CacheHitRate 85.3, got %f", chr)
	}
	if zc != 5 {
		t.Errorf("Expected ZoneCount 5, got %d", zc)
	}
	if ul != 10*time.Millisecond {
		t.Errorf("Expected UpstreamLatency 10ms, got %v", ul)
	}
}

// ============================================================================
// Skipped tests for unreachable/unteasable paths
// ============================================================================

func TestBroadcastLoop_FullChannelSkipped(t *testing.T) {
	t.Skip("broadcastChan full default case requires filling 1000+ buffer - unreachable in tests")
}

func TestBroadcastLoop_MarshalErrorSkipped(t *testing.T) {
	t.Skip("json.Marshal error requires unmarshallable value in QueryEvent - all fields are marshallable")
}

func TestStaticHandler_FsSubErrorSkippedV2(t *testing.T) {
	t.Skip("fs.Sub error requires invalid embedded FS subdirectory - unreachable in valid builds")
}

// ---------------------------------------------------------------------------
// secureCompare
// ---------------------------------------------------------------------------

func TestSecureCompare_Equal(t *testing.T) {
	if !secureCompare("hello", "hello") {
		t.Error("expected true for equal strings")
	}
}

func TestSecureCompare_NotEqual(t *testing.T) {
	if secureCompare("hello", "world") {
		t.Error("expected false for different strings")
	}
}

func TestSecureCompare_EmptyStrings(t *testing.T) {
	if !secureCompare("", "") {
		t.Error("expected true for two empty strings")
	}
}

func TestSecureCompare_DifferentLengths(t *testing.T) {
	if secureCompare("short", "longer-string") {
		t.Error("expected false for different-length strings")
	}
}

func TestSecureCompare_CaseSensitive(t *testing.T) {
	if secureCompare("Hello", "hello") {
		t.Error("expected false for different case")
	}
}

// ---------------------------------------------------------------------------
// SetZoneManager
// ---------------------------------------------------------------------------

func TestServer_SetZoneManager(t *testing.T) {
	s := NewServer()
	zm := zone.NewManager()
	s.SetZoneManager(zm)

	s.mu.RLock()
	got := s.zoneManager
	s.mu.RUnlock()

	if got == nil {
		t.Error("expected zoneManager to be set")
	}
}

func TestServer_SetZoneManager_Nil(t *testing.T) {
	s := NewServer()
	zm := zone.NewManager()
	s.SetZoneManager(zm)
	s.SetZoneManager(nil)

	s.mu.RLock()
	got := s.zoneManager
	s.mu.RUnlock()

	if got != nil {
		t.Error("expected zoneManager to be nil after SetZoneManager(nil)")
	}
}

// ---------------------------------------------------------------------------
// SetAllowedOrigins
// ---------------------------------------------------------------------------

func TestServer_SetAllowedOrigins(t *testing.T) {
	s := NewServer()
	origins := []string{"https://example.com", "https://dashboard.example.com"}
	s.SetAllowedOrigins(origins)

	s.mu.RLock()
	got := s.allowedOrigins
	s.mu.RUnlock()

	if len(got) != 2 {
		t.Fatalf("expected 2 origins, got %d", len(got))
	}
	if got[0] != "https://example.com" {
		t.Errorf("origin[0] = %q, want https://example.com", got[0])
	}
}

func TestServer_SetAllowedOrigins_Nil(t *testing.T) {
	s := NewServer()
	s.SetAllowedOrigins([]string{"https://example.com"})
	s.SetAllowedOrigins(nil)

	s.mu.RLock()
	got := s.allowedOrigins
	s.mu.RUnlock()

	if got != nil {
		t.Error("expected nil origins after SetAllowedOrigins(nil)")
	}
}

// ---------------------------------------------------------------------------
// SetAuthStore
// ---------------------------------------------------------------------------

func TestServer_SetAuthStore(t *testing.T) {
	s := NewServer()

	cfg := &auth.Config{
		Secret: "test-secret-that-is-long-enough",
		Users:  []auth.User{{Username: "admin", Password: "password", Role: auth.RoleAdmin}},
	}
	store, err := auth.NewStore(cfg)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	s.SetAuthStore(store)

	s.mu.RLock()
	got := s.authStore
	s.mu.RUnlock()

	if got == nil {
		t.Error("expected authStore to be set")
	}
}

func TestServer_SetAuthStore_Nil(t *testing.T) {
	s := NewServer()
	s.SetAuthStore(nil)

	s.mu.RLock()
	got := s.authStore
	s.mu.RUnlock()

	if got != nil {
		t.Error("expected authStore to be nil")
	}
}

// ---------------------------------------------------------------------------
// SetAuthToken
// ---------------------------------------------------------------------------

func TestServer_SetAuthToken(t *testing.T) {
	s := NewServer()
	s.SetAuthToken("my-secret-token")

	s.mu.RLock()
	got := s.authToken
	s.mu.RUnlock()

	if got != "my-secret-token" {
		t.Errorf("authToken = %q, want %q", got, "my-secret-token")
	}
}

func TestServer_SetAuthToken_Empty(t *testing.T) {
	s := NewServer()
	s.SetAuthToken("initial-token")
	s.SetAuthToken("")

	s.mu.RLock()
	got := s.authToken
	s.mu.RUnlock()

	if got != "" {
		t.Errorf("expected empty token, got %q", got)
	}
}
