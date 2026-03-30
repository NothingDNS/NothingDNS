package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

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
		Cached:       true,
		Blocked:      false,
		Duration:     15000,
	}
	server.RecordQuery(event)

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
}

// ============================================================================
// ServeHTTP - stats endpoint returns valid JSON
// ============================================================================

func TestServeHTTP_StatsEndpointValidJSON(t *testing.T) {
	server := NewServer()
	defer server.Stop()

	// Record some queries to populate stats
	for i := 0; i < 5; i++ {
		server.RecordQuery(&QueryEvent{
			Domain:    "stats.example.com",
			QueryType: "A",
		})
	}

	req := httptest.NewRequest("GET", "/api/dashboard/stats", nil)
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
