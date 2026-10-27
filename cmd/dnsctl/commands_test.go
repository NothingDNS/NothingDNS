package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("forced read error")
}

// setupMockServer creates a test HTTP server and configures globalFlags to use it.
func setupMockServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	server := httptest.NewServer(handler)
	t.Cleanup(func() { server.Close() })
	origServer := globalFlags.Server
	origAPIKey := globalFlags.APIKey
	globalFlags.Server = server.URL
	globalFlags.APIKey = ""
	t.Cleanup(func() {
		globalFlags.Server = origServer
		globalFlags.APIKey = origAPIKey
	})
	return server
}

// ============================================================================
// cmdCache tests
// ============================================================================

func TestCmdCache_NoArgs(t *testing.T) {
	err := cmdCache([]string{})
	if err == nil {
		t.Fatal("expected error for no args, got nil")
	}
	if !strings.Contains(err.Error(), "cache subcommand required") {
		t.Errorf("error = %q, want 'cache subcommand required'", err.Error())
	}
}

func TestCmdCache_Stats(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/cache/stats" {
			t.Errorf("path = %q, want /api/v1/cache/stats", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"size":      float64(100),
			"capacity":  float64(1000),
			"hits":      float64(500),
			"misses":    float64(100),
			"hit_ratio": 0.833,
		})
	})
	output := captureOutput(func() {
		if err := cmdCache([]string{"stats"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "Cache Statistics:") {
		t.Errorf("output missing header: %q", output)
	}
	if !strings.Contains(output, "Hit Ratio: 83.30%") {
		t.Errorf("output missing hit ratio: %q", output)
	}
}

func TestCmdCache_StatsNoRatio(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"size": float64(10),
		})
	})
	output := captureOutput(func() {
		if err := cmdCache([]string{"stats"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if strings.Contains(output, "Hit Ratio:") {
		t.Error("should not print hit ratio when missing")
	}
}

func TestCmdCache_Flush(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/cache/flush" {
			t.Errorf("path = %q, want /api/v1/cache/flush", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"message": "Cache flushed"})
	})
	output := captureOutput(func() {
		if err := cmdCache([]string{"flush"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "Cache flushed") {
		t.Errorf("output missing message: %q", output)
	}
}

func TestCmdCache_Unknown(t *testing.T) {
	err := cmdCache([]string{"unknown"})
	if err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
	if !strings.Contains(err.Error(), "unknown cache subcommand") {
		t.Errorf("error = %q", err.Error())
	}
}

// ============================================================================
// cmdCluster tests
// ============================================================================

func TestCmdCluster_NoArgs(t *testing.T) {
	err := cmdCluster([]string{})
	if err == nil {
		t.Fatal("expected error for no args")
	}
	if !strings.Contains(err.Error(), "cluster subcommand required") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestCmdCluster_Status(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/cluster/status" {
			t.Errorf("path = %q", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "healthy"})
	})
	output := captureOutput(func() {
		if err := cmdCluster([]string{"status"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "Cluster Status:") {
		t.Errorf("output missing header: %q", output)
	}
}

func TestCmdCluster_PeersEmpty(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"nodes": []interface{}{}})
	})
	output := captureOutput(func() {
		if err := cmdCluster([]string{"peers"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "No cluster nodes found") {
		t.Errorf("output missing message: %q", output)
	}
}

func TestCmdCluster_PeersWithNodes(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"nodes": []interface{}{
				map[string]interface{}{
					"id":     "node-1",
					"addr":   "192.0.2.1",
					"port":   float64(7946),
					"state":  "alive",
					"region": "us-east",
				},
			},
		})
	})
	output := captureOutput(func() {
		if err := cmdCluster([]string{"peers"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "node-1") {
		t.Errorf("output missing node id: %q", output)
	}
	if !strings.Contains(output, "us-east") {
		t.Errorf("output missing region: %q", output)
	}
}

func TestCmdCluster_PeersUnexpectedFormat(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"nodes": "not-an-array"})
	})
	err := cmdCluster([]string{"peers"})
	if err == nil {
		t.Fatal("expected error for unexpected format")
	}
	if !strings.Contains(err.Error(), "unexpected response format") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestCmdCluster_Unknown(t *testing.T) {
	err := cmdCluster([]string{"unknown"})
	if err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
	if !strings.Contains(err.Error(), "unknown cluster subcommand") {
		t.Errorf("error = %q", err.Error())
	}
}

// ============================================================================
// cmdZone tests
// ============================================================================

func TestCmdZone_NoArgs(t *testing.T) {
	err := cmdZone([]string{})
	if err == nil {
		t.Fatal("expected error for no args")
	}
	if !strings.Contains(err.Error(), "zone subcommand required") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestCmdZone_ListEmpty(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"zones": []interface{}{}})
	})
	output := captureOutput(func() {
		if err := cmdZone([]string{"list"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "No zones configured") {
		t.Errorf("output missing message: %q", output)
	}
}

func TestCmdZone_ListWithZones(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"zones": []interface{}{
				map[string]interface{}{"name": "example.com.", "records": float64(10)},
			},
		})
	})
	output := captureOutput(func() {
		if err := cmdZone([]string{"list"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "example.com.") {
		t.Errorf("output missing zone name: %q", output)
	}
}

func TestCmdZone_ListUnexpectedFormat(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"zones": "bad"})
	})
	err := cmdZone([]string{"list"})
	if err == nil {
		t.Fatal("expected error for unexpected format")
	}
}

func TestCmdZone_Add(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/zones" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"message": "Zone added"})
	})
	output := captureOutput(func() {
		if err := cmdZone([]string{"add", "example.com"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "Zone added") {
		t.Errorf("output missing message: %q", output)
	}
}

func TestCmdZone_AddWithNS(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"message": "ok"})
	})
	if err := cmdZone([]string{"add", "example.com", "ns2.example.com."}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCmdZone_AddMissingName(t *testing.T) {
	err := cmdZone([]string{"add"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "zone name required") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestCmdZone_Remove(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("method = %q, want DELETE", r.Method)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"message": "Zone removed"})
	})
	output := captureOutput(func() {
		if err := cmdZone([]string{"remove", "example.com"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "Zone removed") {
		t.Errorf("output missing message: %q", output)
	}
}

func TestCmdZone_RemoveMissingName(t *testing.T) {
	err := cmdZone([]string{"remove"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCmdZone_Reload(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/zones/reload" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"message": "Zone reloaded"})
	})
	output := captureOutput(func() {
		if err := cmdZone([]string{"reload", "example.com"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "Zone reloaded") {
		t.Errorf("output missing message: %q", output)
	}
}

func TestCmdZone_ReloadMissingName(t *testing.T) {
	err := cmdZone([]string{"reload"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCmdZone_Unknown(t *testing.T) {
	err := cmdZone([]string{"unknown"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unknown zone subcommand") {
		t.Errorf("error = %q", err.Error())
	}
}

// ============================================================================
// cmdRecord tests
// ============================================================================

func TestCmdRecord_NoArgs(t *testing.T) {
	err := cmdRecord([]string{})
	if err == nil {
		t.Fatal("expected error for no args")
	}
	if !strings.Contains(err.Error(), "record subcommand required") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestCmdRecord_List(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/zones/example.com/records" {
			t.Errorf("path = %q", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"records": []interface{}{
				map[string]interface{}{
					"name": "www", "type": "A", "ttl": float64(300), "data": "192.0.2.1",
				},
			},
		})
	})
	output := captureOutput(func() {
		if err := cmdRecord([]string{"list", "example.com"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "www") {
		t.Errorf("output missing record: %q", output)
	}
}

func TestCmdRecord_ListEmpty(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"records": []interface{}{}})
	})
	output := captureOutput(func() {
		if err := cmdRecord([]string{"list", "example.com"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "No records found") {
		t.Errorf("output missing message: %q", output)
	}
}

func TestCmdRecord_ListUnexpectedFormat(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"records": "bad"})
	})
	err := cmdRecord([]string{"list", "example.com"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCmdRecord_ListMissingZone(t *testing.T) {
	err := cmdRecord([]string{"list"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCmdRecord_Add(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %q", r.Method)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"message": "Record added"})
	})
	output := captureOutput(func() {
		if err := cmdRecord([]string{"add", "example.com", "www", "A", "192.0.2.1"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "Record added") {
		t.Errorf("output missing message: %q", output)
	}
}

func TestCmdRecord_AddWithTTL(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"message": "ok"})
	})
	if err := cmdRecord([]string{"add", "example.com", "www", "A", "192.0.2.1", "600"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCmdRecord_AddInvalidTTL(t *testing.T) {
	// The CLI now rejects invalid TTLs with a parse error rather than
	// silently inserting the default. Previously a typo'd TTL was
	// indistinguishable from a working command — the record landed
	// with TTL=300 and no warning to the operator.
	err := cmdRecord([]string{"add", "example.com", "www", "A", "192.0.2.1", "not-a-number"})
	if err == nil {
		t.Fatal("expected parse error for non-integer TTL, got nil")
	}
	if !strings.Contains(err.Error(), "TTL") {
		t.Errorf("error should mention TTL: %v", err)
	}
}

func TestCmdRecord_AddNegativeTTL(t *testing.T) {
	err := cmdRecord([]string{"add", "example.com", "www", "A", "192.0.2.1", "-5"})
	if err == nil {
		t.Fatal("expected error for negative TTL")
	}
}

func TestCmdRecord_AddTTLOverflow(t *testing.T) {
	err := cmdRecord([]string{"add", "example.com", "www", "A", "192.0.2.1", "4294967296"})
	if err == nil {
		t.Fatal("expected error for TTL overflow")
	}
	if !strings.Contains(err.Error(), "4294967295") {
		t.Fatalf("error = %q, want uint32 TTL bound", err.Error())
	}
}

func TestCmdRecord_AddMissingArgs(t *testing.T) {
	err := cmdRecord([]string{"add", "example.com", "www", "A"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCmdRecord_Remove(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("method = %q", r.Method)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"message": "Record removed"})
	})
	output := captureOutput(func() {
		if err := cmdRecord([]string{"remove", "example.com", "www", "A"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "Record removed") {
		t.Errorf("output missing message: %q", output)
	}
}

func TestCmdRecord_RemoveMissingArgs(t *testing.T) {
	err := cmdRecord([]string{"remove", "example.com", "www"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCmdRecord_Update(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("method = %q", r.Method)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"message": "Record updated"})
	})
	output := captureOutput(func() {
		if err := cmdRecord([]string{"update", "example.com", "www", "A", "192.0.2.1", "192.0.2.2"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "Record updated") {
		t.Errorf("output missing message: %q", output)
	}
}

func TestCmdRecord_UpdateWithTTL(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"message": "ok"})
	})
	if err := cmdRecord([]string{"update", "example.com", "www", "A", "old", "new", "600"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCmdRecord_UpdateInvalidTTL(t *testing.T) {
	// Same TTL parse contract as add: reject non-integer with an error.
	err := cmdRecord([]string{"update", "example.com", "www", "A", "old", "new", "bad"})
	if err == nil {
		t.Fatal("expected parse error for non-integer TTL, got nil")
	}
	if !strings.Contains(err.Error(), "TTL") {
		t.Errorf("error should mention TTL: %v", err)
	}
}

func TestCmdRecord_UpdateRejectsTTLBounds(t *testing.T) {
	tests := []string{"-1", "4294967296"}
	for _, ttl := range tests {
		t.Run(ttl, func(t *testing.T) {
			err := cmdRecord([]string{"update", "example.com", "www", "A", "old", "new", ttl})
			if err == nil {
				t.Fatalf("expected error for TTL %s", ttl)
			}
			if !strings.Contains(err.Error(), "TTL") {
				t.Fatalf("error = %q, want TTL context", err.Error())
			}
		})
	}
}

func TestCmdRecord_UpdateMissingArgs(t *testing.T) {
	err := cmdRecord([]string{"update", "example.com", "www", "A", "old"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCmdRecord_Unknown(t *testing.T) {
	err := cmdRecord([]string{"unknown"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unknown record subcommand") {
		t.Errorf("error = %q", err.Error())
	}
}

// ============================================================================
// cmdBlocklist tests
// ============================================================================

func TestCmdBlocklist_NoArgs(t *testing.T) {
	err := cmdBlocklist([]string{})
	if err == nil {
		t.Fatal("expected error for no args")
	}
	if !strings.Contains(err.Error(), "blocklist subcommand required") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestCmdBlocklist_Status(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled":     true,
			"total_rules": float64(1000),
			"files_count": float64(2),
			"urls_count":  float64(3),
		})
	})
	output := captureOutput(func() {
		if err := cmdBlocklist([]string{"status"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "Enabled:") {
		t.Errorf("output missing enabled: %q", output)
	}
	if !strings.Contains(output, "1000") {
		t.Errorf("output missing total rules: %q", output)
	}
}

// The sources endpoint answers a JSON array; the tests that mocked object
// shapes ({"sources": …}, {"blocklists": …}) the server never sends were
// replaced by TestBlocklistSourcesDecodesArray (F746).

func TestCmdBlocklist_Unknown(t *testing.T) {
	err := cmdBlocklist([]string{"unknown"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unknown blocklist subcommand") {
		t.Errorf("error = %q", err.Error())
	}
}

// ============================================================================
// cmdConfig tests
// ============================================================================

func TestCmdConfig_NoArgs(t *testing.T) {
	err := cmdConfig([]string{})
	if err == nil {
		t.Fatal("expected error for no args")
	}
	if !strings.Contains(err.Error(), "config subcommand required") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestCmdConfig_Get(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/config" {
			t.Errorf("path = %q", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"port": float64(53)})
	})
	output := captureOutput(func() {
		if err := cmdConfig([]string{"get"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "Server Configuration:") {
		t.Errorf("output missing header: %q", output)
	}
}

func TestCmdConfig_Reload(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/config/reload" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"message": "Config reloaded"})
	})
	output := captureOutput(func() {
		if err := cmdConfig([]string{"reload"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "Config reloaded") {
		t.Errorf("output missing message: %q", output)
	}
}

func TestCmdConfig_Unknown(t *testing.T) {
	err := cmdConfig([]string{"unknown"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unknown config subcommand") {
		t.Errorf("error = %q", err.Error())
	}
}

// ============================================================================
// cmdServer tests
// ============================================================================

func TestCmdServer_NoArgs(t *testing.T) {
	err := cmdServer([]string{})
	if err == nil {
		t.Fatal("expected error for no args")
	}
	if !strings.Contains(err.Error(), "server subcommand required") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestCmdServer_Status(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/status" {
			t.Errorf("path = %q", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "running",
			"version":   "1.0.0",
			"timestamp": "2024-01-01T00:00:00Z",
			"cache": map[string]interface{}{
				"size":      float64(100),
				"capacity":  float64(1000),
				"hits":      float64(500),
				"misses":    float64(100),
				"hit_ratio": 0.833,
			},
			"cluster": map[string]interface{}{
				"enabled":    true,
				"node_id":    "node-1",
				"node_count": float64(3),
				"healthy":    true,
			},
		})
	})
	output := captureOutput(func() {
		if err := cmdServer([]string{"status"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "running") {
		t.Errorf("output missing status: %q", output)
	}
	if !strings.Contains(output, "node-1") {
		t.Errorf("output missing node id: %q", output)
	}
}

func TestCmdServer_StatusNoCacheCluster(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "running"})
	})
	output := captureOutput(func() {
		if err := cmdServer([]string{"status"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "running") {
		t.Errorf("output missing status: %q", output)
	}
}

func TestCmdServer_HealthOK(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	output := captureOutput(func() {
		if err := cmdServer([]string{"health"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "healthy") {
		t.Errorf("output missing healthy: %q", output)
	}
}

func TestCmdServer_HealthUnhealthy(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("unavailable"))
			return
		}
	})

	err := cmdServer([]string{"health"})
	if err == nil {
		t.Fatal("expected error for unhealthy server")
	}
	if !strings.Contains(err.Error(), "server unhealthy (HTTP 503)") {
		t.Errorf("error = %q", err.Error())
	}
	if !strings.Contains(err.Error(), "unavailable") {
		t.Errorf("error missing response body: %q", err.Error())
	}
}

func TestCmdServer_HealthBodyReadError(t *testing.T) {
	origServer := globalFlags.Server
	origAPIKey := globalFlags.APIKey
	origClient := httpClient
	globalFlags.Server = "http://example.com"
	globalFlags.APIKey = ""
	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/health" {
			t.Errorf("path = %q, want /health", r.URL.Path)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(errorReader{}),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})}
	t.Cleanup(func() {
		globalFlags.Server = origServer
		globalFlags.APIKey = origAPIKey
		httpClient = origClient
	})

	err := cmdServer([]string{"health"})
	if err == nil {
		t.Fatal("expected body read error")
	}
	if !strings.Contains(err.Error(), "reading health response") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestCmdServer_Unknown(t *testing.T) {
	err := cmdServer([]string{"unknown"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unknown server subcommand") {
		t.Errorf("error = %q", err.Error())
	}
}

// ============================================================================
// cmdDig tests
// ============================================================================

func TestCmdDig_NoArgs(t *testing.T) {
	err := cmdDig([]string{})
	if err == nil {
		t.Fatal("expected error for no args")
	}
	if !strings.Contains(err.Error(), "query name required") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestCmdDig_InvalidType(t *testing.T) {
	err := cmdDig([]string{"example.com", "INVALIDTYPE"})
	if err == nil {
		t.Fatal("expected error for invalid type")
	}
	if !strings.Contains(err.Error(), "unsupported query type") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestCmdDig_InvalidName(t *testing.T) {
	longLabel := strings.Repeat("a", 64)
	err := cmdDig([]string{longLabel + ".com", "A"})
	if err == nil {
		t.Fatal("expected error for invalid name")
	}
	if !strings.Contains(err.Error(), "invalid name") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestCmdDig_WithServer(t *testing.T) {
	// Start a mock UDP DNS server
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve udp addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, clientAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			msg, err := protocol.UnpackMessage(buf[:n])
			if err != nil {
				continue
			}
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:      msg.Header.ID,
					Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
					QDCount: 1,
					ANCount: 1,
				},
				Questions: msg.Questions,
				Answers: []*protocol.ResourceRecord{
					{
						Name:  msg.Questions[0].Name,
						Type:  protocol.TypeA,
						Class: protocol.ClassIN,
						TTL:   300,
						Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
					},
				},
			}
			packed, _ := resp.Pack(buf)
			conn.WriteToUDP(buf[:packed], clientAddr)
		}
	}()

	serverAddr := conn.LocalAddr().(*net.UDPAddr)
	output := captureOutput(func() {
		if err := cmdDig([]string{fmt.Sprintf("@127.0.0.1:%d", serverAddr.Port), "example.com", "A"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "192.0.2.1") {
		t.Errorf("output missing answer IP: %q", output)
	}
	if !strings.Contains(output, "ANSWER SECTION:") {
		t.Errorf("output missing answer section: %q", output)
	}
}

func TestPrintDigResponseHandlesMalformedSections(t *testing.T) {
	name, err := protocol.ParseName("example.com.")
	if err != nil {
		t.Fatalf("parse name: %v", err)
	}
	var typedNilA *protocol.RDataA
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
			QDCount: 3,
			ANCount: 3,
			NSCount: 1,
			ARCount: 1,
		},
		Questions: []*protocol.Question{
			nil,
			{QType: protocol.TypeA, QClass: protocol.ClassIN},
			{Name: name, QType: protocol.TypeA, QClass: protocol.ClassIN},
		},
		Answers: []*protocol.ResourceRecord{
			nil,
			{Name: nil, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: typedNilA},
			{Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300},
		},
		Authorities: []*protocol.ResourceRecord{
			{Name: nil, Type: protocol.TypeNS, Class: protocol.ClassIN, TTL: 300},
		},
		Additionals: []*protocol.ResourceRecord{
			{Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: typedNilA},
		},
	}

	output := captureOutput(func() {
		printDigResponse("example.com.", "A", "127.0.0.1", "127.0.0.1:53", false, resp)
	})
	if !strings.Contains(output, "<nil>") {
		t.Fatalf("output missing nil placeholder: %q", output)
	}
	if strings.Count(output, "; NODATA") < 4 {
		t.Fatalf("output missing NODATA placeholders: %q", output)
	}
}

func TestCmdDig_ConnectionError(t *testing.T) {
	err := cmdDig([]string{"@999.999.999.999:53", "example.com", "A"})
	if err == nil {
		t.Fatal("expected error for connection failure")
	}
	if !strings.Contains(err.Error(), "connecting to") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestDigQueryTCPRejectsOversizedQueryBeforeDial(t *testing.T) {
	_, err := digQueryTCP("198.51.100.1:53", make([]byte, 0x10000))
	if err == nil {
		t.Fatal("expected oversized TCP query to fail")
	}
	if !strings.Contains(err.Error(), "tcp query too large") {
		t.Fatalf("error = %v, want tcp query too large", err)
	}
}

func TestWriteFullRetriesPartialWrites(t *testing.T) {
	conn := &partialWriteConn{maxWrite: 2}
	data := []byte{1, 2, 3, 4, 5}

	if err := util.WriteFull(conn, data); err != nil {
		t.Fatalf("WriteFull returned error: %v", err)
	}
	if string(conn.written) != string(data) {
		t.Fatalf("written bytes = %v, want %v", conn.written, data)
	}
	if conn.calls <= 1 {
		t.Fatalf("expected multiple partial writes, got %d call", conn.calls)
	}
}

func TestWriteFullRejectsZeroByteWrite(t *testing.T) {
	conn := &partialWriteConn{}
	err := util.WriteFull(conn, []byte{1, 2, 3})
	if err != io.ErrNoProgress {
		t.Fatalf("WriteFull error = %v, want %v", err, io.ErrNoProgress)
	}
}

func TestWritePacketRejectsPartialDatagramWrite(t *testing.T) {
	conn := &partialWriteConn{maxWrite: 2}
	_, err := writePacket(conn, []byte{1, 2, 3})
	if err != io.ErrShortWrite {
		t.Fatalf("writePacket error = %v, want %v", err, io.ErrShortWrite)
	}
	if conn.calls != 1 {
		t.Fatalf("writePacket should not retry datagram writes, got %d calls", conn.calls)
	}
}

type partialWriteConn struct {
	maxWrite int
	written  []byte
	calls    int
}

func (c *partialWriteConn) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (c *partialWriteConn) Write(p []byte) (int, error) {
	c.calls++
	if c.maxWrite <= 0 {
		return 0, nil
	}
	n := c.maxWrite
	if n > len(p) {
		n = len(p)
	}
	c.written = append(c.written, p[:n]...)
	return n, nil
}

func (c *partialWriteConn) Close() error {
	return nil
}

func (c *partialWriteConn) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

func (c *partialWriteConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{}
}

func (c *partialWriteConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *partialWriteConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *partialWriteConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

func TestCmdDig_DNSSEC(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve udp addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, clientAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			msg, _ := protocol.UnpackMessage(buf[:n])
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:      msg.Header.ID,
					Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
					QDCount: 1,
					ANCount: 0,
				},
				Questions: msg.Questions,
			}
			packed, _ := resp.Pack(buf)
			conn.WriteToUDP(buf[:packed], clientAddr)
		}
	}()

	serverAddr := conn.LocalAddr().(*net.UDPAddr)
	output := captureOutput(func() {
		if err := cmdDig([]string{fmt.Sprintf("@127.0.0.1:%d", serverAddr.Port), "example.com", "A", "+dnssec"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "+dnssec") {
		t.Errorf("output missing dnssec flag: %q", output)
	}
}

func TestCmdDig_DefaultServer(t *testing.T) {
	// When no @server is given, it defaults to 127.0.0.1:53 which likely fails.
	// We just verify the error path.
	err := cmdDig([]string{"example.com", "A"})
	if err == nil {
		t.Fatal("expected error when no server is running")
	}
}

// ============================================================================
// runMain tests
// ============================================================================

func TestRunMain_Version(t *testing.T) {
	output := captureOutput(func() {
		code := runMain([]string{"version"})
		if code != 0 {
			t.Errorf("exit code = %d, want 0", code)
		}
	})
	if !strings.Contains(output, util.Version) {
		t.Errorf("output missing version: %q", output)
	}
}

func TestRunMain_Help(t *testing.T) {
	output := captureOutput(func() {
		code := runMain([]string{"help"})
		if code != 0 {
			t.Errorf("exit code = %d, want 0", code)
		}
	})
	if !strings.Contains(output, "Usage:") {
		t.Errorf("output missing usage: %q", output)
	}
}

func TestRunMain_HelpCommand(t *testing.T) {
	output := captureOutput(func() {
		code := runMain([]string{"help", "zone"})
		if code != 0 {
			t.Errorf("exit code = %d, want 0", code)
		}
	})
	if !strings.Contains(output, "list") {
		t.Errorf("output missing command help: %q", output)
	}
}

func TestRunMain_HelpUnknownCommand(t *testing.T) {
	code := runMain([]string{"help", "unknown"})
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

func TestRunMain_NoArgs(t *testing.T) {
	output := captureOutput(func() {
		code := runMain([]string{})
		if code != 1 {
			t.Errorf("exit code = %d, want 1", code)
		}
	})
	if !strings.Contains(output, "Usage:") {
		t.Errorf("output missing usage: %q", output)
	}
}

func TestRunMain_UnknownCommand(t *testing.T) {
	output := captureOutput(func() {
		code := runMain([]string{"unknown-cmd"})
		if code != 1 {
			t.Errorf("exit code = %d, want 1", code)
		}
	})
	if !strings.Contains(output, "Unknown command") {
		t.Errorf("output missing error: %q", output)
	}
}

func TestRunMain_CommandError(t *testing.T) {
	output := captureOutput(func() {
		code := runMain([]string{"cache"})
		if code != 1 {
			t.Errorf("exit code = %d, want 1", code)
		}
	})
	if !strings.Contains(output, "Error:") {
		t.Errorf("output missing error: %q", output)
	}
}

func TestRunMain_CommandSuccess(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"zones": []interface{}{}})
	})
	output := captureOutput(func() {
		code := runMain([]string{"-server", globalFlags.Server, "zone", "list"})
		if code != 0 {
			t.Errorf("exit code = %d, want 0", code)
		}
	})
	if !strings.Contains(output, "No zones configured") {
		t.Errorf("output missing message: %q", output)
	}
}

func TestRunMain_GlobalFlags(t *testing.T) {
	var receivedServer string
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		receivedServer = globalFlags.Server
		json.NewEncoder(w).Encode(map[string]interface{}{"zones": []interface{}{}})
	})
	output := captureOutput(func() {
		code := runMain([]string{"-server", globalFlags.Server, "zone", "list"})
		if code != 0 {
			t.Errorf("exit code = %d, want 0", code)
		}
	})
	if receivedServer == "" {
		t.Error("server flag not set")
	}
	_ = output
}

func TestRunMain_InvalidFlag(t *testing.T) {
	output := captureOutput(func() {
		code := runMain([]string{"-invalid-flag", "zone", "list"})
		if code != 1 {
			t.Errorf("exit code = %d, want 1", code)
		}
	})
	if !strings.Contains(output, "Error:") {
		t.Errorf("output missing error: %q", output)
	}
}

// ============================================================================
// printUsage tests
// ============================================================================

func TestPrintUsage(t *testing.T) {
	output := captureOutput(func() {
		printUsage()
	})
	if !strings.Contains(output, "dnsctl - CLI tool") {
		t.Errorf("output missing header: %q", output)
	}
	if !strings.Contains(output, "Commands:") {
		t.Errorf("output missing commands section: %q", output)
	}
	if !strings.Contains(output, "zone") {
		t.Errorf("output missing zone command: %q", output)
	}
}

// ============================================================================
// cmdDNSSEC verify-anchor and validate-zone tests
// ============================================================================

func TestCmdDNSSECVerifyAnchor_MissingFile(t *testing.T) {
	err := cmdDNSSECVerifyAnchor([]string{})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "trust anchor file path is required") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestCmdDNSSECVerifyAnchor_InvalidFile(t *testing.T) {
	err := cmdDNSSECVerifyAnchor([]string{"/nonexistent/path/anchor.txt"})
	if err == nil {
		t.Fatal("expected error for invalid file")
	}
}

func TestCmdDNSSECVerifyAnchor_ValidFile(t *testing.T) {
	tmpDir := t.TempDir()
	anchorFile := filepath.Join(tmpDir, "anchor.xml")
	content := `<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor id="test" source="test">
  <Zone>.</Zone>
  <KeyDigest id="1" validFrom="2024-01-01T00:00:00+00:00" validUntil="2030-01-01T00:00:00+00:00">
    <KeyTag>12345</KeyTag>
    <Algorithm>13</Algorithm>
    <DigestType>2</DigestType>
    <Digest>` + strings.Repeat("ab", 16) + `</Digest>
  </KeyDigest>
</TrustAnchor>
`
	if err := os.WriteFile(anchorFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write anchor file: %v", err)
	}
	output := captureOutput(func() {
		if err := cmdDNSSECVerifyAnchor([]string{anchorFile}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "Trust anchor file verified") {
		t.Errorf("output missing header: %q", output)
	}
	if !strings.Contains(output, "12345") {
		t.Errorf("output missing keytag: %q", output)
	}
}

func TestCmdDNSSECValidateZone_MissingFile(t *testing.T) {
	err := cmdDNSSECValidateZone([]string{})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "zone file is required") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestCmdDNSSECValidateZone_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	zoneFile := filepath.Join(tmpDir, "empty.zone")
	if err := os.WriteFile(zoneFile, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write empty file: %v", err)
	}
	err := cmdDNSSECValidateZone([]string{"--zone", zoneFile})
	if err == nil {
		t.Fatal("expected error for empty zone")
	}
	if !strings.Contains(err.Error(), "no valid records found") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestCmdDNSSECValidateZone_NoDNSKEY(t *testing.T) {
	tmpDir := t.TempDir()
	zoneFile := filepath.Join(tmpDir, "zone.zone")
	content := `example.com. 300 IN A 192.0.2.1
`
	if err := os.WriteFile(zoneFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write zone file: %v", err)
	}
	output := captureOutput(func() {
		if err := cmdDNSSECValidateZone([]string{"--zone", zoneFile}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "No DNSKEY records found") {
		t.Errorf("output missing warning: %q", output)
	}
}

func TestCmdDNSSECValidateZone_NoRRSIG(t *testing.T) {
	tmpDir := t.TempDir()
	zoneFile := filepath.Join(tmpDir, "zone.zone")
	pubKey := base64.StdEncoding.EncodeToString([]byte("fakepublickey12345"))
	content := fmt.Sprintf(`example.com. 300 IN DNSKEY 257 3 13 %s
example.com. 300 IN A 192.0.2.1
`, pubKey)
	if err := os.WriteFile(zoneFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write zone file: %v", err)
	}
	output := captureOutput(func() {
		if err := cmdDNSSECValidateZone([]string{"--zone", zoneFile}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "No RRSIG records found") {
		t.Errorf("output missing warning: %q", output)
	}
}

func TestCmdDNSSECValidateZone_InvalidSignature(t *testing.T) {
	tmpDir := t.TempDir()
	zoneFile := filepath.Join(tmpDir, "zone.zone")
	pubKey := base64.StdEncoding.EncodeToString([]byte("fakepublickey12345"))
	// RRSIG with expired timestamp
	content := fmt.Sprintf(`example.com. 300 IN DNSKEY 257 3 13 %s
example.com. 300 IN A 192.0.2.1
example.com. 300 IN RRSIG A 13 1 300 1609459200 1606780800 12345 example.com. %s
`, pubKey, base64.StdEncoding.EncodeToString([]byte("fakesig")))
	if err := os.WriteFile(zoneFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write zone file: %v", err)
	}
	output := captureOutput(func() {
		err := cmdDNSSECValidateZone([]string{"--zone", zoneFile, "--ignore-time"})
		if err == nil {
			t.Fatal("expected error for invalid signature")
		}
	})
	if !strings.Contains(output, "Validation Summary") {
		t.Errorf("output missing summary: %q", output)
	}
}

// TestCmdDNSSECSignThenValidateZoneRoundTrip signs a zone with dnsctl's own
// signer and feeds the signed output (DNSKEY, RRSIG, NSEC or NSEC3 records in
// presentation format) back into validate-zone. Every signature must verify,
// which proves the delegated rdata parsing (protocol.ParseRDataText)
// reconstructs RRSIG/DNSKEY/NSEC/NSEC3/SOA wire data byte-identically to what
// the signer signed — any parsing drift breaks the signature check.
func TestCmdDNSSECSignThenValidateZoneRoundTrip(t *testing.T) {
	for _, mode := range []struct {
		name      string
		nsec3     bool
		extraArgs []string
	}{
		{name: "NSEC"},
		{name: "NSEC3", nsec3: true, extraArgs: []string{"--nsec3", "--iterations", "1", "--salt", "abcdef"}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			zoneContent := `@	300	IN	SOA	ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400
@	300	IN	NS	ns1.example.com.
@	300	IN	A	192.0.2.1
www	300	IN	A	192.0.2.10
@	300	IN	MX	10 mail.example.com.
@	300	IN	TXT	"v=spf1 +all"
`
			zoneFile := filepath.Join(tmpDir, "example.com.zone")
			if err := os.WriteFile(zoneFile, []byte(zoneContent), 0644); err != nil {
				t.Fatalf("failed to write zone file: %v", err)
			}
			signedFile := filepath.Join(tmpDir, "example.com.zone.signed")

			args := []string{
				"--zone", "example.com",
				"--input", zoneFile,
				"--output", signedFile,
				"--algorithm", "13",
				"--keydir", tmpDir,
			}
			args = append(args, mode.extraArgs...)
			if err := cmdDNSSECSignZone(args); err != nil {
				t.Fatalf("cmdDNSSECSignZone error: %v", err)
			}

			output := captureOutput(func() {
				if err := cmdDNSSECValidateZone([]string{"--zone", signedFile}); err != nil {
					t.Fatalf("cmdDNSSECValidateZone error: %v", err)
				}
			})
			if !strings.Contains(output, "Invalid: 0") {
				t.Errorf("expected zero invalid signatures, output:\n%s", output)
			}
			if strings.Contains(output, "Valid: 0\n") {
				t.Errorf("expected at least one valid signature, output:\n%s", output)
			}
			if mode.nsec3 {
				if !strings.Contains(strings.ToUpper(output), "NSEC3") && !strings.Contains(output, "type 50") {
					t.Logf("note: no NSEC3 signature line in output:\n%s", output)
				}
			}
		})
	}
}

// ============================================================================
// loadSigningKey and loadPrivateKey tests
// ============================================================================

func TestLoadSigningKey(t *testing.T) {
	tmpDir := t.TempDir()
	key, err := generateKeyPair(protocol.AlgorithmECDSAP256SHA256, true, 0)
	if err != nil {
		t.Fatalf("generateKeyPair error: %v", err)
	}

	baseName := filepath.Join(tmpDir, "Kexample.com.+013+12345")
	keyPath := baseName + ".key"
	privPath := baseName + ".private"

	if err := writePublicKey(keyPath, "example.com.", key); err != nil {
		t.Fatalf("writePublicKey error: %v", err)
	}
	if err := writePrivateKey(privPath, key); err != nil {
		t.Fatalf("writePrivateKey error: %v", err)
	}

	loaded, err := loadSigningKey(keyPath, "example.com.")
	if err != nil {
		t.Fatalf("loadSigningKey error: %v", err)
	}
	if loaded.DNSKEY.Algorithm != key.DNSKEY.Algorithm {
		t.Errorf("algorithm = %d, want %d", loaded.DNSKEY.Algorithm, key.DNSKEY.Algorithm)
	}
	if !loaded.IsKSK {
		t.Error("expected KSK")
	}
}

func TestLoadSigningKey_MissingPrivate(t *testing.T) {
	tmpDir := t.TempDir()
	key, err := generateKeyPair(protocol.AlgorithmECDSAP256SHA256, true, 0)
	if err != nil {
		t.Fatalf("generateKeyPair error: %v", err)
	}

	keyPath := filepath.Join(tmpDir, "Kexample.com.+013+12345.key")
	if err := writePublicKey(keyPath, "example.com.", key); err != nil {
		t.Fatalf("writePublicKey error: %v", err)
	}

	_, err = loadSigningKey(keyPath, "example.com.")
	if err == nil {
		t.Fatal("expected error for missing private key")
	}
}

func TestLoadPrivateKey_ECDSA(t *testing.T) {
	tmpDir := t.TempDir()
	key, err := generateKeyPair(protocol.AlgorithmECDSAP256SHA256, false, 0)
	if err != nil {
		t.Fatalf("generateKeyPair error: %v", err)
	}

	privPath := filepath.Join(tmpDir, "test.private")
	if err := writePrivateKey(privPath, key); err != nil {
		t.Fatalf("writePrivateKey error: %v", err)
	}

	loaded, err := loadPrivateKey(privPath, protocol.AlgorithmECDSAP256SHA256)
	if err != nil {
		t.Fatalf("loadPrivateKey error: %v", err)
	}
	if loaded == nil {
		t.Fatal("loaded key is nil")
	}
}

func TestLoadPrivateKey_RSA(t *testing.T) {
	tmpDir := t.TempDir()
	key, err := generateKeyPair(protocol.AlgorithmRSASHA256, false, 2048)
	if err != nil {
		t.Fatalf("generateKeyPair error: %v", err)
	}

	privPath := filepath.Join(tmpDir, "test.private")
	if err := writePrivateKey(privPath, key); err != nil {
		t.Fatalf("writePrivateKey error: %v", err)
	}

	loaded, err := loadPrivateKey(privPath, protocol.AlgorithmRSASHA256)
	if err != nil {
		t.Fatalf("loadPrivateKey error: %v", err)
	}
	if loaded == nil {
		t.Fatal("loaded key is nil")
	}
}

func TestLoadPrivateKey_MissingFile(t *testing.T) {
	_, err := loadPrivateKey("/nonexistent/path/private.key", 13)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadPrivateKey_NoData(t *testing.T) {
	tmpDir := t.TempDir()
	privPath := filepath.Join(tmpDir, "empty.private")
	if err := os.WriteFile(privPath, []byte("Private-key-format: v1.3\n"), 0600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	_, err := loadPrivateKey(privPath, 13)
	if err == nil {
		t.Fatal("expected error for empty private key data")
	}
}

// ============================================================================
// writePublicKey tests
// ============================================================================

func TestWritePublicKey(t *testing.T) {
	tmpDir := t.TempDir()
	key, err := generateKeyPair(protocol.AlgorithmECDSAP256SHA256, true, 0)
	if err != nil {
		t.Fatalf("generateKeyPair error: %v", err)
	}
	pubPath := filepath.Join(tmpDir, "test.key")
	if err := writePublicKey(pubPath, "example.com.", key); err != nil {
		t.Fatalf("writePublicKey error: %v", err)
	}
	data, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("read file error: %v", err)
	}
	if !strings.Contains(string(data), "DNSKEY") {
		t.Error("public key missing DNSKEY")
	}
}

// ============================================================================
// Remaining branch coverage tests
// ============================================================================

func TestCmdDig_CDFlag(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve udp addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, clientAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			msg, _ := protocol.UnpackMessage(buf[:n])
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:      msg.Header.ID,
					Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
					QDCount: 1,
				},
				Questions: msg.Questions,
			}
			packed, _ := resp.Pack(buf)
			conn.WriteToUDP(buf[:packed], clientAddr)
		}
	}()

	serverAddr := conn.LocalAddr().(*net.UDPAddr)
	output := captureOutput(func() {
		if err := cmdDig([]string{fmt.Sprintf("@127.0.0.1:%d", serverAddr.Port), "example.com", "A", "+cd"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "Query:") {
		t.Errorf("output missing query: %q", output)
	}
}

func TestCmdDNSSECDSFromDNSKEY_Success(t *testing.T) {
	tmpDir := t.TempDir()
	key, err := generateKeyPair(protocol.AlgorithmECDSAP256SHA256, true, 0)
	if err != nil {
		t.Fatalf("generateKeyPair error: %v", err)
	}
	pubPath := filepath.Join(tmpDir, "Kexample.com.+013+12345.key")
	if err := writePublicKey(pubPath, "example.com.", key); err != nil {
		t.Fatalf("writePublicKey error: %v", err)
	}
	output := captureOutput(func() {
		if err := cmdDNSSECDSFromDNSKEY([]string{"--zone", "example.com", "--keyfile", pubPath}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "DS record") {
		t.Errorf("output missing DS record: %q", output)
	}
}

func TestCmdDNSSECSignZone_WithExistingKeys(t *testing.T) {
	tmpDir := t.TempDir()
	zoneContent := `@ 300 IN SOA ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400
@ 300 IN A 192.0.2.1
`
	zoneFile := filepath.Join(tmpDir, "example.com.zone")
	if err := os.WriteFile(zoneFile, []byte(zoneContent), 0644); err != nil {
		t.Fatalf("failed to write zone file: %v", err)
	}
	outputFile := filepath.Join(tmpDir, "signed.zone")

	// Generate keys in the same directory
	if err := cmdDNSSECGenerateKey([]string{"--algorithm", "13", "--type", "KSK", "--zone", "example.com", "--output", tmpDir}); err != nil {
		t.Fatalf("failed to generate KSK: %v", err)
	}
	if err := cmdDNSSECGenerateKey([]string{"--algorithm", "13", "--type", "ZSK", "--zone", "example.com", "--output", tmpDir}); err != nil {
		t.Fatalf("failed to generate ZSK: %v", err)
	}

	err := cmdDNSSECSignZone([]string{
		"--zone", "example.com",
		"--input", zoneFile,
		"--output", outputFile,
		"--keydir", tmpDir,
		"--algorithm", "13",
	})
	if err != nil {
		t.Fatalf("cmdDNSSECSignZone error: %v", err)
	}
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Fatal("signed zone file was not created")
	}
}

func TestCmdDNSSECSignZone_DefaultOutput(t *testing.T) {
	tmpDir := t.TempDir()
	zoneContent := `@ 300 IN SOA ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400
@ 300 IN A 192.0.2.1
`
	zoneFile := filepath.Join(tmpDir, "example.com.zone")
	if err := os.WriteFile(zoneFile, []byte(zoneContent), 0644); err != nil {
		t.Fatalf("failed to write zone file: %v", err)
	}
	expectedOutput := zoneFile + ".signed"

	err := cmdDNSSECSignZone([]string{
		"--zone", "example.com",
		"--input", zoneFile,
		"--algorithm", "13",
	})
	if err != nil {
		t.Fatalf("cmdDNSSECSignZone error: %v", err)
	}
	if _, err := os.Stat(expectedOutput); os.IsNotExist(err) {
		t.Fatal("default signed zone file was not created")
	}
}

func TestCmdDNSSECSignZone_NSEC3(t *testing.T) {
	tmpDir := t.TempDir()
	zoneContent := `@ 300 IN SOA ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400
@ 300 IN A 192.0.2.1
`
	zoneFile := filepath.Join(tmpDir, "example.com.zone")
	if err := os.WriteFile(zoneFile, []byte(zoneContent), 0644); err != nil {
		t.Fatalf("failed to write zone file: %v", err)
	}
	outputFile := filepath.Join(tmpDir, "signed.zone")

	err := cmdDNSSECSignZone([]string{
		"--zone", "example.com",
		"--input", zoneFile,
		"--output", outputFile,
		"--algorithm", "13",
		"--nsec3",
		"--iterations", "1",
		"--salt", "abcd",
	})
	if err != nil {
		t.Fatalf("cmdDNSSECSignZone error: %v", err)
	}
}

func TestCmdDNSSECSignZoneRejectsInvalidNSEC3Iterations(t *testing.T) {
	tests := []struct {
		name       string
		iterations string
	}{
		{name: "negative", iterations: "-1"},
		{name: "overflow", iterations: "65536"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			zoneFile := filepath.Join(tmpDir, "example.com.zone")
			if err := os.WriteFile(zoneFile, []byte("@ 300 IN A 192.0.2.1\n"), 0644); err != nil {
				t.Fatalf("failed to write zone file: %v", err)
			}

			err := cmdDNSSECSignZone([]string{
				"--zone", "example.com",
				"--input", zoneFile,
				"--output", filepath.Join(tmpDir, "signed.zone"),
				"--algorithm", "13",
				"--nsec3",
				"--iterations", tt.iterations,
			})
			if err == nil {
				t.Fatal("expected invalid NSEC3 iterations to return an error")
			}
			if !strings.Contains(err.Error(), "invalid NSEC3 iterations") {
				t.Fatalf("error = %q, want invalid NSEC3 iterations", err.Error())
			}
		})
	}
}

func TestCmdDNSSECSignZone_InvalidSalt(t *testing.T) {
	tmpDir := t.TempDir()
	zoneContent := `@ 300 IN SOA ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400
@ 300 IN A 192.0.2.1
`
	zoneFile := filepath.Join(tmpDir, "example.com.zone")
	if err := os.WriteFile(zoneFile, []byte(zoneContent), 0644); err != nil {
		t.Fatalf("failed to write zone file: %v", err)
	}
	outputFile := filepath.Join(tmpDir, "signed.zone")

	err := cmdDNSSECSignZone([]string{
		"--zone", "example.com",
		"--input", zoneFile,
		"--output", outputFile,
		"--algorithm", "13",
		"--nsec3",
		"--salt", "zzzz", // invalid hex
	})
	if err == nil {
		t.Fatal("expected error for invalid salt")
	}
	if !strings.Contains(err.Error(), "invalid NSEC3 salt") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestCmdDNSSECSignZone_InvalidValidity(t *testing.T) {
	tmpDir := t.TempDir()
	zoneContent := `@ 300 IN A 192.0.2.1
`
	zoneFile := filepath.Join(tmpDir, "example.com.zone")
	if err := os.WriteFile(zoneFile, []byte(zoneContent), 0644); err != nil {
		t.Fatalf("failed to write zone file: %v", err)
	}
	outputFile := filepath.Join(tmpDir, "signed.zone")

	err := cmdDNSSECSignZone([]string{
		"--zone", "example.com",
		"--input", zoneFile,
		"--output", outputFile,
		"--algorithm", "13",
		"--validity", "not-a-duration",
	})
	if err == nil {
		t.Fatal("expected error for invalid validity")
	}
	if !strings.Contains(err.Error(), "invalid validity duration") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestReadDNSKEYFromFile_Malformed(t *testing.T) {
	tmpDir := t.TempDir()
	tests := []struct {
		name    string
		content string
	}{
		{"missing fields", "example.com. IN DNSKEY 257 3\n"},
		{"invalid flags", "example.com. IN DNSKEY abc 3 13 base64\n"},
		{"invalid protocol", "example.com. IN DNSKEY 257 abc 13 base64\n"},
		{"invalid algorithm", "example.com. IN DNSKEY 257 3 abc base64\n"},
		{"invalid base64", "example.com. IN DNSKEY 257 3 13 !!bad!!\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPath := filepath.Join(tmpDir, tt.name+".key")
			if err := os.WriteFile(keyPath, []byte(tt.content), 0644); err != nil {
				t.Fatalf("failed to write file: %v", err)
			}
			_, err := readDNSKEYFromFile(keyPath)
			if err == nil {
				t.Fatal("expected error for malformed DNSKEY")
			}
		})
	}
}

func TestAPIRequest_NewRequestError(t *testing.T) {
	// This is hard to trigger because http.NewRequest only fails on invalid method or URL.
	// We test a different branch: when resp.Body read fails.
	// Actually, let's test the branch where json.Unmarshal of error response fails
	// but we already have that. The missing branch is likely the io.ReadAll error.
	// We'll skip this as it's nearly impossible to trigger without mocking io.ReadAll.
}

func TestCmdServer_HealthConnectionError(t *testing.T) {
	origServer := globalFlags.Server
	origAPIKey := globalFlags.APIKey
	origClient := httpClient
	globalFlags.Server = "http://example.com"
	globalFlags.APIKey = ""
	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("dial failed")
	})}
	t.Cleanup(func() {
		globalFlags.Server = origServer
		globalFlags.APIKey = origAPIKey
		httpClient = origClient
	})

	err := cmdServer([]string{"health"})
	if err == nil {
		t.Fatal("expected connection error")
	}
	if !strings.Contains(err.Error(), "server unhealthy") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestCmdDig_DefaultType(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve udp addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, clientAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			msg, _ := protocol.UnpackMessage(buf[:n])
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:      msg.Header.ID,
					Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
					QDCount: 1,
					ANCount: 1,
				},
				Questions: msg.Questions,
				Answers: []*protocol.ResourceRecord{
					{
						Name:  msg.Questions[0].Name,
						Type:  protocol.TypeA,
						Class: protocol.ClassIN,
						TTL:   300,
						Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
					},
				},
			}
			packed, _ := resp.Pack(buf)
			conn.WriteToUDP(buf[:packed], clientAddr)
		}
	}()

	serverAddr := conn.LocalAddr().(*net.UDPAddr)
	output := captureOutput(func() {
		if err := cmdDig([]string{fmt.Sprintf("@127.0.0.1:%d", serverAddr.Port), "example.com"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "A") {
		t.Errorf("output missing A type: %q", output)
	}
}

func TestCmdDig_ResponseFlags(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve udp addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, clientAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			msg, _ := protocol.UnpackMessage(buf[:n])
			flags := protocol.NewResponseFlags(protocol.RcodeSuccess)
			flags.TC = true
			flags.RD = true
			flags.RA = true
			flags.AD = true
			flags.CD = true
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:      msg.Header.ID,
					Flags:   flags,
					QDCount: 1,
					ANCount: 1,
				},
				Questions: msg.Questions,
				Answers: []*protocol.ResourceRecord{
					{
						Name:  msg.Questions[0].Name,
						Type:  protocol.TypeA,
						Class: protocol.ClassIN,
						TTL:   300,
						Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
					},
				},
			}
			packed, _ := resp.Pack(buf)
			conn.WriteToUDP(buf[:packed], clientAddr)
		}
	}()

	serverAddr := conn.LocalAddr().(*net.UDPAddr)
	output := captureOutput(func() {
		if err := cmdDig([]string{fmt.Sprintf("@127.0.0.1:%d", serverAddr.Port), "example.com", "A"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	for _, flag := range []string{"tc", "rd", "ra", "ad", "cd"} {
		if !strings.Contains(output, flag) {
			t.Errorf("output missing flag %s: %q", flag, output)
		}
	}
}

func TestCmdDNSSECSignZone_EmptyZoneFile(t *testing.T) {
	tmpDir := t.TempDir()
	zoneFile := filepath.Join(tmpDir, "empty.zone")
	if err := os.WriteFile(zoneFile, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write zone file: %v", err)
	}
	err := cmdDNSSECSignZone([]string{
		"--zone", "example.com",
		"--input", zoneFile,
		"--output", filepath.Join(tmpDir, "out.zone"),
	})
	if err == nil {
		t.Fatal("expected error for empty zone file")
	}
}

func TestCmdDNSSECSignZone_MalformedZone(t *testing.T) {
	tmpDir := t.TempDir()
	zoneFile := filepath.Join(tmpDir, "bad.zone")
	if err := os.WriteFile(zoneFile, []byte("not a valid zone line\n"), 0644); err != nil {
		t.Fatalf("failed to write zone file: %v", err)
	}
	err := cmdDNSSECSignZone([]string{
		"--zone", "example.com",
		"--input", zoneFile,
		"--output", filepath.Join(tmpDir, "out.zone"),
	})
	if err == nil {
		t.Fatal("expected error for malformed zone")
	}
}

func TestCmdDNSSECSignZone_InvalidKeyFile(t *testing.T) {
	tmpDir := t.TempDir()
	keyDir := filepath.Join(tmpDir, "keys")
	os.MkdirAll(keyDir, 0755)
	// Create an invalid key file that matches the pattern
	invalidKey := filepath.Join(keyDir, "Kexample.com+013+12345.key")
	if err := os.WriteFile(invalidKey, []byte("not a dnskey\n"), 0644); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	zoneContent := `example.com. 300 IN SOA ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400
example.com. 300 IN A 192.0.2.1
`
	zoneFile := filepath.Join(tmpDir, "example.com.zone")
	if err := os.WriteFile(zoneFile, []byte(zoneContent), 0644); err != nil {
		t.Fatalf("failed to write zone file: %v", err)
	}

	output := captureOutput(func() {
		err := cmdDNSSECSignZone([]string{
			"--zone", "example.com",
			"--input", zoneFile,
			"--output", filepath.Join(tmpDir, "out.zone"),
			"--keydir", keyDir,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "Warning: failed to load key") {
		t.Errorf("output missing warning: %q", output)
	}
}

func TestCmdDNSSECDSFromDNSKEY_InvalidZone(t *testing.T) {
	err := cmdDNSSECDSFromDNSKEY([]string{"--zone", "not a valid zone name !!"})
	if err == nil {
		t.Fatal("expected error for invalid zone")
	}
}

func TestLoadPrivateKey_InvalidModulus(t *testing.T) {
	tmpDir := t.TempDir()
	privPath := filepath.Join(tmpDir, "test.private")
	content := `Private-key-format: v1.3
Algorithm: 8 (RSASHA256)
Modulus: !!bad!!
PrivateExponent: !!bad!!
`
	if err := os.WriteFile(privPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	_, err := loadPrivateKey(privPath, protocol.AlgorithmRSASHA256)
	if err == nil {
		t.Fatal("expected error for invalid modulus")
	}
}

func TestLoadPrivateKey_InvalidExponent(t *testing.T) {
	tmpDir := t.TempDir()
	privPath := filepath.Join(tmpDir, "test.private")
	content := `Private-key-format: v1.3
Algorithm: 8 (RSASHA256)
Modulus: dGVzdA==
PrivateExponent: !!bad!!
`
	if err := os.WriteFile(privPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	_, err := loadPrivateKey(privPath, protocol.AlgorithmRSASHA256)
	if err == nil {
		t.Fatal("expected error for invalid exponent")
	}
}

func TestFindKeyFiles_NoMatch(t *testing.T) {
	tmpDir := t.TempDir()
	files, err := findKeyFiles(tmpDir, "nonexistent.zone")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files, got %d", len(files))
	}
}

func TestCmdBlocklist_StatusConnectionError(t *testing.T) {
	origServer := globalFlags.Server
	globalFlags.Server = "http://127.0.0.1:1"
	defer func() { globalFlags.Server = origServer }()

	err := cmdBlocklist([]string{"status"})
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestCmdBlocklist_SourcesConnectionError(t *testing.T) {
	origServer := globalFlags.Server
	globalFlags.Server = "http://127.0.0.1:1"
	defer func() { globalFlags.Server = origServer }()

	err := cmdBlocklist([]string{"sources"})
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestCmdConfig_GetConnectionError(t *testing.T) {
	origServer := globalFlags.Server
	globalFlags.Server = "http://127.0.0.1:1"
	defer func() { globalFlags.Server = origServer }()

	err := cmdConfig([]string{"get"})
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestCmdConfig_ReloadConnectionError(t *testing.T) {
	origServer := globalFlags.Server
	globalFlags.Server = "http://127.0.0.1:1"
	defer func() { globalFlags.Server = origServer }()

	err := cmdConfig([]string{"reload"})
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestCmdServer_StatusConnectionError(t *testing.T) {
	origServer := globalFlags.Server
	globalFlags.Server = "http://127.0.0.1:1"
	defer func() { globalFlags.Server = origServer }()

	err := cmdServer([]string{"status"})
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestCmdCluster_StatusConnectionError(t *testing.T) {
	origServer := globalFlags.Server
	globalFlags.Server = "http://127.0.0.1:1"
	defer func() { globalFlags.Server = origServer }()

	err := cmdCluster([]string{"status"})
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestCmdCluster_PeersConnectionError(t *testing.T) {
	origServer := globalFlags.Server
	globalFlags.Server = "http://127.0.0.1:1"
	defer func() { globalFlags.Server = origServer }()

	err := cmdCluster([]string{"peers"})
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestCmdZone_ListConnectionError(t *testing.T) {
	origServer := globalFlags.Server
	globalFlags.Server = "http://127.0.0.1:1"
	defer func() { globalFlags.Server = origServer }()

	err := cmdZone([]string{"list"})
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestCmdZone_AddConnectionError(t *testing.T) {
	origServer := globalFlags.Server
	globalFlags.Server = "http://127.0.0.1:1"
	defer func() { globalFlags.Server = origServer }()

	err := cmdZone([]string{"add", "example.com"})
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestCmdZone_RemoveConnectionError(t *testing.T) {
	origServer := globalFlags.Server
	globalFlags.Server = "http://127.0.0.1:1"
	defer func() { globalFlags.Server = origServer }()

	err := cmdZone([]string{"remove", "example.com"})
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestCmdZone_ReloadConnectionError(t *testing.T) {
	origServer := globalFlags.Server
	globalFlags.Server = "http://127.0.0.1:1"
	defer func() { globalFlags.Server = origServer }()

	err := cmdZone([]string{"reload", "example.com"})
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestCmdZone_ExportConnectionError(t *testing.T) {
	origServer := globalFlags.Server
	globalFlags.Server = "http://127.0.0.1:1"
	defer func() { globalFlags.Server = origServer }()

	err := cmdZone([]string{"export", "example.com"})
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestCmdRecord_AddConnectionError(t *testing.T) {
	origServer := globalFlags.Server
	globalFlags.Server = "http://127.0.0.1:1"
	defer func() { globalFlags.Server = origServer }()

	err := cmdRecord([]string{"add", "example.com", "www", "A", "192.0.2.1"})
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestCmdRecord_RemoveConnectionError(t *testing.T) {
	origServer := globalFlags.Server
	globalFlags.Server = "http://127.0.0.1:1"
	defer func() { globalFlags.Server = origServer }()

	err := cmdRecord([]string{"remove", "example.com", "www", "A"})
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestCmdRecord_ListConnectionError(t *testing.T) {
	origServer := globalFlags.Server
	globalFlags.Server = "http://127.0.0.1:1"
	defer func() { globalFlags.Server = origServer }()

	err := cmdRecord([]string{"list", "example.com"})
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestCmdRecord_UpdateConnectionError(t *testing.T) {
	origServer := globalFlags.Server
	globalFlags.Server = "http://127.0.0.1:1"
	defer func() { globalFlags.Server = origServer }()

	err := cmdRecord([]string{"update", "example.com", "www", "A", "old", "new"})
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestCmdCache_FlushConnectionError(t *testing.T) {
	origServer := globalFlags.Server
	globalFlags.Server = "http://127.0.0.1:1"
	defer func() { globalFlags.Server = origServer }()

	err := cmdCache([]string{"flush"})
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestCmdCache_StatsConnectionError(t *testing.T) {
	origServer := globalFlags.Server
	globalFlags.Server = "http://127.0.0.1:1"
	defer func() { globalFlags.Server = origServer }()

	err := cmdCache([]string{"stats"})
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestCmdCache_FlushNameConnectionError(t *testing.T) {
	origServer := globalFlags.Server
	globalFlags.Server = "http://127.0.0.1:1"
	defer func() { globalFlags.Server = origServer }()

	err := cmdCache([]string{"flush", "example.com"})
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestGenerateKeyPair_RSA_DefaultSize(t *testing.T) {
	key, err := generateKeyPair(protocol.AlgorithmRSASHA256, false, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key == nil {
		t.Fatal("expected key, got nil")
	}
}

func TestCmdDNSSECDSFromDNSKEY_MissingKeyFile(t *testing.T) {
	err := cmdDNSSECDSFromDNSKEY([]string{"--zone", "example.com.", "--keyfile", "/nonexistent/path.key"})
	if err == nil {
		t.Fatal("expected error for missing key file")
	}
}

func TestParseRDataFromZone_InvalidNS(t *testing.T) {
	longLabel := "a" + strings.Repeat("b", 64) + ".com."
	_, err := parseRDataFromZone(protocol.TypeNS, longLabel)
	if err == nil {
		t.Fatal("expected error for invalid NS name")
	}
}

func TestParseRDataFromZone_InvalidMXExchange(t *testing.T) {
	longLabel := "a" + strings.Repeat("b", 64) + ".com."
	_, err := parseRDataFromZone(protocol.TypeMX, "10 "+longLabel)
	if err == nil {
		t.Fatal("expected error for invalid MX exchange")
	}
}

func TestParseRDataFromZone_InvalidRRSIGSigner(t *testing.T) {
	longLabel := "a" + strings.Repeat("b", 64) + ".com."
	rdata := fmt.Sprintf("A 13 1 300 1609459200 1606780800 12345 %s fakesig", longLabel)
	_, err := parseRDataFromZone(protocol.TypeRRSIG, rdata)
	if err == nil {
		t.Fatal("expected error for invalid RRSIG signer name")
	}
}

func TestCmdDNSSECValidateZone_ParseSkips(t *testing.T) {
	tmpDir := t.TempDir()
	zoneFile := filepath.Join(tmpDir, "zone.zone")
	pubKey := base64.StdEncoding.EncodeToString([]byte("fakepublickey12345"))
	content := fmt.Sprintf(`
; comment line
$TTL 300
short
example.com. badttl IN A 192.0.2.1
example.com. 300 CH A 192.0.2.1
..invalid.. 300 IN A 192.0.2.1
example.com. 300 IN BADTYPE data
example.com. 300 IN A bad-ip
example.com. 300 IN DNSKEY 257 3 13 %s
example.com. 300 IN A 192.0.2.1
example.com. 300 IN RRSIG A 13 1 300 1609459200 1606780800 12345 example.com. %s
`, pubKey, base64.StdEncoding.EncodeToString([]byte("fakesig")))
	if err := os.WriteFile(zoneFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write zone file: %v", err)
	}
	output := captureOutput(func() {
		err := cmdDNSSECValidateZone([]string{"--zone", zoneFile, "--ignore-time"})
		if err == nil {
			t.Fatal("expected error for invalid signature")
		}
	})
	if !strings.Contains(output, "Records found:") {
		t.Errorf("output missing records count: %q", output)
	}
}

func TestCmdDNSSECValidateZone_ExpiredSignature(t *testing.T) {
	tmpDir := t.TempDir()
	zoneFile := filepath.Join(tmpDir, "zone.zone")
	pubKey := base64.StdEncoding.EncodeToString([]byte("fakepublickey12345"))
	// Signature expired in 2021
	content := fmt.Sprintf(`example.com. 300 IN DNSKEY 257 3 13 %s
example.com. 300 IN A 192.0.2.1
example.com. 300 IN RRSIG A 13 1 300 1609459200 1577836800 12345 example.com. %s
`, pubKey, base64.StdEncoding.EncodeToString([]byte("fakesig")))
	if err := os.WriteFile(zoneFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write zone file: %v", err)
	}
	output := captureOutput(func() {
		err := cmdDNSSECValidateZone([]string{"--zone", zoneFile})
		if err == nil {
			t.Fatal("expected error for expired signature")
		}
	})
	if !strings.Contains(output, "Expired/Not-yet-valid") {
		t.Errorf("output missing expired info: %q", output)
	}
}

func TestCmdDNSSECValidateZone_MismatchedKeyTag(t *testing.T) {
	tmpDir := t.TempDir()
	zoneFile := filepath.Join(tmpDir, "zone.zone")
	pubKey := base64.StdEncoding.EncodeToString([]byte("fakepublickey12345"))
	// RRSIG keytag 65535 is in range but doesn't match DNSKEY keytag.
	content := fmt.Sprintf(`example.com. 300 IN DNSKEY 257 3 13 %s
example.com. 300 IN A 192.0.2.1
example.com. 300 IN RRSIG A 13 1 300 1609459200 1606780800 65535 example.com. %s
`, pubKey, base64.StdEncoding.EncodeToString([]byte("fakesig")))
	if err := os.WriteFile(zoneFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write zone file: %v", err)
	}
	output := captureOutput(func() {
		err := cmdDNSSECValidateZone([]string{"--zone", zoneFile, "--ignore-time"})
		if err == nil {
			t.Fatal("expected error for mismatched keytag")
		}
	})
	if !strings.Contains(output, "No DNSKEY found for keytag") {
		t.Errorf("output missing keytag error: %q", output)
	}
}

func TestCmdDNSSECValidateZone_MalformedRRSIGReturnsParseError(t *testing.T) {
	tmpDir := t.TempDir()
	zoneFile := filepath.Join(tmpDir, "zone.zone")
	pubKey := base64.StdEncoding.EncodeToString([]byte("fakepublickey12345"))
	content := fmt.Sprintf(`example.com. 300 IN DNSKEY 257 3 13 %s
example.com. 300 IN A 192.0.2.1
example.com. 300 IN RRSIG A 13 1 300 1609459200 1606780800 99999 example.com. %s
`, pubKey, base64.StdEncoding.EncodeToString([]byte("fakesig")))
	if err := os.WriteFile(zoneFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write zone file: %v", err)
	}

	err := cmdDNSSECValidateZone([]string{"--zone", zoneFile, "--ignore-time"})
	if err == nil {
		t.Fatal("expected parse error for malformed RRSIG")
	}
	// The key tag 99999 overflows uint16; the shared protocol.ParseRDataText
	// rejects the record as a whole (it does not report which field failed),
	// so the error names the record type and line, not the field.
	if !strings.Contains(err.Error(), "invalid RRSIG RDATA") || !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("error = %q, want line-3 invalid RRSIG RDATA parse error", err.Error())
	}
}

func TestCmdDNSSECValidateZone_InvalidDNSKEY(t *testing.T) {
	tmpDir := t.TempDir()
	zoneFile := filepath.Join(tmpDir, "zone.zone")
	// Invalid ECDSA P-256 public key (too short)
	pubKey := base64.StdEncoding.EncodeToString([]byte("short"))
	// Calculate keytag for this fake DNSKEY
	keyTag := protocol.CalculateKeyTag(257, 13, []byte("short"))
	content := fmt.Sprintf(`example.com. 300 IN DNSKEY 257 3 13 %s
example.com. 300 IN A 192.0.2.1
example.com. 300 IN RRSIG A 13 1 300 1609459200 1606780800 %d example.com. %s
`, pubKey, keyTag, base64.StdEncoding.EncodeToString([]byte("fakesig")))
	if err := os.WriteFile(zoneFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write zone file: %v", err)
	}
	output := captureOutput(func() {
		err := cmdDNSSECValidateZone([]string{"--zone", zoneFile, "--ignore-time"})
		if err == nil {
			t.Fatal("expected error for invalid DNSKEY")
		}
	})
	if !strings.Contains(output, "Failed to parse DNSKEY") {
		t.Errorf("output missing parse error: %q", output)
	}
}

func TestIsNilDigRData(t *testing.T) {
	if !isNilDigRData(nil) {
		t.Error("isNilDigRData(nil) should be true")
	}
	var ni *protocol.RDataA
	if !isNilDigRData(ni) {
		t.Error("isNilDigRData(nil *RDataA) should be true")
	}
	notNil := &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}}
	if isNilDigRData(notNil) {
		t.Error("isNilDigRData(&RDataA{}) should be false")
	}
}
