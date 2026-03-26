package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/cluster"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// TestHandleHealth tests the /health endpoint
func TestHandleHealth(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		expectedStatus int
	}{
		{"GET request", http.MethodGet, http.StatusOK},
		{"POST request", http.MethodPost, http.StatusOK}, // Health endpoint allows any method
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.HTTPConfig{
				Enabled: true,
				Bind:    "127.0.0.1:0",
			}
			server := NewServer(cfg, nil, nil, nil, nil, nil)

			req := httptest.NewRequest(tt.method, "/health", nil)
			rec := httptest.NewRecorder()

			server.handleHealth(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rec.Code)
			}

			var response map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatalf("Failed to parse response: %v", err)
			}

			if response["status"] != "healthy" {
				t.Errorf("Expected status 'healthy', got %v", response["status"])
			}

			if _, ok := response["timestamp"]; !ok {
				t.Error("Expected timestamp in response")
			}
		})
	}
}

// TestHandleStatus tests the /api/v1/status endpoint
func TestHandleStatus(t *testing.T) {
	t.Run("without cache or cluster", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		server := NewServer(cfg, nil, nil, nil, nil, nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		rec := httptest.NewRecorder()

		server.handleStatus(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if response["status"] != "running" {
			t.Errorf("Expected status 'running', got %v", response["status"])
		}

		if response["version"] != "0.1.0" {
			t.Errorf("Expected version '0.1.0', got %v", response["version"])
		}

		clusterInfo, ok := response["cluster"].(map[string]interface{})
		if !ok {
			t.Fatal("Expected cluster info in response")
		}
		if clusterInfo["enabled"] != false {
			t.Errorf("Expected cluster.enabled to be false, got %v", clusterInfo["enabled"])
		}
	})

	t.Run("with cache", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		cacheCfg := cache.Config{
			Capacity:   500,
			MinTTL:     60,
			MaxTTL:     3600,
			DefaultTTL: 300,
		}
		c := cache.New(cacheCfg)

		server := NewServer(cfg, nil, c, nil, nil, nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		rec := httptest.NewRecorder()

		server.handleStatus(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		cacheInfo, ok := response["cache"].(map[string]interface{})
		if !ok {
			t.Fatal("Expected cache info in response")
		}

		if cacheInfo["capacity"].(float64) != 500 {
			t.Errorf("Expected cache capacity 500, got %v", cacheInfo["capacity"])
		}
	})
}

// TestHandleZones tests the /api/v1/zones endpoint
func TestHandleZones(t *testing.T) {
	t.Run("GET zones without zone manager", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		server := NewServer(cfg, nil, nil, nil, nil, nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
		rec := httptest.NewRecorder()

		server.handleZones(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		zones, ok := response["zones"].([]interface{})
		if !ok {
			t.Fatal("Expected zones array in response")
		}
		if len(zones) != 0 {
			t.Errorf("Expected empty zones array, got %d zones", len(zones))
		}
	})

	t.Run("GET zones with zone manager", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		zm := zone.NewManager()

		// Create a test zone
		testZone := &zone.Zone{
			Origin:    "example.com.",
			DefaultTTL: 3600,
			Records: map[string][]zone.Record{
				"example.com.": {
					{Name: "example.com.", TTL: 3600, Class: "IN", Type: "A", RData: "192.168.1.1"},
				},
			},
		}
		zm.LoadZone(testZone, "")

		server := NewServer(cfg, zm, nil, nil, nil, nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
		rec := httptest.NewRecorder()

		server.handleZones(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		zones, ok := response["zones"].([]interface{})
		if !ok {
			t.Fatal("Expected zones array in response")
		}
		if len(zones) != 1 {
			t.Errorf("Expected 1 zone, got %d", len(zones))
		}
	})

	t.Run("POST zones - method not allowed", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		server := NewServer(cfg, nil, nil, nil, nil, nil)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/zones", nil)
		rec := httptest.NewRecorder()

		server.handleZones(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if response["error"] != "Method not allowed" {
			t.Errorf("Expected error 'Method not allowed', got %v", response["error"])
		}
	})

	t.Run("PUT zones - method not allowed", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		server := NewServer(cfg, nil, nil, nil, nil, nil)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/zones", nil)
		rec := httptest.NewRecorder()

		server.handleZones(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
		}
	})

	t.Run("DELETE zones - method not allowed", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		server := NewServer(cfg, nil, nil, nil, nil, nil)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/zones", nil)
		rec := httptest.NewRecorder()

		server.handleZones(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
		}
	})
}

// TestHandleZoneReload tests the /api/v1/zones/reload endpoint
func TestHandleZoneReload(t *testing.T) {
	t.Run("POST without zone parameter", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		server := NewServer(cfg, nil, nil, nil, nil, nil)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/reload", nil)
		rec := httptest.NewRecorder()

		server.handleZoneReload(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rec.Code)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if response["error"] != "Missing zone parameter" {
			t.Errorf("Expected error 'Missing zone parameter', got %v", response["error"])
		}
	})

	t.Run("POST without zone manager", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		server := NewServer(cfg, nil, nil, nil, nil, nil)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/reload?zone=example.com.", nil)
		rec := httptest.NewRecorder()

		server.handleZoneReload(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("Expected status %d, got %d", http.StatusServiceUnavailable, rec.Code)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if response["error"] != "Zone manager not available" {
			t.Errorf("Expected error 'Zone manager not available', got %v", response["error"])
		}
	})

	t.Run("POST with non-existent zone", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		zm := zone.NewManager()
		server := NewServer(cfg, zm, nil, nil, nil, nil)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/reload?zone=nonexistent.com.", nil)
		rec := httptest.NewRecorder()

		server.handleZoneReload(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rec.Code)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if !strings.Contains(response["error"].(string), "Failed to reload zone") {
			t.Errorf("Expected error containing 'Failed to reload zone', got %v", response["error"])
		}
	})

	t.Run("GET - method not allowed", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		server := NewServer(cfg, nil, nil, nil, nil, nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/zones/reload", nil)
		rec := httptest.NewRecorder()

		server.handleZoneReload(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
		}
	})
}

// TestHandleCacheStats tests the /api/v1/cache/stats endpoint
func TestHandleCacheStats(t *testing.T) {
	t.Run("GET without cache", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		server := NewServer(cfg, nil, nil, nil, nil, nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/cache/stats", nil)
		rec := httptest.NewRecorder()

		server.handleCacheStats(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("Expected status %d, got %d", http.StatusServiceUnavailable, rec.Code)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if response["error"] != "Cache not available" {
			t.Errorf("Expected error 'Cache not available', got %v", response["error"])
		}
	})

	t.Run("GET with cache", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		cacheCfg := cache.Config{
			Capacity:   1000,
			MinTTL:     60,
			MaxTTL:     3600,
			DefaultTTL: 300,
		}
		c := cache.New(cacheCfg)

		server := NewServer(cfg, nil, c, nil, nil, nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/cache/stats", nil)
		rec := httptest.NewRecorder()

		server.handleCacheStats(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if response["capacity"].(float64) != 1000 {
			t.Errorf("Expected capacity 1000, got %v", response["capacity"])
		}
	})

	t.Run("POST - method not allowed", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		cacheCfg := cache.Config{
			Capacity:   1000,
			MinTTL:     60,
			MaxTTL:     3600,
			DefaultTTL: 300,
		}
		c := cache.New(cacheCfg)

		server := NewServer(cfg, nil, c, nil, nil, nil)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/cache/stats", nil)
		rec := httptest.NewRecorder()

		server.handleCacheStats(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
		}
	})
}

// TestHandleCacheFlush tests the /api/v1/cache/flush endpoint
func TestHandleCacheFlush(t *testing.T) {
	t.Run("POST without cache", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		server := NewServer(cfg, nil, nil, nil, nil, nil)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/cache/flush", nil)
		rec := httptest.NewRecorder()

		server.handleCacheFlush(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("Expected status %d, got %d", http.StatusServiceUnavailable, rec.Code)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if response["error"] != "Cache not available" {
			t.Errorf("Expected error 'Cache not available', got %v", response["error"])
		}
	})

	t.Run("POST with cache", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		cacheCfg := cache.Config{
			Capacity:   1000,
			MinTTL:     60,
			MaxTTL:     3600,
			DefaultTTL: 300,
		}
		c := cache.New(cacheCfg)

		server := NewServer(cfg, nil, c, nil, nil, nil)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/cache/flush", nil)
		rec := httptest.NewRecorder()

		server.handleCacheFlush(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if response["message"] != "Cache flushed" {
			t.Errorf("Expected message 'Cache flushed', got %v", response["message"])
		}
	})

	t.Run("GET - method not allowed", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		cacheCfg := cache.Config{
			Capacity:   1000,
			MinTTL:     60,
			MaxTTL:     3600,
			DefaultTTL: 300,
		}
		c := cache.New(cacheCfg)

		server := NewServer(cfg, nil, c, nil, nil, nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/cache/flush", nil)
		rec := httptest.NewRecorder()

		server.handleCacheFlush(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
		}
	})
}

// TestHandleConfigReload tests the /api/v1/config/reload endpoint
func TestHandleConfigReload(t *testing.T) {
	t.Run("POST without reload function", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		server := NewServer(cfg, nil, nil, nil, nil, nil)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/config/reload", nil)
		rec := httptest.NewRecorder()

		server.handleConfigReload(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("Expected status %d, got %d", http.StatusServiceUnavailable, rec.Code)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if response["error"] != "Reload not available" {
			t.Errorf("Expected error 'Reload not available', got %v", response["error"])
		}
	})

	t.Run("POST with successful reload", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		reloadFunc := func() error {
			return nil
		}
		server := NewServer(cfg, nil, nil, reloadFunc, nil, nil)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/config/reload", nil)
		rec := httptest.NewRecorder()

		server.handleConfigReload(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if response["message"] != "Configuration reloaded" {
			t.Errorf("Expected message 'Configuration reloaded', got %v", response["message"])
		}
	})

	t.Run("POST with failed reload", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		reloadFunc := func() error {
			return fmt.Errorf("config file not found")
		}
		server := NewServer(cfg, nil, nil, reloadFunc, nil, nil)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/config/reload", nil)
		rec := httptest.NewRecorder()

		server.handleConfigReload(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rec.Code)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if !strings.Contains(response["error"].(string), "Failed to reload config") {
			t.Errorf("Expected error containing 'Failed to reload config', got %v", response["error"])
		}
	})

	t.Run("GET - method not allowed", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		server := NewServer(cfg, nil, nil, nil, nil, nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/config/reload", nil)
		rec := httptest.NewRecorder()

		server.handleConfigReload(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
		}
	})
}

// TestHandleClusterStatus tests the /api/v1/cluster/status endpoint
func TestHandleClusterStatus(t *testing.T) {
	t.Run("GET without cluster", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		server := NewServer(cfg, nil, nil, nil, nil, nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/cluster/status", nil)
		rec := httptest.NewRecorder()

		server.handleClusterStatus(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("Expected status %d, got %d", http.StatusServiceUnavailable, rec.Code)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if response["error"] != "Cluster not available" {
			t.Errorf("Expected error 'Cluster not available', got %v", response["error"])
		}
	})

	t.Run("GET with cluster", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}

		clusterCfg := cluster.Config{
			Enabled:    true,
			NodeID:     "test-node-1",
			BindAddr:   "127.0.0.1",
			GossipPort: 7946,
		}
		c, err := cluster.New(clusterCfg, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create cluster: %v", err)
		}

		server := NewServer(cfg, nil, nil, nil, nil, c)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/cluster/status", nil)
		rec := httptest.NewRecorder()

		server.handleClusterStatus(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if response["node_id"] != "test-node-1" {
			t.Errorf("Expected node_id 'test-node-1', got %v", response["node_id"])
		}
	})

	t.Run("POST - method not allowed", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		server := NewServer(cfg, nil, nil, nil, nil, nil)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/status", nil)
		rec := httptest.NewRecorder()

		server.handleClusterStatus(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
		}
	})
}

// TestHandleClusterNodes tests the /api/v1/cluster/nodes endpoint
func TestHandleClusterNodes(t *testing.T) {
	t.Run("GET without cluster", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		server := NewServer(cfg, nil, nil, nil, nil, nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/cluster/nodes", nil)
		rec := httptest.NewRecorder()

		server.handleClusterNodes(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("Expected status %d, got %d", http.StatusServiceUnavailable, rec.Code)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if response["error"] != "Cluster not available" {
			t.Errorf("Expected error 'Cluster not available', got %v", response["error"])
		}
	})

	t.Run("GET with cluster", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}

		clusterCfg := cluster.Config{
			Enabled:    true,
			NodeID:     "test-node-1",
			BindAddr:   "127.0.0.1",
			GossipPort: 7947,
		}
		c, err := cluster.New(clusterCfg, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create cluster: %v", err)
		}

		server := NewServer(cfg, nil, nil, nil, nil, c)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/cluster/nodes", nil)
		rec := httptest.NewRecorder()

		server.handleClusterNodes(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		nodes, ok := response["nodes"].([]interface{})
		if !ok {
			t.Fatal("Expected nodes array in response")
		}
		// Should have at least the local node
		if len(nodes) < 1 {
			t.Errorf("Expected at least 1 node, got %d", len(nodes))
		}
	})

	t.Run("POST - method not allowed", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		server := NewServer(cfg, nil, nil, nil, nil, nil)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/nodes", nil)
		rec := httptest.NewRecorder()

		server.handleClusterNodes(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
		}
	})
}

// TestAuthMiddleware tests the authentication middleware
func TestAuthMiddleware(t *testing.T) {
	t.Run("no auth token configured", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled:   true,
			Bind:      "127.0.0.1:0",
			AuthToken: "",
		}
		server := NewServer(cfg, nil, nil, nil, nil, nil)

		handlerCalled := false
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		rec := httptest.NewRecorder()

		server.authMiddleware(testHandler).ServeHTTP(rec, req)

		if !handlerCalled {
			t.Error("Expected handler to be called when no auth token configured")
		}
		if rec.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
		}
	})

	t.Run("auth with Bearer token in header", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled:   true,
			Bind:      "127.0.0.1:0",
			AuthToken: "secret-token",
		}
		server := NewServer(cfg, nil, nil, nil, nil, nil)

		handlerCalled := false
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		req.Header.Set("Authorization", "Bearer secret-token")
		rec := httptest.NewRecorder()

		server.authMiddleware(testHandler).ServeHTTP(rec, req)

		if !handlerCalled {
			t.Error("Expected handler to be called with valid Bearer token")
		}
		if rec.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
		}
	})

	t.Run("auth with token in query parameter", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled:   true,
			Bind:      "127.0.0.1:0",
			AuthToken: "secret-token",
		}
		server := NewServer(cfg, nil, nil, nil, nil, nil)

		handlerCalled := false
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/api/v1/status?token=secret-token", nil)
		rec := httptest.NewRecorder()

		server.authMiddleware(testHandler).ServeHTTP(rec, req)

		if !handlerCalled {
			t.Error("Expected handler to be called with valid token in query")
		}
		if rec.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
		}
	})

	t.Run("auth with raw token in header (no Bearer prefix)", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled:   true,
			Bind:      "127.0.0.1:0",
			AuthToken: "secret-token",
		}
		server := NewServer(cfg, nil, nil, nil, nil, nil)

		handlerCalled := false
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		req.Header.Set("Authorization", "secret-token")
		rec := httptest.NewRecorder()

		server.authMiddleware(testHandler).ServeHTTP(rec, req)

		if !handlerCalled {
			t.Error("Expected handler to be called with valid raw token")
		}
		if rec.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
		}
	})

	t.Run("auth fails with invalid token", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled:   true,
			Bind:      "127.0.0.1:0",
			AuthToken: "secret-token",
		}
		server := NewServer(cfg, nil, nil, nil, nil, nil)

		handlerCalled := false
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		rec := httptest.NewRecorder()

		server.authMiddleware(testHandler).ServeHTTP(rec, req)

		if handlerCalled {
			t.Error("Expected handler NOT to be called with invalid token")
		}
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, rec.Code)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if response["error"] != "Unauthorized" {
			t.Errorf("Expected error 'Unauthorized', got %v", response["error"])
		}
	})

	t.Run("auth fails with no token", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled:   true,
			Bind:      "127.0.0.1:0",
			AuthToken: "secret-token",
		}
		server := NewServer(cfg, nil, nil, nil, nil, nil)

		handlerCalled := false
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		rec := httptest.NewRecorder()

		server.authMiddleware(testHandler).ServeHTTP(rec, req)

		if handlerCalled {
			t.Error("Expected handler NOT to be called without token")
		}
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, rec.Code)
		}
	})
}

// TestCorsMiddleware tests the CORS middleware
func TestCorsMiddleware(t *testing.T) {
	t.Run("OPTIONS request returns OK", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		server := NewServer(cfg, nil, nil, nil, nil, nil)

		handlerCalled := false
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodOptions, "/api/v1/status", nil)
		rec := httptest.NewRecorder()

		server.corsMiddleware(testHandler).ServeHTTP(rec, req)

		if handlerCalled {
			t.Error("Expected handler NOT to be called for OPTIONS request")
		}
		if rec.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
		}
	})

	t.Run("CORS headers are set", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		server := NewServer(cfg, nil, nil, nil, nil, nil)

		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		rec := httptest.NewRecorder()

		server.corsMiddleware(testHandler).ServeHTTP(rec, req)

		if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("Expected Access-Control-Allow-Origin '*', got %v", rec.Header().Get("Access-Control-Allow-Origin"))
		}

		if rec.Header().Get("Access-Control-Allow-Methods") != "GET, POST, PUT, DELETE, OPTIONS" {
			t.Errorf("Unexpected Access-Control-Allow-Methods: %v", rec.Header().Get("Access-Control-Allow-Methods"))
		}

		if rec.Header().Get("Access-Control-Allow-Headers") != "Content-Type, Authorization" {
			t.Errorf("Unexpected Access-Control-Allow-Headers: %v", rec.Header().Get("Access-Control-Allow-Headers"))
		}
	})

	t.Run("Non-OPTIONS request passes through", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		server := NewServer(cfg, nil, nil, nil, nil, nil)

		handlerCalled := false
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		rec := httptest.NewRecorder()

		server.corsMiddleware(testHandler).ServeHTTP(rec, req)

		if !handlerCalled {
			t.Error("Expected handler to be called for GET request")
		}
		if rec.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
		}
	})
}

// TestWriteJSON tests the writeJSON helper
func TestWriteJSON(t *testing.T) {
	t.Run("writes JSON response", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:0",
		}
		server := NewServer(cfg, nil, nil, nil, nil, nil)

		rec := httptest.NewRecorder()

		data := map[string]interface{}{
			"message": "test",
			"count":   42,
		}

		server.writeJSON(rec, http.StatusCreated, data)

		if rec.Code != http.StatusCreated {
			t.Errorf("Expected status %d, got %d", http.StatusCreated, rec.Code)
		}

		if rec.Header().Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type 'application/json', got %v", rec.Header().Get("Content-Type"))
		}

		var response map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if response["message"] != "test" {
			t.Errorf("Expected message 'test', got %v", response["message"])
		}

		if response["count"].(float64) != 42 {
			t.Errorf("Expected count 42, got %v", response["count"])
		}
	})
}

// TestWriteError tests the writeError helper
func TestWriteError(t *testing.T) {
	tests := []struct {
		name         string
		status       int
		message      string
		expectedBody string
	}{
		{"Bad Request", http.StatusBadRequest, "Invalid parameter", `{"error":"Invalid parameter"}` + "\n"},
		{"Unauthorized", http.StatusUnauthorized, "Unauthorized", `{"error":"Unauthorized"}` + "\n"},
		{"Not Found", http.StatusNotFound, "Resource not found", `{"error":"Resource not found"}` + "\n"},
		{"Internal Error", http.StatusInternalServerError, "Something went wrong", `{"error":"Something went wrong"}` + "\n"},
		{"Service Unavailable", http.StatusServiceUnavailable, "Service unavailable", `{"error":"Service unavailable"}` + "\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.HTTPConfig{
				Enabled: true,
				Bind:    "127.0.0.1:0",
			}
			server := NewServer(cfg, nil, nil, nil, nil, nil)

			rec := httptest.NewRecorder()

			server.writeError(rec, tt.status, tt.message)

			if rec.Code != tt.status {
				t.Errorf("Expected status %d, got %d", tt.status, rec.Code)
			}

			if rec.Header().Get("Content-Type") != "application/json" {
				t.Errorf("Expected Content-Type 'application/json', got %v", rec.Header().Get("Content-Type"))
			}

			if rec.Body.String() != tt.expectedBody {
				t.Errorf("Expected body %q, got %q", tt.expectedBody, rec.Body.String())
			}
		})
	}
}

// TestNewServer tests the NewServer constructor
func TestNewServer(t *testing.T) {
	cfg := config.HTTPConfig{
		Enabled:   true,
		Bind:      "127.0.0.1:8080",
		AuthToken: "test-token",
	}

	zm := zone.NewManager()
	cacheCfg := cache.Config{Capacity: 100}
	c := cache.New(cacheCfg)
	reloadFunc := func() error { return nil }

	server := NewServer(cfg, zm, c, reloadFunc, nil, nil)

	if server == nil {
		t.Fatal("Expected server to be created")
	}

	if server.config.Bind != "127.0.0.1:8080" {
		t.Errorf("Expected bind '127.0.0.1:8080', got %v", server.config.Bind)
	}

	if server.zoneManager != zm {
		t.Error("Expected zone manager to be set")
	}

	if server.cache != c {
		t.Error("Expected cache to be set")
	}

	if server.reloadFunc == nil {
		t.Error("Expected reload function to be set")
	}
}

// TestStartStop tests the Start and Stop methods
func TestStartStop(t *testing.T) {
	t.Run("start and stop with enabled server", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:18090",
		}

		server := NewServer(cfg, nil, nil, nil, nil, nil)

		if err := server.Start(); err != nil {
			t.Fatalf("Failed to start server: %v", err)
		}

		// Give server time to start
		time.Sleep(50 * time.Millisecond)

		// Verify server is running
		resp, err := http.Get("http://127.0.0.1:18090/health")
		if err != nil {
			t.Fatalf("Failed to reach server: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		if err := server.Stop(); err != nil {
			t.Fatalf("Failed to stop server: %v", err)
		}
	})

	t.Run("start with disabled server", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: false,
			Bind:    "127.0.0.1:18091",
		}

		server := NewServer(cfg, nil, nil, nil, nil, nil)

		if err := server.Start(); err != nil {
			t.Errorf("Start should not fail when disabled: %v", err)
		}

		// Stop should also not fail
		if err := server.Stop(); err != nil {
			t.Errorf("Stop should not fail when disabled: %v", err)
		}
	})

	t.Run("stop without start", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:18092",
		}

		server := NewServer(cfg, nil, nil, nil, nil, nil)

		// Stop without start should not fail
		if err := server.Stop(); err != nil {
			t.Errorf("Stop should not fail without start: %v", err)
		}
	})

	t.Run("multiple stop calls", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled: true,
			Bind:    "127.0.0.1:18093",
		}

		server := NewServer(cfg, nil, nil, nil, nil, nil)

		if err := server.Start(); err != nil {
			t.Fatalf("Failed to start server: %v", err)
		}

		time.Sleep(50 * time.Millisecond)

		// First stop
		if err := server.Stop(); err != nil {
			t.Fatalf("First stop failed: %v", err)
		}

		// Second stop should not fail
		if err := server.Stop(); err != nil {
			t.Errorf("Second stop should not fail: %v", err)
		}
	})
}

// TestMiddlewareChain tests that middleware is applied in correct order
func TestMiddlewareChain(t *testing.T) {
	t.Run("CORS headers present even with auth failure", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled:   true,
			Bind:      "127.0.0.1:18094",
			AuthToken: "secret",
		}

		server := NewServer(cfg, nil, nil, nil, nil, nil)
		server.Start()
		time.Sleep(50 * time.Millisecond)
		defer server.Stop()

		// Make request without auth
		resp, err := http.Get("http://127.0.0.1:18094/api/v1/status")
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		// Should get 401
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", resp.StatusCode)
		}

		// CORS headers should still be present
		if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("Expected CORS header to be present")
		}
	})
}

// TestIntegration tests full request flow
func TestIntegration(t *testing.T) {
	t.Run("full API flow with auth", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled:   true,
			Bind:      "127.0.0.1:18095",
			AuthToken: "test-api-key",
		}

		cacheCfg := cache.Config{
			Capacity:   1000,
			MinTTL:     60,
			MaxTTL:     3600,
			DefaultTTL: 300,
		}
		c := cache.New(cacheCfg)

		reloadCalled := false
		reloadFunc := func() error {
			reloadCalled = true
			return nil
		}

		server := NewServer(cfg, nil, c, reloadFunc, nil, nil)
		server.Start()
		time.Sleep(50 * time.Millisecond)
		defer server.Stop()

		// Helper function for authenticated requests
		doRequest := func(method, path string, body io.Reader) *http.Response {
			req, _ := http.NewRequest(method, "http://127.0.0.1:18095"+path, body)
			req.Header.Set("Authorization", "Bearer test-api-key")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			return resp
		}

		// Test health endpoint (no auth required but should still work with auth)
		resp := doRequest(http.MethodGet, "/health", nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Health check failed: %d", resp.StatusCode)
		}
		resp.Body.Close()

		// Test status endpoint
		resp = doRequest(http.MethodGet, "/api/v1/status", nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Status check failed: %d", resp.StatusCode)
		}
		var status map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&status)
		resp.Body.Close()

		if status["status"] != "running" {
			t.Errorf("Expected status 'running', got %v", status["status"])
		}

		// Test cache stats
		resp = doRequest(http.MethodGet, "/api/v1/cache/stats", nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Cache stats failed: %d", resp.StatusCode)
		}
		resp.Body.Close()

		// Test cache flush
		resp = doRequest(http.MethodPost, "/api/v1/cache/flush", bytes.NewReader([]byte{}))
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Cache flush failed: %d", resp.StatusCode)
		}
		resp.Body.Close()

		// Test config reload
		resp = doRequest(http.MethodPost, "/api/v1/config/reload", bytes.NewReader([]byte{}))
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Config reload failed: %d", resp.StatusCode)
		}
		resp.Body.Close()

		if !reloadCalled {
			t.Error("Expected reload function to be called")
		}
	})

	t.Run("unauthenticated requests are rejected", func(t *testing.T) {
		cfg := config.HTTPConfig{
			Enabled:   true,
			Bind:      "127.0.0.1:18096",
			AuthToken: "secret-key",
		}

		server := NewServer(cfg, nil, nil, nil, nil, nil)
		server.Start()
		time.Sleep(50 * time.Millisecond)
		defer server.Stop()

		// Requests without auth should fail
		endpoints := []string{
			"/api/v1/status",
			"/api/v1/zones",
			"/api/v1/cache/stats",
		}

		for _, endpoint := range endpoints {
			resp, err := http.Get("http://127.0.0.1:18096" + endpoint)
			if err != nil {
				t.Fatalf("Request to %s failed: %v", endpoint, err)
			}
			resp.Body.Close()

			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("Expected 401 for %s, got %d", endpoint, resp.StatusCode)
			}
		}
	})
}

// TestErrorResponseFormat tests that all error responses have consistent format
func TestErrorResponseFormat(t *testing.T) {
	cfg := config.HTTPConfig{
		Enabled:   true,
		AuthToken: "test-token",
		Bind:      "127.0.0.1:18097",
	}

	cacheCfg := cache.Config{Capacity: 100}
	c := cache.New(cacheCfg)

	server := NewServer(cfg, nil, c, nil, nil, nil)
	server.Start()
	time.Sleep(50 * time.Millisecond)
	defer server.Stop()

	tests := []struct {
		name     string
		method   string
		path     string
		useAuth  bool
		expected int
	}{
		{"Unauthorized", http.MethodGet, "/api/v1/status", false, http.StatusUnauthorized},
		{"Method not allowed - zones", http.MethodPost, "/api/v1/zones", true, http.StatusMethodNotAllowed},
		{"Method not allowed - cache stats", http.MethodPost, "/api/v1/cache/stats", true, http.StatusMethodNotAllowed},
		{"Method not allowed - cache flush", http.MethodGet, "/api/v1/cache/flush", true, http.StatusMethodNotAllowed},
		{"Method not allowed - config reload", http.MethodGet, "/api/v1/config/reload", true, http.StatusMethodNotAllowed},
		{"Method not allowed - zone reload", http.MethodGet, "/api/v1/zones/reload", true, http.StatusMethodNotAllowed},
		{"Missing zone param", http.MethodPost, "/api/v1/zones/reload", true, http.StatusBadRequest},
		{"No cache - cache stats", http.MethodGet, "/api/v1/cache/stats", true, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, "http://127.0.0.1:18097"+tt.path, nil)
			if tt.useAuth {
				req.Header.Set("Authorization", "Bearer test-token")
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expected {
				t.Errorf("Expected status %d, got %d", tt.expected, resp.StatusCode)
			}

			// Verify response is JSON
			contentType := resp.Header.Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf("Expected Content-Type 'application/json', got %v", contentType)
			}

			// Verify body is valid JSON
			var body map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Errorf("Failed to decode response body: %v", err)
			}
		})
	}
}

// TestOptionsPreflight tests CORS preflight requests
func TestOptionsPreflight(t *testing.T) {
	cfg := config.HTTPConfig{
		Enabled:   true,
		AuthToken: "test-token",
		Bind:      "127.0.0.1:18098",
	}

	server := NewServer(cfg, nil, nil, nil, nil, nil)
	server.Start()
	time.Sleep(50 * time.Millisecond)
	defer server.Stop()

	// Test OPTIONS request on various endpoints
	endpoints := []string{
		"/api/v1/status",
		"/api/v1/zones",
		"/api/v1/cache/flush",
		"/api/v1/config/reload",
	}

	for _, endpoint := range endpoints {
		req, _ := http.NewRequest(http.MethodOptions, "http://127.0.0.1:18098"+endpoint, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("OPTIONS request to %s failed: %v", endpoint, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 for OPTIONS %s, got %d", endpoint, resp.StatusCode)
		}

		// Verify CORS headers
		if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("Missing Access-Control-Allow-Origin for %s", endpoint)
		}
	}
}

// TestConcurrentRequests tests that the server handles concurrent requests
func TestConcurrentRequests(t *testing.T) {
	cfg := config.HTTPConfig{
		Enabled:   true,
		AuthToken: "test-token",
		Bind:      "127.0.0.1:18099",
	}

	cacheCfg := cache.Config{Capacity: 1000}
	c := cache.New(cacheCfg)

	server := NewServer(cfg, nil, c, nil, nil, nil)
	server.Start()
	time.Sleep(50 * time.Millisecond)
	defer server.Stop()

	// Make concurrent requests
	numRequests := 10
	done := make(chan bool, numRequests)

	for i := 0; i < numRequests; i++ {
		go func() {
			req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:18099/api/v1/status", nil)
			req.Header.Set("Authorization", "Bearer test-token")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Errorf("Request failed: %v", err)
				done <- false
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected 200, got %d", resp.StatusCode)
			}
			done <- true
		}()
	}

	// Wait for all requests to complete
	for i := 0; i < numRequests; i++ {
		<-done
	}
}
