package api

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/config"
)

func TestAPIServer(t *testing.T) {
	// Use a free port dynamically to avoid conflicts
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find free port: %v", err)
	}
	addr := l.Addr().String()
	l.Close()

	cfg := config.HTTPConfig{
		Enabled: true,
		Bind:    addr,
	}

	server := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start API server: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Test health endpoint
	resp, err := http.Get("http://" + addr + "/health")
	if err != nil {
		t.Fatalf("Failed to get health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var health map[string]interface{}
	if err := json.Unmarshal(body, &health); err != nil {
		t.Fatalf("Failed to parse health response: %v", err)
	}

	if health["status"] != "healthy" {
		t.Errorf("Expected status healthy, got %v", health["status"])
	}

	server.Stop()
}

func TestAPIStatus(t *testing.T) {
	cfg := config.HTTPConfig{
		Enabled: true,
		Bind:    "127.0.0.1:18081",
	}

	cacheCfg := cache.Config{
		Capacity:   1000,
		MinTTL:     60,
		MaxTTL:     3600,
		DefaultTTL: 300,
	}
	c := cache.New(cacheCfg)

	server := NewServer(cfg, nil, c, nil, nil, nil, nil)
	server.Start()
	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get("http://127.0.0.1:18081/api/v1/status")
	if err != nil {
		t.Fatalf("Failed to get status: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var status map[string]interface{}
	if err := json.Unmarshal(body, &status); err != nil {
		t.Fatalf("Failed to parse status response: %v", err)
	}

	if status["status"] != "running" {
		t.Errorf("Expected status running, got %v", status["status"])
	}

	// Check cache info
	if cacheInfo, ok := status["cache"].(map[string]interface{}); ok {
		if capacity, ok := cacheInfo["capacity"].(float64); !ok || capacity != 1000 {
			t.Errorf("Expected capacity 1000, got %v", capacity)
		}
	} else {
		t.Error("Expected cache info in status")
	}

	server.Stop()
}

func TestAPICacheFlush(t *testing.T) {
	cfg := config.HTTPConfig{
		Enabled: true,
		Bind:    "127.0.0.1:18082",
	}

	cacheCfg := cache.Config{
		Capacity:   1000,
		MinTTL:     60,
		MaxTTL:     3600,
		DefaultTTL: 300,
	}
	c := cache.New(cacheCfg)

	server := NewServer(cfg, nil, c, nil, nil, nil, nil)
	server.Start()
	time.Sleep(100 * time.Millisecond)

	resp, err := http.Post("http://127.0.0.1:18082/api/v1/cache/flush", "", nil)
	if err != nil {
		t.Fatalf("Failed to flush cache: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if result["message"] != "Cache flushed" {
		t.Errorf("Expected 'Cache flushed' message, got %v", result["message"])
	}

	server.Stop()
}

func TestAPIAuth(t *testing.T) {
	cfg := config.HTTPConfig{
		Enabled:   true,
		Bind:      "127.0.0.1:18083",
		AuthToken: "test-token-123",
	}

	server := NewServer(cfg, nil, nil, nil, nil, nil, nil)
	server.Start()
	time.Sleep(100 * time.Millisecond)

	// Test without auth
	resp, err := http.Get("http://127.0.0.1:18083/api/v1/status")
	if err != nil {
		t.Fatalf("Failed to request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", resp.StatusCode)
	}

	// Test with auth header
	req, _ := http.NewRequest("GET", "http://127.0.0.1:18083/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer test-token-123")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 with auth, got %d", resp.StatusCode)
	}

	// Test with query param
	resp, err = http.Get("http://127.0.0.1:18083/api/v1/status?token=test-token-123")
	if err != nil {
		t.Fatalf("Failed to request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 with token param, got %d", resp.StatusCode)
	}

	server.Stop()
}

func TestAPIDisabled(t *testing.T) {
	cfg := config.HTTPConfig{
		Enabled: false,
		Bind:    "127.0.0.1:18084",
	}

	server := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	if err := server.Start(); err != nil {
		t.Errorf("Start should not fail when disabled: %v", err)
	}

	if err := server.Stop(); err != nil {
		t.Errorf("Stop should not fail when disabled: %v", err)
	}
}
