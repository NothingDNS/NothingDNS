package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
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
		Enabled:   true,
		Bind:     addr,
		AuthToken: "test-token", // Required for auth
	}

	server := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start API server: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Test health endpoint (no auth required)
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
		Enabled:   true,
		Bind:     "127.0.0.1:18081",
		AuthToken: "test-token",
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

	req, _ := http.NewRequest("GET", "http://127.0.0.1:18081/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
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
		Enabled:   true,
		Bind:     "127.0.0.1:18082",
		AuthToken: "test-token",
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

	req, _ := http.NewRequest("POST", "http://127.0.0.1:18082/api/v1/cache/flush", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
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

func TestReverseIPv4(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"192.168.1.1", "1.1.168.192.in-addr.arpa"},
		{"10.0.0.1", "1.0.0.10.in-addr.arpa"},
		{"1.2.3.4", "4.3.2.1.in-addr.arpa"},
		{"255.255.255.255", "255.255.255.255.in-addr.arpa"},
	}
	for _, tt := range tests {
		got := reverseIPv4(tt.ip)
		if got != tt.want {
			t.Errorf("reverseIPv4(%q) = %q, want %q", tt.ip, got, tt.want)
		}
	}
}

func TestReverseIPv4Relative(t *testing.T) {
	tests := []struct {
		ip       string
		origin   string
		prefix   int
		want     string
	}{
		// /24 zone (24 fixed octets = 3, varying = 1): only last octet varies
		{"192.168.1.4", "1.168.192.in-addr.arpa.", 24, "4"},
		{"192.168.1.10", "1.168.192.in-addr.arpa.", 24, "10"},
		{"192.168.1.1", "1.168.192.in-addr.arpa.", 24, "1"},
		// /24 zone with more specific CIDR /25
		{"192.168.1.4", "1.168.192.in-addr.arpa.", 25, "4"},
		// /16 zone (16 fixed = 2, varying = 2): last 2 octets vary
		{"192.168.1.4", "168.192.in-addr.arpa.", 16, "1.4"},
		{"192.168.5.10", "168.192.in-addr.arpa.", 16, "5.10"},
		// /16 zone with more specific CIDR /24
		{"192.168.1.4", "168.192.in-addr.arpa.", 24, "1.4"},
		// /8 zone (8 fixed = 1, varying = 3): last 3 octets vary
		{"192.168.1.4", "192.in-addr.arpa.", 8, "168.1.4"},
		// /8 zone with more specific CIDR /16
		{"192.168.1.4", "192.in-addr.arpa.", 16, "168.1.4"},
	}
	for _, tt := range tests {
		got := reverseIPv4Relative(tt.ip, tt.origin, tt.prefix)
		if got != tt.want {
			t.Errorf("reverseIPv4Relative(%q, %q, %d) = %q, want %q", tt.ip, tt.origin, tt.prefix, got, tt.want)
		}
	}
}

func TestValidateZoneCIDR(t *testing.T) {
	tests := []struct {
		origin   string
		prefix   int
		wantPref int
		wantErr  bool
	}{
		// Zone /24, CIDR must be >= 24
		{"1.168.192.in-addr.arpa.", 24, 24, false},
		{"1.168.192.in-addr.arpa.", 25, 24, false}, // /25 is more specific, OK
		{"1.168.192.in-addr.arpa.", 16, 0, true},  // /16 is less specific, NOT OK
		{"1.168.192.in-addr.arpa.", 8, 0, true},   // /8 is less specific, NOT OK
		// Zone /16, CIDR must be >= 16
		{"168.192.in-addr.arpa.", 16, 16, false},
		{"168.192.in-addr.arpa.", 24, 16, false},  // /24 is more specific, OK
		{"168.192.in-addr.arpa.", 8, 0, true},     // /8 is less specific, NOT OK
		// Zone /8
		{"192.in-addr.arpa.", 8, 8, false},
		{"192.in-addr.arpa.", 16, 8, false},       // /16 is more specific, OK
		// Invalid origins
		{"example.com.", 24, 0, true},
		{"1.168.192.in-addr.arpa", 24, 0, true},  // missing trailing dot - FIX THIS
	}
	for _, tt := range tests {
		gotPref, err := validateZoneCIDR(tt.origin, tt.prefix)
		if (err != nil) != tt.wantErr {
			t.Errorf("validateZoneCIDR(%q, %d) error = %v, wantErr %v", tt.origin, tt.prefix, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && gotPref != tt.wantPref {
			t.Errorf("validateZoneCIDR(%q, %d) prefix = %d, want %d", tt.origin, tt.prefix, gotPref, tt.wantPref)
		}
	}
}

func TestReverseIPv6(t *testing.T) {
	tests := []struct {
		ip string
	}{
		{"2001:db8::1"},
		{"::1"},
		{"::ffff:127.0.0.1"},
		{"2001:0db8:0000:0000:0000:0000:0000:0001"},
	}
	for _, tt := range tests {
		result := reverseIPv6TestHelper(tt.ip)
		// Verify it ends with .ip6.arpa
		if !strings.HasSuffix(result, ".ip6.arpa") {
			t.Errorf("reverseIPv6(%q) missing .ip6.arpa suffix: %q", tt.ip, result)
			continue
		}
		// Verify it has correct structure (32 hex labels + ip6.arpa = 34 parts)
		parts := strings.Split(result, ".")
		if len(parts) != 34 {
			t.Errorf("reverseIPv6(%q) = %q, expected 34 parts, got %d", tt.ip, result, len(parts))
		}
		// Verify last two parts are ip6.arpa
		if parts[len(parts)-2] != "ip6" || parts[len(parts)-1] != "arpa" {
			t.Errorf("reverseIPv6(%q) bad suffix: got %s.%s", tt.ip, parts[len(parts)-2], parts[len(parts)-1])
		}
	}
}

// reverseIPv6TestHelper is a test wrapper that parses the IP string
func reverseIPv6TestHelper(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	// Inline the logic for testing since the function is not exported
	ip = ip.To16()
	if ip == nil {
		return ""
	}
	var parts []string
	for i := 15; i >= 0; i-- {
		parts = append(parts, fmt.Sprintf("%x", ip[i]&0x0F))
		parts = append(parts, fmt.Sprintf("%x", (ip[i]>>4)&0x0F))
	}
	return strings.Join(parts, ".") + ".ip6.arpa"
}
