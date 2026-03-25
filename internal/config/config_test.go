package config

import (
	"os"
	"reflect"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Server defaults
	if len(cfg.Server.Bind) != 2 || cfg.Server.Bind[0] != "0.0.0.0" || cfg.Server.Bind[1] != "::" {
		t.Errorf("unexpected bind: %v", cfg.Server.Bind)
	}
	if cfg.Server.Port != 53 {
		t.Errorf("expected port 53, got %d", cfg.Server.Port)
	}
	if cfg.Server.UDPWorkers != 0 {
		t.Errorf("expected UDPWorkers 0, got %d", cfg.Server.UDPWorkers)
	}
	if cfg.Server.TCPWorkers != 0 {
		t.Errorf("expected TCPWorkers 0, got %d", cfg.Server.TCPWorkers)
	}

	// Upstream defaults
	if len(cfg.Upstream.Servers) != 2 {
		t.Errorf("expected 2 upstream servers, got %d", len(cfg.Upstream.Servers))
	}
	if cfg.Upstream.Strategy != "random" {
		t.Errorf("expected strategy 'random', got %q", cfg.Upstream.Strategy)
	}

	// Cache defaults
	if !cfg.Cache.Enabled {
		t.Error("expected cache to be enabled by default")
	}
	if cfg.Cache.Size != 10000 {
		t.Errorf("expected cache size 10000, got %d", cfg.Cache.Size)
	}
	if cfg.Cache.DefaultTTL != 300 {
		t.Errorf("expected default TTL 300, got %d", cfg.Cache.DefaultTTL)
	}

	// Logging defaults
	if cfg.Logging.Level != "info" {
		t.Errorf("expected level 'info', got %q", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "text" {
		t.Errorf("expected format 'text', got %q", cfg.Logging.Format)
	}

	// Metrics defaults
	if cfg.Metrics.Enabled {
		t.Error("expected metrics to be disabled by default")
	}

	// DNSSEC defaults
	if cfg.DNSSEC.Enabled {
		t.Error("expected DNSSEC to be disabled by default")
	}
}

func TestUnmarshalYAMLBasic(t *testing.T) {
	input := `
server:
  port: 5353
  bind:
    - 127.0.0.1
upstream:
  strategy: round_robin
  servers:
    - 1.1.1.1:53
    - 8.8.8.8:53
`

	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Server.Port != 5353 {
		t.Errorf("expected port 5353, got %d", cfg.Server.Port)
	}

	if len(cfg.Server.Bind) != 1 || cfg.Server.Bind[0] != "127.0.0.1" {
		t.Errorf("unexpected bind: %v", cfg.Server.Bind)
	}

	if cfg.Upstream.Strategy != "round_robin" {
		t.Errorf("expected strategy 'round_robin', got %q", cfg.Upstream.Strategy)
	}

	if len(cfg.Upstream.Servers) != 2 {
		t.Errorf("expected 2 servers, got %d", len(cfg.Upstream.Servers))
	}
}

func TestUnmarshalYAMLCache(t *testing.T) {
	input := `
cache:
  enabled: false
  size: 5000
  default_ttl: 600
  min_ttl: 10
  max_ttl: 3600
  negative_ttl: 120
  prefetch: true
  prefetch_threshold: 30
`

	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Cache.Enabled {
		t.Error("expected cache to be disabled")
	}
	if cfg.Cache.Size != 5000 {
		t.Errorf("expected size 5000, got %d", cfg.Cache.Size)
	}
	if cfg.Cache.DefaultTTL != 600 {
		t.Errorf("expected default_ttl 600, got %d", cfg.Cache.DefaultTTL)
	}
	if cfg.Cache.MinTTL != 10 {
		t.Errorf("expected min_ttl 10, got %d", cfg.Cache.MinTTL)
	}
	if cfg.Cache.MaxTTL != 3600 {
		t.Errorf("expected max_ttl 3600, got %d", cfg.Cache.MaxTTL)
	}
	if cfg.Cache.NegativeTTL != 120 {
		t.Errorf("expected negative_ttl 120, got %d", cfg.Cache.NegativeTTL)
	}
	if !cfg.Cache.Prefetch {
		t.Error("expected prefetch to be enabled")
	}
	if cfg.Cache.PrefetchThreshold != 30 {
		t.Errorf("expected prefetch_threshold 30, got %d", cfg.Cache.PrefetchThreshold)
	}
}

func TestUnmarshalYAMLLogging(t *testing.T) {
	input := `
logging:
  level: debug
  format: json
  output: /var/log/dns.log
  query_log: true
  query_log_file: /var/log/queries.log
`

	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Logging.Level != "debug" {
		t.Errorf("expected level 'debug', got %q", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("expected format 'json', got %q", cfg.Logging.Format)
	}
	if cfg.Logging.Output != "/var/log/dns.log" {
		t.Errorf("expected output '/var/log/dns.log', got %q", cfg.Logging.Output)
	}
	if !cfg.Logging.QueryLog {
		t.Error("expected query_log to be true")
	}
	if cfg.Logging.QueryLogFile != "/var/log/queries.log" {
		t.Errorf("expected query_log_file '/var/log/queries.log', got %q", cfg.Logging.QueryLogFile)
	}
}

func TestUnmarshalYAMLACL(t *testing.T) {
	input := `
acl:
  - name: local
    networks:
      - "127.0.0.1/32"
      - "10.0.0.0/8"
    types:
      - A
      - AAAA
    action: allow
  - name: block-external
    networks:
      - "0.0.0.0/0"
    types:
      - AXFR
    action: deny
  - name: redirect-ads
    networks:
      - "0.0.0.0/0"
    action: redirect
    redirect: "0.0.0.0"
`

	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.ACL) != 3 {
		t.Fatalf("expected 3 ACL rules, got %d", len(cfg.ACL))
	}

	// First rule
	if cfg.ACL[0].Name != "local" {
		t.Errorf("expected name 'local', got %q", cfg.ACL[0].Name)
	}
	if len(cfg.ACL[0].Networks) != 2 {
		t.Errorf("expected 2 networks, got %d", len(cfg.ACL[0].Networks))
	}
	if cfg.ACL[0].Action != "allow" {
		t.Errorf("expected action 'allow', got %q", cfg.ACL[0].Action)
	}

	// Second rule
	if cfg.ACL[1].Name != "block-external" {
		t.Errorf("expected name 'block-external', got %q", cfg.ACL[1].Name)
	}
	if cfg.ACL[1].Action != "deny" {
		t.Errorf("expected action 'deny', got %q", cfg.ACL[1].Action)
	}

	// Third rule
	if cfg.ACL[2].Action != "redirect" {
		t.Errorf("expected action 'redirect', got %q", cfg.ACL[2].Action)
	}
	if cfg.ACL[2].Redirect != "0.0.0.0" {
		t.Errorf("expected redirect '0.0.0.0', got %q", cfg.ACL[2].Redirect)
	}
}

func TestUnmarshalYAMLZones(t *testing.T) {
	input := `
zones:
  - /etc/dns/zones/example.com.zone
  - /etc/dns/zones/local.zone
`

	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Zones) != 2 {
		t.Errorf("expected 2 zones, got %d", len(cfg.Zones))
	}

	expected := []string{
		"/etc/dns/zones/example.com.zone",
		"/etc/dns/zones/local.zone",
	}
	if !reflect.DeepEqual(cfg.Zones, expected) {
		t.Errorf("unexpected zones: %v", cfg.Zones)
	}
}

func TestUnmarshalYAMLWithEnvVars(t *testing.T) {
	// Set environment variables
	os.Setenv("DNS_PORT", "5353")
	os.Setenv("DNS_BIND", "127.0.0.1")
	defer os.Unsetenv("DNS_PORT")
	defer os.Unsetenv("DNS_BIND")

	input := `
server:
  port: ${DNS_PORT}
  bind:
    - $DNS_BIND
`

	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The values are expanded as strings during YAML parsing,
	// but numeric fields need to parse correctly
	if cfg.Server.Port != 5353 {
		t.Errorf("expected port 5353, got %d", cfg.Server.Port)
	}

	if len(cfg.Server.Bind) != 1 || cfg.Server.Bind[0] != "127.0.0.1" {
		t.Errorf("unexpected bind: %v", cfg.Server.Bind)
	}
}

func TestUnmarshalYAMLPartial(t *testing.T) {
	// Test that partial configs merge with defaults
	input := `
server:
  port: 5353
`

	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Custom value
	if cfg.Server.Port != 5353 {
		t.Errorf("expected port 5353, got %d", cfg.Server.Port)
	}

	// Default values should still be present
	if len(cfg.Upstream.Servers) != 2 {
		t.Errorf("expected default upstream servers, got %d", len(cfg.Upstream.Servers))
	}

	if cfg.Cache.Size != 10000 {
		t.Errorf("expected default cache size, got %d", cfg.Cache.Size)
	}
}

func TestUnmarshalYAMLInvalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "invalid indentation",
			input: "server:\n    port: 53\n  bind: 0.0.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalYAML(tt.input)
			if err == nil {
				t.Error("expected an error but got none")
			}
		})
	}
}

func TestExpandEnvVars(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		input    string
		expected string
	}{
		{
			name:     "no expansion",
			input:    "hello world",
			expected: "hello world",
		},
		{
			name:     "braced variable",
			env:      map[string]string{"FOO": "bar"},
			input:    "hello ${FOO}",
			expected: "hello bar",
		},
		{
			name:     "unbraced variable",
			env:      map[string]string{"FOO": "bar"},
			input:    "hello $FOO",
			expected: "hello bar",
		},
		{
			name:     "multiple variables",
			env:      map[string]string{"A": "1", "B": "2"},
			input:    "${A} and ${B}",
			expected: "1 and 2",
		},
		{
			name:     "undefined variable",
			input:    "hello ${UNDEFINED}",
			expected: "hello ",
		},
		{
			name:     "variable with underscore",
			env:      map[string]string{"MY_VAR": "value"},
			input:    "$MY_VAR",
			expected: "value",
		},
		{
			name:     "mixed content",
			env:      map[string]string{"PORT": "8080"},
			input:    "bind: :${PORT}",
			expected: "bind: :8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			for k, v := range tt.env {
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}

			result := expandEnvVars(tt.input)
			if result != tt.expected {
				t.Errorf("expandEnvVars(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
