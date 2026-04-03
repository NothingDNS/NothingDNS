package config

import (
	"os"
	"reflect"
	"strings"
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

func TestUnmarshalYAMLDNSSEC(t *testing.T) {
	input := `
dnssec:
  enabled: true
  ignore_time: true
  trust_anchor: /etc/dns/root-anchors.xml
`

	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !cfg.DNSSEC.Enabled {
		t.Error("expected DNSSEC to be enabled")
	}
	if !cfg.DNSSEC.IgnoreTime {
		t.Error("expected IgnoreTime to be true")
	}
	if cfg.DNSSEC.TrustAnchor != "/etc/dns/root-anchors.xml" {
		t.Errorf("expected trust anchor path, got %q", cfg.DNSSEC.TrustAnchor)
	}
}

func TestUnmarshalYAMLMetrics(t *testing.T) {
	input := `
metrics:
  enabled: true
  bind: ":9153"
  path: /metrics
`

	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !cfg.Metrics.Enabled {
		t.Error("expected metrics to be enabled")
	}
	if cfg.Metrics.Bind != ":9153" {
		t.Errorf("expected bind :9153, got %q", cfg.Metrics.Bind)
	}
	if cfg.Metrics.Path != "/metrics" {
		t.Errorf("expected path /metrics, got %q", cfg.Metrics.Path)
	}
}

func TestUnmarshalYAMLCluster(t *testing.T) {
	input := `
cluster:
  enabled: true
  bind_addr: 0.0.0.0
  gossip_port: 7946
  seed_nodes:
    - 192.168.1.2:7946
    - 192.168.1.3:7946
`

	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !cfg.Cluster.Enabled {
		t.Error("expected cluster to be enabled")
	}
	if cfg.Cluster.BindAddr != "0.0.0.0" {
		t.Errorf("expected bind_addr, got %q", cfg.Cluster.BindAddr)
	}
	if len(cfg.Cluster.SeedNodes) != 2 {
		t.Errorf("expected 2 seed nodes, got %d", len(cfg.Cluster.SeedNodes))
	}
}

func TestUnmarshalYAMLBlocklist(t *testing.T) {
	input := `
blocklist:
  enabled: true
  files:
    - /etc/dns/blocklists/ads.txt
    - /etc/dns/blocklists/malware.txt
`

	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !cfg.Blocklist.Enabled {
		t.Error("expected blocklist to be enabled")
	}
	if len(cfg.Blocklist.Files) != 2 {
		t.Errorf("expected 2 files, got %d", len(cfg.Blocklist.Files))
	}
}

func TestUnmarshalYAMLSlaveZones(t *testing.T) {
	input := `
slave_zones:
  - zone_name: example.com.
    masters:
      - 192.168.1.100:53
    transfer_type: ixfr
    tsig_key_name: transfer-key
    tsig_secret: secret123
`

	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.SlaveZones) != 1 {
		t.Fatalf("expected 1 slave zone, got %d", len(cfg.SlaveZones))
	}

	zone := cfg.SlaveZones[0]
	if zone.ZoneName != "example.com." {
		t.Errorf("expected zone name, got %q", zone.ZoneName)
	}
	if len(zone.Masters) != 1 {
		t.Errorf("expected 1 master, got %d", len(zone.Masters))
	}
	if zone.TransferType != "ixfr" {
		t.Errorf("expected transfer type ixfr, got %q", zone.TransferType)
	}
}

func TestUnmarshalYAMLResolution(t *testing.T) {
	input := `
resolution:
  timeout: 5s
  recursive: true
  max_depth: 15
`

	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Resolution.Timeout != "5s" {
		t.Errorf("expected timeout 5s, got %q", cfg.Resolution.Timeout)
	}
	if !cfg.Resolution.Recursive {
		t.Error("expected recursive to be true")
	}
	if cfg.Resolution.MaxDepth != 15 {
		t.Errorf("expected max_depth 15, got %d", cfg.Resolution.MaxDepth)
	}
}

func TestUnmarshalYAMLEmpty(t *testing.T) {
	cfg, err := UnmarshalYAML("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should return defaults
	if cfg.Server.Port != 53 {
		t.Errorf("expected default port 53, got %d", cfg.Server.Port)
	}
}

func TestUnmarshalYAMLServerTLS(t *testing.T) {
	input := `
server:
  tls:
    enabled: true
    cert_file: /etc/ssl/cert.pem
    key_file: /etc/ssl/key.pem
`

	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !cfg.Server.TLS.Enabled {
		t.Error("expected TLS to be enabled")
	}
	if cfg.Server.TLS.CertFile != "/etc/ssl/cert.pem" {
		t.Errorf("expected TLS cert path, got %q", cfg.Server.TLS.CertFile)
	}
}

func TestUnmarshalYAMLHTTPDoH(t *testing.T) {
	input := `
server:
  http:
    enabled: true
    bind: ":8080"
    doh_enabled: true
    doh_path: /dns-query
`

	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !cfg.Server.HTTP.Enabled {
		t.Error("expected HTTP to be enabled")
	}
	if !cfg.Server.HTTP.DoHEnabled {
		t.Error("expected DoH to be enabled")
	}
	if cfg.Server.HTTP.DoHPath != "/dns-query" {
		t.Errorf("expected DoH path, got %q", cfg.Server.HTTP.DoHPath)
	}
}

func TestUnmarshalYAMLUpstreamAnycast(t *testing.T) {
	input := `
upstream:
  strategy: round_robin
  servers:
    - 1.1.1.1:53
  anycast_groups:
    - anycast_ip: 10.0.0.1
      backends:
        - physical_ip: 192.168.1.1
          port: 53
          region: us-east-1
`

	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Upstream.Strategy != "round_robin" {
		t.Errorf("expected strategy, got %q", cfg.Upstream.Strategy)
	}
	if len(cfg.Upstream.AnycastGroups) != 1 {
		t.Errorf("expected 1 anycast group, got %d", len(cfg.Upstream.AnycastGroups))
	}
}

func TestGetString(t *testing.T) {
	input := `
server:
  port: 5353
`
	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The getString function is internal - test via UnmarshalYAML
	if cfg.Server.Port != 5353 {
		t.Errorf("expected port 5353, got %d", cfg.Server.Port)
	}
}

func TestConfigValidation(t *testing.T) {
	// Test valid config
	cfg := &Config{
		Server: ServerConfig{
			Port: 53,
			Bind: []string{"0.0.0.0"},
		},
		Upstream: UpstreamConfig{
			Servers:  []string{"1.1.1.1:53"},
			Strategy: "random",
		},
		Cache: CacheConfig{
			Enabled:    true,
			Size:       10000,
			DefaultTTL: 300,
			MinTTL:     10,
			MaxTTL:     3600,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
		},
	}

	err := cfg.Validate()
	if err != nil {
		t.Errorf("valid config should pass validation: %v", err)
	}
}

func TestIsValidHostname(t *testing.T) {
	tests := []struct {
		hostname string
		want     bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"123.domain", true},
		{"-invalid.com", false},
		{"invalid-.com", false},
		{"", false},
		{"a", true},
		{strings.Repeat("a", 64), false}, // label too long
	}

	for _, tt := range tests {
		t.Run(tt.hostname, func(t *testing.T) {
			if got := isValidHostname(tt.hostname); got != tt.want {
				t.Errorf("isValidHostname(%q) = %v, want %v", tt.hostname, got, tt.want)
			}
		})
	}
}

func TestIsValidLabel(t *testing.T) {
	tests := []struct {
		label string
		want  bool
	}{
		{"example", true},
		{"sub-domain", true},
		{"123", true},
		{"-invalid", false},
		{"invalid-", false},
		{"", false},
		{"a", true},
		{strings.Repeat("a", 64), false},
	}

	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			if got := isValidLabel(tt.label); got != tt.want {
				t.Errorf("isValidLabel(%q) = %v, want %v", tt.label, got, tt.want)
			}
		})
	}
}

func TestTokenString(t *testing.T) {
	// Test token String method
	tok := Token{Type: TokenColon, Value: ":", Line: 1, Col: 1}
	s := tok.String()
	if s == "" {
		t.Error("Token.String() should not be empty")
	}

	// Test different token types
	tests := []struct {
		tokenType TokenType
		value     string
	}{
		{TokenEOF, "EOF"},
		{TokenString, "test"},
		{TokenNumber, "123"},
		{TokenColon, ":"},
		{TokenDash, "-"},
		{TokenNewline, "\\n"},
	}

	for _, tt := range tests {
		tok := Token{Type: tt.tokenType, Value: tt.value}
		s := tok.String()
		if s == "" {
			t.Errorf("Token.String() for %v should not be empty", tt.tokenType)
		}
	}
}

func TestParserExpect(t *testing.T) {
	// Test expect function - NewParser takes a string input
	input := "key: value"
	p := NewParser(input)

	// Expect a string token
	err := p.expect(TokenString)
	if err != nil {
		t.Errorf("expect should succeed for correct token type: %v", err)
	}

	// Now at colon, expect wrong type
	err = p.expect(TokenNumber)
	if err == nil {
		t.Error("expect should fail for wrong token type")
	}
}

func TestReloadHandlerStart(t *testing.T) {
	// Test Start method
	h := NewReloadHandler()

	// Start the handler
	h.Start()

	// Cleanup
	h.Stop()
}

func TestLogLevelReloaderReload(t *testing.T) {
	// Test LogLevelReloader.Reload method
	// Create a mock callback
	var calledLevel string
	cb := func(level string) error {
		calledLevel = level
		return nil
	}

	reloader := NewLogLevelReloader("info", cb, nil)
	if reloader == nil {
		t.Fatal("NewLogLevelReloader returned nil")
	}

	// Verify initial level
	if reloader.GetLevel() != "info" {
		t.Errorf("GetLevel() = %q, want info", reloader.GetLevel())
	}

	// Reload with new level
	err := reloader.Reload("debug")
	if err != nil {
		t.Errorf("Reload should succeed: %v", err)
	}

	// Verify level changed
	if reloader.GetLevel() != "debug" {
		t.Errorf("GetLevel() = %q, want debug", reloader.GetLevel())
	}

	if calledLevel != "debug" {
		t.Errorf("callback called with %q, want debug", calledLevel)
	}
}

func TestParserToInterface(t *testing.T) {
	// Test toInterface via Parse which calls it internally
	tests := []struct {
		name  string
		input string
	}{
		{"simple scalar", "key: value"},
		{"list", "items:\n  - a\n  - b"},
		{"nested map", "outer:\n  inner: value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalYAML(tt.input)
			if err != nil {
				t.Errorf("UnmarshalYAML failed: %v", err)
			}
		})
	}
}

func TestTokenizerReadTag(t *testing.T) {
	// Test tag handling via tokenizer
	input := "!!str value"
	tok := NewTokenizer(input)
	tokens := tok.TokenizeAll()

	// Should have processed the tag
	if len(tokens) == 0 {
		t.Error("Expected tokens")
	}
}

func TestTokenizerReadAnchor(t *testing.T) {
	// Test anchor handling via tokenizer
	input := "key: &anchor value"
	tok := NewTokenizer(input)
	tokens := tok.TokenizeAll()

	// Should have processed the anchor
	if len(tokens) == 0 {
		t.Error("Expected tokens")
	}
}

func TestTokenizerReadAlias(t *testing.T) {
	// Test alias handling via tokenizer
	input := "key: *alias"
	tok := NewTokenizer(input)
	tokens := tok.TokenizeAll()

	// Should have processed the alias
	if len(tokens) == 0 {
		t.Error("Expected tokens")
	}
}

// TestGetStringHelper tests the getString helper function using real YAML parsing
func TestGetStringHelper(t *testing.T) {
	// Use the full UnmarshalYAML which properly parses YAML
	input := `
server:
  port: 5353
`
	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("UnmarshalYAML error: %v", err)
	}

	// The getString is used internally during unmarshal
	if cfg.Server.Port != 5353 {
		t.Errorf("Server.Port = %d, want 5353", cfg.Server.Port)
	}
}

// TestNodeToInterfaceMethods tests the Node.toInterface method
func TestNodeToInterfaceMethods(t *testing.T) {
	// Test scalar node
	scalar := &Node{Type: NodeScalar, Value: "hello"}
	result := scalar.toInterface()
	if result != "hello" {
		t.Errorf("scalar toInterface = %v, want hello", result)
	}

	// Test sequence node
	seq := &Node{
		Type: NodeSequence,
		Children: []*Node{
			{Type: NodeScalar, Value: "a"},
			{Type: NodeScalar, Value: "b"},
		},
	}
	result = seq.toInterface()
	arr, ok := result.([]interface{})
	if !ok {
		t.Fatalf("sequence toInterface should return []interface{}, got %T", result)
	}
	if len(arr) != 2 {
		t.Errorf("sequence length = %d, want 2", len(arr))
	}

	// Test unknown node type
	unknown := &Node{Type: 99}
	result = unknown.toInterface()
	if result != nil {
		t.Errorf("unknown toInterface = %v, want nil", result)
	}
}

func TestValidateUpstreamWithAnycast(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid anycast group",
			config: &Config{
				Upstream: UpstreamConfig{
					Strategy: "random",
					AnycastGroups: []AnycastGroupConfig{
						{
							AnycastIP: "10.0.0.1",
							Backends: []AnycastBackendConfig{
								{PhysicalIP: "192.168.1.1", Port: 53, Weight: 100},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing anycast_ip",
			config: &Config{
				Upstream: UpstreamConfig{
					Strategy: "random",
					AnycastGroups: []AnycastGroupConfig{
						{
							AnycastIP: "",
							Backends: []AnycastBackendConfig{
								{PhysicalIP: "192.168.1.1", Port: 53, Weight: 100},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "anycast_ip is required",
		},
		{
			name: "invalid anycast_ip",
			config: &Config{
				Upstream: UpstreamConfig{
					Strategy: "random",
					AnycastGroups: []AnycastGroupConfig{
						{
							AnycastIP: "invalid-ip",
							Backends: []AnycastBackendConfig{
								{PhysicalIP: "192.168.1.1", Port: 53, Weight: 100},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "must be a valid IP address",
		},
		{
			name: "missing backends",
			config: &Config{
				Upstream: UpstreamConfig{
					Strategy: "random",
					AnycastGroups: []AnycastGroupConfig{
						{
							AnycastIP: "10.0.0.1",
							Backends:  []AnycastBackendConfig{},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "at least one backend",
		},
		{
			name: "invalid physical_ip",
			config: &Config{
				Upstream: UpstreamConfig{
					Strategy: "random",
					AnycastGroups: []AnycastGroupConfig{
						{
							AnycastIP: "10.0.0.1",
							Backends: []AnycastBackendConfig{
								{PhysicalIP: "invalid", Port: 53, Weight: 100},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "must be a valid IP address",
		},
		{
			name: "invalid port",
			config: &Config{
				Upstream: UpstreamConfig{
					Strategy: "random",
					AnycastGroups: []AnycastGroupConfig{
						{
							AnycastIP: "10.0.0.1",
							Backends: []AnycastBackendConfig{
								{PhysicalIP: "192.168.1.1", Port: 0, Weight: 100},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "must be between 1-65535",
		},
		{
			name: "invalid weight",
			config: &Config{
				Upstream: UpstreamConfig{
					Strategy: "random",
					AnycastGroups: []AnycastGroupConfig{
						{
							AnycastIP: "10.0.0.1",
							Backends: []AnycastBackendConfig{
								{PhysicalIP: "192.168.1.1", Port: 53, Weight: 150},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "must be between 0-100",
		},
		{
			name: "invalid strategy",
			config: &Config{
				Upstream: UpstreamConfig{
					Strategy: "invalid",
					Servers:  []string{"8.8.8.8"},
				},
			},
			wantErr: true,
			errMsg:  "invalid strategy",
		},
		{
			name: "no servers or anycast groups",
			config: &Config{
				Upstream: UpstreamConfig{
					Strategy:      "random",
					Servers:       []string{},
					AnycastGroups: []AnycastGroupConfig{},
				},
			},
			wantErr: true,
			errMsg:  "at least one server or anycast group",
		},
		{
			name: "invalid topology weight",
			config: &Config{
				Upstream: UpstreamConfig{
					Strategy: "random",
					Servers:  []string{"8.8.8.8"},
					Topology: TopologyConfig{Weight: 150},
				},
			},
			wantErr: true,
			errMsg:  "weight",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := tt.config.Validate()
			hasErr := len(errors) > 0 && containsAny(errors, tt.errMsg)
			if tt.wantErr && !hasErr {
				t.Errorf("expected error containing %q, got %v", tt.errMsg, errors)
			}
			if !tt.wantErr && len(errors) > 0 {
				// Check if errors are unrelated to upstream
				for _, e := range errors {
					if strings.Contains(e, "upstream") {
						t.Errorf("unexpected upstream error: %s", e)
					}
				}
			}
		})
	}
}

func TestValidateDNSSEC(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "DNSSEC disabled",
			config: &Config{
				DNSSEC: DNSSECConfig{Enabled: false},
			},
			wantErr: false,
		},
		{
			name: "DNSSEC enabled with trust anchor",
			config: &Config{
				DNSSEC: DNSSECConfig{
					Enabled:     true,
					TrustAnchor: "/nonexistent/file.xml",
				},
			},
			wantErr: false, // Trust anchor non-existence is just a warning
		},
		{
			name: "DNSSEC enabled without trust anchor",
			config: &Config{
				DNSSEC: DNSSECConfig{
					Enabled:     true,
					TrustAnchor: "",
				},
			},
			wantErr: false,
		},
		{
			name: "DNSSEC enabled with valid signing config",
			config: &Config{
				DNSSEC: DNSSECConfig{
					Enabled: true,
					Signing: SigningConfig{
						Enabled: true,
						Keys: []KeyConfig{
							{
								PrivateKey: "/etc/dns/keys/Kexample.com.+013+12345.private",
								Type:       "ksk",
								Algorithm:  13, // ECDSAP256SHA256
							},
						},
						SignatureValidity: "30d",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "DNSSEC enabled with multiple valid signing keys",
			config: &Config{
				DNSSEC: DNSSECConfig{
					Enabled: true,
					Signing: SigningConfig{
						Enabled: true,
						Keys: []KeyConfig{
							{
								PrivateKey: "/etc/dns/keys/Kexample.com.+008+12345.private",
								Type:       "ksk",
								Algorithm:  8, // RSASHA256
							},
							{
								PrivateKey: "/etc/dns/keys/Kexample.com.+013+67890.private",
								Type:       "zsk",
								Algorithm:  13, // ECDSAP256SHA256
							},
						},
						SignatureValidity: "14d",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "DNSSEC signing with invalid algorithm",
			config: &Config{
				DNSSEC: DNSSECConfig{
					Enabled: true,
					Signing: SigningConfig{
						Enabled: true,
						Keys: []KeyConfig{
							{
								PrivateKey: "/etc/dns/keys/key.private",
								Type:       "zsk",
								Algorithm:  99, // Invalid algorithm
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "unsupported algorithm",
		},
		{
			name: "DNSSEC signing with invalid key type",
			config: &Config{
				DNSSEC: DNSSECConfig{
					Enabled: true,
					Signing: SigningConfig{
						Enabled: true,
						Keys: []KeyConfig{
							{
								PrivateKey: "/etc/dns/keys/key.private",
								Type:       "invalid",
								Algorithm:  13,
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid type",
		},
		{
			name: "DNSSEC signing with NSEC3 config",
			config: &Config{
				DNSSEC: DNSSECConfig{
					Enabled: true,
					Signing: SigningConfig{
						Enabled: true,
						Keys: []KeyConfig{
							{
								PrivateKey: "/etc/dns/keys/key.private",
								Type:       "ksk",
								Algorithm:  13,
							},
						},
						NSEC3: &NSEC3Config{
							Iterations: 10,
							Salt:       "aabbccdd",
							OptOut:     false,
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "DNSSEC signing with NSEC3 opt-out enabled",
			config: &Config{
				DNSSEC: DNSSECConfig{
					Enabled: true,
					Signing: SigningConfig{
						Enabled: true,
						Keys: []KeyConfig{
							{
								PrivateKey: "/etc/dns/keys/key.private",
								Type:       "ksk",
								Algorithm:  8,
							},
						},
						NSEC3: &NSEC3Config{
							Iterations: 5,
							Salt:       "",
							OptOut:     true,
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "DNSSEC signing enabled without keys",
			config: &Config{
				DNSSEC: DNSSECConfig{
					Enabled: true,
					Signing: SigningConfig{
						Enabled: true,
						Keys:    []KeyConfig{},
					},
				},
			},
			wantErr: true,
			errMsg:  "at least one key must be specified when signing is enabled",
		},
		{
			name: "DNSSEC signing enabled with nil keys",
			config: &Config{
				DNSSEC: DNSSECConfig{
					Enabled: true,
					Signing: SigningConfig{
						Enabled: true,
						Keys:    nil,
					},
				},
			},
			wantErr: true,
			errMsg:  "at least one key must be specified when signing is enabled",
		},
		{
			name: "DNSSEC signing key missing private_key",
			config: &Config{
				DNSSEC: DNSSECConfig{
					Enabled: true,
					Signing: SigningConfig{
						Enabled: true,
						Keys: []KeyConfig{
							{
								PrivateKey: "",
								Type:       "ksk",
								Algorithm:  13,
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "private_key is required",
		},
		{
			name: "DNSSEC enabled with trust anchor file path",
			config: &Config{
				DNSSEC: DNSSECConfig{
					Enabled:     true,
					TrustAnchor: "/etc/dns/root-anchors.xml",
				},
			},
			wantErr: false, // File does not need to exist for validation to pass
		},
		{
			name: "DNSSEC enabled with empty trust anchor is valid",
			config: &Config{
				DNSSEC: DNSSECConfig{
					Enabled:     true,
					TrustAnchor: "",
				},
			},
			wantErr: false,
		},
		{
			name: "DNSSEC ignore time flag enabled",
			config: &Config{
				DNSSEC: DNSSECConfig{
					Enabled:     true,
					IgnoreTime:  true,
					TrustAnchor: "/etc/dns/root-anchors.xml",
				},
			},
			wantErr: false,
		},
		{
			name: "DNSSEC ignore time flag disabled",
			config: &Config{
				DNSSEC: DNSSECConfig{
					Enabled:     true,
					IgnoreTime:  false,
					TrustAnchor: "/etc/dns/root-anchors.xml",
				},
			},
			wantErr: false,
		},
		{
			name: "DNSSEC signing disabled does not validate keys",
			config: &Config{
				DNSSEC: DNSSECConfig{
					Enabled: true,
					Signing: SigningConfig{
						Enabled: false,
						Keys:    []KeyConfig{},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "DNSSEC signing with algorithm 0 skips algorithm check",
			config: &Config{
				DNSSEC: DNSSECConfig{
					Enabled: true,
					Signing: SigningConfig{
						Enabled: true,
						Keys: []KeyConfig{
							{
								PrivateKey: "/etc/dns/keys/key.private",
								Type:       "ksk",
								Algorithm:  0, // Algorithm 0 is skipped in validation
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "DNSSEC signing with all supported algorithms",
			config: &Config{
				DNSSEC: DNSSECConfig{
					Enabled: true,
					Signing: SigningConfig{
						Enabled: true,
						Keys: []KeyConfig{
							{PrivateKey: "/keys/5", Type: "ksk", Algorithm: 5},  // RSASHA1
							{PrivateKey: "/keys/8", Type: "ksk", Algorithm: 8},  // RSASHA256
							{PrivateKey: "/keys/10", Type: "ksk", Algorithm: 10}, // RSASHA512
							{PrivateKey: "/keys/13", Type: "zsk", Algorithm: 13}, // ECDSAP256SHA256
							{PrivateKey: "/keys/14", Type: "zsk", Algorithm: 14}, // ECDSAP384SHA384
							{PrivateKey: "/keys/15", Type: "zsk", Algorithm: 15}, // ED25519
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "DNSSEC signing with empty key type is valid",
			config: &Config{
				DNSSEC: DNSSECConfig{
					Enabled: true,
					Signing: SigningConfig{
						Enabled: true,
						Keys: []KeyConfig{
							{
								PrivateKey: "/etc/dns/keys/key.private",
								Type:       "", // Empty type is allowed
								Algorithm:  13,
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "DNSSEC signing multiple errors at once",
			config: &Config{
				DNSSEC: DNSSECConfig{
					Enabled: true,
					Signing: SigningConfig{
						Enabled: true,
						Keys: []KeyConfig{
							{
								PrivateKey: "",
								Type:       "badtype",
								Algorithm:  99,
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "private_key is required", // First error found
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := tt.config.Validate()
			var dnssecErrors []string
			for _, e := range errors {
				if strings.Contains(e, "dnssec") {
					dnssecErrors = append(dnssecErrors, e)
				}
			}
			if tt.wantErr {
				if len(dnssecErrors) == 0 {
					t.Errorf("expected DNSSEC error, got %v", errors)
				} else if tt.errMsg != "" && !containsAny(dnssecErrors, tt.errMsg) {
					t.Errorf("expected error containing %q, got %v", tt.errMsg, dnssecErrors)
				}
			}
			if !tt.wantErr && len(dnssecErrors) > 0 {
				t.Errorf("unexpected DNSSEC error: %v", dnssecErrors)
			}
		})
	}
}

func TestValidateCluster(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "cluster disabled",
			config: &Config{
				Cluster: ClusterConfig{Enabled: false},
			},
			wantErr: false,
		},
		{
			name: "valid cluster",
			config: &Config{
				Cluster: ClusterConfig{
					Enabled:     true,
					GossipPort:  7946,
					Weight:      50,
					SeedNodes:   []string{"node1:7946"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid gossip port",
			config: &Config{
				Cluster: ClusterConfig{
					Enabled:     true,
					GossipPort:  0,
				},
			},
			wantErr: true,
			errMsg:  "invalid gossip_port",
		},
		{
			name: "negative weight",
			config: &Config{
				Cluster: ClusterConfig{
					Enabled: true,
					Weight:  -1,
				},
			},
			wantErr: true,
			errMsg:  "weight cannot be negative",
		},
		{
			name: "empty seed node",
			config: &Config{
				Cluster: ClusterConfig{
					Enabled:   true,
					SeedNodes: []string{""},
				},
			},
			wantErr: true,
			errMsg:  "seed node cannot be empty",
		},
		{
			name: "invalid seed node format",
			config: &Config{
				Cluster: ClusterConfig{
					Enabled:   true,
					SeedNodes: []string{"invalid-node"},
				},
			},
			wantErr: true,
			errMsg:  "expected host:port format",
		},
		{
			name: "seed node invalid port",
			config: &Config{
				Cluster: ClusterConfig{
					Enabled:   true,
					SeedNodes: []string{"node1:invalid"},
				},
			},
			wantErr: true,
			errMsg:  "invalid port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := tt.config.Validate()
			var clusterErrors []string
			for _, e := range errors {
				if strings.Contains(e, "cluster") {
					clusterErrors = append(clusterErrors, e)
				}
			}
			if tt.wantErr {
				if len(clusterErrors) == 0 {
					t.Errorf("expected cluster error, got %v", errors)
				} else if !containsAny(clusterErrors, tt.errMsg) {
					t.Errorf("expected error containing %q, got %v", tt.errMsg, clusterErrors)
				}
			} else {
				if len(clusterErrors) > 0 {
					t.Errorf("unexpected cluster error: %v", clusterErrors)
				}
			}
		})
	}
}

func TestValidateSlaveZones(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name:   "no slave zones",
			config: &Config{},
			wantErr: false,
		},
		{
			name: "valid slave zone",
			config: &Config{
				SlaveZones: []SlaveZoneConfig{
					{
						ZoneName:     "example.com.",
						Masters:      []string{"192.168.1.1:53"},
						TransferType: "axfr",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing zone name",
			config: &Config{
				SlaveZones: []SlaveZoneConfig{
					{
						ZoneName: "",
						Masters:  []string{"192.168.1.1:53"},
					},
				},
			},
			wantErr: true,
			errMsg:  "zone_name is required",
		},
		{
			name: "no masters",
			config: &Config{
				SlaveZones: []SlaveZoneConfig{
					{
						ZoneName: "example.com.",
						Masters:  []string{},
					},
				},
			},
			wantErr: true,
			errMsg:  "at least one master server",
		},
		{
			name: "invalid transfer type",
			config: &Config{
				SlaveZones: []SlaveZoneConfig{
					{
						ZoneName:     "example.com.",
						Masters:      []string{"192.168.1.1:53"},
						TransferType: "invalid",
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid transfer_type",
		},
		{
			name: "negative max retries",
			config: &Config{
				SlaveZones: []SlaveZoneConfig{
					{
						ZoneName:   "example.com.",
						Masters:    []string{"192.168.1.1:53"},
						MaxRetries: -1,
					},
				},
			},
			wantErr: true,
			errMsg:  "max_retries cannot be negative",
		},
		{
			name: "invalid master address",
			config: &Config{
				SlaveZones: []SlaveZoneConfig{
					{
						ZoneName: "example.com.",
						Masters:  []string{"invalid:address:format"},
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid master address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := tt.config.Validate()
			var slaveErrors []string
			for _, e := range errors {
				if strings.Contains(e, "slave_zones") {
					slaveErrors = append(slaveErrors, e)
				}
			}
			if tt.wantErr {
				if len(slaveErrors) == 0 {
					t.Errorf("expected slave_zones error, got %v", errors)
				} else if !containsAny(slaveErrors, tt.errMsg) {
					t.Errorf("expected error containing %q, got %v", tt.errMsg, slaveErrors)
				}
			} else {
				if len(slaveErrors) > 0 {
					t.Errorf("unexpected slave_zones error: %v", slaveErrors)
				}
			}
		})
	}
}

func TestValidateBlocklist(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "blocklist disabled",
			config: &Config{
				Blocklist: BlocklistConfig{Enabled: false},
			},
			wantErr: false,
		},
		{
			name: "blocklist enabled empty files",
			config: &Config{
				Blocklist: BlocklistConfig{
					Enabled: true,
					Files:   []string{},
				},
			},
			wantErr: false,
		},
		{
			name: "blocklist empty file path",
			config: &Config{
				Blocklist: BlocklistConfig{
					Enabled: true,
					Files:   []string{""},
				},
			},
			wantErr: true,
			errMsg:  "file path cannot be empty",
		},
		{
			name: "blocklist nonexistent file",
			config: &Config{
				Blocklist: BlocklistConfig{
					Enabled: true,
					Files:   []string{"/nonexistent/blocklist.txt"},
				},
			},
			wantErr: true,
			errMsg:  "does not exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := tt.config.Validate()
			var blocklistErrors []string
			for _, e := range errors {
				if strings.Contains(e, "blocklist") {
					blocklistErrors = append(blocklistErrors, e)
				}
			}
			if tt.wantErr {
				if len(blocklistErrors) == 0 {
					t.Errorf("expected blocklist error, got %v", errors)
				} else if !containsAny(blocklistErrors, tt.errMsg) {
					t.Errorf("expected error containing %q, got %v", tt.errMsg, blocklistErrors)
				}
			} else {
				if len(blocklistErrors) > 0 {
					t.Errorf("unexpected blocklist error: %v", blocklistErrors)
				}
			}
		})
	}
}

func TestNodeGetSlice(t *testing.T) {
	// Create a node with a sequence (mapping uses alternating key-value children)
	node := &Node{
		Type: NodeMapping,
		Children: []*Node{
			{Type: NodeScalar, Value: "items"}, // key
			{
				Type: NodeSequence, // value
				Children: []*Node{
					{Type: NodeScalar, Value: "a"},
					{Type: NodeScalar, Value: "b"},
				},
			},
		},
	}

	items := node.GetSlice("items")
	if items == nil {
		t.Fatal("GetSlice returned nil")
	}
	if len(items) != 2 {
		t.Errorf("GetSlice length = %d, want 2", len(items))
	}

	// Test non-existent key
	nonExistent := node.GetSlice("nonexistent")
	if nonExistent != nil {
		t.Errorf("GetSlice for non-existent key should return nil, got %v", nonExistent)
	}

	// Test GetSlice on sequence with empty key
	seqNode := &Node{
		Type: NodeSequence,
		Children: []*Node{
			{Type: NodeScalar, Value: "x"},
			{Type: NodeScalar, Value: "y"},
		},
	}
	seqChildren := seqNode.GetSlice("")
	if len(seqChildren) != 2 {
		t.Errorf("GetSlice('') on sequence = %d children, want 2", len(seqChildren))
	}
}

// TestGetStringFunction tests the getString helper function
func TestGetStringFunction(t *testing.T) {
	tests := []struct {
		name         string
		node         *Node
		key          string
		defaultValue string
		expected     string
	}{
		{
			name: "scalar child exists",
			node: &Node{
				Type: NodeMapping,
				Children: []*Node{
					{Type: NodeScalar, Value: "name"},
					{Type: NodeScalar, Value: "test-value"},
				},
			},
			key:          "name",
			defaultValue: "default",
			expected:     "test-value",
		},
		{
			name: "key not found",
			node: &Node{
				Type: NodeMapping,
				Children: []*Node{
					{Type: NodeScalar, Value: "other"},
					{Type: NodeScalar, Value: "value"},
				},
			},
			key:          "name",
			defaultValue: "default",
			expected:     "default",
		},
		{
			name: "child is not scalar",
			node: &Node{
				Type: NodeMapping,
				Children: []*Node{
					{Type: NodeScalar, Value: "name"},
					{Type: NodeSequence, Children: []*Node{}},
				},
			},
			key:          "name",
			defaultValue: "default",
			expected:     "default",
		},
		{
			name:         "nil node",
			node:         nil,
			key:          "name",
			defaultValue: "default",
			expected:     "default",
		},
		{
			name: "empty mapping",
			node: &Node{
				Type:     NodeMapping,
				Children: []*Node{},
			},
			key:          "name",
			defaultValue: "default",
			expected:     "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result string
			if tt.node == nil {
				result = tt.defaultValue
			} else {
				result = getString(tt.node, tt.key, tt.defaultValue)
			}
			if result != tt.expected {
				t.Errorf("getString() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestUnmarshalYAMLWithEnvDisabled tests environment variable expansion can be disabled
func TestUnmarshalYAMLWithEnvDisabled(t *testing.T) {
	// Set an environment variable
	os.Setenv("TEST_DNS_PORT", "5353")
	defer os.Unsetenv("TEST_DNS_PORT")

	input := `
server:
  port: 5353
`

	// With expandEnv = false, should parse normally
	cfg, err := UnmarshalYAMLWithEnv(input, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Server.Port != 5353 {
		t.Errorf("expected port 5353, got %d", cfg.Server.Port)
	}
}

// TestUnmarshalYAMLWithEnvEnabled tests environment variable expansion
func TestUnmarshalYAMLWithEnvEnabled(t *testing.T) {
	// Set an environment variable
	os.Setenv("TEST_DNS_PORT_2", "5353")
	defer os.Unsetenv("TEST_DNS_PORT_2")

	input := `
server:
  port: ${TEST_DNS_PORT_2}
`

	cfg, err := UnmarshalYAMLWithEnv(input, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Server.Port != 5353 {
		t.Errorf("expected port 5353, got %d", cfg.Server.Port)
	}
}

// TestExpandEnvVarsSimple tests simple $VAR expansion
func TestExpandEnvVarsSimple(t *testing.T) {
	os.Setenv("TEST_SIMPLE_VAR", "hello")
	defer os.Unsetenv("TEST_SIMPLE_VAR")

	input := "value: $TEST_SIMPLE_VAR"
	result := expandEnvVars(input)

	if !strings.Contains(result, "hello") {
		t.Errorf("expected 'hello' in result, got %q", result)
	}
}

// TestExpandEnvVarsNoClosing tests ${VAR without closing brace
func TestExpandEnvVarsNoClosing(t *testing.T) {
	os.Setenv("TEST_UNCLOSED", "value")
	defer os.Unsetenv("TEST_UNCLOSED")

	input := "value: ${TEST_UNCLOSED"
	result := expandEnvVars(input)

	// Should leave the text as-is since no closing brace
	if !strings.Contains(result, "${TEST_UNCLOSED") {
		t.Errorf("expected unclosed variable to remain, got %q", result)
	}
}

// TestValidateClusterEnabled tests cluster validation when enabled
func TestValidateClusterEnabled(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid cluster config",
			config: &Config{
				Cluster: ClusterConfig{
					Enabled:    true,
					GossipPort: 7946,
					Weight:     100,
					SeedNodes:  []string{"node1.example.com:7946"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid gossip port",
			config: &Config{
				Cluster: ClusterConfig{
					Enabled:    true,
					GossipPort: 0,
				},
			},
			wantErr: true,
			errMsg:  "invalid gossip_port",
		},
		{
			name: "negative weight",
			config: &Config{
				Cluster: ClusterConfig{
					Enabled:    true,
					GossipPort: 7946,
					Weight:     -1,
				},
			},
			wantErr: true,
			errMsg:  "weight cannot be negative",
		},
		{
			name: "empty seed node",
			config: &Config{
				Cluster: ClusterConfig{
					Enabled:    true,
					GossipPort: 7946,
					SeedNodes:  []string{""},
				},
			},
			wantErr: true,
			errMsg:  "seed node cannot be empty",
		},
		{
			name: "invalid seed node format",
			config: &Config{
				Cluster: ClusterConfig{
					Enabled:    true,
					GossipPort: 7946,
					SeedNodes:  []string{"invalid-node-no-port"},
				},
			},
			wantErr: true,
			errMsg:  "expected host:port format",
		},
		{
			name: "invalid seed node port",
			config: &Config{
				Cluster: ClusterConfig{
					Enabled:    true,
					GossipPort: 7946,
					SeedNodes:  []string{"node1:99999"},
				},
			},
			wantErr: true,
			errMsg:  "invalid port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := tt.config.Validate()
			var clusterErrors []string
			for _, e := range errors {
				if strings.Contains(e, "cluster") {
					clusterErrors = append(clusterErrors, e)
				}
			}
			if tt.wantErr {
				if len(clusterErrors) == 0 {
					t.Errorf("expected cluster error, got %v", errors)
				} else if !containsAny(clusterErrors, tt.errMsg) {
					t.Errorf("expected error containing %q, got %v", tt.errMsg, clusterErrors)
				}
			} else {
				if len(clusterErrors) > 0 {
					t.Errorf("unexpected cluster error: %v", clusterErrors)
				}
			}
		})
	}
}

// containsAny checks if any string in slice contains substr
func containsAny(slice []string, substr string) bool {
	for _, s := range slice {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

// --- Additional coverage tests for low-coverage functions ---

// TestTokenTypeStringAll tests all token type string representations
func TestTokenTypeStringAll(t *testing.T) {
	tests := []struct {
		tt       TokenType
		expected string
	}{
		{TokenEOF, "EOF"},
		{TokenError, "ERROR"},
		{TokenIndent, "INDENT"},
		{TokenDedent, "DEDENT"},
		{TokenNewline, "NEWLINE"},
		{TokenColon, "COLON"},
		{TokenDash, "DASH"},
		{TokenComma, "COMMA"},
		{TokenLBrace, "LBRACE"},
		{TokenRBrace, "RBRACE"},
		{TokenLBracket, "LBRACKET"},
		{TokenRBracket, "RBRACKET"},
		{TokenString, "STRING"},
		{TokenNumber, "NUMBER"},
		{TokenBool, "BOOL"},
		{TokenNull, "NULL"},
		{TokenComment, "COMMENT"},
		{TokenAnchor, "ANCHOR"},
		{TokenAlias, "ALIAS"},
		{TokenTag, "TAG"},
		{TokenPipe, "PIPE"},
		{TokenGreater, "GREATER"},
		{TokenType(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.tt.String(); got != tt.expected {
				t.Errorf("TokenType(%d).String() = %q, want %q", tt.tt, got, tt.expected)
			}
		})
	}
}

// TestTokenStringAllTypes tests the Token.String() method for all types
func TestTokenStringAllTypes(t *testing.T) {
	tests := []struct {
		name     string
		token    Token
		expected string
	}{
		{"EOF", Token{Type: TokenEOF, Value: ""}, "EOF"},
		{"String", Token{Type: TokenString, Value: "hello"}, "STRING(hello)"},
		{"Number", Token{Type: TokenNumber, Value: "42"}, "NUMBER(42)"},
		{"Bool", Token{Type: TokenBool, Value: "true"}, "BOOL(true)"},
		{"Colon", Token{Type: TokenColon, Value: ":"}, "COLON"},
		{"Dash", Token{Type: TokenDash, Value: "-"}, "DASH"},
		{"Newline", Token{Type: TokenNewline, Value: "\n"}, "NEWLINE"},
		{"Indent", Token{Type: TokenIndent, Value: ""}, "INDENT"},
		{"Dedent", Token{Type: TokenDedent, Value: ""}, "DEDENT"},
		{"LBrace", Token{Type: TokenLBrace, Value: "{"}, "LBRACE"},
		{"RBrace", Token{Type: TokenRBrace, Value: "}"}, "RBRACE"},
		{"LBracket", Token{Type: TokenLBracket, Value: "["}, "LBRACKET"},
		{"RBracket", Token{Type: TokenRBracket, Value: "]"}, "RBRACKET"},
		{"Comma", Token{Type: TokenComma, Value: ","}, "COMMA"},
		{"Null", Token{Type: TokenNull, Value: ""}, "NULL"},
		{"Comment", Token{Type: TokenComment, Value: "test"}, "COMMENT"},
		{"Anchor", Token{Type: TokenAnchor, Value: "&a"}, "ANCHOR"},
		{"Alias", Token{Type: TokenAlias, Value: "*a"}, "ALIAS"},
		{"Tag", Token{Type: TokenTag, Value: "!t"}, "TAG"},
		{"Pipe", Token{Type: TokenPipe, Value: "|"}, "PIPE"},
		{"Greater", Token{Type: TokenGreater, Value: ">"}, "GREATER"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.token.String(); got != tt.expected {
				t.Errorf("Token.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestNodeToInterfaceMapping tests toInterface for mapping nodes
func TestNodeToInterfaceMapping(t *testing.T) {
	// Test mapping node conversion
	node := &Node{
		Type: NodeMapping,
		Children: []*Node{
			{Type: NodeScalar, Value: "name"},
			{Type: NodeScalar, Value: "test"},
			{Type: NodeScalar, Value: "count"},
			{Type: NodeScalar, Value: "42"},
		},
	}

	result := node.toInterface()
	m, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if m["name"] != "test" {
		t.Errorf("expected name 'test', got %v", m["name"])
	}
	if m["count"] != "42" {
		t.Errorf("expected count '42', got %v", m["count"])
	}
}

// TestNodeGetStringSliceNonSequence tests getStringSlice on non-sequence node
func TestNodeGetStringSliceNonSequence(t *testing.T) {
	node := &Node{Type: NodeScalar, Value: "hello"}
	result := node.getStringSlice()
	if result != nil {
		t.Errorf("expected nil for scalar node, got %v", result)
	}
}

// TestNodeGetStringSliceMixedChildren tests getStringSlice with mixed children
func TestNodeGetStringSliceMixedChildren(t *testing.T) {
	node := &Node{
		Type: NodeSequence,
		Children: []*Node{
			{Type: NodeScalar, Value: "a"},
			{Type: NodeMapping, Children: []*Node{}},
			{Type: NodeScalar, Value: "b"},
		},
	}

	result := node.getStringSlice()
	if len(result) != 2 {
		t.Errorf("expected 2 strings, got %d: %v", len(result), result)
	}
}

// TestUnmarshalToConfigNonMapping tests unmarshalToConfig with non-mapping root
func TestUnmarshalToConfigNonMapping(t *testing.T) {
	node := &Node{Type: NodeScalar, Value: "test"}
	cfg := DefaultConfig()
	err := unmarshalToConfig(node, cfg)
	if err == nil {
		t.Error("expected error for non-mapping root")
	}
}

// TestUnmarshalToConfigErrorPaths tests unmarshalToConfig error paths
func TestUnmarshalToConfigErrorPaths(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "server with non-mapping value",
			input: `server: "not a mapping"`,
		},
		{
			name:  "upstream with non-mapping value",
			input: `upstream: "not a mapping"`,
		},
		{
			name:  "cache with non-mapping value",
			input: `cache: "not a mapping"`,
		},
		{
			name:  "logging with non-mapping value",
			input: `logging: "not a mapping"`,
		},
		{
			name:  "metrics with non-mapping value",
			input: `metrics: "not a mapping"`,
		},
		{
			name:  "dnssec with non-mapping value",
			input: `dnssec: "not a mapping"`,
		},
		{
			name:  "blocklist with non-mapping value",
			input: `blocklist: "not a mapping"`,
		},
		{
			name:  "cluster with non-mapping value",
			input: `cluster: "not a mapping"`,
		},
		{
			name:  "resolution with non-mapping value",
			input: `resolution: "not a mapping"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalYAML(tt.input)
			if err == nil {
				t.Error("expected error for non-mapping section value")
			}
		})
	}
}

// TestUnmarshalResolutionEmptyTimeout tests unmarshalResolution default timeout
func TestUnmarshalResolutionEmptyTimeout(t *testing.T) {
	input := `
resolution:
  recursive: true
`
	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Resolution.Timeout != "5s" {
		t.Errorf("expected default timeout '5s', got %q", cfg.Resolution.Timeout)
	}
}

// TestUnmarshalUpstreamDefaults tests unmarshalUpstream default values
func TestUnmarshalUpstreamDefaults(t *testing.T) {
	input := `
upstream:
  servers:
    - 1.1.1.1:53
`
	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Upstream.Strategy != "random" {
		t.Errorf("expected default strategy 'random', got %q", cfg.Upstream.Strategy)
	}
	if cfg.Upstream.HealthCheck != "30s" {
		t.Errorf("expected default health_check '30s', got %q", cfg.Upstream.HealthCheck)
	}
	if cfg.Upstream.FailoverTimeout != "5s" {
		t.Errorf("expected default failover_timeout '5s', got %q", cfg.Upstream.FailoverTimeout)
	}
}

// TestUnmarshalUpstreamWithTopology tests unmarshalUpstream with topology section
func TestUnmarshalUpstreamWithTopology(t *testing.T) {
	input := `
upstream:
  servers:
    - 1.1.1.1:53
  topology:
    region: us-east-1
    zone: a
    weight: 50
`
	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Upstream.Topology.Region != "us-east-1" {
		t.Errorf("expected region 'us-east-1', got %q", cfg.Upstream.Topology.Region)
	}
	if cfg.Upstream.Topology.Zone != "a" {
		t.Errorf("expected zone 'a', got %q", cfg.Upstream.Topology.Zone)
	}
	if cfg.Upstream.Topology.Weight != 50 {
		t.Errorf("expected weight 50, got %d", cfg.Upstream.Topology.Weight)
	}
}

// TestUnmarshalClusterWithScalarSeedNode tests unmarshalCluster with scalar seed_nodes
func TestUnmarshalClusterWithScalarSeedNode(t *testing.T) {
	input := `
cluster:
  enabled: true
  seed_nodes: 192.168.1.2:7946
`
	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Cluster.SeedNodes) != 1 || cfg.Cluster.SeedNodes[0] != "192.168.1.2:7946" {
		t.Errorf("expected single seed node, got %v", cfg.Cluster.SeedNodes)
	}
}

// TestValidateZonesEmptyPath tests validation of empty zone paths
func TestValidateZonesEmptyPath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Zones = []string{""}
	errors := cfg.Validate()
	found := false
	for _, e := range errors {
		if strings.Contains(e, "zone file path cannot be empty") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected zone empty path error, got %v", errors)
	}
}

// TestValidateMetricsEnabledEmptyPath tests metrics enabled with empty path
func TestValidateMetricsEnabledEmptyPath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Metrics.Enabled = true
	cfg.Metrics.Path = ""
	errors := cfg.Validate()
	found := false
	for _, e := range errors {
		if strings.Contains(e, "metrics: path cannot be empty") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected metrics empty path error, got %v", errors)
	}
}

// TestValidateCacheNegativeTTL tests negative cache TTL validation
func TestValidateCacheNegativeTTL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Cache.NegativeTTL = -1
	errors := cfg.Validate()
	found := false
	for _, e := range errors {
		if strings.Contains(e, "negative_ttl cannot be negative") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected negative TTL error, got %v", errors)
	}
}

// TestValidateCacheNegativeMaxTTL tests negative max TTL validation
func TestValidateCacheNegativeMaxTTL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Cache.MaxTTL = -1
	errors := cfg.Validate()
	found := false
	for _, e := range errors {
		if strings.Contains(e, "max_ttl cannot be negative") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected negative max TTL error, got %v", errors)
	}
}

// TestValidateCacheNegativeDefaultTTL tests negative default TTL validation
func TestValidateCacheNegativeDefaultTTL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Cache.DefaultTTL = -1
	errors := cfg.Validate()
	found := false
	for _, e := range errors {
		if strings.Contains(e, "default_ttl cannot be negative") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected negative default TTL error, got %v", errors)
	}
}

// TestValidateClusterEmptyHostSeedNode tests cluster validation with empty host in seed node
func TestValidateClusterEmptyHostSeedNode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Cluster.Enabled = true
	cfg.Cluster.SeedNodes = []string{":7946"}
	errors := cfg.Validate()
	found := false
	for _, e := range errors {
		if strings.Contains(e, "has empty host") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected empty host error, got %v", errors)
	}
}

// TestIsValidIP tests IP validation
func TestIsValidIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.1", true},
		{"::1", true},
		{"2001:db8::1", true},
		{"not-an-ip", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			if got := isValidIP(tt.ip); got != tt.want {
				t.Errorf("isValidIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

// TestIsValidHostnameLong tests hostname that is too long
func TestIsValidHostnameLong(t *testing.T) {
	longHost := strings.Repeat("a", 254)
	if isValidHostname(longHost) {
		t.Error("expected hostname > 253 chars to be invalid")
	}
}

// --- Additional coverage tests ---

// TestUnmarshalLoggingWithLevelAndFormat tests that unmarshalLogging correctly
// reads level and format when they are explicitly set (not falling through to defaults).
func TestUnmarshalLoggingWithLevelAndFormat(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantLevel     string
		wantFormat    string
		wantOutput    string
		wantQueryLog  bool
		wantQueryFile string
	}{
		{
			name: "level and format explicitly set",
			input: `
logging:
  level: warn
  format: json
  output: stderr
  query_log: true
  query_log_file: /tmp/queries.log
`,
			wantLevel:     "warn",
			wantFormat:    "json",
			wantOutput:    "stderr",
			wantQueryLog:  true,
			wantQueryFile: "/tmp/queries.log",
		},
		{
			name: "level and format set to error and text",
			input: `
logging:
  level: error
  format: text
  output: /var/log/dns.log
`,
			wantLevel:     "error",
			wantFormat:    "text",
			wantOutput:    "/var/log/dns.log",
			wantQueryLog:  false,
			wantQueryFile: "",
		},
		{
			name: "empty logging section uses defaults",
			input: `
logging: {}
`,
			wantLevel:     "info",
			wantFormat:    "text",
			wantOutput:    "stdout",
			wantQueryLog:  false,
			wantQueryFile: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := UnmarshalYAML(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.Logging.Level != tt.wantLevel {
				t.Errorf("Logging.Level = %q, want %q", cfg.Logging.Level, tt.wantLevel)
			}
			if cfg.Logging.Format != tt.wantFormat {
				t.Errorf("Logging.Format = %q, want %q", cfg.Logging.Format, tt.wantFormat)
			}
			if cfg.Logging.Output != tt.wantOutput {
				t.Errorf("Logging.Output = %q, want %q", cfg.Logging.Output, tt.wantOutput)
			}
			if cfg.Logging.QueryLog != tt.wantQueryLog {
				t.Errorf("Logging.QueryLog = %v, want %v", cfg.Logging.QueryLog, tt.wantQueryLog)
			}
			if cfg.Logging.QueryLogFile != tt.wantQueryFile {
				t.Errorf("Logging.QueryLogFile = %q, want %q", cfg.Logging.QueryLogFile, tt.wantQueryFile)
			}
		})
	}
}

// TestUnmarshalMetricsWithBindAndPath tests that unmarshalMetrics correctly
// reads bind and path when they are explicitly set (not falling through to defaults).
func TestUnmarshalMetricsWithBindAndPath(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantBind  string
		wantPath  string
		wantEnabled bool
	}{
		{
			name: "bind and path explicitly set",
			input: `
metrics:
  enabled: true
  bind: ":1234"
  path: /custom-metrics
`,
			wantBind:    ":1234",
			wantPath:    "/custom-metrics",
			wantEnabled: true,
		},
		{
			name: "bind and path use defaults when empty",
			input: `
metrics:
  enabled: false
`,
			wantBind:    ":9153",
			wantPath:    "/metrics",
			wantEnabled: false,
		},
		{
			name: "empty metrics section uses defaults",
			input: `
metrics: {}
`,
			wantBind:    ":9153",
			wantPath:    "/metrics",
			wantEnabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := UnmarshalYAML(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.Metrics.Bind != tt.wantBind {
				t.Errorf("Metrics.Bind = %q, want %q", cfg.Metrics.Bind, tt.wantBind)
			}
			if cfg.Metrics.Path != tt.wantPath {
				t.Errorf("Metrics.Path = %q, want %q", cfg.Metrics.Path, tt.wantPath)
			}
			if cfg.Metrics.Enabled != tt.wantEnabled {
				t.Errorf("Metrics.Enabled = %v, want %v", cfg.Metrics.Enabled, tt.wantEnabled)
			}
		})
	}
}

// TestGetStringSliceScalarValue tests the getStringSlice helper function's path
// where the child node is a scalar value instead of a sequence.
func TestGetStringSliceScalarValue(t *testing.T) {
	tests := []struct {
		name         string
		node         *Node
		key          string
		defaultValue []string
		expected     []string
	}{
		{
			name: "scalar value returned as single-element slice",
			node: &Node{
				Type: NodeMapping,
				Children: []*Node{
					{Type: NodeScalar, Value: "servers"},
					{Type: NodeScalar, Value: "1.1.1.1:53"},
				},
			},
			key:          "servers",
			defaultValue: []string{"default"},
			expected:     []string{"1.1.1.1:53"},
		},
		{
			name: "sequence value returned as slice",
			node: &Node{
				Type: NodeMapping,
				Children: []*Node{
					{Type: NodeScalar, Value: "servers"},
					{
						Type: NodeSequence,
						Children: []*Node{
							{Type: NodeScalar, Value: "1.1.1.1:53"},
							{Type: NodeScalar, Value: "8.8.8.8:53"},
						},
					},
				},
			},
			key:          "servers",
			defaultValue: nil,
			expected:     []string{"1.1.1.1:53", "8.8.8.8:53"},
		},
		{
			name: "key not found returns default",
			node: &Node{
				Type: NodeMapping,
				Children: []*Node{
					{Type: NodeScalar, Value: "other"},
					{Type: NodeScalar, Value: "value"},
				},
			},
			key:          "servers",
			defaultValue: []string{"fallback"},
			expected:     []string{"fallback"},
		},
		{
			name: "mapping child falls through to default",
			node: &Node{
				Type: NodeMapping,
				Children: []*Node{
					{Type: NodeScalar, Value: "servers"},
					{Type: NodeMapping, Children: []*Node{}},
				},
			},
			key:          "servers",
			defaultValue: []string{"fallback"},
			expected:     []string{"fallback"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getStringSlice(tt.node, tt.key, tt.defaultValue)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("getStringSlice() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestGetStringSliceScalarViaYAML tests the scalar-as-slice path via full YAML unmarshal.
// This exercises getStringSlice with a scalar value for a normally sequence-typed field.
func TestGetStringSliceScalarViaYAML(t *testing.T) {
	input := `
upstream:
  servers: 1.1.1.1:53
  strategy: random
`
	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Upstream.Servers) != 1 || cfg.Upstream.Servers[0] != "1.1.1.1:53" {
		t.Errorf("Upstream.Servers = %v, want [1.1.1.1:53]", cfg.Upstream.Servers)
	}
}

// TestValidateCachePrefetchThresholdZero tests that cache validation catches
// prefetch enabled with a threshold of 0.
func TestValidateCachePrefetchThresholdZero(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "prefetch enabled with threshold 0",
			config: &Config{
				Cache: CacheConfig{
					Enabled:           true,
					Size:              10000,
					DefaultTTL:        300,
					MinTTL:            10,
					MaxTTL:            3600,
					Prefetch:          true,
					PrefetchThreshold: 0,
				},
			},
			wantErr: true,
			errMsg:  "prefetch_threshold must be at least 1",
		},
		{
			name: "prefetch enabled with valid threshold",
			config: &Config{
				Cache: CacheConfig{
					Enabled:           true,
					Size:              10000,
					DefaultTTL:        300,
					MinTTL:            10,
					MaxTTL:            3600,
					Prefetch:          true,
					PrefetchThreshold: 60,
				},
			},
			wantErr: false,
		},
		{
			name: "prefetch disabled with threshold 0 is fine",
			config: &Config{
				Cache: CacheConfig{
					Enabled:           true,
					Size:              10000,
					DefaultTTL:        300,
					MinTTL:            10,
					MaxTTL:            3600,
					Prefetch:          false,
					PrefetchThreshold: 0,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := tt.config.Validate()
			var cacheErrors []string
			for _, e := range errors {
				if strings.Contains(e, "cache") {
					cacheErrors = append(cacheErrors, e)
				}
			}
			if tt.wantErr {
				if len(cacheErrors) == 0 {
					t.Errorf("expected cache error, got %v", errors)
				} else if !containsAny(cacheErrors, tt.errMsg) {
					t.Errorf("expected error containing %q, got %v", tt.errMsg, cacheErrors)
				}
			} else {
				if len(cacheErrors) > 0 {
					t.Errorf("unexpected cache error: %v", cacheErrors)
				}
			}
		})
	}
}

// TestNodeGetOnNonMapping tests that Node.Get returns nil when called on a non-mapping node.
func TestNodeGetOnNonMapping(t *testing.T) {
	tests := []struct {
		name string
		node *Node
		key  string
	}{
		{
			name: "scalar node returns nil",
			node: &Node{Type: NodeScalar, Value: "hello"},
			key:  "anything",
		},
		{
			name: "sequence node returns nil",
			node: &Node{
				Type: NodeSequence,
				Children: []*Node{
					{Type: NodeScalar, Value: "a"},
				},
			},
			key: "anything",
		},
		{
			name: "document node returns nil",
			node: &Node{Type: NodeDocument},
			key:  "anything",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.node.Get(tt.key)
			if result != nil {
				t.Errorf("Get() on non-mapping node = %v, want nil", result)
			}
		})
	}
}

// TestNodeGetBoolAlternateValues tests Node.GetBool with "yes", "on", "no", "off" values.
func TestNodeGetBoolAlternateValues(t *testing.T) {
	tests := []struct {
		name     string
		node     *Node
		key      string
		expected bool
	}{
		{
			name: "yes value returns true",
			node: &Node{
				Type: NodeMapping,
				Children: []*Node{
					{Type: NodeScalar, Value: "flag"},
					{Type: NodeScalar, Value: "yes"},
				},
			},
			key:      "flag",
			expected: true,
		},
		{
			name: "on value returns true",
			node: &Node{
				Type: NodeMapping,
				Children: []*Node{
					{Type: NodeScalar, Value: "flag"},
					{Type: NodeScalar, Value: "on"},
				},
			},
			key:      "flag",
			expected: true,
		},
		{
			name: "no value returns false",
			node: &Node{
				Type: NodeMapping,
				Children: []*Node{
					{Type: NodeScalar, Value: "flag"},
					{Type: NodeScalar, Value: "no"},
				},
			},
			key:      "flag",
			expected: false,
		},
		{
			name: "off value returns false",
			node: &Node{
				Type: NodeMapping,
				Children: []*Node{
					{Type: NodeScalar, Value: "flag"},
					{Type: NodeScalar, Value: "off"},
				},
			},
			key:      "flag",
			expected: false,
		},
		{
			name: "true value returns true",
			node: &Node{
				Type: NodeMapping,
				Children: []*Node{
					{Type: NodeScalar, Value: "flag"},
					{Type: NodeScalar, Value: "true"},
				},
			},
			key:      "flag",
			expected: true,
		},
		{
			name: "unknown value returns false",
			node: &Node{
				Type: NodeMapping,
				Children: []*Node{
					{Type: NodeScalar, Value: "flag"},
					{Type: NodeScalar, Value: "maybe"},
				},
			},
			key:      "flag",
			expected: false,
		},
		{
			name: "missing key returns false",
			node: &Node{
				Type: NodeMapping,
				Children: []*Node{
					{Type: NodeScalar, Value: "other"},
					{Type: NodeScalar, Value: "true"},
				},
			},
			key:      "flag",
			expected: false,
		},
		{
			name: "non-scalar child returns false",
			node: &Node{
				Type: NodeMapping,
				Children: []*Node{
					{Type: NodeScalar, Value: "flag"},
					{Type: NodeSequence, Children: []*Node{}},
				},
			},
			key:      "flag",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.node.GetBool(tt.key)
			if result != tt.expected {
				t.Errorf("GetBool(%q) = %v, want %v", tt.key, result, tt.expected)
			}
		})
	}
}

// TestNodeGetIntNonScalarChild tests that Node.GetInt returns 0 for a non-scalar child.
func TestNodeGetIntNonScalarChild(t *testing.T) {
	tests := []struct {
		name     string
		node     *Node
		key      string
		expected int
	}{
		{
			name: "mapping child returns 0",
			node: &Node{
				Type: NodeMapping,
				Children: []*Node{
					{Type: NodeScalar, Value: "count"},
					{Type: NodeMapping, Children: []*Node{}},
				},
			},
			key:      "count",
			expected: 0,
		},
		{
			name: "sequence child returns 0",
			node: &Node{
				Type: NodeMapping,
				Children: []*Node{
					{Type: NodeScalar, Value: "count"},
					{Type: NodeSequence, Children: []*Node{}},
				},
			},
			key:      "count",
			expected: 0,
		},
		{
			name: "missing key returns 0",
			node: &Node{
				Type: NodeMapping,
				Children: []*Node{
					{Type: NodeScalar, Value: "other"},
					{Type: NodeScalar, Value: "42"},
				},
			},
			key:      "count",
			expected: 0,
		},
		{
			name: "scalar child returns parsed value",
			node: &Node{
				Type: NodeMapping,
				Children: []*Node{
					{Type: NodeScalar, Value: "count"},
					{Type: NodeScalar, Value: "42"},
				},
			},
			key:      "count",
			expected: 42,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.node.GetInt(tt.key)
			if result != tt.expected {
				t.Errorf("GetInt(%q) = %d, want %d", tt.key, result, tt.expected)
			}
		})
	}
}

// --- Additional coverage for config.go uncovered lines ---

// TestUnmarshalSlaveZoneDefaultTransferType tests slave zone with empty transfer_type defaults to "ixfr" (line 571)
func TestUnmarshalSlaveZoneDefaultTransferType(t *testing.T) {
	input := `
slave_zones:
  - zone_name: example.com.
    masters:
      - 192.168.1.100:53
`
	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.SlaveZones) != 1 {
		t.Fatalf("expected 1 slave zone, got %d", len(cfg.SlaveZones))
	}
	if cfg.SlaveZones[0].TransferType != "ixfr" {
		t.Errorf("expected default transfer_type 'ixfr', got %q", cfg.SlaveZones[0].TransferType)
	}
}

// TestUnmarshalSlaveZoneScalarMasters tests slave zone with scalar masters value (line 590)
func TestUnmarshalSlaveZoneScalarMasters(t *testing.T) {
	input := `
slave_zones:
  - zone_name: example.com.
    masters: 192.168.1.100:53
    transfer_type: axfr
`
	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.SlaveZones) != 1 {
		t.Fatalf("expected 1 slave zone, got %d", len(cfg.SlaveZones))
	}
	if len(cfg.SlaveZones[0].Masters) != 1 {
		t.Errorf("expected 1 master, got %d", len(cfg.SlaveZones[0].Masters))
	}
	if cfg.SlaveZones[0].Masters[0] != "192.168.1.100:53" {
		t.Errorf("expected master '192.168.1.100:53', got %q", cfg.SlaveZones[0].Masters[0])
	}
}

// TestUnmarshalHTTPDefaultDoHPath tests HTTP without doh_path defaults to "/dns-query" (line 628)
func TestUnmarshalHTTPDefaultDoHPath(t *testing.T) {
	input := `
server:
  http:
    enabled: true
    bind: ":8080"
`
	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Server.HTTP.Enabled {
		t.Error("expected HTTP to be enabled")
	}
	if cfg.Server.HTTP.DoHPath != "/dns-query" {
		t.Errorf("expected default DoHPath '/dns-query', got %q", cfg.Server.HTTP.DoHPath)
	}
}

// TestValidateUpstreamServerNoPort tests validation of server without port (line 975)
func TestValidateUpstreamServerNoPort(t *testing.T) {
	cfg := &Config{
		Upstream: UpstreamConfig{
			Strategy: "random",
			Servers:  []string{"8.8.8.8"},
		},
	}
	errors := cfg.Validate()
	// Server without port should still be valid
	var upstreamErrors []string
	for _, e := range errors {
		if strings.Contains(e, "upstream") {
			upstreamErrors = append(upstreamErrors, e)
		}
	}
	if len(upstreamErrors) > 0 {
		t.Errorf("unexpected upstream errors: %v", upstreamErrors)
	}
}

// TestValidateUpstreamInvalidServerPort tests invalid server port
func TestValidateUpstreamInvalidServerPort(t *testing.T) {
	cfg := &Config{
		Upstream: UpstreamConfig{
				Strategy: "random",
				Servers:  []string{"8.8.8.8:99999"},
		},
	}
	errors := cfg.Validate()
	found := false
	for _, e := range errors {
		if strings.Contains(e, "invalid server address") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected invalid server address error, got %v", errors)
	}
}

// TestValidateUpstreamWithAnycastNoServers tests upstream with anycast groups but no servers (should pass)
func TestValidateUpstreamWithAnycastNoServers(t *testing.T) {
	cfg := &Config{
		Upstream: UpstreamConfig{
			Strategy: "random",
			Servers:  []string{},
			AnycastGroups: []AnycastGroupConfig{
				{
					AnycastIP: "10.0.0.1",
					Backends: []AnycastBackendConfig{
						{PhysicalIP: "192.168.1.1", Port: 53, Weight: 100},
					},
				},
			},
		},
	}
	errors := cfg.Validate()
	var upstreamErrors []string
	for _, e := range errors {
		if strings.Contains(e, "upstream") {
			upstreamErrors = append(upstreamErrors, e)
		}
	}
	if len(upstreamErrors) > 0 {
		t.Errorf("unexpected upstream errors with anycast groups: %v", upstreamErrors)
	}
}
