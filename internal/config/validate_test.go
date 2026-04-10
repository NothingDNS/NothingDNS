package config

import (
	"strings"
	"testing"
)

func TestValidateServer(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *Config
		wantErr  bool
		errCount int
	}{
		{
			name:    "valid default config",
			cfg:     DefaultConfig(),
			wantErr: false,
		},
		{
			name: "no bind addresses",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Server.Bind = []string{}
				c.Server.TCPBind = []string{}
				c.Server.UDPBind = []string{}
				return c
			}(),
			wantErr:  true,
			errCount: 1,
		},
		{
			name: "invalid port - zero",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Server.Port = 0
				return c
			}(),
			wantErr:  true,
			errCount: 1,
		},
		{
			name: "invalid port - too high",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Server.Port = 70000
				return c
			}(),
			wantErr:  true,
			errCount: 1,
		},
		{
			name: "TLS enabled but no cert",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Server.TLS.Enabled = true
				c.Server.TLS.CertFile = ""
				c.Server.TLS.KeyFile = "/key.pem"
				return c
			}(),
			wantErr:  true,
			errCount: 1,
		},
		{
			name: "TLS enabled but no key",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Server.TLS.Enabled = true
				c.Server.TLS.CertFile = "/cert.pem"
				c.Server.TLS.KeyFile = ""
				return c
			}(),
			wantErr:  true,
			errCount: 1,
		},
		{
			name: "negative UDP workers",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Server.UDPWorkers = -1
				return c
			}(),
			wantErr:  true,
			errCount: 1,
		},
		{
			name: "negative TCP workers",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Server.TCPWorkers = -1
				return c
			}(),
			wantErr:  true,
			errCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := tt.cfg.Validate()
			if tt.wantErr && len(errors) == 0 {
				t.Errorf("expected errors but got none")
			}
			if !tt.wantErr && len(errors) > 0 {
				t.Errorf("expected no errors but got: %v", errors)
			}
			if tt.wantErr && tt.errCount > 0 && len(errors) != tt.errCount {
				t.Errorf("expected %d errors but got %d: %v", tt.errCount, len(errors), errors)
			}
		})
	}
}

func TestValidateUpstream(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *Config
		wantErr  bool
		errCount int
	}{
		{
			name:    "valid upstream",
			cfg:     DefaultConfig(),
			wantErr: false,
		},
		{
			name: "no servers",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Upstream.Servers = []string{}
				return c
			}(),
			wantErr:  true,
			errCount: 1,
		},
		{
			name: "invalid strategy",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Upstream.Strategy = "invalid"
				return c
			}(),
			wantErr:  true,
			errCount: 1,
		},
		{
			name: "invalid server address",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Upstream.Servers = []string{"not-a-valid-address!!!"}
				return c
			}(),
			wantErr: true,
		},
		{
			name: "valid round_robin strategy",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Upstream.Strategy = "round_robin"
				return c
			}(),
			wantErr: false,
		},
		{
			name: "valid fastest strategy",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Upstream.Strategy = "fastest"
				return c
			}(),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := tt.cfg.Validate()
			if tt.wantErr && len(errors) == 0 {
				t.Errorf("expected errors but got none")
			}
			if !tt.wantErr && len(errors) > 0 {
				t.Errorf("expected no errors but got: %v", errors)
			}
		})
	}
}

func TestValidateCache(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name:    "valid cache config",
			cfg:     DefaultConfig(),
			wantErr: false,
		},
		{
			name: "disabled cache - other settings ignored",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Cache.Enabled = false
				c.Cache.Size = -1 // Invalid but ignored
				return c
			}(),
			wantErr: false,
		},
		{
			name: "invalid size",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Cache.Size = 0
				return c
			}(),
			wantErr: true,
		},
		{
			name: "negative min_ttl",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Cache.MinTTL = -1
				return c
			}(),
			wantErr: true,
		},
		{
			name: "min > max ttl",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Cache.MinTTL = 100
				c.Cache.MaxTTL = 50
				return c
			}(),
			wantErr: true,
		},
		{
			name: "default_ttl out of range",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Cache.DefaultTTL = 100000
				return c
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := tt.cfg.Validate()
			if tt.wantErr && len(errors) == 0 {
				t.Errorf("expected errors but got none")
			}
			if !tt.wantErr && len(errors) > 0 {
				t.Errorf("expected no errors but got: %v", errors)
			}
		})
	}
}

func TestValidateLogging(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name:    "valid logging config",
			cfg:     DefaultConfig(),
			wantErr: false,
		},
		{
			name: "invalid level",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Logging.Level = "invalid"
				return c
			}(),
			wantErr: true,
		},
		{
			name: "invalid format",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Logging.Format = "xml"
				return c
			}(),
			wantErr: true,
		},
		{
			name: "valid debug level",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Logging.Level = "debug"
				return c
			}(),
			wantErr: false,
		},
		{
			name: "valid json format",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Logging.Format = "json"
				return c
			}(),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := tt.cfg.Validate()
			if tt.wantErr && len(errors) == 0 {
				t.Errorf("expected errors but got none")
			}
			if !tt.wantErr && len(errors) > 0 {
				t.Errorf("expected no errors but got: %v", errors)
			}
		})
	}
}

func TestValidateMetrics(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name: "disabled metrics - no validation",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Metrics.Enabled = false
				return c
			}(),
			wantErr: false,
		},
		{
			name: "enabled with empty bind",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Metrics.Enabled = true
				c.Metrics.Bind = ""
				return c
			}(),
			wantErr: true,
		},
		{
			name: "path without leading slash",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Metrics.Enabled = true
				c.Metrics.Path = "metrics"
				return c
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := tt.cfg.Validate()
			if tt.wantErr && len(errors) == 0 {
				t.Errorf("expected errors but got none")
			}
			if !tt.wantErr && len(errors) > 0 {
				t.Errorf("expected no errors but got: %v", errors)
			}
		})
	}
}

func TestValidateACL(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name:    "empty ACL - valid",
			cfg:     DefaultConfig(),
			wantErr: false,
		},
		{
			name: "valid ACL rules",
			cfg: func() *Config {
				c := DefaultConfig()
				c.ACL = []ACLRule{
					{
						Name:     "local",
						Networks: []string{"127.0.0.1/32", "10.0.0.0/8"},
						Action:   "allow",
					},
				}
				return c
			}(),
			wantErr: false,
		},
		{
			name: "invalid action",
			cfg: func() *Config {
				c := DefaultConfig()
				c.ACL = []ACLRule{
					{
						Name:   "test",
						Action: "invalid",
					},
				}
				return c
			}(),
			wantErr: true,
		},
		{
			name: "redirect without target",
			cfg: func() *Config {
				c := DefaultConfig()
				c.ACL = []ACLRule{
					{
						Name:   "block",
						Action: "redirect",
						// Redirect field is empty
					},
				}
				return c
			}(),
			wantErr: true,
		},
		{
			name: "invalid CIDR",
			cfg: func() *Config {
				c := DefaultConfig()
				c.ACL = []ACLRule{
					{
						Name:     "test",
						Networks: []string{"not-a-valid-cidr"},
						Action:   "allow",
					},
				}
				return c
			}(),
			wantErr: true,
		},
		{
			name: "invalid query type",
			cfg: func() *Config {
				c := DefaultConfig()
				c.ACL = []ACLRule{
					{
						Name:   "test",
						Types:  []string{"INVALIDTYPE"},
						Action: "allow",
					},
				}
				return c
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := tt.cfg.Validate()
			if tt.wantErr && len(errors) == 0 {
				t.Errorf("expected errors but got none")
			}
			if !tt.wantErr && len(errors) > 0 {
				t.Errorf("expected no errors but got: %v", errors)
			}
		})
	}
}

func TestIsValidServerAddress(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"8.8.8.8:53", true},
		{"127.0.0.1", true},
		{"localhost", true},
		{"::1", true},
		{"", false},
		{"not-a-valid-address!!!", false},
		{"1.2.3.4:99999", false}, // port too high
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			if got := isValidServerAddress(tt.addr); got != tt.want {
				t.Errorf("isValidServerAddress(%q) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestIsValidCIDR(t *testing.T) {
	tests := []struct {
		cidr string
		want bool
	}{
		{"127.0.0.1/32", true},
		{"10.0.0.0/8", true},
		{"192.168.1.0/24", true},
		{"0.0.0.0/0", true},
		{"::1/128", true},
		{"fe80::/10", true},
		{"192.168.1.0/33", false}, // invalid prefix
		{"not-a-cidr", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			if got := isValidCIDR(tt.cidr); got != tt.want {
				t.Errorf("isValidCIDR(%q) = %v, want %v", tt.cidr, got, tt.want)
			}
		})
	}
}

func TestIsValidQueryType(t *testing.T) {
	tests := []struct {
		qt   string
		want bool
	}{
		{"A", true},
		{"AAAA", true},
		{"MX", true},
		{"CNAME", true},
		{"TXT", true},
		{"SRV", true},
		{"a", true}, // case insensitive
		{"TYPE123", true},
		{"INVALID", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.qt, func(t *testing.T) {
			if got := isValidQueryType(tt.qt); got != tt.want {
				t.Errorf("isValidQueryType(%q) = %v, want %v", tt.qt, got, tt.want)
			}
		})
	}
}

func TestValidateMultipleErrors(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Bind: []string{},
			Port: 0,
			TLS: TLSConfig{
				Enabled:  true,
				CertFile: "",
				KeyFile:  "",
			},
		},
		Upstream: UpstreamConfig{
			Servers:  []string{},
			Strategy: "invalid",
		},
		Cache: CacheConfig{
			Enabled: true,
			Size:    0,
		},
		Logging: LoggingConfig{
			Level:  "invalid",
			Format: "invalid",
		},
	}

	errors := cfg.Validate()

	// Should have multiple errors
	if len(errors) < 3 {
		t.Errorf("expected multiple errors, got %d: %v", len(errors), errors)
	}

	// Check that each error contains the relevant section
	hasServer := false
	hasUpstream := false
	hasCache := false
	hasLogging := false

	for _, err := range errors {
		if strings.Contains(err, "server") {
			hasServer = true
		}
		if strings.Contains(err, "upstream") {
			hasUpstream = true
		}
		if strings.Contains(err, "cache") {
			hasCache = true
		}
		if strings.Contains(err, "logging") {
			hasLogging = true
		}
	}

	if !hasServer {
		t.Error("expected server validation errors")
	}
	if !hasUpstream {
		t.Error("expected upstream validation errors")
	}
	if !hasCache {
		t.Error("expected cache validation errors")
	}
	if !hasLogging {
		t.Error("expected logging validation errors")
	}
}
