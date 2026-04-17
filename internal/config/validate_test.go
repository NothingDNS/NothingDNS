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

// TestValidateSecrets_RefusesPlaceholders locks in VULN-050: Validate() must
// reject any secret field that still carries a known template placeholder.
// The failure mode being prevented is an operator shipping the example
// deploy/production.yaml unchanged — the server would hash
// "UNIQUE-STRONG-PASSWORD" into a real credential and every deployment would
// share the same trivially-guessable login.
func TestValidateSecrets_RefusesPlaceholders(t *testing.T) {
	c := DefaultConfig()
	c.Server.HTTP.Enabled = true
	c.Server.HTTP.AuthSecret = "CHANGE-THIS-TO-256-BIT-STRONG-SECRET"
	c.Server.HTTP.AuthToken = "changeme"
	c.Server.HTTP.Users = []AuthUserConfig{
		{Username: "admin", Password: "UNIQUE-STRONG-PASSWORD", Role: "admin"},
		{Username: "viewer", Password: "s3cretly-random-2f9a...", Role: "viewer"}, // legitimate
	}

	errs := c.validateSecrets()
	if len(errs) != 3 {
		t.Fatalf("got %d errors, want 3 (auth_token + auth_secret + admin user). errors=%v", len(errs), errs)
	}

	joined := strings.Join(errs, "\n")
	for _, want := range []string{"auth_token", "auth_secret", `users[0]`, `"admin"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("error messages missing %q. full output:\n%s", want, joined)
		}
	}
	// The legitimate viewer password must NOT show up in the error list.
	if strings.Contains(joined, "viewer") {
		t.Errorf("viewer user flagged falsely — real secrets should pass. output:\n%s", joined)
	}
}

func TestValidateSecrets_AcceptsEmptyAndRealSecrets(t *testing.T) {
	c := DefaultConfig()
	c.Server.HTTP.Enabled = true
	// Empty auth_secret is allowed — it means "auto-generate at startup".
	c.Server.HTTP.AuthSecret = ""
	c.Server.HTTP.AuthToken = ""
	c.Server.HTTP.Users = []AuthUserConfig{
		{Username: "admin", Password: "hunter2-but-actually-strong-9f2a-c481", Role: "admin"},
	}

	if errs := c.validateSecrets(); len(errs) != 0 {
		t.Errorf("valid config should pass secret validation, got: %v", errs)
	}
}

func TestLooksLikePlaceholderSecret(t *testing.T) {
	for _, tc := range []struct {
		in       string
		wantHit  bool
		wantSubs string // expected token substring in the returned match
	}{
		{"", false, ""},
		{"hunter2-7F9a-c481-2d3e", false, ""},
		{"CHANGE-THIS-TO-256-BIT-STRONG-SECRET", true, "CHANGE-THIS"},
		{"change-this-to-something", true, "CHANGE-THIS"},
		{"ChangeMe", true, "CHANGEME"},
		{"unique-strong-password", true, "UNIQUE-STRONG"},
		{"my-placeholder-value", true, "PLACEHOLDER"},
		{"replaceme", true, "REPLACEME"},
		{"REPLACE-ME", true, "REPLACE-ME"},
		{"your-secret-here", true, "YOUR-SECRET"},
	} {
		got := looksLikePlaceholderSecret(tc.in)
		if tc.wantHit && got == "" {
			t.Errorf("looksLikePlaceholderSecret(%q) = \"\", want hit on %q", tc.in, tc.wantSubs)
		}
		if !tc.wantHit && got != "" {
			t.Errorf("looksLikePlaceholderSecret(%q) = %q, want no hit", tc.in, got)
		}
		if tc.wantHit && got != "" && got != tc.wantSubs {
			t.Errorf("looksLikePlaceholderSecret(%q) matched token %q, expected %q", tc.in, got, tc.wantSubs)
		}
	}
}
