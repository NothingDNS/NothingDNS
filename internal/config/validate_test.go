package config

import (
	"os"
	"path/filepath"
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
			name: "QUIC enabled but no cert",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Server.QUIC.Enabled = true
				return c
			}(),
			wantErr:  true,
			errCount: 1,
		},
		{
			name: "QUIC enabled with TLS cert fallback",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Server.QUIC.Enabled = true
				c.Server.TLS.CertFile = "/cert.pem"
				c.Server.TLS.KeyFile = "/key.pem"
				return c
			}(),
			wantErr: false,
		},
		{
			name: "XoT enabled but no cert",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Server.XoT.Enabled = true
				return c
			}(),
			wantErr:  true,
			errCount: 1,
		},
		{
			name: "XoT enabled with TLS cert fallback",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Server.XoT.Enabled = true
				c.Server.TLS.CertFile = "/cert.pem"
				c.Server.TLS.KeyFile = "/key.pem"
				return c
			}(),
			wantErr: false,
		},
		{
			name: "XoT invalid min TLS version",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Server.XoT.Enabled = true
				c.Server.XoT.CertFile = "/cert.pem"
				c.Server.XoT.KeyFile = "/key.pem"
				c.Server.XoT.MinTLSVersion = 11
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

func TestValidateResolution(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *Config
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid default resolution config",
			cfg:     DefaultConfig(),
			wantErr: false,
		},
		{
			name: "negative max_depth",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Resolution.MaxDepth = -1
				return c
			}(),
			wantErr:   true,
			errSubstr: "max_depth cannot be negative",
		},
		{
			name: "negative edns0 buffer size",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Resolution.EDNS0BufferSize = -1
				return c
			}(),
			wantErr:   true,
			errSubstr: "edns0_buffer_size",
		},
		{
			name: "edns0 buffer size over uint16",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Resolution.EDNS0BufferSize = 65536
				return c
			}(),
			wantErr:   true,
			errSubstr: "edns0_buffer_size",
		},
		{
			name: "invalid timeout",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Resolution.Timeout = "eventually"
				return c
			}(),
			wantErr:   true,
			errSubstr: "invalid timeout",
		},
		{
			name: "recursive root hints file missing",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Resolution.Recursive = true
				c.Resolution.RootHints = filepath.Join(t.TempDir(), "missing.root")
				return c
			}(),
			wantErr:   true,
			errSubstr: "root_hints",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := tt.cfg.Validate()
			if tt.wantErr {
				if len(errors) == 0 {
					t.Fatalf("expected errors but got none")
				}
				if tt.errSubstr != "" {
					found := false
					for _, err := range errors {
						if strings.Contains(err, tt.errSubstr) {
							found = true
							break
						}
					}
					if !found {
						t.Fatalf("errors = %v, want substring %q", errors, tt.errSubstr)
					}
				}
				return
			}
			if len(errors) > 0 {
				t.Fatalf("expected no errors but got: %v", errors)
			}
		})
	}
}

func TestValidateZoneFiles(t *testing.T) {
	tmpDir := t.TempDir()
	zoneFile := filepath.Join(tmpDir, "example.zone")
	if err := os.WriteFile(zoneFile, []byte("$ORIGIN example.\n"), 0644); err != nil {
		t.Fatalf("write zone file: %v", err)
	}
	zoneDir := filepath.Join(tmpDir, "zones")
	if err := os.Mkdir(zoneDir, 0755); err != nil {
		t.Fatalf("mkdir zone dir: %v", err)
	}

	tests := []struct {
		name      string
		mutate    func(*Config)
		errSubstr string
	}{
		{
			name: "valid configured zone sources",
			mutate: func(c *Config) {
				c.Zones = []string{zoneFile}
				c.ZoneDir = zoneDir
				c.Views = []ViewConfig{{
					Name:         "internal",
					MatchClients: []string{"10.0.0.0/8"},
					ZoneFiles:    []string{zoneFile},
				}}
			},
		},
		{
			name: "missing configured zone file",
			mutate: func(c *Config) {
				c.Zones = []string{filepath.Join(tmpDir, "missing.zone")}
			},
			errSubstr: "zones[0]: cannot access zone file",
		},
		{
			name: "configured zone path is directory",
			mutate: func(c *Config) {
				c.Zones = []string{zoneDir}
			},
			errSubstr: "zones[0]",
		},
		{
			name: "zone_dir path is file",
			mutate: func(c *Config) {
				c.ZoneDir = zoneFile
			},
			errSubstr: "zone_dir",
		},
		{
			name: "missing view zone file",
			mutate: func(c *Config) {
				c.Views = []ViewConfig{{
					Name:         "internal",
					MatchClients: []string{"10.0.0.0/8"},
					ZoneFiles:    []string{filepath.Join(tmpDir, "missing-view.zone")},
				}}
			},
			errSubstr: "views[0].zone_files[0]: cannot access zone file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := DefaultConfig()
			tt.mutate(c)

			errors := c.Validate()
			if tt.errSubstr == "" {
				if len(errors) != 0 {
					t.Fatalf("expected no errors, got %v", errors)
				}
				return
			}
			for _, err := range errors {
				if strings.Contains(err, tt.errSubstr) {
					return
				}
			}
			t.Fatalf("errors = %v, want substring %q", errors, tt.errSubstr)
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
			name: "invalid health check duration",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Upstream.HealthCheck = "eventually"
				return c
			}(),
			wantErr:  true,
			errCount: 1,
		},
		{
			name: "invalid failover timeout duration",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Upstream.FailoverTimeout = "soon"
				return c
			}(),
			wantErr:  true,
			errCount: 1,
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

func TestValidateGeoDNS(t *testing.T) {
	tmpDir := t.TempDir()
	mmdbFile := filepath.Join(tmpDir, "geo.mmdb")
	if err := os.WriteFile(mmdbFile, []byte("placeholder mmdb bytes"), 0644); err != nil {
		t.Fatalf("write mmdb fixture: %v", err)
	}

	tests := []struct {
		name      string
		mutate    func(*Config)
		errSubstr string
	}{
		{
			name: "disabled ignores missing mmdb",
			mutate: func(c *Config) {
				c.GeoDNS.Enabled = false
				c.GeoDNS.MMDBFile = filepath.Join(tmpDir, "missing.mmdb")
			},
		},
		{
			name: "enabled with existing mmdb file",
			mutate: func(c *Config) {
				c.GeoDNS.Enabled = true
				c.GeoDNS.MMDBFile = mmdbFile
			},
		},
		{
			name: "enabled with missing mmdb file",
			mutate: func(c *Config) {
				c.GeoDNS.Enabled = true
				c.GeoDNS.MMDBFile = filepath.Join(tmpDir, "missing.mmdb")
			},
			errSubstr: "geodns.mmdb_file: cannot access",
		},
		{
			name: "enabled with mmdb directory",
			mutate: func(c *Config) {
				c.GeoDNS.Enabled = true
				c.GeoDNS.MMDBFile = tmpDir
			},
			errSubstr: "geodns.mmdb_file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := DefaultConfig()
			tt.mutate(c)

			errors := c.Validate()
			if tt.errSubstr == "" {
				if len(errors) != 0 {
					t.Fatalf("expected no errors, got %v", errors)
				}
				return
			}
			for _, err := range errors {
				if strings.Contains(err, tt.errSubstr) {
					return
				}
			}
			t.Fatalf("errors = %v, want substring %q", errors, tt.errSubstr)
		})
	}
}

func TestValidateDNS64(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*Config)
		errSubstr string
	}{
		{
			name: "disabled ignores invalid settings",
			mutate: func(c *Config) {
				c.DNS64.Enabled = false
				c.DNS64.Prefix = "not-an-ip"
				c.DNS64.PrefixLen = 99
				c.DNS64.ExcludeNets = []string{"not-a-cidr"}
			},
		},
		{
			name: "enabled with valid defaults",
			mutate: func(c *Config) {
				c.DNS64.Enabled = true
			},
		},
		{
			name: "enabled with invalid prefix length",
			mutate: func(c *Config) {
				c.DNS64.Enabled = true
				c.DNS64.PrefixLen = 99
			},
			errSubstr: "dns64: invalid prefix_len",
		},
		{
			name: "enabled with invalid prefix",
			mutate: func(c *Config) {
				c.DNS64.Enabled = true
				c.DNS64.Prefix = "not-an-ip"
			},
			errSubstr: "dns64: invalid prefix",
		},
		{
			name: "enabled with IPv4 prefix",
			mutate: func(c *Config) {
				c.DNS64.Enabled = true
				c.DNS64.Prefix = "192.0.2.1"
			},
			errSubstr: "must be IPv6",
		},
		{
			name: "enabled with invalid exclude net",
			mutate: func(c *Config) {
				c.DNS64.Enabled = true
				c.DNS64.ExcludeNets = []string{"not-a-cidr"}
			},
			errSubstr: "dns64.exclude_nets: invalid CIDR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := DefaultConfig()
			tt.mutate(c)

			errors := c.Validate()
			if tt.errSubstr == "" {
				if len(errors) != 0 {
					t.Fatalf("expected no errors, got %v", errors)
				}
				return
			}
			for _, err := range errors {
				if strings.Contains(err, tt.errSubstr) {
					return
				}
			}
			t.Fatalf("errors = %v, want substring %q", errors, tt.errSubstr)
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

func TestValidateDurationFields(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*Config)
		errSubstr string
	}{
		{
			name: "invalid shutdown timeout",
			mutate: func(c *Config) {
				c.ShutdownTimeout = "eventually"
			},
			errSubstr: "invalid shutdown_timeout",
		},
		{
			name: "invalid cookie secret rotation",
			mutate: func(c *Config) {
				c.Cookie.SecretRotation = "hourly"
			},
			errSubstr: "cookie: invalid secret_rotation",
		},
		{
			name: "invalid slave zone timeout",
			mutate: func(c *Config) {
				c.SlaveZones = []SlaveZoneConfig{{
					ZoneName:      "example.com.",
					Masters:       []string{"192.0.2.1:53"},
					TransferType:  "ixfr",
					Timeout:       "later",
					RetryInterval: "5m",
				}}
			},
			errSubstr: "slave_zones[0]: invalid timeout",
		},
		{
			name: "invalid slave zone retry interval",
			mutate: func(c *Config) {
				c.SlaveZones = []SlaveZoneConfig{{
					ZoneName:      "example.com.",
					Masters:       []string{"192.0.2.1:53"},
					TransferType:  "ixfr",
					Timeout:       "30s",
					RetryInterval: "later",
				}}
			},
			errSubstr: "slave_zones[0]: invalid retry_interval",
		},
		{
			name: "invalid DSO session timeout",
			mutate: func(c *Config) {
				c.DSO.SessionTimeout = "later"
			},
			errSubstr: "dso: invalid session_timeout",
		},
		{
			name: "invalid DSO heartbeat interval",
			mutate: func(c *Config) {
				c.DSO.HeartbeatInterval = "sometimes"
			},
			errSubstr: "dso: invalid heartbeat_interval",
		},
		{
			name: "invalid mDNS multicast IP",
			mutate: func(c *Config) {
				c.MDNS.Enabled = true
				c.MDNS.MulticastIP = "not-an-ip"
			},
			errSubstr: "mdns: multicast_ip",
		},
		{
			name: "mDNS IPv6 multicast unsupported",
			mutate: func(c *Config) {
				c.MDNS.Enabled = true
				c.MDNS.MulticastIP = "ff02::fb"
			},
			errSubstr: "must be an IPv4 multicast address",
		},
		{
			name: "mDNS unicast IP unsupported",
			mutate: func(c *Config) {
				c.MDNS.Enabled = true
				c.MDNS.MulticastIP = "127.0.0.1"
			},
			errSubstr: "must be an IPv4 multicast address",
		},
		{
			name: "invalid mDNS port",
			mutate: func(c *Config) {
				c.MDNS.Enabled = true
				c.MDNS.Port = 70000
			},
			errSubstr: "mdns: invalid port",
		},
		{
			name: "invalid ODoH KEM",
			mutate: func(c *Config) {
				c.ODoH.Enabled = true
				c.ODoH.KEM = 99
			},
			errSubstr: "odoh: unsupported kem",
		},
		{
			name: "invalid ODoH KDF",
			mutate: func(c *Config) {
				c.ODoH.Enabled = true
				c.ODoH.KDF = 2
			},
			errSubstr: "odoh: unsupported kdf",
		},
		{
			name: "invalid ODoH AEAD",
			mutate: func(c *Config) {
				c.ODoH.Enabled = true
				c.ODoH.AEAD = 2
			},
			errSubstr: "odoh: unsupported aead",
		},
		{
			name: "invalid HTTP ODoH KEM",
			mutate: func(c *Config) {
				c.Server.HTTP.ODoHEnabled = true
				c.Server.HTTP.ODoHKEM = 99
			},
			errSubstr: "http: unsupported odoh_kem",
		},
		{
			name: "invalid ODoH target URL",
			mutate: func(c *Config) {
				c.ODoH.Enabled = true
				c.ODoH.TargetURL = "://bad"
			},
			errSubstr: "odoh: invalid target_url",
		},
		{
			name: "catalog enabled but runtime integration unavailable",
			mutate: func(c *Config) {
				c.Catalog.Enabled = true
			},
			errSubstr: "catalog: enabled but catalog zones are not wired into the daemon runtime",
		},
		{
			name: "YANG enabled but runtime integration unavailable",
			mutate: func(c *Config) {
				c.YANG.Enabled = true
			},
			errSubstr: "yang: enabled but YANG services are not wired into the daemon runtime",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := DefaultConfig()
			tt.mutate(c)

			errors := c.Validate()
			for _, err := range errors {
				if strings.Contains(err, tt.errSubstr) {
					return
				}
			}
			t.Fatalf("errors = %v, want substring %q", errors, tt.errSubstr)
		})
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
		{Username: "admin", Password: "placeholder-password-123456", Role: "admin"},
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

func TestValidateHTTPUsersRejectsInvalidConfiguredUsers(t *testing.T) {
	tests := []struct {
		name    string
		users   []AuthUserConfig
		wantErr []string
	}{
		{
			name:    "empty_username",
			users:   []AuthUserConfig{{Username: "", Password: "password", Role: "admin"}},
			wantErr: []string{"http.users[0].username", "username must not be empty"},
		},
		{
			name:    "control_character_username",
			users:   []AuthUserConfig{{Username: "admin\nroot", Password: "password", Role: "admin"}},
			wantErr: []string{"http.users[0].username", "control characters"},
		},
		{
			name: "duplicate_username",
			users: []AuthUserConfig{
				{Username: "admin", Password: "password", Role: "admin"},
				{Username: "admin", Password: "password2", Role: "viewer"},
			},
			wantErr: []string{"http.users[1].username", "duplicate username"},
		},
		{
			name:    "short_password",
			users:   []AuthUserConfig{{Username: "admin", Password: "short", Role: "admin"}},
			wantErr: []string{"http.users[0].password", "at least 8"},
		},
		{
			name:    "invalid_role",
			users:   []AuthUserConfig{{Username: "admin", Password: "password", Role: "owner"}},
			wantErr: []string{"http.users[0].role", "invalid role"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := DefaultConfig()
			c.Server.HTTP.Enabled = true
			c.Server.HTTP.Users = tc.users

			joined := strings.Join(c.Validate(), "\n")
			for _, want := range tc.wantErr {
				if !strings.Contains(joined, want) {
					t.Fatalf("Validate() missing %q. errors:\n%s", want, joined)
				}
			}
		})
	}
}

func TestValidateHTTPUsersRejectsInvalidAuthTokenRole(t *testing.T) {
	c := DefaultConfig()
	c.Server.HTTP.Enabled = true
	c.Server.HTTP.AuthToken = ""
	c.Server.HTTP.AuthTokenRole = "owner"
	c.Server.HTTP.Users = []AuthUserConfig{
		{Username: "admin", Password: "password", Role: "admin"},
	}

	joined := strings.Join(c.Validate(), "\n")
	if !strings.Contains(joined, "http.auth_token_role") || !strings.Contains(joined, "invalid role") {
		t.Fatalf("Validate() missing auth_token_role error. errors:\n%s", joined)
	}
}

func TestValidateHTTPUsersAcceptsValidAuthTokenRoles(t *testing.T) {
	for _, role := range []string{"", "viewer", "operator", "admin", "ADMIN"} {
		t.Run(role, func(t *testing.T) {
			c := DefaultConfig()
			c.Server.HTTP.Enabled = true
			c.Server.HTTP.AuthToken = ""
			c.Server.HTTP.AuthTokenRole = role
			c.Server.HTTP.Users = []AuthUserConfig{
				{Username: "admin", Password: "password", Role: "admin"},
			}

			for _, err := range c.Validate() {
				if strings.Contains(err, "http.auth_token_role") {
					t.Fatalf("valid auth_token_role %q rejected: %v", role, err)
				}
			}
		})
	}
}

func TestValidateHTTPUsersRequiresAuthSecretForTokenPersistence(t *testing.T) {
	c := DefaultConfig()
	c.Server.HTTP.Enabled = true
	c.Server.HTTP.AuthSecret = ""
	c.Server.HTTP.TokenPersistencePath = "/var/lib/nothingdns/tokens.enc"
	c.Server.HTTP.Users = []AuthUserConfig{
		{Username: "admin", Password: "password", Role: "admin"},
	}

	joined := strings.Join(c.Validate(), "\n")
	if !strings.Contains(joined, "http.token_persistence_path requires http.auth_secret") {
		t.Fatalf("Validate() missing token persistence auth_secret error. errors:\n%s", joined)
	}
}

func TestValidateHTTPUsersRejectsNegativeMaxSessionsPerUser(t *testing.T) {
	c := DefaultConfig()
	c.Server.HTTP.Enabled = true
	c.Server.HTTP.MaxSessionsPerUser = -1
	c.Server.HTTP.Users = []AuthUserConfig{
		{Username: "admin", Password: "password", Role: "admin"},
	}

	joined := strings.Join(c.Validate(), "\n")
	if !strings.Contains(joined, "http.max_sessions_per_user cannot be negative") {
		t.Fatalf("Validate() missing max_sessions_per_user error. errors:\n%s", joined)
	}
}

// TestValidate_AuthSecret_RejectsShortString regresses SECURITY-REPORT.md
// L-5. http.auth_secret had a placeholder-check but no entropy check,
// so a config with auth_secret: "x" or auth_secret: "short" passed
// validation despite being a uselessly short HMAC-SHA512 signing
// key. Post-fix it runs through the same secretHasMinEntropy gate the
// auth_token block uses (>= 32 bytes, >= 3 character classes).
func TestValidate_AuthSecret_RejectsShortString(t *testing.T) {
	for _, tc := range []struct {
		name      string
		secret    string
		wantError bool
	}{
		{"empty — allowed (per-run random)", "", false},
		{"5 bytes — too short", "short", true},
		{"31 bytes — one below minimum", "abcdefghij1234567890ABCDEFGHIJ", true},
		{"32 bytes, 3 classes — accepted", "abcdefghij1234567890ABCDEFGHIJKL", false},
		{"32 bytes, only lowercase — too few classes", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := DefaultConfig()
			c.Server.HTTP.AuthSecret = tc.secret
			errors := c.Validate()
			gotHit := false
			for _, e := range errors {
				if strings.Contains(e, "http.auth_secret") {
					gotHit = true
					break
				}
			}
			if gotHit != tc.wantError {
				t.Errorf("got hit=%v wantError=%v; errors=%v", gotHit, tc.wantError, errors)
			}
		})
	}
}

// TestValidate_AtRestEncryptionKeys regresses SECURITY-REPORT.md L-6
// wiring. The two new keys (storage.encryption_key,
// cluster.snapshot_encryption_key) must be 32-byte hex when set, and
// each one must differ from the others — key separation is the
// load-bearing property when one of the three trust domains leaks.
func TestValidate_AtRestEncryptionKeys(t *testing.T) {
	// "aa..." × 32 / "bb..." × 32 / "cc..." × 32 → three distinct valid keys.
	keyA := strings.Repeat("aa", 32) // 64 hex chars
	keyB := strings.Repeat("bb", 32)
	keyC := strings.Repeat("cc", 32)

	cases := []struct {
		name       string
		storageKey string
		snapKey    string
		gossipKey  string
		clusterOn  bool
		expectHit  []string // substrings the error set must contain
	}{
		{
			name:       "all empty — no error",
			storageKey: "", snapKey: "", gossipKey: "",
		},
		{
			name:       "storage non-hex",
			storageKey: "not-hex-at-all", expectHit: []string{"storage.encryption_key"},
		},
		{
			name:    "snap wrong length",
			snapKey: "deadbeef", expectHit: []string{"cluster.snapshot_encryption_key"},
		},
		{
			name:       "storage == gossip — key reuse",
			storageKey: keyA, gossipKey: keyA, clusterOn: true,
			expectHit: []string{"storage.encryption_key must differ from cluster.encryption_key"},
		},
		{
			name:    "snap == gossip — key reuse",
			snapKey: keyB, gossipKey: keyB, clusterOn: true,
			expectHit: []string{"cluster.snapshot_encryption_key must differ from cluster.encryption_key"},
		},
		{
			name:       "storage == snap — key reuse",
			storageKey: keyC, snapKey: keyC,
			expectHit: []string{"storage.encryption_key must differ from cluster.snapshot_encryption_key"},
		},
		{
			name:       "three distinct keys, all valid hex — no error",
			storageKey: keyA, snapKey: keyB, gossipKey: keyC, clusterOn: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := DefaultConfig()
			c.Storage.EncryptionKey = tc.storageKey
			c.Cluster.SnapshotEncryptionKey = tc.snapKey
			c.Cluster.EncryptionKey = tc.gossipKey
			c.Cluster.Enabled = tc.clusterOn
			errors := c.Validate()
			joined := strings.Join(errors, "\n")
			for _, needle := range tc.expectHit {
				if !strings.Contains(joined, needle) {
					t.Errorf("expected error containing %q, got: %v", needle, errors)
				}
			}
			if len(tc.expectHit) == 0 {
				for _, e := range errors {
					if strings.Contains(e, "storage.encryption_key") ||
						strings.Contains(e, "snapshot_encryption_key") {
						t.Errorf("unexpected at-rest-key error: %s", e)
					}
				}
			}
		})
	}
}

func TestValidateRejectsDoTAndXoTBindCollision(t *testing.T) {
	tests := []struct {
		name    string
		dotBind string
		xotBind string
	}{
		{name: "explicit_same_bind", dotBind: ":853", xotBind: ":853"},
		{name: "shared_default_bind"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := DefaultConfig()
			c.Server.TLS = TLSConfig{
				Enabled:  true,
				CertFile: "/etc/nothingdns/tls.crt",
				KeyFile:  "/etc/nothingdns/tls.key",
				Bind:     tc.dotBind,
			}
			c.Server.XoT = XoTConfig{
				Enabled:       true,
				CertFile:      "/etc/nothingdns/xot.crt",
				KeyFile:       "/etc/nothingdns/xot.key",
				CAFile:        "/etc/nothingdns/xot-ca.crt",
				Bind:          tc.xotBind,
				MinTLSVersion: 13,
			}

			joined := strings.Join(c.Validate(), "\n")
			if !strings.Contains(joined, "server.xot.bind conflicts with server.tls.bind") {
				t.Fatalf("Validate missing DoT/XoT bind collision error. errors:\n%s", joined)
			}
		})
	}
}

func TestValidateProduction_AcceptsHardenedConfig(t *testing.T) {
	c := productionReadyTestConfig()

	if errs := c.ValidateProduction(); len(errs) != 0 {
		t.Fatalf("production-ready config should pass, got: %v", errs)
	}
}

func TestValidateProduction_RejectsUnsafeProductionConfig(t *testing.T) {
	c := productionReadyTestConfig()
	c.Server.HTTP.AuthSecret = ""
	c.Server.HTTP.Users = nil
	c.Server.HTTP.Bind = "0.0.0.0:8080"
	c.Server.HTTP.TLSCertFile = ""
	c.Server.HTTP.TLSKeyFile = ""
	c.Resolution.Recursive = true
	c.ACL = nil
	c.Server.ACLAllowUnrestrictedRecursion = true
	c.DNSSEC.IgnoreTime = true
	c.Storage.DataDir = ""
	c.Storage.EncryptionKey = ""
	c.Cluster.AllowInsecureCluster = true
	c.Cluster.EncryptionKey = ""
	c.Cluster.DataDir = ""
	c.Metrics.Enabled = true
	c.Metrics.Bind = ":9153"
	c.Metrics.AuthToken = ""
	c.Transfer.AllowList = []string{"10.0.0.0/8"}
	c.Transfer.RequireTSIG = false

	errs := c.ValidateProduction()
	joined := strings.Join(errs, "\n")
	for _, want := range []string{
		"production: http.auth_secret",
		"production: at least one http.users",
		"production: public http.bind",
		"production: recursive resolver cannot run open",
		"production: dnssec.ignore_time",
		"production: storage.data_dir",
		"production: storage.encryption_key",
		"production: cluster.allow_insecure",
		"production: cluster.encryption_key",
		"production: cluster.data_dir",
		"production: public metrics.bind",
		"production: transfer.require_tsig",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("ValidateProduction missing %q. errors:\n%s", want, joined)
		}
	}
}

func TestValidateProduction_RequiresAdminHTTPUser(t *testing.T) {
	c := productionReadyTestConfig()
	c.Server.HTTP.Users = []AuthUserConfig{
		{Username: "operator", Password: "abcdefghij1234567890ABCDEFGHIJKL", Role: "operator"},
	}

	errs := c.ValidateProduction()
	joined := strings.Join(errs, "\n")
	if !strings.Contains(joined, "production: at least one http.users entry must have role admin") {
		t.Fatalf("ValidateProduction missing admin-user error. errors:\n%s", joined)
	}
}

func TestValidateProduction_RejectsWildcardCORSOnPublicHTTPBind(t *testing.T) {
	c := productionReadyTestConfig()
	c.Server.HTTP.Bind = "0.0.0.0:8080"
	c.Server.HTTP.TLSCertFile = "/etc/nothingdns/tls.crt"
	c.Server.HTTP.TLSKeyFile = "/etc/nothingdns/tls.key"
	c.Server.HTTP.AllowedOrigins = []string{"*"}

	errs := c.ValidateProduction()
	joined := strings.Join(errs, "\n")
	if !strings.Contains(joined, "production: public http.bind cannot use wildcard http.allowed_origins") {
		t.Fatalf("ValidateProduction missing wildcard CORS error. errors:\n%s", joined)
	}
}

func TestValidateProduction_AllowsNonPublicOrExplicitCORSOrigins(t *testing.T) {
	tests := []struct {
		name           string
		bind           string
		allowedOrigins []string
	}{
		{
			name:           "loopback_wildcard_for_development",
			bind:           "127.0.0.1:8080",
			allowedOrigins: []string{"*"},
		},
		{
			name:           "public_explicit_origin",
			bind:           "0.0.0.0:8080",
			allowedOrigins: []string{"https://console.example"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := productionReadyTestConfig()
			c.Server.HTTP.Bind = tc.bind
			c.Server.HTTP.TLSCertFile = "/etc/nothingdns/tls.crt"
			c.Server.HTTP.TLSKeyFile = "/etc/nothingdns/tls.key"
			c.Server.HTTP.AllowedOrigins = tc.allowedOrigins

			for _, err := range c.ValidateProduction() {
				if strings.Contains(err, "wildcard http.allowed_origins") {
					t.Fatalf("unexpected wildcard CORS error: %v", err)
				}
			}
		})
	}
}

func TestValidateProduction_RequiresAbsoluteTokenPersistencePath(t *testing.T) {
	c := productionReadyTestConfig()
	c.Server.HTTP.TokenPersistencePath = "tokens.enc"

	errs := c.ValidateProduction()
	joined := strings.Join(errs, "\n")
	if !strings.Contains(joined, "production: http.token_persistence_path must be an absolute path") {
		t.Fatalf("ValidateProduction missing token persistence path error. errors:\n%s", joined)
	}
}

func TestValidateProduction_AllowsAbsoluteTokenPersistencePath(t *testing.T) {
	c := productionReadyTestConfig()
	c.Server.HTTP.TokenPersistencePath = "/var/lib/nothingdns/tokens.enc"

	for _, err := range c.ValidateProduction() {
		if strings.Contains(err, "token_persistence_path") {
			t.Fatalf("unexpected token persistence path error: %v", err)
		}
	}
}

func productionReadyTestConfig() *Config {
	c := DefaultConfig()
	c.Server.HTTP.Enabled = true
	c.Server.HTTP.Bind = "127.0.0.1:8080"
	c.Server.HTTP.AuthSecret = "abcdefghij1234567890ABCDEFGHIJKL"
	c.Server.HTTP.Users = []AuthUserConfig{
		{Username: "admin", Password: "abcdefghij1234567890ABCDEFGHIJKL", Role: "admin"},
	}
	c.DNSSEC.Enabled = true
	c.DNSSEC.IgnoreTime = false
	c.Storage.DataDir = "/var/lib/nothingdns"
	c.Storage.EncryptionKey = strings.Repeat("aa", 32)
	c.Cluster.Enabled = true
	c.Cluster.ConsensusMode = "raft"
	c.Cluster.DataDir = "/var/lib/nothingdns/raft"
	c.Cluster.EncryptionKey = "abcdefghij1234567890ABCDEFGHIJKL"
	c.Cluster.AllowInsecureCluster = false
	c.Metrics.Enabled = true
	c.Metrics.Bind = "127.0.0.1:9153"
	c.Metrics.AuthToken = ""
	c.Transfer.AllowList = nil
	c.Transfer.RequireTSIG = false
	return c
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
		{"change-this-to-something", true, "change-this"},
		{"ChangeMe", true, "ChangeMe"},
		{"placeholder-password-value", true, "placeholder"},
		{"replaceme", true, "replaceme"},
		{"REPLACE-ME", true, "REPLACE-ME"},
		{"your-secret-here", true, "your-secret"},
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
