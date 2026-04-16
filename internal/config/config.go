package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/nothingdns/nothingdns/internal/util"
)

// Config represents the DNS server configuration.
type Config struct {
	// Server configuration
	Server ServerConfig `yaml:"server"`

	// Cluster configuration
	Cluster ClusterConfig `yaml:"cluster"`

	// DNS resolution configuration
	Resolution ResolutionConfig `yaml:"resolution"`

	// Upstream DNS servers
	Upstream UpstreamConfig `yaml:"upstream"`

	// Cache configuration
	Cache CacheConfig `yaml:"cache"`

	// Logging configuration
	Logging LoggingConfig `yaml:"logging"`

	// Metrics configuration
	Metrics MetricsConfig `yaml:"metrics"`

	// DNSSEC configuration
	DNSSEC DNSSECConfig `yaml:"dnssec"`

	// Zone files to load
	Zones []string `yaml:"zones"`

	// Directory for zone file storage (defaults to ./zones/)
	ZoneDir string `yaml:"zone_dir"`

	// ZONEMD enables RFC 8976 zone message digests for integrity verification.
	// When enabled, a ZONEMD record is computed for each zone and included in AXFR.
	ZONEMD bool `yaml:"zonemd"`

	// ACL configuration
	ACL []ACLRule `yaml:"acl"`

	// RRL configuration
	RRL RRLConfig `yaml:"rrl"`

	// Blocklist configuration
	Blocklist BlocklistConfig `yaml:"blocklist"`

	// RPZ (Response Policy Zone) configuration
	RPZ RPZConfig `yaml:"rpz"`

	// GeoDNS configuration
	GeoDNS GeoDNSConfig `yaml:"geodns"`

	// DNS64 configuration
	DNS64 DNS64Config `yaml:"dns64"`

	// Cookie configuration (RFC 7873)
	Cookie CookieConfig `yaml:"cookie"`

	// Slave zone configuration for automatic zone transfers
	SlaveZones []SlaveZoneConfig `yaml:"slave_zones"`

	// Split-Horizon view configuration
	Views []ViewConfig `yaml:"views"`

	// Memory limit in MB (0 = unlimited). When exceeded, caches are cleared.
	MemoryLimitMB int `yaml:"memory_limit_mb"`

	// Shutdown timeout duration (default: 30s). Maximum time to wait for in-flight
	// queries to complete before force-terminating the server.
	ShutdownTimeout string `yaml:"shutdown_timeout"`

	// IDNA configuration (RFC 5891 - Internationalized Domain Names)
	IDNA IDNAConfig `yaml:"idna"`

	// ODoH configuration (RFC 9230 - Oblivious DNS over HTTPS)
	ODoH ODoHConfig `yaml:"odoh"`

	// mDNS configuration (RFC 6762 - Multicast DNS)
	MDNS mDNSConfig `yaml:"mdns"`

	// Catalog Zone configuration (RFC 9432)
	Catalog CatalogConfig `yaml:"catalog"`

	// DSO configuration (RFC 1034 - DNS Stateful Operations)
	DSO DSOConfig `yaml:"dso"`

	// YANG configuration (RFC 9094 - YANG Models for DNS)
	YANG YANGConfig `yaml:"yang"`
}

// ViewConfig holds configuration for a single split-horizon view.
type ViewConfig struct {
	// Name is a unique identifier for this view.
	Name string `yaml:"name"`

	// MatchClients contains CIDR networks or "any" for a catch-all.
	MatchClients []string `yaml:"match_clients"`

	// ZoneFiles lists zone file paths specific to this view.
	ZoneFiles []string `yaml:"zone_files"`
}

// BlocklistConfig holds blocklist configuration.
type BlocklistConfig struct {
	Enabled bool     `yaml:"enabled"`
	Files   []string `yaml:"files"`
	URLs    []string `yaml:"urls"` // URLs to download blocklists from (e.g., adguard, malware domains)
}

// RPZConfig holds Response Policy Zone configuration.
type RPZConfig struct {
	Enabled bool            `yaml:"enabled"`
	Files   []string        `yaml:"files"`
	Zones   []RPZPolicyZone `yaml:"zones"`
}

// RPZPolicyZone configures a single RPZ policy zone.
type RPZPolicyZone struct {
	Name     string `yaml:"name"`
	File     string `yaml:"file"`
	Priority int    `yaml:"priority"`
}

// GeoDNSConfig holds GeoDNS configuration.
type GeoDNSConfig struct {
	Enabled  bool         `yaml:"enabled"`
	MMDBFile string       `yaml:"mmdb_file"`
	Rules    []GeoDNSRule `yaml:"rules"`
}

// GeoDNSRule configures a single geo DNS rule.
type GeoDNSRule struct {
	Domain  string            `yaml:"domain"`
	Type    string            `yaml:"type"`
	Default string            `yaml:"default"`
	Records map[string]string `yaml:"records"`
}

// CookieConfig holds DNS Cookie (RFC 7873) configuration.
type CookieConfig struct {
	// Enable DNS cookies
	Enabled bool `yaml:"enabled"`

	// Secret rotation interval (duration string, e.g., "1h")
	SecretRotation string `yaml:"secret_rotation"`
}

// DNS64Config holds DNS64/NAT64 configuration.
type DNS64Config struct {
	Enabled     bool     `yaml:"enabled"`
	Prefix      string   `yaml:"prefix"`
	PrefixLen   int      `yaml:"prefix_len"`
	ExcludeNets []string `yaml:"exclude_nets"`
}

// IDNAConfig holds IDNA (RFC 5891) configuration for internationalized domain names.
type IDNAConfig struct {
	// Enable IDNA validation
	Enabled bool `yaml:"enabled"`

	// Use STD3 ASCII rules (RFC 5891)
	UseSTD3Rules bool `yaml:"use_std3_rules"`

	// Allow unassigned code points
	AllowUnassigned bool `yaml:"allow_unassigned"`

	// Check bidirectional rules
	CheckBidi bool `yaml:"check_bidi"`

	// Check joiner restrictions
	CheckJoiner bool `yaml:"check_joiner"`
}

// ODoHConfig holds ODoH (RFC 9230 - Oblivious DNS over HTTPS) configuration.
type ODoHConfig struct {
	// Enable ODoH server
	Enabled bool `yaml:"enabled"`

	// Listen address for ODoH proxy
	Bind string `yaml:"bind"`

	// Target resolver URL (where queries are forwarded)
	TargetURL string `yaml:"target_url"`

	// Proxy URL (public URL where ODoH is hosted)
	ProxyURL string `yaml:"proxy_url"`

	// HPKE key encapsulation method (1=P-256, 2=P-384, 3=P-521, 4=X25519)
	KEM int `yaml:"kem"`

	// HPKE key derivation function (1=HKDF-SHA256, 2=HKDF-SHA384, 3=HKDF-SHA512)
	KDF int `yaml:"kdf"`

	// HPKE authenticated encryption (1=AES-256-GCM, 2=ChaCha20-Poly1305)
	AEAD int `yaml:"aead"`
}

// mDNSConfig holds mDNS (RFC 6762 - Multicast DNS) configuration.
type mDNSConfig struct {
	// Enable mDNS responder
	Enabled bool `yaml:"enabled"`

	// Listen address (default: 224.0.0.251:5353)
	MulticastIP string `yaml:"multicast_ip"`

	// Port (default: 5353)
	Port int `yaml:"port"`

	// Enable mDNS browser (service discovery)
	Browser bool `yaml:"browser"`

	// Host name for this responder
	HostName string `yaml:"hostname"`
}

// CatalogConfig holds Catalog Zone (RFC 9432) configuration.
type CatalogConfig struct {
	// Enable Catalog Zones
	Enabled bool `yaml:"enabled"`

	// Catalog zone name (default: "catalog.inbound.")
	CatalogZone string `yaml:"catalog_zone"`

	// Producer class (default: "CLDNSET")
	ProducerClass string `yaml:"producer_class"`

	// Consumer class (default: "CLDNSET")
	ConsumerClass string `yaml:"consumer_class"`
}

// DSOConfig holds DSO (DNS Stateful Operations, RFC 1034) configuration.
type DSOConfig struct {
	// Enable DSO support
	Enabled bool `yaml:"enabled"`

	// Session timeout (duration string, e.g., "10m")
	SessionTimeout string `yaml:"session_timeout"`

	// Maximum sessions
	MaxSessions int `yaml:"max_sessions"`

	// Heartbeat interval (duration string, e.g., "1m")
	HeartbeatInterval string `yaml:"heartbeat_interval"`
}

// YANGConfig holds YANG (RFC 9094) configuration for DNS data models.
type YANGConfig struct {
	// Enable YANG models
	Enabled bool `yaml:"enabled"`

	// Enable CLI RPC commands
	EnableCLI bool `yaml:"enable_cli"`

	// Enable NETCONF (RFC 8040) interface
	EnableNETCONF bool `yaml:"enable_netconf"`

	// NETCONF bind address
	NETCONFBind string `yaml:"netconf_bind"`

	// YANG models to enable (dns-zone, dns-query, etc.)
	Models []string `yaml:"models"`
}

// SlaveZoneConfig represents configuration for a slave zone.
// Slave zones are replicated from master servers via zone transfers.
type SlaveZoneConfig struct {
	// Zone name (e.g., "example.com.")
	ZoneName string `yaml:"zone_name"`

	// Master servers to transfer from (host:port format)
	// Multiple masters can be specified for redundancy
	Masters []string `yaml:"masters"`

	// Transfer type: "ixfr" (incremental) or "axfr" (full)
	// Default is "ixfr" with fallback to "axfr"
	TransferType string `yaml:"transfer_type"`

	// TSIG key name for authenticated transfers (optional)
	TSIGKeyName string `yaml:"tsig_key_name"`

	// TSIG secret for authenticated transfers (optional)
	TSIGSecret string `yaml:"tsig_secret"`

	// Transfer timeout (duration string, e.g., "30s", "1m")
	Timeout string `yaml:"timeout"`

	// Retry interval on transfer failure (duration string, e.g., "5m")
	RetryInterval string `yaml:"retry_interval"`

	// Maximum retry attempts (0 = unlimited)
	MaxRetries int `yaml:"max_retries"`
}

// ServerConfig contains server-level settings.
type ServerConfig struct {
	// Listen addresses
	Bind []string `yaml:"bind"`

	// TCP listen addresses (defaults to bind if not specified)
	TCPBind []string `yaml:"tcp_bind"`

	// UDP listen addresses (defaults to bind if not specified)
	UDPBind []string `yaml:"udp_bind"`

	// Port to listen on (default: 53)
	Port int `yaml:"port"`

	// TLS configuration
	TLS TLSConfig `yaml:"tls"`

	// QUIC configuration (DNS over QUIC, RFC 9250)
	QUIC QUICConfig `yaml:"quic"`

	// XoT configuration (DNS Zone Transfer over TLS, RFC 9103)
	XoT XoTConfig `yaml:"xot"`

	// HTTP API configuration
	HTTP HTTPConfig `yaml:"http"`

	// Worker pool sizes
	UDPWorkers int `yaml:"udp_workers"`
	TCPWorkers int `yaml:"tcp_workers"`

	// PID file path (optional, for daemon mode)
	PIDFile string `yaml:"pid_file"`

	// Systemd notify socket path (empty = disabled)
	SystemdNotify string `yaml:"systemd_notify"`
}

// TLSConfig contains TLS settings for DNS over TLS.
type TLSConfig struct {
	// Enable DoT
	Enabled bool `yaml:"enabled"`

	// Certificate file
	CertFile string `yaml:"cert_file"`

	// Key file
	KeyFile string `yaml:"key_file"`

	// Listen address
	Bind string `yaml:"bind"`
}

// QUICConfig contains DNS over QUIC (RFC 9250) settings.
type QUICConfig struct {
	// Enable DoQ
	Enabled bool `yaml:"enabled"`

	// Certificate file (same as TLS cert)
	CertFile string `yaml:"cert_file"`

	// Key file (same as TLS key)
	KeyFile string `yaml:"key_file"`

	// Listen address (default ":853")
	Bind string `yaml:"bind"`
}

// XoTConfig contains DNS Zone Transfer over TLS (RFC 9103) settings.
type XoTConfig struct {
	// Enable XoT (Zone Transfer over TLS)
	Enabled bool `yaml:"enabled"`

	// Certificate file for TLS
	CertFile string `yaml:"cert_file"`

	// Key file for TLS
	KeyFile string `yaml:"key_file"`

	// CA file for client certificate verification (optional)
	CAFile string `yaml:"ca_file"`

	// Listen address (default ":853")
	Bind string `yaml:"bind"`

	// Minimum TLS version (12 or 13, default 12)
	MinTLSVersion int `yaml:"min_tls_version"`
}

// ClusterConfig contains cluster settings.
type ClusterConfig struct {
	// Enable clustering
	Enabled bool `yaml:"enabled"`

	// Node ID (auto-generated if empty)
	NodeID string `yaml:"node_id"`

	// Bind address for gossip protocol
	BindAddr string `yaml:"bind_addr"`

	// Gossip port (default: 7946)
	GossipPort int `yaml:"gossip_port"`

	// Region for topology awareness
	Region string `yaml:"region"`

	// Zone for topology awareness
	Zone string `yaml:"zone"`

	// Weight for load balancing
	Weight int `yaml:"weight"`

	// Seed nodes to join (format: "host:port")
	SeedNodes []string `yaml:"seed_nodes"`

	// Enable cache synchronization
	CacheSync bool `yaml:"cache_sync"`

	// Encryption key for gossip traffic (32 bytes, hex-encoded).
	// When set, all inter-node communication is encrypted with AES-256-GCM.
	EncryptionKey string `yaml:"encryption_key"`

	// Consensus mode for cluster coordination: "raft" (default) or "swim".
	// Raft provides strong consistency for zone replication.
	// SWIM provides eventual consistency with gossip-based membership.
	ConsensusMode string `yaml:"consensus_mode"`
}

// HTTPConfig contains HTTP API settings.
type HTTPConfig struct {
	// Enable HTTP API
	Enabled bool `yaml:"enabled"`

	// Listen address
	Bind string `yaml:"bind"`

	// TLS certificate and key for HTTPS (required for DoH)
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`

	// Authentication token (legacy, single shared token)
	AuthToken string `yaml:"auth_token"`

	// Role bound to AuthToken when legacy shared-token auth is used.
	// Valid: "admin", "operator", "viewer". Default: "viewer".
	// Previously the legacy token silently synthesized admin context,
	// collapsing RBAC to a single shared secret.
	AuthTokenRole string `yaml:"auth_token_role"`

	// Auth users for multi-user auth (username/password/role)
	Users []AuthUserConfig `yaml:"users"`

	// Auth secret for JWT signing (auto-generated if empty)
	AuthSecret string `yaml:"auth_secret"`

	// DoH (DNS over HTTPS) settings
	DoHEnabled bool   `yaml:"doh_enabled"` // Enable DoH endpoint
	DoHPath    string `yaml:"doh_path"`    // DoH endpoint path (default: /dns-query)

	// DoWS (DNS over WebSocket) settings
	DoWSEnabled bool   `yaml:"dows_enabled"` // Enable DoWS endpoint
	DoWSPath    string `yaml:"dows_path"`    // DoWS endpoint path (default: /dns-ws)

	// ODoH (Oblivious DNS over HTTPS, RFC 9230) settings
	ODoHEnabled bool   `yaml:"odoh_enabled"` // Enable ODoH endpoint
	ODoHPath    string `yaml:"odoh_path"`    // ODoH endpoint path (default: /odoh)
	ODoHKEM     int    `yaml:"odoh_kem"`     // HPKE KEM for target (default: 4 = X25519)
	ODoHKDF     int    `yaml:"odoh_kdf"`     // HPKE KDF for target (default: 1 = HKDF-SHA256)
	ODoHAEAD    int    `yaml:"odoh_aead"`    // HPKE AEAD for target (default: 1 = AES-256-GCM)

	// Allowed origins for CORS (empty means only same-origin requests allowed)
	// Use "*" to allow all origins (not recommended for production)
	AllowedOrigins []string `yaml:"allowed_origins"`
}

// AuthUserConfig defines a user for authentication.
type AuthUserConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Role     string `yaml:"role"` // admin, operator, viewer
}

// ResolutionConfig contains DNS resolution settings.
type ResolutionConfig struct {
	// Enable recursive resolution
	Recursive bool `yaml:"recursive"`

	// Root hints file for recursive resolution
	RootHints string `yaml:"root_hints"`

	// Maximum recursion depth
	MaxDepth int `yaml:"max_depth"`

	// Timeout for queries
	Timeout string `yaml:"timeout"`

	// EDNS0 UDP buffer size
	EDNS0BufferSize int `yaml:"edns0_buffer_size"`

	// QNAME Minimization (RFC 7816) — reduces privacy leakage
	QnameMinimization bool `yaml:"qname_minimization"`

	// DNS 0x20 encoding (Vixie/Dagon) — randomizes query name case for spoofing resistance
	Use0x20 bool `yaml:"use_0x20"`
}

// UpstreamConfig contains upstream DNS server settings.
type UpstreamConfig struct {
	// List of upstream servers
	Servers []string `yaml:"servers"`

	// Strategy for selecting upstream (random, round_robin, fastest)
	Strategy string `yaml:"strategy"`

	// Health check interval
	HealthCheck string `yaml:"health_check"`

	// Failover timeout
	FailoverTimeout string `yaml:"failover_timeout"`

	// Anycast groups for advanced load balancing
	AnycastGroups []AnycastGroupConfig `yaml:"anycast_groups"`

	// Topology configuration for this instance
	Topology TopologyConfig `yaml:"topology"`
}

// AnycastGroupConfig holds configuration for an anycast group.
type AnycastGroupConfig struct {
	// Anycast IP address shared by all backends
	AnycastIP string `yaml:"anycast_ip"`

	// Backend servers in this group
	Backends []AnycastBackendConfig `yaml:"backends"`

	// Health check interval (overrides global setting)
	HealthCheck string `yaml:"health_check"`
}

// AnycastBackendConfig holds configuration for an anycast backend.
type AnycastBackendConfig struct {
	// Physical IP address of the backend
	PhysicalIP string `yaml:"physical_ip"`

	// Port (default: 53)
	Port int `yaml:"port"`

	// Region identifier (e.g., "us-east-1")
	Region string `yaml:"region"`

	// Zone identifier within region (e.g., "a", "b")
	Zone string `yaml:"zone"`

	// Weight for load balancing (0-100, default: 100)
	Weight int `yaml:"weight"`
}

// TopologyConfig holds topology information for routing decisions.
type TopologyConfig struct {
	// Region identifier (e.g., "us-east-1")
	Region string `yaml:"region"`

	// Zone identifier within region (e.g., "a", "b")
	Zone string `yaml:"zone"`

	// Weight for load balancing (0-100)
	Weight int `yaml:"weight"`
}

// CacheConfig contains DNS cache settings.
type CacheConfig struct {
	// Enable caching
	Enabled bool `yaml:"enabled"`

	// Maximum number of entries
	Size int `yaml:"size"`

	// Default TTL for positive responses
	DefaultTTL int `yaml:"default_ttl"`

	// Maximum TTL
	MaxTTL int `yaml:"max_ttl"`

	// Minimum TTL
	MinTTL int `yaml:"min_ttl"`

	// Negative cache TTL (for NXDOMAIN, etc.)
	NegativeTTL int `yaml:"negative_ttl"`

	// Prefetch before expiration
	Prefetch bool `yaml:"prefetch"`

	// Prefetch threshold (seconds before expiration)
	PrefetchThreshold int `yaml:"prefetch_threshold"`

	// RFC 8767: Serve stale responses when upstream is unavailable
	ServeStale bool `yaml:"serve_stale"`

	// Stale grace period in seconds (how long past TTL expiry to keep entries)
	StaleGraceSecs int `yaml:"stale_grace_secs"`
}

// LoggingConfig contains logging settings.
type LoggingConfig struct {
	// Log level (debug, info, warn, error)
	Level string `yaml:"level"`

	// Log format (json, text)
	Format string `yaml:"format"`

	// Log output (stdout, stderr, or file path)
	Output string `yaml:"output"`

	// Query logging
	QueryLog bool `yaml:"query_log"`

	// Query log file (if empty, uses Output)
	QueryLogFile string `yaml:"query_log_file"`
}

// MetricsConfig contains metrics settings.
type MetricsConfig struct {
	// Enable metrics
	Enabled bool `yaml:"enabled"`

	// Listen address for metrics endpoint
	Bind string `yaml:"bind"`

	// Path for metrics endpoint
	Path string `yaml:"path"`
}

// DNSSECConfig contains DNSSEC settings.
type DNSSECConfig struct {
	// Enable DNSSEC validation
	Enabled bool `yaml:"enabled"`

	// Trust anchor file
	TrustAnchor string `yaml:"trust_anchor"`

	// Ignore signature expiration (for testing)
	IgnoreTime bool `yaml:"ignore_time"`

	// Require DNSSEC for all queries (fail if validation unavailable)
	RequireDNSSEC bool `yaml:"require_dnssec"`

	// Zone signing configuration
	Signing SigningConfig `yaml:"signing"`
}

// SigningConfig holds zone signing parameters.
type SigningConfig struct {
	// Enable zone signing
	Enabled bool `yaml:"enabled"`

	// Private key files (one per algorithm)
	Keys []KeyConfig `yaml:"keys"`

	// NSEC3 parameters (if empty, use NSEC)
	NSEC3 *NSEC3Config `yaml:"nsec3"`

	// Signature validity period (e.g., "30d")
	SignatureValidity string `yaml:"signature_validity"`
}

// KeyConfig holds a DNSSEC key file configuration.
type KeyConfig struct {
	// Private key file (PEM format)
	PrivateKey string `yaml:"private_key"`

	// Key type: ksk or zsk
	Type string `yaml:"type"`

	// Algorithm (8=RSASHA256, 13=ECDSAP256SHA256, etc.)
	Algorithm uint8 `yaml:"algorithm"`
}

// NSEC3Config holds NSEC3 parameters for zone signing.
type NSEC3Config struct {
	// Number of hash iterations
	Iterations uint16 `yaml:"iterations"`

	// Salt (hex string, optional)
	Salt string `yaml:"salt"`

	// Opt-out (for insecure delegations)
	OptOut bool `yaml:"opt_out"`
}

// ACLRule defines an access control rule.
type ACLRule struct {
	// Rule name
	Name string `yaml:"name"`

	// Source networks (CIDR notation)
	Networks []string `yaml:"networks"`

	// Allowed query types
	Types []string `yaml:"types"`

	// Action: allow, deny, or redirect
	Action string `yaml:"action"`

	// Redirect target (for action=redirect)
	Redirect string `yaml:"redirect"`
}

// RRLConfig holds response rate limiting configuration.
type RRLConfig struct {
	// Enable rate limiting
	Enabled bool `yaml:"enabled"`

	// Responses per second per client (default 5)
	Rate int `yaml:"rate"`

	// Maximum burst size (default 20)
	Burst int `yaml:"burst"`

	// Maximum number of tracked client buckets (default 10000)
	// Prevents unbounded memory growth during high-volume attacks
	MaxBuckets int `yaml:"max_buckets"`
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Bind:       []string{"0.0.0.0", "::"},
			Port:       53,
			UDPWorkers: 0, // Will use NumCPU * 4
			TCPWorkers: 0, // Will use NumCPU * 2
		},
		Resolution: ResolutionConfig{
			Recursive:         false,
			MaxDepth:          10,
			Timeout:           "5s",
			EDNS0BufferSize:   4096,
			QnameMinimization: true,
		},
		Upstream: UpstreamConfig{
			Servers:         []string{"8.8.8.8:53", "8.8.4.4:53"},
			Strategy:        "random",
			HealthCheck:     "30s",
			FailoverTimeout: "5s",
		},
		Cache: CacheConfig{
			Enabled:           true,
			Size:              10000,
			DefaultTTL:        300,
			MaxTTL:            86400,
			MinTTL:            5,
			NegativeTTL:       60,
			Prefetch:          false,
			PrefetchThreshold: 60,
			ServeStale:        false,
			StaleGraceSecs:    86400, // 24 hours
		},
		Logging: LoggingConfig{
			Level:        "info",
			Format:       "text",
			Output:       "stdout",
			QueryLog:     false,
			QueryLogFile: "",
		},
		Metrics: MetricsConfig{
			Enabled: false,
			Bind:    ":9153",
			Path:    "/metrics",
		},
		DNSSEC: DNSSECConfig{
			Enabled:     true, // Enable DNSSEC validation by default using built-in IANA root anchors
			TrustAnchor: "",
			IgnoreTime:  false,
		},
		Blocklist: BlocklistConfig{
			Enabled: false,
			Files:   []string{},
		},
		RPZ: RPZConfig{
			Enabled: false,
			Files:   []string{},
		},
		GeoDNS: GeoDNSConfig{
			Enabled: false,
		},
		DNS64: DNS64Config{
			Prefix:    "64:ff9b::",
			PrefixLen: 96,
		},
		Cookie: CookieConfig{
			Enabled:        true,
			SecretRotation: "1h",
		},
		IDNA: IDNAConfig{
			Enabled:         false,
			UseSTD3Rules:    true,
			AllowUnassigned: false,
			CheckBidi:       true,
			CheckJoiner:     true,
		},
		ODoH: ODoHConfig{
			Enabled: false,
			Bind:    ":8080",
			KEM:     4, // X25519
			KDF:     1, // HKDF-SHA256
			AEAD:    1, // AES-256-GCM
		},
		MDNS: mDNSConfig{
			Enabled:     false,
			MulticastIP: "224.0.0.251",
			Port:        5353,
			Browser:     false,
		},
		Catalog: CatalogConfig{
			Enabled:       false,
			CatalogZone:   "catalog.inbound.",
			ProducerClass: "CLDNSET",
			ConsumerClass: "CLDNSET",
		},
		DSO: DSOConfig{
			Enabled:           false,
			SessionTimeout:    "10m",
			MaxSessions:       10000,
			HeartbeatInterval: "1m",
		},
		YANG: YANGConfig{
			Enabled:       false,
			EnableCLI:     true,
			EnableNETCONF: false,
			NETCONFBind:   ":8300",
			Models:        []string{"dns-zone", "dns-query"},
		},
		Cluster: ClusterConfig{
			Enabled:    false,
			GossipPort: 7946,
			Weight:     100,
			CacheSync:  true,
		},
		ShutdownTimeout: "30s",
	}
}

// UnmarshalYAML parses YAML into a Config struct.
func UnmarshalYAML(data string) (*Config, error) {
	return UnmarshalYAMLWithEnv(data, true)
}

// UnmarshalYAMLWithEnv parses YAML with optional environment variable expansion.
func UnmarshalYAMLWithEnv(data string, expandEnv bool) (*Config, error) {
	if expandEnv {
		data = expandEnvVars(data)
	}

	parser := NewParser(data)
	node, err := parser.ParseMapping()
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	cfg := DefaultConfig()
	if err := unmarshalToConfig(node, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal error: %w", err)
	}

	return cfg, nil
}

// expandEnvVars expands ${VAR} and $VAR in the input.
// Logs a warning if an environment variable is not set.
func expandEnvVars(input string) string {
	var result strings.Builder
	i := 0

	for i < len(input) {
		if input[i] == '$' {
			// Check for ${VAR} syntax
			if i+1 < len(input) && input[i+1] == '{' {
				// Find closing brace
				end := strings.Index(input[i+2:], "}")
				if end != -1 {
					varName := input[i+2 : i+2+end]
					varValue, ok := os.LookupEnv(varName)
					if !ok {
						// Environment variable not set — warn to prevent silent misconfiguration
						util.Warnf("config: environment variable ${%s} is not set, substituting empty string", varName)
					}
					result.WriteString(varValue)
					i += end + 3
					continue
				}
			}

			// Simple $VAR syntax
			j := i + 1
			for j < len(input) && (isAlphaNum(input[j]) || input[j] == '_') {
				j++
			}
			if j > i+1 {
				varName := input[i+1 : j]
				varValue, ok := os.LookupEnv(varName)
				if !ok {
					// Environment variable not set — warn to prevent silent misconfiguration
					util.Warnf("config: environment variable $%s is not set, substituting empty string", varName)
				}
				result.WriteString(varValue)
				i = j
				continue
			}
		}

		result.WriteByte(input[i])
		i++
	}

	return result.String()
}

func isAlphaNum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// unmarshalToConfig unmarshals a node tree into a Config struct.
func unmarshalToConfig(node *Node, cfg *Config) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping at root")
	}

	// Server config
	if serverNode := node.Get("server"); serverNode != nil {
		if err := unmarshalServer(serverNode, &cfg.Server); err != nil {
			return fmt.Errorf("server: %w", err)
		}
	}

	// Resolution config
	if resNode := node.Get("resolution"); resNode != nil {
		if err := unmarshalResolution(resNode, &cfg.Resolution); err != nil {
			return fmt.Errorf("resolution: %w", err)
		}
	}

	// Upstream config
	if upstreamNode := node.Get("upstream"); upstreamNode != nil {
		if err := unmarshalUpstream(upstreamNode, &cfg.Upstream); err != nil {
			return fmt.Errorf("upstream: %w", err)
		}
	}

	// Cache config
	if cacheNode := node.Get("cache"); cacheNode != nil {
		if err := unmarshalCache(cacheNode, &cfg.Cache); err != nil {
			return fmt.Errorf("cache: %w", err)
		}
	}

	// Logging config
	if loggingNode := node.Get("logging"); loggingNode != nil {
		if err := unmarshalLogging(loggingNode, &cfg.Logging); err != nil {
			return fmt.Errorf("logging: %w", err)
		}
	}

	// Metrics config
	if metricsNode := node.Get("metrics"); metricsNode != nil {
		if err := unmarshalMetrics(metricsNode, &cfg.Metrics); err != nil {
			return fmt.Errorf("metrics: %w", err)
		}
	}

	// DNSSEC config
	if dnssecNode := node.Get("dnssec"); dnssecNode != nil {
		if err := unmarshalDNSSEC(dnssecNode, &cfg.DNSSEC); err != nil {
			return fmt.Errorf("dnssec: %w", err)
		}
	}

	// Zones list
	if zonesNode := node.Get("zones"); zonesNode != nil && zonesNode.Type == NodeSequence {
		cfg.Zones = zonesNode.getStringSlice()
	}

	// Zone directory
	if zdn := node.Get("zone_dir"); zdn != nil && zdn.Value != "" {
		cfg.ZoneDir = zdn.Value
	}

	// Memory limit
	if mlNode := node.Get("memory_limit_mb"); mlNode != nil && mlNode.Value != "" {
		if v, err := strconv.Atoi(mlNode.Value); err == nil && v > 0 {
			cfg.MemoryLimitMB = v
		}
	}

	// ACL rules
	if aclNode := node.Get("acl"); aclNode != nil && aclNode.Type == NodeSequence {
		for _, ruleNode := range aclNode.Children {
			if ruleNode.Type == NodeMapping {
				var rule ACLRule
				rule.Name = ruleNode.GetString("name")
				rule.Action = ruleNode.GetString("action")
				rule.Redirect = ruleNode.GetString("redirect")
				if networksNode := ruleNode.Get("networks"); networksNode != nil && networksNode.Type == NodeSequence {
					rule.Networks = networksNode.getStringSlice()
				}
				if typesNode := ruleNode.Get("types"); typesNode != nil && typesNode.Type == NodeSequence {
					rule.Types = typesNode.getStringSlice()
				}
				cfg.ACL = append(cfg.ACL, rule)
			}
		}
	}

	// Blocklist config
	if blocklistNode := node.Get("blocklist"); blocklistNode != nil {
		if err := unmarshalBlocklist(blocklistNode, &cfg.Blocklist); err != nil {
			return fmt.Errorf("blocklist: %w", err)
		}
	}

	// RPZ config
	if rpzNode := node.Get("rpz"); rpzNode != nil {
		if err := unmarshalRPZ(rpzNode, &cfg.RPZ); err != nil {
			return fmt.Errorf("rpz: %w", err)
		}
	}

	// GeoDNS config
	if geodnsNode := node.Get("geodns"); geodnsNode != nil {
		if err := unmarshalGeoDNS(geodnsNode, &cfg.GeoDNS); err != nil {
			return fmt.Errorf("geodns: %w", err)
		}
	}

	// DNS64 config
	if dns64Node := node.Get("dns64"); dns64Node != nil {
		if err := unmarshalDNS64(dns64Node, &cfg.DNS64); err != nil {
			return fmt.Errorf("dns64: %w", err)
		}
	}

	// Cookie config (RFC 7873)
	if cookieNode := node.Get("cookie"); cookieNode != nil {
		if err := unmarshalCookie(cookieNode, &cfg.Cookie); err != nil {
			return fmt.Errorf("cookie: %w", err)
		}
	}

	// Cluster config
	if clusterNode := node.Get("cluster"); clusterNode != nil {
		if err := unmarshalCluster(clusterNode, &cfg.Cluster); err != nil {
			return fmt.Errorf("cluster: %w", err)
		}
	}

	// Slave zones config
	if slaveZonesNode := node.Get("slave_zones"); slaveZonesNode != nil && slaveZonesNode.Type == NodeSequence {
		for _, slaveNode := range slaveZonesNode.Children {
			if slaveNode.Type == NodeMapping {
				var slave SlaveZoneConfig
				slave.ZoneName = slaveNode.GetString("zone_name")
				slave.TransferType = slaveNode.GetString("transfer_type")
				if slave.TransferType == "" {
					slave.TransferType = "ixfr"
				}
				slave.TSIGKeyName = slaveNode.GetString("tsig_key_name")
				slave.TSIGSecret = slaveNode.GetString("tsig_secret")
				slave.Timeout = slaveNode.GetString("timeout")
				if slave.Timeout == "" {
					slave.Timeout = "30s"
				}
				slave.RetryInterval = slaveNode.GetString("retry_interval")
				if slave.RetryInterval == "" {
					slave.RetryInterval = "5m"
				}
				slave.MaxRetries = getInt(slaveNode, "max_retries", 0)

				// Parse masters
				if mastersNode := slaveNode.Get("masters"); mastersNode != nil {
					if mastersNode.Type == NodeSequence {
						slave.Masters = mastersNode.getStringSlice()
					} else if mastersNode.Type == NodeScalar {
						slave.Masters = []string{mastersNode.Value}
					}
				}

				cfg.SlaveZones = append(cfg.SlaveZones, slave)
			}
		}
	}

	// Parse views (split-horizon)
	if viewsNode := node.Get("views"); viewsNode != nil && viewsNode.Type == NodeSequence {
		for _, viewNode := range viewsNode.Children {
			if viewNode.Type == NodeMapping {
				var view ViewConfig
				view.Name = viewNode.GetString("name")
				view.MatchClients = getStringSlice(viewNode, "match_clients", nil)
				view.ZoneFiles = getStringSlice(viewNode, "zone_files", nil)
				cfg.Views = append(cfg.Views, view)
			}
		}
	}

	return nil
}

func unmarshalServer(node *Node, cfg *ServerConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Bind = getStringSlice(node, "bind", cfg.Bind)
	cfg.TCPBind = getStringSlice(node, "tcp_bind", cfg.TCPBind)
	cfg.UDPBind = getStringSlice(node, "udp_bind", cfg.UDPBind)
	cfg.Port = getInt(node, "port", cfg.Port)
	cfg.UDPWorkers = getInt(node, "udp_workers", cfg.UDPWorkers)
	cfg.TCPWorkers = getInt(node, "tcp_workers", cfg.TCPWorkers)

	if tlsNode := node.Get("tls"); tlsNode != nil {
		cfg.TLS.Enabled = getBool(tlsNode, "enabled", cfg.TLS.Enabled)
		cfg.TLS.CertFile = tlsNode.GetString("cert_file")
		cfg.TLS.KeyFile = tlsNode.GetString("key_file")
		cfg.TLS.Bind = tlsNode.GetString("bind")
	}

	if quicNode := node.Get("quic"); quicNode != nil {
		cfg.QUIC.Enabled = getBool(quicNode, "enabled", cfg.QUIC.Enabled)
		cfg.QUIC.CertFile = quicNode.GetString("cert_file")
		cfg.QUIC.KeyFile = quicNode.GetString("key_file")
		cfg.QUIC.Bind = quicNode.GetString("bind")
	}

	if xotNode := node.Get("xot"); xotNode != nil {
		cfg.XoT.Enabled = getBool(xotNode, "enabled", cfg.XoT.Enabled)
		cfg.XoT.CertFile = xotNode.GetString("cert_file")
		cfg.XoT.KeyFile = xotNode.GetString("key_file")
		cfg.XoT.CAFile = xotNode.GetString("ca_file")
		cfg.XoT.Bind = xotNode.GetString("bind")
		cfg.XoT.MinTLSVersion = getInt(xotNode, "min_tls_version", 12)
	}

	if httpNode := node.Get("http"); httpNode != nil {
		cfg.HTTP.Enabled = getBool(httpNode, "enabled", cfg.HTTP.Enabled)
		cfg.HTTP.Bind = httpNode.GetString("bind")
		cfg.HTTP.TLSCertFile = httpNode.GetString("tls_cert_file")
		cfg.HTTP.TLSKeyFile = httpNode.GetString("tls_key_file")
		cfg.HTTP.AuthToken = httpNode.GetString("auth_token")
		cfg.HTTP.AuthTokenRole = httpNode.GetString("auth_token_role")
		cfg.HTTP.AuthSecret = httpNode.GetString("auth_secret")
		cfg.HTTP.AllowedOrigins = getStringSlice(httpNode, "allowed_origins", cfg.HTTP.AllowedOrigins)
		cfg.HTTP.DoHEnabled = getBool(httpNode, "doh_enabled", cfg.HTTP.DoHEnabled)
		cfg.HTTP.DoHPath = httpNode.GetString("doh_path")
		if cfg.HTTP.DoHPath == "" {
			cfg.HTTP.DoHPath = "/dns-query"
		}
		cfg.HTTP.DoWSEnabled = getBool(httpNode, "dows_enabled", cfg.HTTP.DoWSEnabled)
		cfg.HTTP.DoWSPath = httpNode.GetString("dows_path")
		if cfg.HTTP.DoWSPath == "" {
			cfg.HTTP.DoWSPath = "/dns-ws"
		}
		cfg.HTTP.ODoHEnabled = getBool(httpNode, "odoh_enabled", cfg.HTTP.ODoHEnabled)
		cfg.HTTP.ODoHPath = httpNode.GetString("odoh_path")
		if cfg.HTTP.ODoHPath == "" {
			cfg.HTTP.ODoHPath = "/odoh"
		}
		cfg.HTTP.ODoHKEM = getInt(httpNode, "odoh_kem", cfg.HTTP.ODoHKEM)
		if cfg.HTTP.ODoHKEM == 0 {
			cfg.HTTP.ODoHKEM = 4 // X25519
		}
		cfg.HTTP.ODoHKDF = getInt(httpNode, "odoh_kdf", cfg.HTTP.ODoHKDF)
		if cfg.HTTP.ODoHKDF == 0 {
			cfg.HTTP.ODoHKDF = 1 // HKDF-SHA256
		}
		cfg.HTTP.ODoHAEAD = getInt(httpNode, "odoh_aead", cfg.HTTP.ODoHAEAD)
		if cfg.HTTP.ODoHAEAD == 0 {
			cfg.HTTP.ODoHAEAD = 1 // AES-256-GCM
		}
		if usersNode := httpNode.Get("users"); usersNode != nil && usersNode.Type == NodeSequence {
			for _, userNode := range usersNode.Children {
				if userNode.Type == NodeMapping {
					cfg.HTTP.Users = append(cfg.HTTP.Users, AuthUserConfig{
						Username: userNode.GetString("username"),
						Password: userNode.GetString("password"),
						Role:     userNode.GetString("role"),
					})
					// SECURITY: Zero out password from YAML node after loading
					// The password is hashed by auth.Store, clear the plaintext
					if passNode := userNode.Get("password"); passNode != nil {
						passNode.Value = strings.Repeat("\x00", len(passNode.Value))
					}
				}
			}
		}
	}

	return nil
}

func unmarshalResolution(node *Node, cfg *ResolutionConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Recursive = getBool(node, "recursive", cfg.Recursive)
	cfg.RootHints = node.GetString("root_hints")
	cfg.MaxDepth = getInt(node, "max_depth", cfg.MaxDepth)
	cfg.Timeout = node.GetString("timeout")
	if cfg.Timeout == "" {
		cfg.Timeout = "5s"
	}
	cfg.EDNS0BufferSize = getInt(node, "edns0_buffer_size", cfg.EDNS0BufferSize)
	cfg.QnameMinimization = node.GetBool("qname_minimization")
	cfg.Use0x20 = getBool(node, "use_0x20", cfg.Use0x20)

	return nil
}

func unmarshalUpstream(node *Node, cfg *UpstreamConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Servers = getStringSlice(node, "servers", cfg.Servers)
	cfg.Strategy = node.GetString("strategy")
	if cfg.Strategy == "" {
		cfg.Strategy = "random"
	}
	cfg.HealthCheck = node.GetString("health_check")
	if cfg.HealthCheck == "" {
		cfg.HealthCheck = "30s"
	}
	cfg.FailoverTimeout = node.GetString("failover_timeout")
	if cfg.FailoverTimeout == "" {
		cfg.FailoverTimeout = "5s"
	}

	// Parse topology configuration
	if topologyNode := node.Get("topology"); topologyNode != nil {
		cfg.Topology.Region = topologyNode.GetString("region")
		cfg.Topology.Zone = topologyNode.GetString("zone")
		cfg.Topology.Weight = getInt(topologyNode, "weight", 100)
	}

	// Parse anycast groups
	if anycastNode := node.Get("anycast_groups"); anycastNode != nil && anycastNode.Type == NodeSequence {
		for _, groupNode := range anycastNode.Children {
			if groupNode.Type == NodeMapping {
				var group AnycastGroupConfig
				group.AnycastIP = groupNode.GetString("anycast_ip")
				group.HealthCheck = groupNode.GetString("health_check")

				// Parse backends
				if backendsNode := groupNode.Get("backends"); backendsNode != nil && backendsNode.Type == NodeSequence {
					for _, backendNode := range backendsNode.Children {
						if backendNode.Type == NodeMapping {
							var backend AnycastBackendConfig
							backend.PhysicalIP = backendNode.GetString("physical_ip")
							backend.Port = getInt(backendNode, "port", 53)
							backend.Region = backendNode.GetString("region")
							backend.Zone = backendNode.GetString("zone")
							backend.Weight = getInt(backendNode, "weight", 100)
							group.Backends = append(group.Backends, backend)
						}
					}
				}

				cfg.AnycastGroups = append(cfg.AnycastGroups, group)
			}
		}
	}

	return nil
}

func unmarshalCache(node *Node, cfg *CacheConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Enabled = getBool(node, "enabled", cfg.Enabled)
	cfg.Size = getInt(node, "size", cfg.Size)
	cfg.DefaultTTL = getInt(node, "default_ttl", cfg.DefaultTTL)
	cfg.MaxTTL = getInt(node, "max_ttl", cfg.MaxTTL)
	cfg.MinTTL = getInt(node, "min_ttl", cfg.MinTTL)
	cfg.NegativeTTL = getInt(node, "negative_ttl", cfg.NegativeTTL)
	cfg.Prefetch = getBool(node, "prefetch", cfg.Prefetch)
	cfg.PrefetchThreshold = getInt(node, "prefetch_threshold", cfg.PrefetchThreshold)

	return nil
}

func unmarshalLogging(node *Node, cfg *LoggingConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Level = node.GetString("level")
	if cfg.Level == "" {
		cfg.Level = "info"
	}
	cfg.Format = node.GetString("format")
	if cfg.Format == "" {
		cfg.Format = "text"
	}
	cfg.Output = node.GetString("output")
	if cfg.Output == "" {
		cfg.Output = "stdout"
	}
	cfg.QueryLog = getBool(node, "query_log", cfg.QueryLog)
	cfg.QueryLogFile = node.GetString("query_log_file")

	return nil
}

func unmarshalMetrics(node *Node, cfg *MetricsConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Enabled = getBool(node, "enabled", cfg.Enabled)
	cfg.Bind = node.GetString("bind")
	if cfg.Bind == "" {
		cfg.Bind = ":9153"
	}
	cfg.Path = node.GetString("path")
	if cfg.Path == "" {
		cfg.Path = "/metrics"
	}

	return nil
}

func unmarshalDNSSEC(node *Node, cfg *DNSSECConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Enabled = getBool(node, "enabled", cfg.Enabled)
	cfg.TrustAnchor = node.GetString("trust_anchor")
	cfg.IgnoreTime = getBool(node, "ignore_time", cfg.IgnoreTime)
	cfg.RequireDNSSEC = getBool(node, "require_dnssec", cfg.RequireDNSSEC)

	// Parse signing configuration
	if signingNode := node.Get("signing"); signingNode != nil {
		cfg.Signing.Enabled = getBool(signingNode, "enabled", cfg.Signing.Enabled)
		cfg.Signing.SignatureValidity = signingNode.GetString("signature_validity")

		// Parse keys
		if keysNode := signingNode.Get("keys"); keysNode != nil && keysNode.Type == NodeSequence {
			for _, keyNode := range keysNode.Children {
				if keyNode.Type == NodeMapping {
					var key KeyConfig
					key.PrivateKey = keyNode.GetString("private_key")
					key.Type = keyNode.GetString("type")
					key.Algorithm = uint8(getInt(keyNode, "algorithm", 0))
					cfg.Signing.Keys = append(cfg.Signing.Keys, key)
				}
			}
		}

		// Parse NSEC3 configuration
		if nsec3Node := signingNode.Get("nsec3"); nsec3Node != nil {
			cfg.Signing.NSEC3 = &NSEC3Config{
				Iterations: uint16(getInt(nsec3Node, "iterations", 0)),
				Salt:       nsec3Node.GetString("salt"),
				OptOut:     getBool(nsec3Node, "opt_out", false),
			}
		}
	}

	return nil
}

func unmarshalBlocklist(node *Node, cfg *BlocklistConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Enabled = getBool(node, "enabled", cfg.Enabled)
	cfg.Files = getStringSlice(node, "files", cfg.Files)

	return nil
}

func unmarshalRPZ(node *Node, cfg *RPZConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Enabled = getBool(node, "enabled", cfg.Enabled)
	cfg.Files = getStringSlice(node, "files", cfg.Files)

	if zonesNode := node.Get("zones"); zonesNode != nil && zonesNode.Type == NodeSequence {
		for _, zoneNode := range zonesNode.Children {
			if zoneNode.Type == NodeMapping {
				var pz RPZPolicyZone
				pz.Name = zoneNode.GetString("name")
				pz.File = zoneNode.GetString("file")
				pz.Priority = getInt(zoneNode, "priority", 0)
				cfg.Zones = append(cfg.Zones, pz)
			}
		}
	}

	return nil
}

func unmarshalGeoDNS(node *Node, cfg *GeoDNSConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Enabled = getBool(node, "enabled", cfg.Enabled)
	cfg.MMDBFile = node.GetString("mmdb_file")

	if rulesNode := node.Get("rules"); rulesNode != nil && rulesNode.Type == NodeSequence {
		for _, ruleNode := range rulesNode.Children {
			if ruleNode.Type == NodeMapping {
				var rule GeoDNSRule
				rule.Domain = ruleNode.GetString("domain")
				rule.Type = ruleNode.GetString("type")
				rule.Default = ruleNode.GetString("default")
				// Parse records from a flat mapping: US, DE, etc.
				rule.Records = make(map[string]string)
				for _, key := range []string{"US", "CA", "DE", "FR", "GB", "JP", "CN", "AU",
					"BR", "IN", "RU", "KR", "MX", "IT", "ES", "NL", "SE", "PL", "NO",
					"NA", "EU", "AS", "SA", "OC", "AF"} {
					if v := ruleNode.GetString(key); v != "" {
						rule.Records[key] = v
					}
				}
				if len(rule.Records) > 0 || rule.Default != "" {
					cfg.Rules = append(cfg.Rules, rule)
				}
			}
		}
	}

	return nil
}

func unmarshalDNS64(node *Node, cfg *DNS64Config) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Enabled = getBool(node, "enabled", cfg.Enabled)
	if p := node.GetString("prefix"); p != "" {
		cfg.Prefix = p
	}
	if pl := getInt(node, "prefix_len", 0); pl > 0 {
		cfg.PrefixLen = pl
	}
	cfg.ExcludeNets = getStringSlice(node, "exclude_nets", nil)

	return nil
}

func unmarshalCookie(node *Node, cfg *CookieConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Enabled = getBool(node, "enabled", cfg.Enabled)
	if sr := node.GetString("secret_rotation"); sr != "" {
		cfg.SecretRotation = sr
	}

	return nil
}

func unmarshalCluster(node *Node, cfg *ClusterConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Enabled = getBool(node, "enabled", cfg.Enabled)
	cfg.NodeID = node.GetString("node_id")
	cfg.BindAddr = node.GetString("bind_addr")
	cfg.GossipPort = getInt(node, "gossip_port", cfg.GossipPort)
	cfg.Region = node.GetString("region")
	cfg.Zone = node.GetString("zone")
	cfg.Weight = getInt(node, "weight", cfg.Weight)
	cfg.CacheSync = getBool(node, "cache_sync", cfg.CacheSync)
	cfg.EncryptionKey = node.GetString("encryption_key")

	// Parse consensus mode (default: raft)
	cfg.ConsensusMode = getString(node, "consensus_mode", "raft")
	if cfg.ConsensusMode == "" {
		cfg.ConsensusMode = "raft"
	}

	// Parse seed nodes
	if seedNodesNode := node.Get("seed_nodes"); seedNodesNode != nil {
		if seedNodesNode.Type == NodeSequence {
			cfg.SeedNodes = seedNodesNode.getStringSlice()
		} else if seedNodesNode.Type == NodeScalar {
			cfg.SeedNodes = []string{seedNodesNode.Value}
		}
	}

	return nil
}

// Helper functions for unmarshaling

func getString(node *Node, key string, defaultValue string) string {
	if child := node.Get(key); child != nil && child.Type == NodeScalar {
		return child.Value
	}
	return defaultValue
}

func getStringSlice(node *Node, key string, defaultValue []string) []string {
	if child := node.Get(key); child != nil {
		if child.Type == NodeSequence {
			return child.getStringSlice()
		}
		if child.Type == NodeScalar {
			// Single value as slice
			return []string{child.Value}
		}
	}
	return defaultValue
}

func getInt(node *Node, key string, defaultValue int) int {
	if child := node.Get(key); child != nil && child.Type == NodeScalar {
		if val, err := strconv.Atoi(child.Value); err == nil {
			return val
		}
	}
	return defaultValue
}

func getBool(node *Node, key string, defaultValue bool) bool {
	if child := node.Get(key); child != nil && child.Type == NodeScalar {
		switch child.Value {
		case "true", "yes", "on":
			return true
		case "false", "no", "off":
			return false
		}
	}
	return defaultValue
}

// Validate checks the configuration for errors and returns a list of validation problems.
func (c *Config) Validate() []string {
	var errors []string

	// Validate server configuration
	errors = append(errors, c.validateServer()...)

	// Validate upstream configuration
	errors = append(errors, c.validateUpstream()...)

	// Validate cache configuration
	errors = append(errors, c.validateCache()...)

	// Validate logging configuration
	errors = append(errors, c.validateLogging()...)

	// Validate metrics configuration
	errors = append(errors, c.validateMetrics()...)

	// Validate DNSSEC configuration
	errors = append(errors, c.validateDNSSEC()...)

	// Validate ACL rules
	errors = append(errors, c.validateACL()...)

	// Validate blocklist configuration
	errors = append(errors, c.validateBlocklist()...)

	// Validate RPZ configuration
	errors = append(errors, c.validateRPZ()...)

	// Validate cluster configuration
	errors = append(errors, c.validateCluster()...)

	// Validate slave zones configuration
	errors = append(errors, c.validateSlaveZones()...)

	// Validate views (split-horizon) configuration
	errors = append(errors, c.validateViews()...)

	// Validate zone files exist
	for _, zone := range c.Zones {
		if zone == "" {
			errors = append(errors, "zone file path cannot be empty")
		}
	}

	return errors
}

func (c *Config) validateServer() []string {
	var errors []string

	// Validate bind addresses
	if len(c.Server.Bind) == 0 && len(c.Server.TCPBind) == 0 && len(c.Server.UDPBind) == 0 {
		errors = append(errors, "server: at least one bind address must be specified")
	}

	// Validate port
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		errors = append(errors, fmt.Sprintf("server: invalid port %d (must be 1-65535)", c.Server.Port))
	}

	// Validate TLS configuration
	if c.Server.TLS.Enabled {
		if c.Server.TLS.CertFile == "" {
			errors = append(errors, "server.tls: cert_file is required when TLS is enabled")
		}
		if c.Server.TLS.KeyFile == "" {
			errors = append(errors, "server.tls: key_file is required when TLS is enabled")
		}
	}

	// Validate HTTP TLS configuration for DoH
	if c.Server.HTTP.Enabled && c.Server.HTTP.DoHEnabled {
		if c.Server.HTTP.TLSCertFile == "" || c.Server.HTTP.TLSKeyFile == "" {
			errors = append(errors, "http: tls_cert_file and tls_key_file are required when DoH is enabled (DoH must use HTTPS)")
		}
	}

	// Validate worker counts
	if c.Server.UDPWorkers < 0 {
		errors = append(errors, "server: udp_workers cannot be negative")
	}
	if c.Server.TCPWorkers < 0 {
		errors = append(errors, "server: tcp_workers cannot be negative")
	}

	return errors
}

func (c *Config) validateUpstream() []string {
	var errors []string

	// Validate strategy
	validStrategies := map[string]bool{"random": true, "round_robin": true, "fastest": true}
	if !validStrategies[c.Upstream.Strategy] {
		errors = append(errors, fmt.Sprintf("upstream: invalid strategy '%s' (must be random, round_robin, or fastest)", c.Upstream.Strategy))
	}

	// Validate servers (only if no anycast groups configured)
	if len(c.Upstream.Servers) == 0 && len(c.Upstream.AnycastGroups) == 0 {
		errors = append(errors, "upstream: at least one server or anycast group must be specified")
	}

	for _, server := range c.Upstream.Servers {
		if !isValidServerAddress(server) {
			errors = append(errors, fmt.Sprintf("upstream: invalid server address '%s'", server))
		}
	}

	// Validate anycast groups
	for i, group := range c.Upstream.AnycastGroups {
		prefix := fmt.Sprintf("upstream.anycast_groups[%d]", i)

		if group.AnycastIP == "" {
			errors = append(errors, fmt.Sprintf("%s: anycast_ip is required", prefix))
		} else if !isValidIP(group.AnycastIP) {
			errors = append(errors, fmt.Sprintf("%s: anycast_ip '%s' must be a valid IP address", prefix, group.AnycastIP))
		}

		if len(group.Backends) == 0 {
			errors = append(errors, fmt.Sprintf("%s: at least one backend must be specified", prefix))
		}

		for j, backend := range group.Backends {
			backendPrefix := fmt.Sprintf("%s.backends[%d]", prefix, j)

			if backend.PhysicalIP == "" {
				errors = append(errors, fmt.Sprintf("%s: physical_ip is required", backendPrefix))
			} else if !isValidIP(backend.PhysicalIP) {
				errors = append(errors, fmt.Sprintf("%s: physical_ip '%s' must be a valid IP address", backendPrefix, backend.PhysicalIP))
			}

			if backend.Port < 1 || backend.Port > 65535 {
				errors = append(errors, fmt.Sprintf("%s: port %d must be between 1-65535", backendPrefix, backend.Port))
			}

			if backend.Weight < 0 || backend.Weight > 100 {
				errors = append(errors, fmt.Sprintf("%s: weight %d must be between 0-100", backendPrefix, backend.Weight))
			}
		}
	}

	// Validate topology
	if c.Upstream.Topology.Weight < 0 || c.Upstream.Topology.Weight > 100 {
		errors = append(errors, fmt.Sprintf("upstream.topology: weight %d must be between 0-100", c.Upstream.Topology.Weight))
	}

	return errors
}

func (c *Config) validateCache() []string {
	var errors []string

	if !c.Cache.Enabled {
		return errors
	}

	// Validate size
	if c.Cache.Size < 1 {
		errors = append(errors, "cache: size must be at least 1")
	}

	// Validate TTLs
	if c.Cache.MinTTL < 0 {
		errors = append(errors, "cache: min_ttl cannot be negative")
	}
	if c.Cache.MaxTTL < 0 {
		errors = append(errors, "cache: max_ttl cannot be negative")
	}
	if c.Cache.DefaultTTL < 0 {
		errors = append(errors, "cache: default_ttl cannot be negative")
	}
	if c.Cache.MinTTL > c.Cache.MaxTTL {
		errors = append(errors, fmt.Sprintf("cache: min_ttl (%d) cannot be greater than max_ttl (%d)", c.Cache.MinTTL, c.Cache.MaxTTL))
	}
	if c.Cache.DefaultTTL < c.Cache.MinTTL || c.Cache.DefaultTTL > c.Cache.MaxTTL {
		errors = append(errors, fmt.Sprintf("cache: default_ttl (%d) must be between min_ttl (%d) and max_ttl (%d)",
			c.Cache.DefaultTTL, c.Cache.MinTTL, c.Cache.MaxTTL))
	}
	if c.Cache.NegativeTTL < 0 {
		errors = append(errors, "cache: negative_ttl cannot be negative")
	}

	// Validate prefetch threshold
	if c.Cache.Prefetch && c.Cache.PrefetchThreshold < 1 {
		errors = append(errors, "cache: prefetch_threshold must be at least 1")
	}

	return errors
}

func (c *Config) validateLogging() []string {
	var errors []string

	// Validate log level
	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true, "fatal": true}
	if !validLevels[c.Logging.Level] {
		errors = append(errors, fmt.Sprintf("logging: invalid level '%s' (must be debug, info, warn, error, or fatal)", c.Logging.Level))
	}

	// Validate format
	validFormats := map[string]bool{"json": true, "text": true}
	if !validFormats[c.Logging.Format] {
		errors = append(errors, fmt.Sprintf("logging: invalid format '%s' (must be json or text)", c.Logging.Format))
	}

	return errors
}

func (c *Config) validateMetrics() []string {
	var errors []string

	if !c.Metrics.Enabled {
		return errors
	}

	// Validate bind address
	if c.Metrics.Bind == "" {
		errors = append(errors, "metrics: bind address cannot be empty when enabled")
	}

	// Validate path
	if c.Metrics.Path == "" {
		errors = append(errors, "metrics: path cannot be empty")
	}
	if !strings.HasPrefix(c.Metrics.Path, "/") {
		errors = append(errors, fmt.Sprintf("metrics: path '%s' must start with /", c.Metrics.Path))
	}

	return errors
}

func (c *Config) validateDNSSEC() []string {
	var errors []string

	if !c.DNSSEC.Enabled {
		return errors
	}

	// Validate signing configuration
	if c.DNSSEC.Signing.Enabled {
		if len(c.DNSSEC.Signing.Keys) == 0 {
			errors = append(errors, "dnssec.signing: at least one key must be specified when signing is enabled")
		}

		validKeyTypes := map[string]bool{"ksk": true, "zsk": true}
		for i, key := range c.DNSSEC.Signing.Keys {
			prefix := fmt.Sprintf("dnssec.signing.keys[%d]", i)
			if key.PrivateKey == "" {
				errors = append(errors, fmt.Sprintf("%s: private_key is required", prefix))
			}
			if key.Type != "" && !validKeyTypes[key.Type] {
				errors = append(errors, fmt.Sprintf("%s: invalid type '%s' (must be ksk or zsk)", prefix, key.Type))
			}
			if key.Algorithm != 0 {
				validAlgorithms := map[uint8]bool{5: true, 8: true, 10: true, 13: true, 14: true, 15: true}
				if !validAlgorithms[key.Algorithm] {
					errors = append(errors, fmt.Sprintf("%s: unsupported algorithm %d", prefix, key.Algorithm))
				}
			}
		}
	}

	return errors
}

func (c *Config) validateACL() []string {
	var errors []string

	validActions := map[string]bool{"allow": true, "deny": true, "redirect": true}

	for i, rule := range c.ACL {
		prefix := fmt.Sprintf("acl[%d]", i)

		// Validate action
		if !validActions[rule.Action] {
			errors = append(errors, fmt.Sprintf("%s: invalid action '%s' (must be allow, deny, or redirect)", prefix, rule.Action))
		}

		// Validate redirect for redirect action
		if rule.Action == "redirect" && rule.Redirect == "" {
			errors = append(errors, fmt.Sprintf("%s: redirect target is required when action is 'redirect'", prefix))
		}

		// Validate networks
		for _, network := range rule.Networks {
			if !isValidCIDR(network) {
				errors = append(errors, fmt.Sprintf("%s: invalid network '%s' (must be valid CIDR)", prefix, network))
			}
		}

		// Validate query types
		for _, qt := range rule.Types {
			if !isValidQueryType(qt) {
				errors = append(errors, fmt.Sprintf("%s: invalid query type '%s'", prefix, qt))
			}
		}
	}

	return errors
}

func (c *Config) validateBlocklist() []string {
	var errors []string

	if !c.Blocklist.Enabled {
		return errors
	}

	// Validate blocklist files exist
	for _, file := range c.Blocklist.Files {
		if file == "" {
			errors = append(errors, "blocklist: file path cannot be empty")
			continue
		}
		if _, err := os.Stat(file); os.IsNotExist(err) {
			errors = append(errors, fmt.Sprintf("blocklist: file '%s' does not exist", file))
		}
	}

	return errors
}

func (c *Config) validateRPZ() []string {
	var errors []string

	if !c.RPZ.Enabled {
		return errors
	}

	for _, file := range c.RPZ.Files {
		if file == "" {
			errors = append(errors, "rpz: file path cannot be empty")
			continue
		}
		if _, err := os.Stat(file); os.IsNotExist(err) {
			errors = append(errors, fmt.Sprintf("rpz: file '%s' does not exist", file))
		}
	}
	for _, pz := range c.RPZ.Zones {
		if pz.File == "" {
			errors = append(errors, "rpz: zone file path cannot be empty")
			continue
		}
		if _, err := os.Stat(pz.File); os.IsNotExist(err) {
			errors = append(errors, fmt.Sprintf("rpz: zone file '%s' does not exist", pz.File))
		}
	}

	return errors
}

func (c *Config) validateCluster() []string {
	var errors []string

	if !c.Cluster.Enabled {
		return errors
	}

	// Validate gossip port
	if c.Cluster.GossipPort < 1 || c.Cluster.GossipPort > 65535 {
		errors = append(errors, fmt.Sprintf("cluster: invalid gossip_port %d (must be 1-65535)", c.Cluster.GossipPort))
	}

	// Validate weight
	if c.Cluster.Weight < 0 {
		errors = append(errors, "cluster: weight cannot be negative")
	}

	// Validate seed nodes format
	for _, seed := range c.Cluster.SeedNodes {
		if seed == "" {
			errors = append(errors, "cluster: seed node cannot be empty")
			continue
		}
		// Seed nodes should be host:port format
		host, port, err := net.SplitHostPort(seed)
		if err != nil {
			errors = append(errors, fmt.Sprintf("cluster: invalid seed node '%s' (expected host:port format)", seed))
			continue
		}
		if host == "" {
			errors = append(errors, fmt.Sprintf("cluster: seed node '%s' has empty host", seed))
		}
		if portNum, err := strconv.Atoi(port); err != nil || portNum < 1 || portNum > 65535 {
			errors = append(errors, fmt.Sprintf("cluster: seed node '%s' has invalid port", seed))
		}
	}

	return errors
}

func (c *Config) validateSlaveZones() []string {
	var errors []string

	for i, slave := range c.SlaveZones {
		prefix := fmt.Sprintf("slave_zones[%d]", i)

		// Validate zone name
		if slave.ZoneName == "" {
			errors = append(errors, fmt.Sprintf("%s: zone_name is required", prefix))
		}

		// Validate masters
		if len(slave.Masters) == 0 {
			errors = append(errors, fmt.Sprintf("%s: at least one master server must be specified", prefix))
		}
		for _, master := range slave.Masters {
			if !isValidServerAddress(master) {
				errors = append(errors, fmt.Sprintf("%s: invalid master address '%s'", prefix, master))
			}
		}

		// Validate transfer type
		if slave.TransferType != "" && slave.TransferType != "ixfr" && slave.TransferType != "axfr" {
			errors = append(errors, fmt.Sprintf("%s: invalid transfer_type '%s' (must be 'ixfr' or 'axfr')", prefix, slave.TransferType))
		}

		// Validate max retries
		if slave.MaxRetries < 0 {
			errors = append(errors, fmt.Sprintf("%s: max_retries cannot be negative", prefix))
		}
	}

	return errors
}

func (c *Config) validateViews() []string {
	var errors []string
	names := make(map[string]bool)

	for i, view := range c.Views {
		prefix := fmt.Sprintf("views[%d]", i)

		if view.Name == "" {
			errors = append(errors, fmt.Sprintf("%s: name is required", prefix))
		} else if names[view.Name] {
			errors = append(errors, fmt.Sprintf("%s: duplicate view name '%s'", prefix, view.Name))
		}
		names[view.Name] = true

		if len(view.MatchClients) == 0 {
			errors = append(errors, fmt.Sprintf("%s: at least one match_clients entry is required", prefix))
		}
		for _, cidr := range view.MatchClients {
			if strings.EqualFold(cidr, "any") {
				continue
			}
			if !strings.Contains(cidr, "/") {
				if net.ParseIP(cidr) == nil {
					errors = append(errors, fmt.Sprintf("%s: invalid match_clients entry '%s'", prefix, cidr))
				}
				continue
			}
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				errors = append(errors, fmt.Sprintf("%s: invalid CIDR '%s'", prefix, cidr))
			}
		}
	}

	return errors
}

// isValidServerAddress checks if a string is a valid DNS server address (host:port or IP:port).
func isValidServerAddress(addr string) bool {
	if addr == "" {
		return false
	}

	// Handle special cases
	if addr == "localhost" || addr == "127.0.0.1" || addr == "::1" {
		return true
	}

	// Check for port
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// No port specified - check if it's a valid IP or hostname
		return isValidIP(addr) || isValidHostname(addr)
	}

	// Validate port
	if port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return false
		}
	}

	// Validate host
	return host == "" || isValidIP(host) || isValidHostname(host)
}

// isValidIP checks if a string is a valid IP address.
func isValidIP(s string) bool {
	return net.ParseIP(s) != nil
}

// isValidHostname checks if a string looks like a valid hostname.
func isValidHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}

	// Each label must be valid
	labels := strings.Split(s, ".")
	for _, label := range labels {
		if !isValidLabel(label) {
			return false
		}
	}

	return true
}

// isValidLabel checks if a DNS label is valid.
func isValidLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}

	// Must start and end with alphanumeric
	if !isAlphaNum(label[0]) || !isAlphaNum(label[len(label)-1]) {
		return false
	}

	// Middle can be alphanumeric or hyphen
	for i := 1; i < len(label)-1; i++ {
		c := label[i]
		if !isAlphaNum(c) && c != '-' {
			return false
		}
	}

	return true
}

// isValidCIDR checks if a string is a valid CIDR notation.
func isValidCIDR(s string) bool {
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// isValidQueryType checks if a string is a valid DNS query type.
func isValidQueryType(s string) bool {
	// Common query types
	validTypes := map[string]bool{
		"A": true, "AAAA": true, "CNAME": true, "MX": true, "NS": true,
		"PTR": true, "SOA": true, "SRV": true, "TXT": true, "ANY": true,
		"DNSKEY": true, "DS": true, "NSEC": true, "NSEC3": true, "RRSIG": true,
		"AFSDB": true, "APL": true, "CAA": true, "CDNSKEY": true, "CDS": true,
		"CERT": true, "DHCID": true, "DLV": true, "DNAME": true, "HINFO": true,
		"HIP": true, "IPSECKEY": true, "KEY": true, "KX": true, "LOC": true,
		"NAPTR": true, "NSEC3PARAM": true, "OPENPGPKEY": true, "RP": true,
		"SIG": true, "SSHFP": true, "TA": true, "TKEY": true, "TLSA": true,
		"TSIG": true, "URI": true, "ZONEMD": true,
	}

	// Check uppercase
	if validTypes[strings.ToUpper(s)] {
		return true
	}

	// Also accept numeric type values (TYPE12345)
	if strings.HasPrefix(strings.ToUpper(s), "TYPE") {
		numStr := s[4:]
		if _, err := strconv.Atoi(numStr); err == nil {
			return true
		}
	}

	return false
}
