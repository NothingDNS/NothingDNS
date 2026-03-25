package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// Config represents the DNS server configuration.
type Config struct {
	// Server configuration
	Server ServerConfig `yaml:"server"`

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

	// ACL configuration
	ACL []ACLRule `yaml:"acl"`

	// Blocklist configuration
	Blocklist BlocklistConfig `yaml:"blocklist"`
}

// BlocklistConfig holds blocklist configuration.
type BlocklistConfig struct {
	Enabled bool     `yaml:"enabled"`
	Files   []string `yaml:"files"`
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

	// HTTP API configuration
	HTTP HTTPConfig `yaml:"http"`

	// Worker pool sizes
	UDPWorkers int `yaml:"udp_workers"`
	TCPWorkers int `yaml:"tcp_workers"`
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

// HTTPConfig contains HTTP API settings.
type HTTPConfig struct {
	// Enable HTTP API
	Enabled bool `yaml:"enabled"`

	// Listen address
	Bind string `yaml:"bind"`

	// Authentication token (optional)
	AuthToken string `yaml:"auth_token"`
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
			Recursive:       false,
			MaxDepth:        10,
			Timeout:         "5s",
			EDNS0BufferSize: 4096,
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
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "text",
			Output:     "stdout",
			QueryLog:   false,
			QueryLogFile: "",
		},
		Metrics: MetricsConfig{
			Enabled: false,
			Bind:    ":9153",
			Path:    "/metrics",
		},
		DNSSEC: DNSSECConfig{
			Enabled:     false,
			TrustAnchor: "",
			IgnoreTime:  false,
		},
		Blocklist: BlocklistConfig{
			Enabled: false,
			Files:   []string{},
		},
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
					varValue := os.Getenv(varName)
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
				varValue := os.Getenv(varName)
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

	if httpNode := node.Get("http"); httpNode != nil {
		cfg.HTTP.Enabled = getBool(httpNode, "enabled", cfg.HTTP.Enabled)
		cfg.HTTP.Bind = httpNode.GetString("bind")
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

	// Validate servers
	if len(c.Upstream.Servers) == 0 {
		errors = append(errors, "upstream: at least one server must be specified")
	}

	for _, server := range c.Upstream.Servers {
		if !isValidServerAddress(server) {
			errors = append(errors, fmt.Sprintf("upstream: invalid server address '%s'", server))
		}
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

	// Trust anchor is recommended but not strictly required (can use built-in)
	if c.DNSSEC.TrustAnchor != "" {
		// Check if file exists (optional validation)
		if _, err := os.Stat(c.DNSSEC.TrustAnchor); os.IsNotExist(err) {
			// Just a warning - don't fail validation for this
			// errors = append(errors, fmt.Sprintf("dnssec: trust_anchor file '%s' does not exist", c.DNSSEC.TrustAnchor))
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
