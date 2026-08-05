package config

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/auth"
)

// placeholderSecretTokens is the list of substrings that must never appear in a
// live secret field. They are the literal strings shipped (historically or now)
// in example configs under deploy/, docs/, and helm/. The match is
// placeholderSecretRE matches common placeholder/weak secret patterns.
// Covers: CHANGE-THIS, CHANGEME, placeholder, your-secret/password,
// insecure, default, replace-me, INSERT-YOUR, and common template markers.
var placeholderSecretRE = regexp.MustCompile(`(?i)(change.?this|changeme|placeholder|your.?secret|your.?password|insecure.?default|replace.?me|insert.?your|temp| dummy|default.?secret|example.?key)`)

// looksLikePlaceholderSecret returns the matched placeholder pattern if s
// contains a known placeholder substring (case-insensitive), or "" if it
// appears to be a real secret.
func looksLikePlaceholderSecret(s string) string {
	if s == "" {
		return ""
	}
	if placeholderSecretRE.MatchString(s) {
		return placeholderSecretRE.FindString(s)
	}
	return ""
}

func appendDurationValidation(errors []string, prefix, field, value string) []string {
	if value == "" {
		return errors
	}
	if _, err := time.ParseDuration(value); err != nil {
		return append(errors, fmt.Sprintf("%s: invalid %s %q: %v", prefix, field, value, err))
	}
	return errors
}

// secretHasMinEntropy returns an error if the secret is below 32 bytes or
// appears to be low-entropy (detectable via Shannon entropy heuristic).
// validateHex32 checks that name's value is exactly 64 hex chars
// (i.e. 32 bytes when decoded). Used by the L-6 at-rest encryption
// keys (storage.encryption_key, cluster.snapshot_encryption_key).
func validateHex32(name, value string) error {
	raw, err := hex.DecodeString(value)
	if err != nil {
		return fmt.Errorf("%s is not valid hex: %w", name, err)
	}
	if len(raw) != 32 {
		return fmt.Errorf("%s must decode to 32 bytes (got %d)", name, len(raw))
	}
	return nil
}

func secretHasMinEntropy(name, secret string) error {
	if len(secret) < 32 {
		return fmt.Errorf("%s is too short: %d bytes (minimum 32)", name, len(secret))
	}
	// Shannon entropy: count character class frequencies
	var lower, upper, digit, other int
	for _, b := range secret {
		switch {
		case b >= 'a' && b <= 'z':
			lower++
		case b >= 'A' && b <= 'Z':
			upper++
		case b >= '0' && b <= '9':
			digit++
		default:
			other++
		}
	}
	n := float64(len(secret))
	// If all chars fall in 2 or fewer classes, it's likely patterned — flag it
	classes := 0
	if lower > 0 {
		classes++
	}
	if upper > 0 {
		classes++
	}
	if digit > 0 {
		classes++
	}
	if other > 0 {
		classes++
	}
	if classes <= 2 && int(n) > 0 {
		dominant := float64(max(lower, max(upper, max(digit, other))))
		if dominant/n > 0.85 {
			return fmt.Errorf("%s appears low-entropy (%.0f%% in one char class) — use a cryptographically random value", name, dominant/n*100)
		}
	}
	return nil
}

// validateSecrets refuses to start when a secret field still contains a known
// template placeholder (VULN-050). The failure mode being prevented: an
// operator copies deploy/production.yaml verbatim, the server hashes
// "UNIQUE-STRONG-PASSWORD" into a real bcrypt credential, and every copy of
// the deployment ships with the same trivially-guessable admin login. Env
// substitution runs before Validate(), so a correctly-set ${NOTHINGDNS_*}
// reference never trips this check — only a literal placeholder does.
func (c *Config) validateSecrets() []string {
	var errors []string

	if token := looksLikePlaceholderSecret(c.Server.HTTP.AuthToken); token != "" {
		errors = append(errors, fmt.Sprintf(
			"http.auth_token still contains placeholder %q — set it via ${NOTHINGDNS_AUTH_TOKEN} or replace with a real secret before starting",
			token))
	} else if c.Server.HTTP.AuthToken != "" {
		// Entropy check only applies when placeholder check passes (non-empty non-placeholder)
		if err := secretHasMinEntropy("http.auth_token", c.Server.HTTP.AuthToken); err != nil {
			errors = append(errors, err.Error())
		}
	}
	if token := looksLikePlaceholderSecret(c.Server.HTTP.AuthSecret); token != "" {
		errors = append(errors, fmt.Sprintf(
			"http.auth_secret still contains placeholder %q — set it via ${NOTHINGDNS_AUTH_SECRET} or replace with a real 32-byte random secret before starting",
			token))
	} else if c.Server.HTTP.AuthSecret != "" {
		// L-5: AuthSecret is the HMAC-SHA512 session-signing key — a
		// short / low-entropy value lets an attacker brute-force token
		// forgery. The placeholder branch above already short-circuits
		// the obvious "REPLACEME" mistakes; this branch catches the
		// less obvious "I picked a short word" mistake. Same gate the
		// auth_token block above uses.
		if err := secretHasMinEntropy("http.auth_secret", c.Server.HTTP.AuthSecret); err != nil {
			errors = append(errors, err.Error())
		}
	}
	if token := looksLikePlaceholderSecret(c.Metrics.AuthToken); token != "" {
		errors = append(errors, fmt.Sprintf(
			"metrics.auth_token still contains placeholder %q — set it via ${NOTHINGDNS_METRICS_AUTH_TOKEN} or replace with a real secret before starting",
			token))
	} else if c.Metrics.AuthToken != "" {
		if err := secretHasMinEntropy("metrics.auth_token", c.Metrics.AuthToken); err != nil {
			errors = append(errors, err.Error())
		}
	}
	for i, user := range c.Server.HTTP.Users {
		if token := looksLikePlaceholderSecret(user.Password); token != "" {
			errors = append(errors, fmt.Sprintf(
				"http.users[%d] (%q) password still contains placeholder %q — set it via an environment variable or replace with a real secret before starting",
				i, user.Username, token))
		}
	}

	// Validate cluster encryption key entropy
	if c.Cluster.Enabled && c.Cluster.EncryptionKey != "" {
		if err := secretHasMinEntropy("cluster.encryption_key", c.Cluster.EncryptionKey); err != nil {
			errors = append(errors, err.Error())
		}
	}

	// L-6: validate the new at-rest encryption keys. Both must be
	// 32-byte hex (64 hex chars) when set. Reject equal-to-other
	// keys to keep the gossip / KV / snapshot trust domains
	// separate; if one leaks, the blast radius stays bounded.
	storageEnc := strings.TrimSpace(c.Storage.EncryptionKey)
	if storageEnc != "" {
		if err := validateHex32("storage.encryption_key", storageEnc); err != nil {
			errors = append(errors, err.Error())
		}
	}
	snapEnc := strings.TrimSpace(c.Cluster.SnapshotEncryptionKey)
	if snapEnc != "" {
		if err := validateHex32("cluster.snapshot_encryption_key", snapEnc); err != nil {
			errors = append(errors, err.Error())
		}
	}
	gossipEnc := strings.TrimSpace(c.Cluster.EncryptionKey)
	if storageEnc != "" && storageEnc == gossipEnc {
		errors = append(errors, "storage.encryption_key must differ from cluster.encryption_key (key separation)")
	}
	if snapEnc != "" && snapEnc == gossipEnc {
		errors = append(errors, "cluster.snapshot_encryption_key must differ from cluster.encryption_key (key separation)")
	}
	if storageEnc != "" && snapEnc != "" && storageEnc == snapEnc {
		errors = append(errors, "storage.encryption_key must differ from cluster.snapshot_encryption_key (key separation)")
	}

	// Validate per-slave TSIG secrets
	for i, slave := range c.SlaveZones {
		if slave.TSIGSecret != "" {
			if err := secretHasMinEntropy(fmt.Sprintf("slave_zones[%d].tsig_secret", i), slave.TSIGSecret); err != nil {
				errors = append(errors, err.Error())
			}
		}
	}

	return errors
}

func (c *Config) validateHTTPUsers() []string {
	var errors []string
	if role := strings.ToLower(strings.TrimSpace(c.Server.HTTP.AuthTokenRole)); role != "" {
		if err := auth.ValidateRole(auth.Role(role)); err != nil {
			errors = append(errors, fmt.Sprintf("http.auth_token_role: %v", err))
		}
	}
	if strings.TrimSpace(c.Server.HTTP.TokenPersistencePath) != "" && strings.TrimSpace(c.Server.HTTP.AuthSecret) == "" {
		errors = append(errors, "http.token_persistence_path requires http.auth_secret so persisted sessions can be decrypted after restart")
	}
	if c.Server.HTTP.MaxSessionsPerUser < 0 {
		errors = append(errors, "http.max_sessions_per_user cannot be negative")
	}
	seen := make(map[string]int, len(c.Server.HTTP.Users))
	for i, user := range c.Server.HTTP.Users {
		prefix := fmt.Sprintf("http.users[%d]", i)
		if err := auth.ValidateUsername(user.Username); err != nil {
			errors = append(errors, fmt.Sprintf("%s.username: %v", prefix, err))
		} else if previous, ok := seen[user.Username]; ok {
			errors = append(errors, fmt.Sprintf("%s.username: duplicate username %q (already defined at http.users[%d])", prefix, user.Username, previous))
		} else {
			seen[user.Username] = i
		}
		if err := auth.ValidatePassword(user.Password); err != nil {
			errors = append(errors, fmt.Sprintf("%s.password: %v", prefix, err))
		}
		if err := auth.ValidateRole(auth.Role(user.Role)); err != nil {
			errors = append(errors, fmt.Sprintf("%s.role: %v", prefix, err))
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
	if c.Server.HTTP.ODoHEnabled {
		errors = appendODoHSuiteValidation(errors, "http", "odoh_kem", "odoh_kdf", "odoh_aead",
			c.Server.HTTP.ODoHKEM, c.Server.HTTP.ODoHKDF, c.Server.HTTP.ODoHAEAD)
	}
	if c.Server.QUIC.Enabled {
		certFile, keyFile := effectiveQUICCertificate(c)
		if certFile == "" || keyFile == "" {
			errors = append(errors, "server.quic: cert_file and key_file are required when QUIC/DoQ is enabled (or configure server.tls cert_file/key_file for fallback)")
		}
	}
	if c.Server.XoT.Enabled {
		certFile, keyFile := effectiveXoTCertificate(c)
		if certFile == "" || keyFile == "" {
			errors = append(errors, "server.xot: cert_file and key_file are required when XoT is enabled (or configure server.tls cert_file/key_file for fallback)")
		}
		if c.Server.XoT.MinTLSVersion != 0 && c.Server.XoT.MinTLSVersion != 12 && c.Server.XoT.MinTLSVersion != 13 {
			errors = append(errors, fmt.Sprintf("server.xot: invalid min_tls_version %d (must be 12 or 13)", c.Server.XoT.MinTLSVersion))
		}
		if c.Server.TLS.Enabled && effectiveTLSBind(c.Server.TLS.Bind) == effectiveTLSBind(c.Server.XoT.Bind) {
			errors = append(errors, "server.xot.bind conflicts with server.tls.bind; DoT and XoT require distinct TCP listen addresses")
		}
	}

	// Validate worker counts
	if c.Server.UDPWorkers < 0 {
		errors = append(errors, "server: udp_workers cannot be negative")
	}
	if c.Server.TCPWorkers < 0 {
		errors = append(errors, "server: tcp_workers cannot be negative")
	}
	errors = appendDurationValidation(errors, "server", "shutdown_timeout", c.ShutdownTimeout)

	return errors
}

func effectiveTLSBind(bind string) string {
	if strings.TrimSpace(bind) == "" {
		return ":853"
	}
	return strings.TrimSpace(bind)
}

func effectiveQUICCertificate(c *Config) (string, string) {
	certFile := c.Server.QUIC.CertFile
	keyFile := c.Server.QUIC.KeyFile
	if certFile == "" && c.Server.TLS.CertFile != "" {
		certFile = c.Server.TLS.CertFile
		keyFile = c.Server.TLS.KeyFile
	}
	return certFile, keyFile
}

func effectiveXoTCertificate(c *Config) (string, string) {
	certFile := c.Server.XoT.CertFile
	keyFile := c.Server.XoT.KeyFile
	if certFile == "" && c.Server.TLS.CertFile != "" {
		certFile = c.Server.TLS.CertFile
		keyFile = c.Server.TLS.KeyFile
	}
	return certFile, keyFile
}

func (c *Config) validateCookie() []string {
	var errors []string

	errors = appendDurationValidation(errors, "cookie", "secret_rotation", c.Cookie.SecretRotation)

	return errors
}

func (c *Config) validateDSO() []string {
	var errors []string

	errors = appendDurationValidation(errors, "dso", "session_timeout", c.DSO.SessionTimeout)
	errors = appendDurationValidation(errors, "dso", "heartbeat_interval", c.DSO.HeartbeatInterval)
	if c.DSO.MaxSessions < 0 {
		errors = append(errors, "dso: max_sessions cannot be negative")
	}

	return errors
}

func (c *Config) validateExtensions() []string {
	var errors []string

	if c.MDNS.Enabled {
		ip := net.ParseIP(c.MDNS.MulticastIP)
		if ip == nil {
			errors = append(errors, fmt.Sprintf("mdns: multicast_ip %q must be a valid IP address", c.MDNS.MulticastIP))
		} else if ip.To4() == nil || !ip.IsMulticast() {
			errors = append(errors, fmt.Sprintf("mdns: multicast_ip %q must be an IPv4 multicast address", c.MDNS.MulticastIP))
		}
		if c.MDNS.Port < 1 || c.MDNS.Port > 65535 {
			errors = append(errors, fmt.Sprintf("mdns: invalid port %d (must be 1-65535)", c.MDNS.Port))
		}
	}

	if c.ODoH.Enabled {
		if c.ODoH.TargetURL == "" {
			errors = appendODoHSuiteValidation(errors, "odoh", "kem", "kdf", "aead",
				c.ODoH.KEM, c.ODoH.KDF, c.ODoH.AEAD)
		}
		errors = appendURLValidation(errors, "odoh", "target_url", c.ODoH.TargetURL)
		errors = appendURLValidation(errors, "odoh", "proxy_url", c.ODoH.ProxyURL)
	}

	if c.Catalog.Enabled {
		errors = append(errors, "catalog: enabled but catalog zones are not wired into the daemon runtime")
	}
	if c.YANG.Enabled {
		errors = append(errors, "yang: enabled but YANG services are not wired into the daemon runtime")
	}

	return errors
}

func appendURLValidation(errors []string, prefix, field, value string) []string {
	if value == "" {
		return errors
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return append(errors, fmt.Sprintf("%s: invalid %s %q", prefix, field, value))
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return append(errors, fmt.Sprintf("%s: invalid %s %q: scheme must be http or https", prefix, field, value))
	}
	return errors
}

func appendODoHSuiteValidation(errors []string, prefix, kemField, kdfField, aeadField string, kem, kdf, aead int) []string {
	if !isValidODoHKEM(kem) {
		errors = append(errors, fmt.Sprintf("%s: unsupported %s %d", prefix, kemField, kem))
	}
	if !isValidODoHKDF(kdf) {
		errors = append(errors, fmt.Sprintf("%s: unsupported %s %d", prefix, kdfField, kdf))
	}
	if !isValidODoHAEAD(aead) {
		errors = append(errors, fmt.Sprintf("%s: unsupported %s %d", prefix, aeadField, aead))
	}
	return errors
}

func isValidODoHKEM(kem int) bool {
	return kem == 4
}

func isValidODoHKDF(kdf int) bool {
	return kdf == 1
}

func isValidODoHAEAD(aead int) bool {
	return aead == 1 || aead == 3
}

func (c *Config) validateResolution() []string {
	var errors []string

	if c.Resolution.MaxDepth < 0 {
		errors = append(errors, "resolution: max_depth cannot be negative")
	}
	if c.Resolution.EDNS0BufferSize < 0 || c.Resolution.EDNS0BufferSize > 65535 {
		errors = append(errors, fmt.Sprintf("resolution: edns0_buffer_size %d must be between 0-65535", c.Resolution.EDNS0BufferSize))
	}
	errors = appendDurationValidation(errors, "resolution", "timeout", c.Resolution.Timeout)
	if c.Resolution.Recursive && c.Resolution.RootHints != "" {
		if _, err := os.Stat(c.Resolution.RootHints); err != nil {
			errors = append(errors, fmt.Sprintf("resolution: root_hints %q is not accessible: %v", c.Resolution.RootHints, err))
		}
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

	errors = appendDurationValidation(errors, "upstream", "health_check", c.Upstream.HealthCheck)
	errors = appendDurationValidation(errors, "upstream", "failover_timeout", c.Upstream.FailoverTimeout)

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

		errors = appendDurationValidation(errors, prefix, "health_check", group.HealthCheck)

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

func (c *Config) validateGeoDNS() []string {
	var errors []string

	if !c.GeoDNS.Enabled {
		return errors
	}

	mmdbFile := strings.TrimSpace(c.GeoDNS.MMDBFile)
	if mmdbFile != "" {
		info, err := os.Stat(mmdbFile)
		if err != nil {
			errors = append(errors, fmt.Sprintf("geodns.mmdb_file: cannot access '%s': %v", mmdbFile, err))
		} else if info.IsDir() {
			errors = append(errors, fmt.Sprintf("geodns.mmdb_file: '%s' must be a file, not a directory", mmdbFile))
		}
	}

	return errors
}

func (c *Config) validateDNS64() []string {
	var errors []string

	if !c.DNS64.Enabled {
		return errors
	}

	if c.DNS64.PrefixLen != 0 && !isValidDNS64PrefixLength(c.DNS64.PrefixLen) {
		errors = append(errors, fmt.Sprintf("dns64: invalid prefix_len %d (must be one of 32, 40, 48, 56, 64, 96)", c.DNS64.PrefixLen))
	}
	if prefix := strings.TrimSpace(c.DNS64.Prefix); prefix != "" {
		ip := net.ParseIP(prefix)
		if ip == nil {
			errors = append(errors, fmt.Sprintf("dns64: invalid prefix %q", prefix))
		} else if ip.To4() != nil {
			errors = append(errors, fmt.Sprintf("dns64: prefix %q must be IPv6", prefix))
		}
	}
	for _, cidr := range c.DNS64.ExcludeNets {
		if !isValidCIDR(cidr) {
			errors = append(errors, fmt.Sprintf("dns64.exclude_nets: invalid CIDR '%s'", cidr))
		}
	}

	return errors
}

func isValidDNS64PrefixLength(prefixLen int) bool {
	switch prefixLen {
	case 32, 40, 48, 56, 64, 96:
		return true
	default:
		return false
	}
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

	// Validate RPC TLS configuration
	if c.Cluster.RPC.Enabled {
		if c.Cluster.RPC.TLSCertFile == "" {
			errors = append(errors, "cluster.rpc: tls_cert_file is required when TLS is enabled")
		}
		if c.Cluster.RPC.TLSKeyFile == "" {
			errors = append(errors, "cluster.rpc: tls_key_file is required when TLS is enabled")
		}
		if c.Cluster.RPC.MinTLSVersion != 0 && c.Cluster.RPC.MinTLSVersion != 12 && c.Cluster.RPC.MinTLSVersion != 13 {
			errors = append(errors, fmt.Sprintf("cluster.rpc: invalid min_tls_version %d (must be 12 or 13)", c.Cluster.RPC.MinTLSVersion))
		}
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
		errors = appendDurationValidation(errors, prefix, "timeout", slave.Timeout)
		errors = appendDurationValidation(errors, prefix, "retry_interval", slave.RetryInterval)
	}

	return errors
}

func (c *Config) validateTransfer() []string {
	var errors []string

	for _, cidr := range c.Transfer.AllowList {
		if !isValidCIDR(cidr) {
			errors = append(errors, fmt.Sprintf("transfer.allow_list: invalid CIDR '%s'", cidr))
		}
	}

	return errors
}

func (c *Config) validateProduction() []string {
	var errors []string

	if c.Server.HTTP.Enabled {
		if strings.TrimSpace(c.Server.HTTP.AuthSecret) == "" {
			errors = append(errors, "production: http.auth_secret must be set to a stable 32-byte random secret")
		}
		if len(c.Server.HTTP.Users) == 0 {
			errors = append(errors, "production: at least one http.users entry is required; do not rely on the auto-created admin")
		} else if !hasHTTPAdminUser(c.Server.HTTP.Users) {
			errors = append(errors, "production: at least one http.users entry must have role admin")
		}
		if isPublicListenAddress(c.Server.HTTP.Bind) && (c.Server.HTTP.TLSCertFile == "" || c.Server.HTTP.TLSKeyFile == "") {
			errors = append(errors, "production: public http.bind requires tls_cert_file and tls_key_file")
		}
		if isPublicListenAddress(c.Server.HTTP.Bind) && hasWildcardOrigin(c.Server.HTTP.AllowedOrigins) {
			errors = append(errors, "production: public http.bind cannot use wildcard http.allowed_origins")
		}
		if tokenPath := strings.TrimSpace(c.Server.HTTP.TokenPersistencePath); tokenPath != "" && !filepath.IsAbs(tokenPath) {
			errors = append(errors, "production: http.token_persistence_path must be an absolute path")
		}
	}

	if c.Resolution.Recursive && len(c.ACL) == 0 && c.Server.ACLAllowUnrestrictedRecursion {
		errors = append(errors, "production: recursive resolver cannot run open; configure acl rules or disable acl_allow_unrestricted_recursion")
	}

	if c.DNSSEC.Enabled && c.DNSSEC.IgnoreTime {
		errors = append(errors, "production: dnssec.ignore_time must be false")
	}

	storageDataDir := strings.TrimSpace(c.Storage.DataDir)
	if storageDataDir == "" {
		errors = append(errors, "production: storage.data_dir is required so persistent zone DB and IXFR journals do not depend on the daemon working directory")
	} else if !filepath.IsAbs(storageDataDir) {
		errors = append(errors, "production: storage.data_dir must be an absolute path")
	}
	if strings.TrimSpace(c.Storage.EncryptionKey) == "" {
		errors = append(errors, "production: storage.encryption_key is required for persistent zone DB encryption at rest")
	}

	if c.Cluster.Enabled {
		if c.Cluster.AllowInsecureCluster {
			errors = append(errors, "production: cluster.allow_insecure must be false")
		}
		if strings.TrimSpace(c.Cluster.EncryptionKey) == "" {
			errors = append(errors, "production: cluster.encryption_key is required when cluster is enabled")
		}
		if strings.EqualFold(c.Cluster.ConsensusMode, "raft") && strings.TrimSpace(c.Cluster.DataDir) == "" {
			errors = append(errors, "production: cluster.data_dir is required for raft consensus")
		} else if strings.EqualFold(c.Cluster.ConsensusMode, "raft") && !filepath.IsAbs(strings.TrimSpace(c.Cluster.DataDir)) {
			errors = append(errors, "production: cluster.data_dir must be an absolute path")
		}
	}

	if c.Metrics.Enabled && isPublicListenAddress(c.Metrics.Bind) && strings.TrimSpace(c.Metrics.AuthToken) == "" {
		errors = append(errors, "production: public metrics.bind requires metrics.auth_token")
	}

	if len(c.Transfer.AllowList) > 0 && !c.Transfer.RequireTSIG {
		errors = append(errors, "production: transfer.require_tsig must be true when transfer.allow_list is non-empty")
	}

	return errors
}

func hasHTTPAdminUser(users []AuthUserConfig) bool {
	for _, user := range users {
		if auth.Role(user.Role) == auth.RoleAdmin {
			return true
		}
	}
	return false
}

func hasWildcardOrigin(origins []string) bool {
	for _, origin := range origins {
		if strings.TrimSpace(origin) == "*" {
			return true
		}
	}
	return false
}

func isPublicListenAddress(addr string) bool {
	if strings.TrimSpace(addr) == "" {
		return true
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.Trim(host, "[]")
	if host == "" || host == "0.0.0.0" || host == "::" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return !strings.EqualFold(host, "localhost")
	}
	return !ip.IsLoopback()
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

func (c *Config) validateZoneFiles() []string {
	var errors []string

	for i, zoneFile := range c.Zones {
		path := strings.TrimSpace(zoneFile)
		if path == "" {
			errors = append(errors, fmt.Sprintf("zones[%d]: zone file path cannot be empty", i))
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			errors = append(errors, fmt.Sprintf("zones[%d]: cannot access zone file %q: %v", i, path, err))
			continue
		}
		if info.IsDir() {
			errors = append(errors, fmt.Sprintf("zones[%d]: %q must be a file, not a directory", i, path))
		}
	}

	if zoneDir := strings.TrimSpace(c.ZoneDir); zoneDir != "" {
		info, err := os.Stat(zoneDir)
		if err != nil {
			errors = append(errors, fmt.Sprintf("zone_dir: cannot access %q: %v", zoneDir, err))
		} else if !info.IsDir() {
			errors = append(errors, fmt.Sprintf("zone_dir: %q must be a directory", zoneDir))
		}
	}

	for i, view := range c.Views {
		for j, zoneFile := range view.ZoneFiles {
			path := strings.TrimSpace(zoneFile)
			if path == "" {
				errors = append(errors, fmt.Sprintf("views[%d].zone_files[%d]: zone file path cannot be empty", i, j))
				continue
			}
			info, err := os.Stat(path)
			if err != nil {
				errors = append(errors, fmt.Sprintf("views[%d].zone_files[%d]: cannot access zone file %q: %v", i, j, path, err))
				continue
			}
			if info.IsDir() {
				errors = append(errors, fmt.Sprintf("views[%d].zone_files[%d]: %q must be a file, not a directory", i, j, path))
			}
		}
	}

	return errors
}

// isValidServerAddress checks if a String is a valid DNS server address (host:port or IP:port).
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
