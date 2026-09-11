package config

import (
	"fmt"
	"strconv"
	"strings"
)

// ServerConfig contains server settings.
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

	// ACLAllowUnrestrictedRecursion permits the server to run as an open resolver
	// when recursion is enabled but no ACL rules are configured. Default: false
	// (deny-by-default when recursion is enabled without ACL rules).
	ACLAllowUnrestrictedRecursion bool `yaml:"acl_allow_unrestricted_recursion"`
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

	// CA file for client certificate verification (optional). When set, XoT
	// enforces mutual TLS (RequireAndVerifyClientCert) and that authenticates the
	// peer regardless of allowed_networks.
	CAFile string `yaml:"ca_file"`

	// Listen address (default ":853")
	Bind string `yaml:"bind"`

	// Minimum TLS version (12 or 13, default 12)
	MinTLSVersion int `yaml:"min_tls_version"`

	// AllowedNetworks restricts which client IPs may request zone transfers,
	// as CIDR strings. When CAFile (mTLS) is not set, at least one entry is
	// required — XoT is deny-by-default and will refuse all transfers otherwise.
	AllowedNetworks []string `yaml:"allowed_networks"`
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

	// TrustedProxies is a list of CIDR networks (or bare IPs) for reverse
	// proxies whose X-Forwarded-For / X-Real-IP headers may be trusted. When
	// RemoteAddr is in this set, the client IP used for rate limiting, login
	// lockout, and the localhost bootstrap gate is taken from the forwarded
	// header instead of the proxy's own address. Empty (default) trusts no
	// header — RemoteAddr is always used. Without this, deploying behind a
	// same-host reverse proxy collapses every client to 127.0.0.1, enabling a
	// remote bootstrap-admin takeover window and a shared/global login-lockout
	// DoS.
	TrustedProxies []string `yaml:"trusted_proxies"`

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

	// TokenPersistencePath writes/loads encrypted session tokens to this file
	// path. When set, tokens survive server restarts. When empty, tokens are
	// in-memory only and all sessions are invalidated on restart.
	TokenPersistencePath string `yaml:"token_persistence_path"`

	// MaxSessionsPerUser caps the number of simultaneous tokens any
	// single user may hold. 0 means unlimited. The auth.Store
	// already implements the cap (with eviction-by-oldest semantics);
	// L-N10 wired this field through to NewStore so operators can
	// actually use it.
	MaxSessionsPerUser int `yaml:"max_sessions_per_user"`

	// DoH (DNS over HTTPS) settings
	DoHEnabled bool   `yaml:"doh_enabled"` // Enable DoH endpoint
	DoHPath    string `yaml:"doh_path"`    // DoH endpoint path (default: /dns-query)

	// DoWS (DNS over WebSocket) settings
	DoWSEnabled bool   `yaml:"dows_enabled"` // Enable DoWS endpoint
	DoWSPath    string `yaml:"dows_path"`    // DoWS endpoint path (default: /dns-ws)

	// ODoH (Oblivious DNS over HTTPS, RFC 9230) settings
	ODoHEnabled bool   `yaml:"odoh_enabled"` // Enable ODoH endpoint
	ODoHPath    string `yaml:"odoh_path"`    // ODoH endpoint path (default: /odoh)
	ODoHKEM     int    `yaml:"odoh_kem"`     // HPKE KEM for target (default: 32 = X25519 / 0x0020)
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

func unmarshalServer(node *Node, cfg *ServerConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Bind = getStringSlice(node, "bind", cfg.Bind)
	cfg.TCPBind = getStringSlice(node, "tcp_bind", cfg.TCPBind)
	cfg.UDPBind = getStringSlice(node, "udp_bind", cfg.UDPBind)
	var err error
	if cfg.Port, err = getRequiredInt(node, "port", cfg.Port); err != nil {
		return err
	}
	if cfg.UDPWorkers, err = getRequiredInt(node, "udp_workers", cfg.UDPWorkers); err != nil {
		return err
	}
	if cfg.TCPWorkers, err = getRequiredInt(node, "tcp_workers", cfg.TCPWorkers); err != nil {
		return err
	}
	cfg.PIDFile = node.GetString("pid_file")
	cfg.SystemdNotify = node.GetString("systemd_notify")
	cfg.ACLAllowUnrestrictedRecursion = getBool(node, "acl_allow_unrestricted_recursion", cfg.ACLAllowUnrestrictedRecursion)

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
		cfg.XoT.AllowedNetworks = getStringSlice(xotNode, "allowed_networks", nil)
		if cfg.XoT.MinTLSVersion, err = getRequiredInt(xotNode, "min_tls_version", 12); err != nil {
			return fmt.Errorf("xot: %w", err)
		}
	}

	if httpNode := node.Get("http"); httpNode != nil {
		cfg.HTTP.Enabled = getBool(httpNode, "enabled", cfg.HTTP.Enabled)
		cfg.HTTP.Bind = httpNode.GetString("bind")
		cfg.HTTP.TLSCertFile = httpNode.GetString("tls_cert_file")
		cfg.HTTP.TLSKeyFile = httpNode.GetString("tls_key_file")
		cfg.HTTP.TrustedProxies = getStringSlice(httpNode, "trusted_proxies", cfg.HTTP.TrustedProxies)
		cfg.HTTP.AuthToken = httpNode.GetString("auth_token")
		cfg.HTTP.AuthTokenRole = httpNode.GetString("auth_token_role")
		cfg.HTTP.AuthSecret = httpNode.GetString("auth_secret")
		cfg.HTTP.TokenPersistencePath = httpNode.GetString("token_persistence_path")
		if cfg.HTTP.MaxSessionsPerUser, err = getRequiredInt(httpNode, "max_sessions_per_user", cfg.HTTP.MaxSessionsPerUser); err != nil {
			return fmt.Errorf("http: %w", err)
		}
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
		if cfg.HTTP.ODoHKEM, err = getRequiredInt(httpNode, "odoh_kem", cfg.HTTP.ODoHKEM); err != nil {
			return fmt.Errorf("http: %w", err)
		}
		if cfg.HTTP.ODoHKEM == 0 {
			cfg.HTTP.ODoHKEM = 32 // X25519 (0x0020) — the KEM the odoh runtime implements
		}
		if cfg.HTTP.ODoHKDF, err = getRequiredInt(httpNode, "odoh_kdf", cfg.HTTP.ODoHKDF); err != nil {
			return fmt.Errorf("http: %w", err)
		}
		if cfg.HTTP.ODoHKDF == 0 {
			cfg.HTTP.ODoHKDF = 1 // HKDF-SHA256
		}
		if cfg.HTTP.ODoHAEAD, err = getRequiredInt(httpNode, "odoh_aead", cfg.HTTP.ODoHAEAD); err != nil {
			return fmt.Errorf("http: %w", err)
		}
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

func getRequiredInt(node *Node, key string, defaultValue int) (int, error) {
	child := node.Get(key)
	if child == nil {
		return defaultValue, nil
	}
	if child.Type != NodeScalar {
		return 0, fmt.Errorf("%s: expected scalar integer", key)
	}
	value, err := strconv.Atoi(child.Value)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid integer %q: %w", key, child.Value, err)
	}
	return value, nil
}
