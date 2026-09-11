package config

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

	// HPKE key encapsulation method (32 = X25519 / 0x0020 — the only KEM
	// the odoh runtime implements; must be 32, see isValidODoHKEM)
	KEM int `yaml:"kem"`

	// HPKE key derivation function (1=HKDF-SHA256)
	KDF int `yaml:"kdf"`

	// HPKE authenticated encryption (1=AES-128-GCM; per RFC 9180 §7.3:
	// 2=AES-256-GCM, 3=ChaCha20-Poly1305 — the runtime implements 1)
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
