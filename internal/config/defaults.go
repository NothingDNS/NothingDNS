package config

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
			Enabled:   false,
			Bind:      ":9153",
			Path:      "/metrics",
			AuthToken: "",
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
			KEM:     32, // X25519 (0x0020) — the KEM the odoh runtime implements
			KDF:     1,  // HKDF-SHA256
			AEAD:    1,  // AES-128-GCM
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
