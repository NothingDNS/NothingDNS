package config

// TransferConfig represents configuration for serving AXFR/IXFR to secondary servers
// and for slave zone transfers.
type TransferConfig struct {
	// AllowList restricts which addresses can request zone transfers.
	AllowList []string `yaml:"allow_list"`

	// RequireTSIG requires TSIG authentication for zone transfers.
	RequireTSIG bool `yaml:"require_tsig"`

	// JournalDir is the directory for IXFR journal storage.
	// When empty, defaults to storage.data_dir/ixfr-journals.
	JournalDir string `yaml:"journal_dir"`
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

	// Timeout for zone transfer (e.g., "30s")
	Timeout string `yaml:"timeout"`

	// Retry interval between transfer attempts (e.g., "5m")
	RetryInterval string `yaml:"retry_interval"`

	// Maximum number of retry attempts (0 = unlimited)
	MaxRetries int `yaml:"max_retries"`
}
