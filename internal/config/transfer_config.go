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

	// TSIGKeys are the keys secondaries use to sign AXFR/IXFR requests to
	// this server. Once any key is configured, every transfer must be signed
	// with one of them (in addition to matching allow_list). A key with
	// allow_update also authorizes Dynamic DNS UPDATEs to those zones.
	TSIGKeys []TransferTSIGKeyConfig `yaml:"tsig_keys"`

	// AlsoNotify lists the secondaries (IP:port) this server sends a DNS
	// NOTIFY (RFC 1996) to whenever the SOA serial of a zone it serves for
	// transfer changes (API/Raft edits, Dynamic DNS, SIGHUP reload). Empty
	// (the default) sends no NOTIFY at all (F547).
	AlsoNotify []string `yaml:"also_notify"`

	// NotifyKey optionally names a tsig_keys entry used to TSIG-sign every
	// outgoing NOTIFY. Empty sends NOTIFY unsigned (F547).
	NotifyKey string `yaml:"notify_key"`
}

// TransferTSIGKeyConfig is a TSIG key accepted for zone transfers served by
// this server (RFC 8945).
type TransferTSIGKeyConfig struct {
	// Name is the key name (e.g. "xfr-key.example."), as sent by the secondary.
	Name string `yaml:"name"`

	// Algorithm is hmac-sha1, hmac-sha224, hmac-sha256 (default), hmac-sha384
	// or hmac-sha512.
	Algorithm string `yaml:"algorithm"`

	// Secret is the base64-encoded shared secret (BIND/tsig-keygen format).
	Secret string `yaml:"secret"`

	// AllowedCIDRs optionally restricts which client addresses may use the key.
	AllowedCIDRs []string `yaml:"allowed_cidrs"`

	// AllowUpdate lists the zones (exact zone origins) this key may modify
	// with RFC 2136 Dynamic DNS UPDATE. Empty/absent grants no update rights:
	// every UPDATE must be signed with a key whose allow_update names the
	// zone, otherwise it is REFUSED.
	AllowUpdate []string `yaml:"allow_update"`
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

	// TSIG secret for authenticated transfers (optional), base64-encoded
	// (BIND/tsig-keygen format); the algorithm is hmac-sha256.
	TSIGSecret string `yaml:"tsig_secret"`

	// Timeout for zone transfer (e.g., "30s")
	Timeout string `yaml:"timeout"`

	// Retry interval between transfer attempts (e.g., "5m")
	RetryInterval string `yaml:"retry_interval"`

	// Maximum number of retry attempts (0 = unlimited)
	MaxRetries int `yaml:"max_retries"`
}
