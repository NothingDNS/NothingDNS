package config

import (
	"fmt"
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

	// Tracing (OpenTelemetry) configuration
	Tracing TracingConfig `yaml:"tracing"`

	// DNSSEC configuration
	DNSSEC DNSSECConfig `yaml:"dnssec"`

	// Storage layer configuration (KV store at-rest encryption etc.)
	Storage StorageConfig `yaml:"storage"`

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

	// Transfer configuration for serving AXFR/IXFR to secondary servers
	Transfer TransferConfig `yaml:"transfer"`

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

// UnmarshalYAML parses YAML into a Config struct.
func UnmarshalYAML(data string) (*Config, error) {
	return UnmarshalYAMLWithEnv(data, true)
}

// UnmarshalYAMLWithEnv parses YAML with optional environment variable expansion.
func UnmarshalYAMLWithEnv(data string, expandEnv bool) (*Config, error) {
	parser := NewParser(data)
	node, err := parser.ParseMapping()
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}
	if expandEnv {
		expandNodeEnvVars(node)
	}

	cfg := DefaultConfig()
	if err := unmarshalToConfig(node, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal error: %w", err)
	}

	return cfg, nil
}

func expandNodeEnvVars(node *Node) {
	if node == nil {
		return
	}
	if node.Type == NodeScalar {
		node.Value = expandEnvVars(node.Value)
		return
	}
	for _, child := range node.Children {
		expandNodeEnvVars(child)
	}
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

// knownTopLevelConfigKeys is the set of YAML keys the config loader
// recognises at the document root. Anything outside this set is a
// typo — we warn so operators don't silently lose configuration
// (e.g. mis-spelling "blocklist" as "blocklists" used to start the
// server with blocklist disabled and zero indication of the typo).
//
// The list is limited to sections referenced by node.Get(...) in
// unmarshalToConfig. Anything else should warn instead of being
// silently accepted as configured.
var knownTopLevelConfigKeys = map[string]struct{}{
	// Core sections wired through unmarshalToConfig.
	"server": {}, "resolution": {}, "upstream": {}, "cache": {},
	"logging": {}, "metrics": {}, "dnssec": {}, "zones": {},
	"zone_dir": {}, "zonemd": {}, "memory_limit_mb": {},
	"shutdown_timeout": {}, "acl": {}, "rrl": {},
	"blocklist": {}, "rpz": {}, "geodns": {}, "dns64": {},
	"cookie": {}, "cluster": {}, "storage": {}, "slave_zones": {},
	"transfer": {}, "views": {}, "dso": {}, "idna": {}, "mdns": {}, "odoh": {},
	"catalog": {}, "yang": {},
}

// documentedButUnwiredKeys lists stale documented keys that operators
// may still have in existing config files but that have NO
// corresponding code path inside unmarshalToConfig.
// The settings inside them are silently dropped. Treating them like
// any other unknown key would (rightly) flag them, but the warning
// here is more actionable: it tells the operator the section was
// recognized as a documented stub, not just a typo.
//
// Move keys out of here only when the corresponding section is
// actually wired through unmarshalToConfig.
var documentedButUnwiredKeys = map[string]struct{}{
	"api": {}, "auth": {}, "ddns": {},
	"resolver": {},
}

// unmarshalToConfig unmarshals a node tree into a Config struct.
func unmarshalToConfig(node *Node, cfg *Config) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping at root")
	}

	// Warn (don't error) on top-level keys we don't know — wrong
	// section names are a common foot-gun and silently ignoring them
	// means an operator can deploy a "validated" config that does the
	// wrong thing. Stop short of erroring because future versions may
	// add new sections that an older binary doesn't recognise.
	for _, k := range node.Keys() {
		if _, ok := knownTopLevelConfigKeys[k]; ok {
			continue
		}
		if _, ok := documentedButUnwiredKeys[k]; ok {
			// Stale documented examples used these names, but the
			// parser has no branch that reads them. Loud-by-default so
			// the operator can't quietly deploy config whose half is
			// dead weight.
			util.Warnf("config: section %q is a stale documented section "+
				"but is not wired into the daemon — its settings will be ignored", k)
			continue
		}
		util.Warnf("config: unknown top-level key %q — ignored (typo?)", k)
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

	// Tracing config
	if tracingNode := node.Get("tracing"); tracingNode != nil {
		if err := unmarshalTracing(tracingNode, &cfg.Tracing); err != nil {
			return fmt.Errorf("tracing: %w", err)
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

	cfg.ZONEMD = getBool(node, "zonemd", cfg.ZONEMD)
	cfg.ShutdownTimeout = getString(node, "shutdown_timeout", cfg.ShutdownTimeout)

	// Memory limit
	if mlNode := node.Get("memory_limit_mb"); mlNode != nil && mlNode.Value != "" {
		v, err := strconv.Atoi(mlNode.Value)
		if err != nil {
			return fmt.Errorf("memory_limit_mb: invalid integer %q: %w", mlNode.Value, err)
		}
		if v < 0 {
			return fmt.Errorf("memory_limit_mb: must be non-negative, got %d", v)
		}
		cfg.MemoryLimitMB = v
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

	// RRL config
	if rrlNode := node.Get("rrl"); rrlNode != nil {
		if err := unmarshalRRL(rrlNode, &cfg.RRL); err != nil {
			return fmt.Errorf("rrl: %w", err)
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

	// Storage config (L-6)
	if storageNode := node.Get("storage"); storageNode != nil {
		cfg.Storage.DataDir = storageNode.GetString("data_dir")
		cfg.Storage.EncryptionKey = storageNode.GetString("encryption_key")
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
				var err error
				if slave.MaxRetries, err = getRequiredInt(slaveNode, "max_retries", 0); err != nil {
					return fmt.Errorf("slave_zones: %w", err)
				}

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

	// Transfer serving config
	if transferNode := node.Get("transfer"); transferNode != nil {
		cfg.Transfer.AllowList = getStringSlice(transferNode, "allow_list", cfg.Transfer.AllowList)
		cfg.Transfer.RequireTSIG = getBool(transferNode, "require_tsig", cfg.Transfer.RequireTSIG)
	}

	// IDNA config
	if idnaNode := node.Get("idna"); idnaNode != nil {
		cfg.IDNA.Enabled = getBool(idnaNode, "enabled", cfg.IDNA.Enabled)
		cfg.IDNA.UseSTD3Rules = getBool(idnaNode, "use_std3_rules", cfg.IDNA.UseSTD3Rules)
		cfg.IDNA.AllowUnassigned = getBool(idnaNode, "allow_unassigned", cfg.IDNA.AllowUnassigned)
		cfg.IDNA.CheckBidi = getBool(idnaNode, "check_bidi", cfg.IDNA.CheckBidi)
		cfg.IDNA.CheckJoiner = getBool(idnaNode, "check_joiner", cfg.IDNA.CheckJoiner)
	}

	// mDNS config
	if mdnsNode := node.Get("mdns"); mdnsNode != nil {
		cfg.MDNS.Enabled = getBool(mdnsNode, "enabled", cfg.MDNS.Enabled)
		cfg.MDNS.MulticastIP = getString(mdnsNode, "multicast_ip", cfg.MDNS.MulticastIP)
		if portNode := mdnsNode.Get("port"); portNode != nil && portNode.Value != "" {
			var err error
			if cfg.MDNS.Port, err = getRequiredInt(mdnsNode, "port", cfg.MDNS.Port); err != nil {
				return fmt.Errorf("mdns: %w", err)
			}
		}
		cfg.MDNS.Browser = getBool(mdnsNode, "browser", cfg.MDNS.Browser)
		cfg.MDNS.HostName = getString(mdnsNode, "hostname", cfg.MDNS.HostName)
	}

	// ODoH config
	if odohNode := node.Get("odoh"); odohNode != nil {
		cfg.ODoH.Enabled = getBool(odohNode, "enabled", cfg.ODoH.Enabled)
		cfg.ODoH.Bind = getString(odohNode, "bind", cfg.ODoH.Bind)
		cfg.ODoH.TargetURL = getString(odohNode, "target_url", cfg.ODoH.TargetURL)
		cfg.ODoH.ProxyURL = getString(odohNode, "proxy_url", cfg.ODoH.ProxyURL)
		var err error
		if cfg.ODoH.KEM, err = getRequiredInt(odohNode, "kem", cfg.ODoH.KEM); err != nil {
			return fmt.Errorf("odoh: %w", err)
		}
		if cfg.ODoH.KDF, err = getRequiredInt(odohNode, "kdf", cfg.ODoH.KDF); err != nil {
			return fmt.Errorf("odoh: %w", err)
		}
		if cfg.ODoH.AEAD, err = getRequiredInt(odohNode, "aead", cfg.ODoH.AEAD); err != nil {
			return fmt.Errorf("odoh: %w", err)
		}
	}

	// Catalog Zone config
	if catalogNode := node.Get("catalog"); catalogNode != nil {
		cfg.Catalog.Enabled = getBool(catalogNode, "enabled", cfg.Catalog.Enabled)
		cfg.Catalog.CatalogZone = getString(catalogNode, "catalog_zone", cfg.Catalog.CatalogZone)
		cfg.Catalog.ProducerClass = getString(catalogNode, "producer_class", cfg.Catalog.ProducerClass)
		cfg.Catalog.ConsumerClass = getString(catalogNode, "consumer_class", cfg.Catalog.ConsumerClass)
	}

	// DSO config
	if dsoNode := node.Get("dso"); dsoNode != nil {
		cfg.DSO.Enabled = getBool(dsoNode, "enabled", cfg.DSO.Enabled)
		cfg.DSO.SessionTimeout = getString(dsoNode, "session_timeout", cfg.DSO.SessionTimeout)
		if maxSessionsNode := dsoNode.Get("max_sessions"); maxSessionsNode != nil && maxSessionsNode.Value != "" {
			var err error
			if cfg.DSO.MaxSessions, err = getRequiredInt(dsoNode, "max_sessions", cfg.DSO.MaxSessions); err != nil {
				return fmt.Errorf("dso: %w", err)
			}
		}
		cfg.DSO.HeartbeatInterval = getString(dsoNode, "heartbeat_interval", cfg.DSO.HeartbeatInterval)
	}

	// YANG config
	if yangNode := node.Get("yang"); yangNode != nil {
		cfg.YANG.Enabled = getBool(yangNode, "enabled", cfg.YANG.Enabled)
		cfg.YANG.EnableCLI = getBool(yangNode, "enable_cli", cfg.YANG.EnableCLI)
		cfg.YANG.EnableNETCONF = getBool(yangNode, "enable_netconf", cfg.YANG.EnableNETCONF)
		cfg.YANG.NETCONFBind = getString(yangNode, "netconf_bind", cfg.YANG.NETCONFBind)
		cfg.YANG.Models = getStringSlice(yangNode, "models", cfg.YANG.Models)
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

func getBool(node *Node, key string, defaultValue bool) bool {
	if child := node.Get(key); child != nil && child.Type == NodeScalar {
		switch strings.ToLower(child.Value) {
		case "true", "yes", "on", "1":
			return true
		case "false", "no", "off", "0":
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

	// Validate that no secret field still contains a known placeholder
	// from a shipped template (VULN-050).
	errors = append(errors, c.validateSecrets()...)

	// Validate HTTP dashboard/API users against the auth store invariants.
	errors = append(errors, c.validateHTTPUsers()...)

	// Validate DNS Cookie configuration
	errors = append(errors, c.validateCookie()...)

	// Validate DSO configuration
	errors = append(errors, c.validateDSO()...)

	// Validate extension configurations
	errors = append(errors, c.validateExtensions()...)

	// Validate upstream configuration
	errors = append(errors, c.validateUpstream()...)

	// Validate recursive resolution configuration
	errors = append(errors, c.validateResolution()...)

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

	// Validate GeoDNS configuration
	errors = append(errors, c.validateGeoDNS()...)

	// Validate DNS64 configuration
	errors = append(errors, c.validateDNS64()...)

	// Validate cluster configuration
	errors = append(errors, c.validateCluster()...)

	// Validate slave zones configuration
	errors = append(errors, c.validateSlaveZones()...)

	// Validate transfer serving configuration
	errors = append(errors, c.validateTransfer()...)

	// Validate views (split-horizon) configuration
	errors = append(errors, c.validateViews()...)

	// Validate configured zone file sources.
	errors = append(errors, c.validateZoneFiles()...)

	return errors
}

// ValidateProduction applies the normal validation plus deployment gates for
// settings that are technically valid for development or staging but unsafe
// for an internet-facing production daemon.
func (c *Config) ValidateProduction() []string {
	errors := c.Validate()
	return append(errors, c.validateProduction()...)
}
