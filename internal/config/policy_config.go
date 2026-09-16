package config

import (
	"fmt"
)

// BlocklistConfig holds blocklist configuration.
type BlocklistConfig struct {
	Enabled bool     `yaml:"enabled"`
	Files   []string `yaml:"files"`
	URLs    []string `yaml:"urls"` // URLs to download blocklists from (e.g., adguard, malware domains)
	// BaseDir confines blocklist file sources to this directory. It is also
	// required for adding file sources at runtime through the API.
	BaseDir string `yaml:"base_dir"`
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

// DNS64Config holds DNS64/NAT64 configuration.
type DNS64Config struct {
	Enabled     bool     `yaml:"enabled"`
	Prefix      string   `yaml:"prefix"`
	PrefixLen   int      `yaml:"prefix_len"`
	ExcludeNets []string `yaml:"exclude_nets"`
}

func unmarshalBlocklist(node *Node, cfg *BlocklistConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Enabled = getBool(node, "enabled", cfg.Enabled)
	cfg.Files = getStringSlice(node, "files", cfg.Files)
	cfg.URLs = getStringSlice(node, "urls", cfg.URLs)

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
				var err error
				if pz.Priority, err = getRequiredInt(zoneNode, "priority", 0); err != nil {
					return fmt.Errorf("zones: %w", err)
				}
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
				// Parse records from the documented nested records map,
				// while keeping the older flat US/DE keys compatible.
				rule.Records = make(map[string]string)
				if recordsNode := ruleNode.Get("records"); recordsNode != nil && recordsNode.Type == NodeMapping {
					for i := 0; i+1 < len(recordsNode.Children); i += 2 {
						key := recordsNode.Children[i].Value
						value := recordsNode.Children[i+1]
						if key != "" && value.Type == NodeScalar && value.Value != "" {
							rule.Records[key] = value.Value
						}
					}
				}
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
	pl, err := getRequiredInt(node, "prefix_len", 0)
	if err != nil {
		return err
	}
	if pl > 0 {
		cfg.PrefixLen = pl
	}
	cfg.ExcludeNets = getStringSlice(node, "exclude_nets", nil)

	return nil
}
