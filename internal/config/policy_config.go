package config

import (
	"fmt"
	"reflect"
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
	cfg.BaseDir = node.GetString("base_dir")

	return nil
}

func unmarshalRPZ(node *Node, cfg *RPZConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Enabled = getBool(node, "enabled", cfg.Enabled)
	cfg.Files = getStringSlice(node, "files", cfg.Files)

	// listItems makes a mis-shaped zones section a load error (AGENTS.md:
	// strict loading, never silent defaults). The previous manual loop
	// required NodeSequence and skipped any non-mapping item, so a zones
	// mapping (missing "- ") or a scalar entry vanished: RPZ loaded enabled
	// with zero policy zones and validateRPZ passed over the emptied list.
	// dnssec.signing.keys already goes through listItems; rpz.zones now
	// gets the same loud errors.
	zoneItems, err := listItems(node, "zones", reflect.TypeOf(RPZPolicyZone{}))
	if err != nil {
		return fmt.Errorf("rpz: %w", err)
	}
	for _, zoneNode := range zoneItems {
		var pz RPZPolicyZone
		pz.Name = zoneNode.GetString("name")
		pz.File = zoneNode.GetString("file")
		var err error
		if pz.Priority, err = getRequiredInt(zoneNode, "priority", 0); err != nil {
			return fmt.Errorf("zones: %w", err)
		}
		cfg.Zones = append(cfg.Zones, pz)
	}

	return nil
}

func unmarshalGeoDNS(node *Node, cfg *GeoDNSConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Enabled = getBool(node, "enabled", cfg.Enabled)
	cfg.MMDBFile = node.GetString("mmdb_file")

	// listItems makes a mis-shaped rules section a load error (AGENTS.md:
	// strict loading, never silent defaults). The previous manual loop
	// required NodeSequence and skipped any non-mapping item, so a rules
	// mapping (missing "- ") or a scalar entry vanished: GeoDNS loaded
	// enabled with zero rules and every domain resolved without geo data.
	// dnssec.signing.keys and rpz.zones already go through listItems;
	// geodns.rules now gets the same loud errors.
	ruleItems, err := listItems(node, "rules", reflect.TypeOf(GeoDNSRule{}))
	if err != nil {
		return fmt.Errorf("geodns: %w", err)
	}
	for i, ruleNode := range ruleItems {
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
		// Flat region keys beside `default:` (the form config.example.yaml
		// documents). Every key shaped like a region code is a record — not a
		// fixed shortlist, which silently dropped HK, TR, AS13335, ... — while
		// anything else (a typo such as `defualt:`) stays out of the records.
		for _, key := range ruleNode.Keys() {
			if !isGeoRegionKey(key) {
				continue
			}
			if v := ruleNode.GetString(key); v != "" {
				rule.Records[key] = v
			}
		}
		// A rule that parsed to no records and no default can never answer:
		// dropping it silently turned key/value typos (a lowercase region
		// key, an empty record value) into "the domain is not geo-steered",
		// with no config error (AGENTS.md: strict loading, never silent
		// defaults — same class as rpz.zones, upstream.anycast_groups and
		// cluster.peers).
		if len(rule.Records) == 0 && rule.Default == "" {
			return fmt.Errorf("geodns: rules[%d]: rule for %q has no records and no default", i, rule.Domain)
		}
		cfg.Rules = append(cfg.Rules, rule)
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
	if pl < 0 {
		return fmt.Errorf("prefix_len must not be negative: %d", pl)
	}
	if pl > 0 {
		cfg.PrefixLen = pl
	}
	cfg.ExcludeNets = getStringSlice(node, "exclude_nets", nil)

	return nil
}

// isGeoRegionKey reports whether key has the shape of a GeoDNS region code:
// an upper-case two-letter ISO 3166-1 country or continent code ("US", "EU"),
// or an autonomous system ("AS13335"). These are the only keys the engine's
// country -> continent -> default lookup can ever match.
func isGeoRegionKey(key string) bool {
	if len(key) == 2 {
		return key[0] >= 'A' && key[0] <= 'Z' && key[1] >= 'A' && key[1] <= 'Z'
	}
	if len(key) > 2 && key[0] == 'A' && key[1] == 'S' {
		for i := 2; i < len(key); i++ {
			if key[i] < '0' || key[i] > '9' {
				return false
			}
		}
		return true
	}
	return false
}
