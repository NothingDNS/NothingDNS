package config

import "testing"

// TestRound048GeoDNSRulesShape pins the AGENTS.md strict-loading contract
// for geodns.rules: a rules section written as a mapping (missing "- ") and
// non-mapping items inside the rules sequence are load errors, never silent
// drops. unmarshalGeoDNS previously required NodeSequence and skipped any
// non-mapping item, so a typo'd rules entry loaded cleanly with GeoDNS
// enabled and zero rules — every domain then resolved without geo data as
// if the feature were not configured. Same defect class and contract as
// rpz.zones (round 047) and dnssec.signing.keys, which go through listItems
// and make both shapes loud errors; geodns.rules now does the same.
//
// Control: the documented shape (docs/CONFIG_REFERENCE.md §geodns,
// config.example.yaml) still parses to one rule with its records.

func TestRound048GeoDNSRulesShape(t *testing.T) {
	// Control: the documented shape parses to one rule.
	cfg, err := UnmarshalYAML("geodns:\n  enabled: true\n  mmdb_file: /etc/GeoLite2-Country.mmdb\n  rules:\n    - domain: cdn.example.com\n      type: A\n      default: 1.2.3.4\n      US: 10.0.0.1\n")
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	if len(cfg.GeoDNS.Rules) != 1 || cfg.GeoDNS.Rules[0].Domain != "cdn.example.com" ||
		cfg.GeoDNS.Rules[0].Default != "1.2.3.4" || cfg.GeoDNS.Rules[0].Records["US"] != "10.0.0.1" {
		t.Fatalf("control: rules = %+v", cfg.GeoDNS.Rules)
	}

	// Shape error 1: rules written as a mapping (missing "- " before the
	// item's keys). Previously: silent skip, enabled=true, zero rules.
	cfg, err = UnmarshalYAML("geodns:\n  enabled: true\n  rules:\n    domain: cdn.example.com\n    default: 1.2.3.4\n")
	if err == nil {
		t.Fatalf("FAIL: mapping-shaped geodns.rules accepted silently; rules=%+v (want a load error naming rules, per AGENTS.md strict loading)", cfg.GeoDNS.Rules)
	}

	// Shape error 2: a non-mapping item inside the rules sequence.
	// Previously: silent skip, enabled=true, zero rules.
	cfg, err = UnmarshalYAML("geodns:\n  enabled: true\n  rules:\n    - cdn.example.com\n")
	if err == nil {
		t.Fatalf("FAIL: scalar geodns.rules item accepted silently; rules=%+v (want a load error naming rules)", cfg.GeoDNS.Rules)
	}
}
