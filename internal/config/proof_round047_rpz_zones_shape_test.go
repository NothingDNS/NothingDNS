package config

import "testing"

// TestRound047RPZZonesShape pins the AGENTS.md strict-loading contract for
// rpz.zones: a zones section written as a mapping (missing "- ") and
// non-mapping items inside the zones sequence are load errors, never silent
// drops. unmarshalRPZ previously required NodeSequence and skipped any
// non-mapping item, so a typo'd zone entry loaded cleanly with RPZ enabled
// and zero policy zones — the filtering control silently off. validateRPZ
// cannot catch it: it iterates the already-emptied cfg.RPZ.Zones and passes.
// dnssec.signing.keys goes through listItems, which makes both shapes loud
// errors ("expected a list of \"- key: value\" items, got a mapping" /
// "zones[N]: expected a mapping, got scalar"); rpz.zones now does the same.
//
// Control: the documented shape (config.example.yaml,
// docs/CONFIG_REFERENCE.md §rpz) still parses to one zone.

func TestRound047RPZZonesShape(t *testing.T) {
	// Control: the documented shape parses to one zone.
	cfg, err := UnmarshalYAML("rpz:\n  enabled: true\n  zones:\n    - name: block\n      file: /etc/rpz/block.rpz\n      priority: 10\n")
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	if len(cfg.RPZ.Zones) != 1 || cfg.RPZ.Zones[0].Name != "block" ||
		cfg.RPZ.Zones[0].File != "/etc/rpz/block.rpz" || cfg.RPZ.Zones[0].Priority != 10 {
		t.Fatalf("control: zones = %+v", cfg.RPZ.Zones)
	}

	// Shape error 1: zones written as a mapping (missing "- " before the
	// item's keys). Previously: silent skip, enabled=true, zero zones.
	cfg, err = UnmarshalYAML("rpz:\n  enabled: true\n  zones:\n    name: block\n    file: /etc/rpz/block.rpz\n")
	if err == nil {
		t.Fatalf("FAIL: mapping-shaped rpz.zones accepted silently; zones=%+v (want a load error naming zones, per AGENTS.md strict loading)", cfg.RPZ.Zones)
	}

	// Shape error 2: a non-mapping item inside the zones sequence.
	// Previously: silent skip, enabled=true, zero zones.
	cfg, err = UnmarshalYAML("rpz:\n  enabled: true\n  zones:\n    - policy.example\n")
	if err == nil {
		t.Fatalf("FAIL: scalar rpz.zones item accepted silently; zones=%+v (want a load error naming zones)", cfg.RPZ.Zones)
	}
}
