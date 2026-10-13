package config

import "testing"

// TestRound049AnycastGroupsShape pins the AGENTS.md strict-loading contract
// for upstream.anycast_groups at both nesting levels: a group list written
// as a mapping (missing "- "), a non-mapping group item, a backends list
// written as a mapping, and a non-mapping backend item are load errors,
// never silent drops. unmarshalUpstream previously required NodeSequence at
// both levels and skipped any non-mapping item, so a typo'd anycast section
// loaded cleanly with GeoDNS-style silence: AnycastGroups came out empty and
// upstream load balancing ran without the configured topology (or startup
// failed with the misleading "no upstream servers configured" when anycast
// was the only upstream source). dnssec.signing.keys, rpz.zones and
// geodns.rules already go through listItems and make all four shapes loud
// errors; upstream.anycast_groups now does the same, one level deep.
//
// Control: the documented shape parses to one group with one backend.

func TestRound049AnycastGroupsShape(t *testing.T) {
	// Control: the documented shape parses to one group with one backend.
	cfg, err := UnmarshalYAML("upstream:\n  servers: [10.0.0.1]\n  anycast_groups:\n    - anycast_ip: 192.0.2.1\n      health_check: 5s\n      backends:\n        - physical_ip: 10.0.0.2\n          port: 53\n          region: us-east-1\n          zone: a\n          weight: 100\n")
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	if len(cfg.Upstream.AnycastGroups) != 1 || cfg.Upstream.AnycastGroups[0].AnycastIP != "192.0.2.1" ||
		len(cfg.Upstream.AnycastGroups[0].Backends) != 1 ||
		cfg.Upstream.AnycastGroups[0].Backends[0].PhysicalIP != "10.0.0.2" ||
		cfg.Upstream.AnycastGroups[0].Backends[0].Port != 53 ||
		cfg.Upstream.AnycastGroups[0].Backends[0].Weight != 100 {
		t.Fatalf("control: groups = %+v", cfg.Upstream.AnycastGroups)
	}

	// Shape error 1: anycast_groups written as a mapping (missing "- ").
	// Previously: silent skip, empty group list.
	if _, err = UnmarshalYAML("upstream:\n  anycast_groups:\n    anycast_ip: 192.0.2.1\n"); err == nil {
		t.Fatalf("FAIL: mapping-shaped upstream.anycast_groups accepted silently (want a load error naming anycast_groups, per AGENTS.md strict loading)")
	}

	// Shape error 2: a non-mapping item inside the anycast_groups sequence.
	// Previously: silent skip.
	if _, err = UnmarshalYAML("upstream:\n  anycast_groups:\n    - 192.0.2.1\n"); err == nil {
		t.Fatalf("FAIL: scalar upstream.anycast_groups item accepted silently (want a load error)")
	}

	// Shape error 3 (nested): a group's backends written as a mapping.
	// Previously: silently empty backends on the group.
	if _, err = UnmarshalYAML("upstream:\n  anycast_groups:\n    - anycast_ip: 192.0.2.1\n      backends:\n        physical_ip: 10.0.0.2\n"); err == nil {
		t.Fatalf("FAIL: mapping-shaped backends accepted silently (want a load error naming backends)")
	}

	// Shape error 4 (nested): a non-mapping item inside backends.
	// Previously: silent skip.
	if _, err = UnmarshalYAML("upstream:\n  anycast_groups:\n    - anycast_ip: 192.0.2.1\n      backends:\n        - 10.0.0.2\n"); err == nil {
		t.Fatalf("FAIL: scalar backends item accepted silently (want a load error)")
	}
}
