package config

// Round-062 proof + regression: unmarshalGeoDNS silently dropped a shaped
// rules[] entry that parsed to no records and no default — e.g. a rule whose
// only region key is a lowercase typo ("us:" fails isGeoRegionKey) or whose
// only record value is empty. The configured domain silently stopped being
// geo-steered and resolved through the normal path instead, with no config
// error. Same strict-loading class as rpz.zones (round-047), geodns.shapes
// (round-048), upstream.anycast_groups (round-049) and cluster.peers
// (round-050): the loader must be loud, not silently filter operator input.

import (
	"strings"
	"testing"
)

func TestUnmarshalYAML_GeoDNSRejectsRuleWithoutRecordsOrDefault(t *testing.T) {
	const typoRegionKey = `
geodns:
  enabled: true
  rules:
    - domain: "cdn.example.com."
      type: "A"
      us: "192.0.2.10"
`
	_, err := UnmarshalYAML(typoRegionKey)
	if err == nil {
		t.Errorf("FAIL: geodns rule with no records and no default (lowercase region-key typo) was accepted silently — the rule is dropped and the domain silently stops being geo-steered")
		return
	}
	if !strings.Contains(err.Error(), "cdn.example.com.") {
		t.Errorf("FAIL: load error does not identify the rule: %v", err)
	}
}

func TestUnmarshalYAML_GeoDNSRejectsRuleWithOnlyEmptyRecordValues(t *testing.T) {
	const emptyRecordValue = `
geodns:
  enabled: true
  rules:
    - domain: "cdn.example.com."
      type: "A"
      records:
        US: ""
`
	if _, err := UnmarshalYAML(emptyRecordValue); err == nil {
		t.Errorf("FAIL: geodns rule whose only record value is empty was accepted silently — rule dropped, domain not geo-steered")
	}
}

// Control: the documented shape keeps loading exactly as before.
func TestUnmarshalYAML_GeoDNSValidRuleStillLoads(t *testing.T) {
	const valid = `
geodns:
  enabled: true
  rules:
    - domain: "cdn.example.com."
      type: "A"
      records:
        US: "192.0.2.10"
        DE: "192.0.2.11"
      default: "192.0.2.1"
`
	cfg, err := UnmarshalYAML(valid)
	if err != nil {
		t.Fatalf("FAIL: control rule rejected: %v", err)
	}
	if cfg == nil || len(cfg.GeoDNS.Rules) != 1 {
		t.Fatalf("FAIL: control rule missing: %+v", cfg.GeoDNS.Rules)
	}
	r := cfg.GeoDNS.Rules[0]
	if r.Domain != "cdn.example.com." || r.Default != "192.0.2.1" || len(r.Records) != 2 {
		t.Fatalf("FAIL: control rule parsed wrong: %+v", r)
	}
}
