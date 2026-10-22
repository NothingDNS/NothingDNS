package config

import "testing"

// geodns.rules accepts region records either under a nested `records:` map or
// as flat keys beside `default:` (the form documented in config.example.yaml
// and docs/SPECIFICATION.md §9.2.2). The flat form must accept ANY region key
// the engine can match — every ISO country code, a continent code, or an
// "AS<n>" ASN — not just a fixed shortlist, or a rule silently loses records.
func TestGeoDNSRulesFlatRegionKeys(t *testing.T) {
	load := func(t *testing.T, body string) map[string]string {
		t.Helper()
		cfg, err := UnmarshalYAML("geodns:\n  enabled: true\n  rules:\n    - domain: cdn.example.com.\n      type: A\n      default: 192.0.2.1\n" + body)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if len(cfg.GeoDNS.Rules) != 1 {
			t.Fatalf("rules = %+v, want exactly one", cfg.GeoDNS.Rules)
		}
		return cfg.GeoDNS.Rules[0].Records
	}

	// Control: flat keys from the fixed shortlist, and the nested form.
	recs := load(t, "      US: 192.0.2.20\n      EU: 192.0.2.30\n")
	if recs["US"] != "192.0.2.20" || recs["EU"] != "192.0.2.30" {
		t.Fatalf("control: shortlist flat keys = %v", recs)
	}
	recs = load(t, "      records:\n        HK: 192.0.2.40\n")
	if recs["HK"] != "192.0.2.40" {
		t.Fatalf("control: nested records HK = %v", recs)
	}

	// Flat keys outside the old shortlist: other countries, and an ASN.
	recs = load(t, "      HK: 192.0.2.40\n      TR: 192.0.2.41\n      AS13335: 192.0.2.42\n")
	for key, want := range map[string]string{"HK": "192.0.2.40", "TR": "192.0.2.41", "AS13335": "192.0.2.42"} {
		if recs[key] != want {
			t.Errorf("FAIL: flat region key %s was dropped from the rule: records = %v", key, recs)
		}
	}
}

// Only region-shaped keys are records. A mistyped field name must not become a
// record (its value would be served as an answer for a bogus region), and the
// real rule fields must never be read as regions.
func TestGeoDNSRulesFlatKeysIgnoreNonRegionKeys(t *testing.T) {
	cfg, err := UnmarshalYAML("geodns:\n  enabled: true\n  rules:\n" +
		"    - domain: cdn.example.com.\n      type: A\n      default: 192.0.2.1\n" +
		"      defualt: 198.51.100.9\n      us: 198.51.100.10\n      USA: 198.51.100.11\n" +
		"      AS: 198.51.100.12\n      ASx: 198.51.100.13\n      HK: 192.0.2.40\n")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.GeoDNS.Rules) != 1 {
		t.Fatalf("rules = %+v, want one", cfg.GeoDNS.Rules)
	}
	r := cfg.GeoDNS.Rules[0]
	if r.Domain != "cdn.example.com." || r.Type != "A" || r.Default != "192.0.2.1" {
		t.Fatalf("rule fields disturbed: %+v", r)
	}
	// "AS" is the Asia continent code, so it is a region; the rest are not.
	want := map[string]string{"HK": "192.0.2.40", "AS": "198.51.100.12"}
	if len(r.Records) != len(want) {
		t.Fatalf("records = %v, want exactly %v", r.Records, want)
	}
	for k, v := range want {
		if r.Records[k] != v {
			t.Errorf("records[%s] = %q, want %q", k, r.Records[k], v)
		}
	}
}

func TestIsGeoRegionKey(t *testing.T) {
	for key, want := range map[string]bool{
		"US": true, "HK": true, "EU": true, "AS": true, "AS13335": true, "AS1": true,
		"us": false, "Us": false, "U": false, "USA": false, "ASx": false, "AS13x": false,
		"": false, "domain": false, "type": false, "default": false, "records": false, "A1": false,
	} {
		if got := isGeoRegionKey(key); got != want {
			t.Errorf("isGeoRegionKey(%q) = %v, want %v", key, got, want)
		}
	}
}
