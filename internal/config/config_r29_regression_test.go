package config

import (
	"strings"
	"testing"
)

// F192: a boolean key with an unrecognised value used to fall back to the
// default silently (`require_tsig: ture` left TSIG off) while the same typo in
// an integer key was a load error.
func TestUnmarshalRejectsInvalidBoolean_F192(t *testing.T) {
	bad := map[string]string{
		"transfer.require_tsig":    "transfer:\n  require_tsig: ture\n",
		"dnssec.require_dnssec":    "dnssec:\n  require_dnssec: enable\n",
		"server.tls.enabled":       "server:\n  tls:\n    enabled: treu\n",
		"cache.prefetch":           "cache:\n  prefetch:\n    - true\n",
		"dnssec.signing.nsec3.opt": "dnssec:\n  signing:\n    nsec3:\n      opt_out: maybe\n",
	}
	for name, y := range bad {
		if _, err := UnmarshalYAMLWithEnv(y, false); err == nil || !strings.Contains(err.Error(), "boolean") {
			t.Errorf("%s: invalid boolean accepted (err=%v)", name, err)
		}
	}

	cfg, err := UnmarshalYAMLWithEnv("transfer:\n  require_tsig: Yes\ndnssec:\n  enabled: off\ncache:\n  enabled:\n", false)
	if err != nil {
		t.Fatalf("valid booleans rejected: %v", err)
	}
	if !cfg.Transfer.RequireTSIG || cfg.DNSSEC.Enabled || !cfg.Cache.Enabled {
		t.Fatalf("valid booleans misparsed: require_tsig=%v dnssec=%v cache(empty→default true)=%v",
			cfg.Transfer.RequireTSIG, cfg.DNSSEC.Enabled, cfg.Cache.Enabled)
	}
}

// F193: list-of-mapping sections written without the "- " item marker parsed
// as a mapping and were dropped silently — an ACL deny rule vanished while the
// config still validated.
func TestUnmarshalRejectsWrongShapeLists_F193(t *testing.T) {
	bad := map[string]string{
		"acl":                 "acl:\n  name: block\n  action: deny\n  networks:\n    - 203.0.113.0/24\n",
		"views":               "views:\n  name: internal\n",
		"slave_zones":         "slave_zones:\n  zone_name: example.com.\n",
		"http.users":          "server:\n  http:\n    users:\n      username: admin\n",
		"dnssec.signing.keys": "dnssec:\n  signing:\n    keys:\n      private_key: /k.pem\n",
		"acl scalar item":     "acl:\n  - deny\n",
		"zones mapping":       "zones:\n  file: example.zone\n",
	}
	for name, y := range bad {
		if _, err := UnmarshalYAMLWithEnv(y, false); err == nil {
			t.Errorf("%s: wrong-shape list accepted silently", name)
		}
	}

	// A mapping holding only foreign keys is reported by the unknown-key
	// warning and still loads (existing fixtures use `acl: {rules: []}`).
	if c, err := UnmarshalYAMLWithEnv("acl:\n  rules: []\n", false); err != nil || len(c.ACL) != 0 {
		t.Fatalf("acl foreign-key mapping: err=%v", err)
	}

	cfg, err := UnmarshalYAMLWithEnv("acl:\n  -\n  - name: a\n    action: allow\n    networks: [10.0.0.0/8]\nviews:\nzones: a.zone\n", false)
	if err != nil {
		t.Fatalf("valid lists rejected: %v", err)
	}
	if len(cfg.ACL) != 1 || len(cfg.Views) != 0 || len(cfg.Zones) != 1 || cfg.Zones[0] != "a.zone" {
		t.Fatalf("got acl=%d views=%d zones=%v", len(cfg.ACL), len(cfg.Views), cfg.Zones)
	}
}
