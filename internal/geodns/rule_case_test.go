package geodns

import (
	"net"
	"testing"
)

// A rule's domain compares case-insensitively (RFC 1035 §2.3.3, RFC 4343):
// resolvers using 0x20 encoding randomize the case of the query name, so the
// spelling of the name must not decide whether a rule applies.
func TestResolveRuleDomainIsCaseInsensitive(t *testing.T) {
	ip := net.ParseIP("203.0.113.9")

	cases := []struct {
		name      string
		ruleName  string
		queryName string
		want      string
	}{
		{"control exact spelling", "www.example.com.", "www.example.com.", "192.0.2.1"},
		{"mixed-case query", "www.example.com.", "WwW.ExAmPlE.cOm.", "192.0.2.1"},
		{"mixed-case rule", "WWW.Example.COM.", "www.example.com.", "192.0.2.1"},
		{"different name still misses", "www.example.com.", "WWW.OTHER.COM.", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := NewEngine(Config{Enabled: true})
			e.SetRule(tc.ruleName, "A", &GeoRecord{Default: "192.0.2.1", Type: "A"})
			if got := e.Resolve(tc.queryName, "A", ip); got != tc.want {
				t.Fatalf("Resolve(%q) with rule %q = %q, want %q", tc.queryName, tc.ruleName, got, tc.want)
			}
		})
	}
}

func TestRemoveRuleAndConfigRulesIgnoreDomainCase(t *testing.T) {
	ip := net.ParseIP("203.0.113.9")

	// Rules supplied through Config.GeoRules are normalized like SetRule.
	e := NewEngine(Config{Enabled: true, GeoRules: map[string]*GeoRecord{
		"CDN.Example.com.:A": {Default: "192.0.2.7", Type: "A"},
	}})
	if got := e.Resolve("cdn.EXAMPLE.com.", "A", ip); got != "192.0.2.7" {
		t.Fatalf("Config.GeoRules rule not matched case-insensitively: got %q", got)
	}

	// RemoveRule finds the rule whatever spelling set or removes it.
	e.RemoveRule("CDN.example.COM.", "A")
	if got := e.Resolve("cdn.example.com.", "A", ip); got != "" {
		t.Fatalf("rule survived RemoveRule with a different spelling: got %q", got)
	}
	if n := e.Stats().Rules; n != 0 {
		t.Fatalf("Rules = %d, want 0 after RemoveRule", n)
	}

	// SetRule twice with different spellings is one rule, not two.
	e.SetRule("a.example.com.", "A", &GeoRecord{Default: "192.0.2.1"})
	e.SetRule("A.EXAMPLE.COM.", "A", &GeoRecord{Default: "192.0.2.2"})
	if n := e.Stats().Rules; n != 1 {
		t.Fatalf("Rules = %d, want 1 (spellings must update the same rule)", n)
	}
	if got := e.Resolve("a.example.com.", "A", ip); got != "192.0.2.2" {
		t.Fatalf("got %q, want the later rule 192.0.2.2", got)
	}
}
