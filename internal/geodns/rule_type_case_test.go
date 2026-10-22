package geodns

import (
	"net"
	"testing"
)

// The record-type mnemonic is case-insensitive in presentation form
// (RFC 1035 §5.1). The resolver path always passes it upper-case, so a rule
// configured with another spelling must still be found.
func TestResolveRuleTypeIsCaseInsensitive(t *testing.T) {
	ip := net.ParseIP("203.0.113.9")

	cases := []struct {
		name      string
		ruleType  string
		lookup    string
		want      string
		ruleValue string
	}{
		{"control: both upper-case", "A", "A", "192.0.2.1", "192.0.2.1"},
		{"lower-case rule type", "a", "A", "192.0.2.1", "192.0.2.1"},
		{"mixed-case rule type", "Aaaa", "AAAA", "2001:db8::1", "2001:db8::1"},
		{"lower-case lookup type", "A", "a", "192.0.2.1", "192.0.2.1"},
		{"different type still misses", "a", "AAAA", "", "192.0.2.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := NewEngine(Config{Enabled: true})
			e.SetRule("cdn.example.com.", tc.ruleType, &GeoRecord{Default: tc.ruleValue, Type: tc.ruleType})
			if got := e.Resolve("cdn.example.com.", tc.lookup, ip); got != tc.want {
				t.Fatalf("rule type %q, lookup %q = %q, want %q", tc.ruleType, tc.lookup, got, tc.want)
			}
		})
	}
}

func TestRuleKeyTypeCaseAcrossEntryPoints(t *testing.T) {
	ip := net.ParseIP("203.0.113.9")

	// Config.GeoRules keys are normalized the same way.
	e := NewEngine(Config{Enabled: true, GeoRules: map[string]*GeoRecord{
		"cdn.example.com.:a": {Default: "192.0.2.7", Type: "a"},
	}})
	if got := e.Resolve("cdn.example.com.", "A", ip); got != "192.0.2.7" {
		t.Fatalf("Config.GeoRules lower-case type not matched: got %q", got)
	}

	// Spellings of the type are one rule: re-setting replaces, RemoveRule removes.
	e.SetRule("cdn.example.com.", "A", &GeoRecord{Default: "192.0.2.8"})
	if n := e.Stats().Rules; n != 1 {
		t.Fatalf("Rules = %d, want 1 (a and A are the same rule)", n)
	}
	e.RemoveRule("cdn.example.com.", "a")
	if n := e.Stats().Rules; n != 0 {
		t.Fatalf("Rules = %d, want 0 after RemoveRule with the other spelling", n)
	}
}
