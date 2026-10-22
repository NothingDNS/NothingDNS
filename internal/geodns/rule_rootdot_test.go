package geodns

import (
	"net"
	"testing"
)

// The root dot is optional in a DNS name's presentation form. Query names
// always arrive with it, so a rule configured without it must still match.
func TestResolveRuleDomainRootDotIsOptional(t *testing.T) {
	ip := net.ParseIP("203.0.113.9")

	cases := []struct {
		name      string
		ruleName  string
		queryName string
		want      string
	}{
		{"control: both with dot", "cdn.example.com.", "cdn.example.com.", "192.0.2.1"},
		{"rule without dot, query with dot", "cdn.example.com", "cdn.example.com.", "192.0.2.1"},
		{"rule with dot, query without dot", "cdn.example.com.", "cdn.example.com", "192.0.2.1"},
		{"rule without dot and mixed case", "CDN.Example.COM", "cdn.example.com.", "192.0.2.1"},
		{"a parent name is not a match", "example.com", "cdn.example.com.", ""},
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

func TestRuleKeyRootDotAcrossEntryPoints(t *testing.T) {
	ip := net.ParseIP("203.0.113.9")

	// Config.GeoRules keys go through the same normalization.
	e := NewEngine(Config{Enabled: true, GeoRules: map[string]*GeoRecord{
		"cdn.example.com:A": {Default: "192.0.2.7", Type: "A"},
	}})
	if got := e.Resolve("cdn.example.com.", "A", ip); got != "192.0.2.7" {
		t.Fatalf("Config.GeoRules rule without root dot not matched: got %q", got)
	}

	// The two spellings are one rule: re-setting replaces, RemoveRule removes.
	e.SetRule("cdn.example.com.", "A", &GeoRecord{Default: "192.0.2.8"})
	if n := e.Stats().Rules; n != 1 {
		t.Fatalf("Rules = %d, want 1 (dot and no-dot spellings are the same rule)", n)
	}
	e.RemoveRule("cdn.example.com", "A")
	if n := e.Stats().Rules; n != 0 {
		t.Fatalf("Rules = %d, want 0 after RemoveRule with the other spelling", n)
	}

	// The record type remains part of the key.
	e.SetRule("cdn.example.com", "A", &GeoRecord{Default: "192.0.2.9"})
	if got := e.Resolve("cdn.example.com.", "AAAA", ip); got != "" {
		t.Fatalf("an A rule answered an AAAA lookup: got %q", got)
	}
}
