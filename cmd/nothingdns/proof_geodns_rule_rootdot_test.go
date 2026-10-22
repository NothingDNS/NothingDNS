package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// A geodns rule's domain is a DNS name, and the root dot is optional in
// presentation form (zones, blocklist and RPZ entries all accept both). A rule
// written "cdn.example.com" loads without error and is counted in the stats,
// so it must apply to the query name "cdn.example.com." exactly like the
// trailing-dot spelling does.
func TestServeDNS_GeoDNSRuleDomainRootDotIsOptional(t *testing.T) {
	geoAddr := [4]byte{192, 0, 2, 20}
	answer := func(ruleDomain string) [4]byte {
		t.Helper()
		yaml := "geodns:\n  enabled: true\n  rules:\n    - domain: " + ruleDomain +
			"\n      type: A\n      default: 192.0.2.20\n"
		cfg, err := config.UnmarshalYAML(yaml)
		if err != nil {
			t.Fatalf("config for %q: %v", ruleDomain, err)
		}
		mgr, err := NewSecurityManager(cfg, newMgrLogger())
		if err != nil {
			t.Fatalf("NewSecurityManager: %v", err)
		}
		defer mgr.Stop()
		if n := mgr.Result().GeoEngine.Stats().Rules; n != 1 {
			t.Fatalf("rule %q not loaded: Rules = %d", ruleDomain, n)
		}

		h := newTestHandler()
		h.security.GeoEngine = mgr.Result().GeoEngine
		addZoneRecords(t, h, "example.com.", []zone.Record{
			{Name: "cdn.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "10.0.0.1"},
		})
		w := newCaptureWriter("10.0.0.1", "udp")
		h.ServeDNS(w, newTestQuery(t, "cdn.example.com.", protocol.TypeA))
		if w.msg == nil || len(w.msg.Answers) != 1 {
			t.Fatalf("expected one answer, got %+v", w.msg)
		}
		return w.msg.Answers[0].Data.(*protocol.RDataA).Address
	}

	if got := answer("cdn.example.com."); got != geoAddr { // control: documented spelling
		t.Fatalf("control: rule with trailing dot got %v, want GeoDNS %v", got, geoAddr)
	}
	if got := answer("cdn.example.com"); got != geoAddr {
		t.Errorf("FAIL: rule without trailing dot loaded but never matched: got %v, want GeoDNS %v", got, geoAddr)
	}
}
