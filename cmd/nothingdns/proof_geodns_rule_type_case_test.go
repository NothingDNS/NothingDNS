package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// Record-type mnemonics are case-insensitive in presentation form (RFC 1035
// §5.1, zone files accept "a" and "A" alike). A geodns rule written
// `type: a` loads without error and is counted in the stats, so it must
// answer an A query exactly like `type: A` does.
func TestServeDNS_GeoDNSRuleTypeCaseIsInsensitive(t *testing.T) {
	geoAddr := [4]byte{192, 0, 2, 20}
	answer := func(ruleType string) [4]byte {
		t.Helper()
		yaml := "geodns:\n  enabled: true\n  rules:\n    - domain: cdn.example.com.\n      type: " + ruleType +
			"\n      default: 192.0.2.20\n"
		cfg, err := config.UnmarshalYAML(yaml)
		if err != nil {
			t.Fatalf("config for type %q: %v", ruleType, err)
		}
		mgr, err := NewSecurityManager(cfg, newMgrLogger())
		if err != nil {
			t.Fatalf("NewSecurityManager: %v", err)
		}
		defer mgr.Stop()
		if n := mgr.Result().GeoEngine.Stats().Rules; n != 1 {
			t.Fatalf("rule with type %q not loaded: Rules = %d", ruleType, n)
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

	if got := answer("A"); got != geoAddr { // control: documented spelling
		t.Fatalf("control: rule type A got %v, want GeoDNS %v", got, geoAddr)
	}
	if got := answer("a"); got != geoAddr {
		t.Errorf("FAIL: rule with lower-case type loaded but never matched: got %v, want GeoDNS %v", got, geoAddr)
	}
}
