package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/geodns"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// A GeoDNS rule must apply whatever case the client spelled the query name in:
// names compare case-insensitively (RFC 1035 §2.3.3) and 0x20-encoding
// resolvers randomize the case of every query.
func TestServeDNS_GeoDNSRuleAppliesToMixedCaseQuery(t *testing.T) {
	geoAddr := [4]byte{192, 168, 1, 1}
	answer := func(qname string) [4]byte {
		t.Helper()
		h := newTestHandler()
		h.security.GeoEngine = geodns.NewEngine(geodns.Config{Enabled: true})
		h.security.GeoEngine.SetRule("www.example.com.", "A", &geodns.GeoRecord{Default: "192.168.1.1", Type: "A", TTL: 300})
		addZoneRecords(t, h, "example.com.", []zone.Record{
			{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "10.0.0.1"},
		})
		w := newCaptureWriter("10.0.0.1", "udp")
		h.ServeDNS(w, newTestQuery(t, qname, protocol.TypeA))
		if w.msg == nil || len(w.msg.Answers) != 1 {
			t.Fatalf("expected one answer for %q, got %+v", qname, w.msg)
		}
		return w.msg.Answers[0].Data.(*protocol.RDataA).Address
	}

	if got := answer("www.example.com."); got != geoAddr { // control
		t.Fatalf("control: exact-case query got %v, want GeoDNS %v", got, geoAddr)
	}
	for _, qname := range []string{"WwW.ExAmPlE.cOm.", "WWW.EXAMPLE.COM."} {
		if got := answer(qname); got != geoAddr {
			t.Errorf("mixed-case query %q bypassed the GeoDNS rule: got %v, want %v", qname, got, geoAddr)
		}
	}
}
