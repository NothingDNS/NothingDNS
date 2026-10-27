package main

// A GeoDNS name exists in its zone: its other types are NODATA (with an NSEC
// at the name in a signed zone), names above it are empty non-terminals, and
// a rule added later is not hidden by a cached NXDOMAIN (F742).

import (
	"slices"
	"testing"

	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/geodns"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func geoTestNSECs(m *protocol.Message) map[string]*protocol.RDataNSEC {
	out := map[string]*protocol.RDataNSEC{}
	for _, rr := range m.Authorities {
		if n, ok := rr.Data.(*protocol.RDataNSEC); ok {
			out[rr.Name.String()] = n
		}
	}
	return out
}

func TestGeoDNSNamesExistInTheirZone(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "signed.test.", []zone.Record{
		{Name: "signed.test.", Type: "SOA", TTL: 300, RData: "ns1.signed.test. h.signed.test. 1 3600 600 604800 300"},
		{Name: "signed.test.", Type: "NS", TTL: 300, RData: "ns1.signed.test."},
		{Name: "www.signed.test.", Type: "A", TTL: 300, RData: "192.0.2.1"},
	})
	h.zoneSigners = map[string]*dnssec.Signer{"signed.test.": dnssecRegSigner(t, "signed.test.")}
	geo := geodns.NewEngine(geodns.Config{Enabled: true})
	geo.SetRule("geo.signed.test.", "A", &geodns.GeoRecord{Default: "192.0.2.10", Type: "A"})
	geo.SetRule("a.deep.signed.test.", "A", &geodns.GeoRecord{Default: "192.0.2.11", Type: "A"})
	h.security.GeoEngine = geo

	// Signed NODATA for the geo name: NSEC at the name, bitmap has A not AAAA.
	m := dnssecRegAsk(t, h, "geo.signed.test.", protocol.TypeAAAA)
	if m.Header.Flags.RCODE != 0 {
		t.Fatalf("geo AAAA rcode %d", m.Header.Flags.RCODE)
	}
	n := geoTestNSECs(m)["geo.signed.test."]
	if n == nil || !slices.Contains(n.TypeBitMap, protocol.TypeA) || slices.Contains(n.TypeBitMap, protocol.TypeAAAA) || !dnssecRegSigCovers(m.Authorities, protocol.TypeNSEC) {
		t.Fatalf("NODATA proof for geo name: %+v", n)
	}

	// Empty non-terminal above a geo name: NODATA.
	if m := dnssecRegAsk(t, h, "deep.signed.test.", protocol.TypeA); m.Header.Flags.RCODE != 0 {
		t.Fatalf("ENT above geo name: rcode %d", m.Header.Flags.RCODE)
	}

	// An unrelated name stays NXDOMAIN and its proof does not cover a geo name.
	m = dnssecRegAsk(t, h, "gzz.signed.test.", protocol.TypeA)
	if m.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Fatalf("unrelated name rcode %d", m.Header.Flags.RCODE)
	}
	for owner := range geoTestNSECs(m) {
		if owner == "geo.signed.test." {
			return
		}
	}
	t.Fatalf("NXDOMAIN proof for gzz.signed.test. not anchored at geo.signed.test.: %v", geoTestNSECs(m))
}

func TestGeoDNSRuleAddedAfterNXDOMAINIsServed(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "plain.test.", []zone.Record{
		{Name: "plain.test.", Type: "SOA", TTL: 300, RData: "ns1.plain.test. h.plain.test. 1 3600 600 604800 300"},
	})
	geo := geodns.NewEngine(geodns.Config{Enabled: true})
	h.security.GeoEngine = geo
	ask := func(name string, qt uint16) uint8 {
		w := newCaptureWriter("192.0.2.100", "udp")
		h.ServeDNS(w, newTestQuery(t, name, qt))
		return w.msg.Header.Flags.RCODE
	}
	if rc := ask("late.plain.test.", protocol.TypeAAAA); rc != protocol.RcodeNameError {
		t.Fatalf("before the rule: rcode %d", rc)
	}
	geo.SetRule("late.plain.test.", "A", &geodns.GeoRecord{Default: "192.0.2.30", Type: "A"})
	if rc := ask("late.plain.test.", protocol.TypeAAAA); rc != 0 {
		t.Fatalf("after the rule: rcode %d (stale cached NXDOMAIN?)", rc)
	}
}
