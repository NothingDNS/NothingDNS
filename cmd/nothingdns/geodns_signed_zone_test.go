package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/geodns"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// A GeoDNS answer in a signed zone carries the RRSIG of its RRset for DO=1
// clients, signed by the zone's active ZSK; unsigned, a validator finds the
// signed zone's answer Bogus (F741).
func TestGeoDNSAnswerSignedInSignedZone(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "signed.test.", []zone.Record{
		{Name: "signed.test.", Type: "SOA", TTL: 300, RData: "ns1.signed.test. h.signed.test. 1 3600 600 604800 300"},
		{Name: "signed.test.", Type: "NS", TTL: 300, RData: "ns1.signed.test."},
	})
	signer := dnssecRegSigner(t, "signed.test.")
	h.zoneSigners = map[string]*dnssec.Signer{"signed.test.": signer}
	geo := geodns.NewEngine(geodns.Config{Enabled: true})
	geo.SetRule("geo.signed.test.", "A", &geodns.GeoRecord{Default: "192.0.2.10", Type: "A"})
	h.security.GeoEngine = geo

	m := dnssecRegAsk(t, h, "geo.signed.test.", protocol.TypeA)
	if dnssecRegCount(m.Answers, protocol.TypeA) != 1 {
		t.Fatalf("geo answer has %d A records, want 1", dnssecRegCount(m.Answers, protocol.TypeA))
	}
	var sig *protocol.RDataRRSIG
	for _, rr := range m.Answers {
		if s, ok := rr.Data.(*protocol.RDataRRSIG); ok && s.TypeCovered == protocol.TypeA {
			sig = s
		}
	}
	if zsk := signer.GetActiveZSKs()[0]; sig == nil || sig.KeyTag != zsk.KeyTag || sig.SignerName.String() != "signed.test." {
		t.Fatalf("geo answer RRSIG = %+v, want one by signed.test. key %d", sig, zsk.KeyTag)
	}
}
