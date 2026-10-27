package main

// Signatures made at query time start an hour in the past, like SignZone's,
// so a validator whose clock is slightly behind does not see them as not yet
// valid (RFC 6781 §4.4.2.2) (F756).

import (
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func TestOnlineSignaturesAreBackdated(t *testing.T) {
	signer := dnssecRegSigner(t, "on.test.")
	h := newTestHandler()
	addZoneRecords(t, h, "on.test.", []zone.Record{
		{Name: "on.test.", Type: "SOA", TTL: 300, RData: "ns1.on.test. h.on.test. 1 3600 600 86400 300"},
		{Name: "www.on.test.", Type: "A", TTL: 300, RData: "192.0.2.1"},
		{Name: "*.wild.on.test.", Type: "TXT", TTL: 300, RData: "\"w\""},
	})
	h.zones["on.test."].SOA = &zone.SOARecord{Name: "on.test.", TTL: 300, MName: "ns1.on.test.", RName: "h.on.test.", Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300}
	h.zoneSigners = map[string]*dnssec.Signer{"on.test.": signer}
	now := time.Now().Unix()
	near := func(got uint32, want int64) bool { d := int64(got) - want; return d >= -5 && d <= 5 }
	n := 0
	for _, q := range []struct {
		name string
		qt   uint16
	}{{"www.on.test.", protocol.TypeA}, {"x.wild.on.test.", protocol.TypeTXT}, {"nx.on.test.", protocol.TypeA}, {"on.test.", protocol.TypeDNSKEY}} {
		m := dnssecRegAsk(t, h, q.name, q.qt)
		for _, sec := range [][]*protocol.ResourceRecord{m.Answers, m.Authorities} {
			for _, rr := range sec {
				s, ok := rr.Data.(*protocol.RDataRRSIG)
				if !ok {
					continue
				}
				n++
				if !near(s.Inception, now-3600) || !near(s.Expiration, now+30*24*3600) {
					t.Fatalf("%s: inception %d expiration %d (now %d)", q.name, s.Inception, s.Expiration, now)
				}
			}
		}
	}
	if n < 6 {
		t.Fatalf("only %d RRSIGs checked", n)
	}
	// A validator that checks times (IgnoreTime off) accepts the answer.
	v := dnssec.NewValidator(func() dnssec.ValidatorConfig { c := dnssec.DefaultValidatorConfig(); c.IgnoreTime = false; return c }(),
		func() *dnssec.TrustAnchorStore {
			s := dnssec.NewTrustAnchorStore()
			k := signer.GetKSKs()[0]
			s.AddAnchor(&dnssec.TrustAnchor{Zone: "on.test.", KeyTag: k.KeyTag, Algorithm: k.DNSKEY.Algorithm, PublicKey: k.DNSKEY.PublicKey})
			return s
		}(), &presignedTestResolver{t: t, h: h})
	if res, err := v.ValidateResponse(t.Context(), dnssecRegAsk(t, h, "www.on.test.", protocol.TypeA), "www.on.test."); res != dnssec.ValidationSecure {
		t.Fatalf("time-checked validation: %v %v", res, err)
	}
}
