package cache

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// cnameNSECFixture caches the proof of an NXDOMAIN for beta.example.com. whose
// covering NSEC is owned by "alias.example.com." — a name that exists. The
// type bitmap of that NSEC is the caller's choice.
func cnameNSECFixture(t *testing.T, bitmap []uint16) *NSECCache {
	t.Helper()
	nc := NewNSECCache(100)

	soa := &protocol.ResourceRecord{
		Name: mustName("example.com."), Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataSOA{
			MName: mustName("ns1.example.com."), RName: mustName("admin.example.com."),
			Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300,
		},
	}
	covering := &protocol.ResourceRecord{
		Name: mustName("alias.example.com."), Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataNSEC{NextDomain: mustName("gamma.example.com."), TypeBitMap: bitmap},
	}
	// Wildcard denial, so the cache is willing to synthesize NXDOMAIN at all.
	wildcard := &protocol.ResourceRecord{
		Name: mustName("example.com."), Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataNSEC{
			NextDomain: mustName("alias.example.com."),
			TypeBitMap: []uint16{protocol.TypeNS, protocol.TypeSOA, protocol.TypeRRSIG, protocol.TypeNSEC},
		},
	}
	nc.AddFromResponse(&protocol.Message{
		Header:      protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeNameError)},
		Authorities: []*protocol.ResourceRecord{soa, covering, wildcard},
	}, true)
	return nc
}

// RFC 6840 §4.3: a NOERROR/NODATA answer may only be derived from an NSEC whose
// type bitmap lacks the CNAME bit as well as the query type. A name that owns a
// CNAME must be answered with the CNAME, never with "no data" — treating it as
// NODATA hides the alias (and hands out AD=1 for it).
func TestNSECCacheDoesNotSynthesizeNODATAForACNAMEOwner(t *testing.T) {
	t.Run("control: no CNAME bit, missing type is NODATA", func(t *testing.T) {
		nc := cnameNSECFixture(t, []uint16{protocol.TypeA, protocol.TypeRRSIG, protocol.TypeNSEC})
		got := nc.Lookup("alias.example.com.", protocol.TypeAAAA)
		if got == nil || got.Header.Flags.RCODE != protocol.RcodeSuccess || len(got.Answers) != 0 {
			t.Fatalf("control: AAAA at an A-only owner should be a synthesized NODATA, got %+v", got)
		}
	})

	t.Run("CNAME bit set: no NODATA for A", func(t *testing.T) {
		nc := cnameNSECFixture(t, []uint16{protocol.TypeCNAME, protocol.TypeRRSIG, protocol.TypeNSEC})
		if got := nc.Lookup("alias.example.com.", protocol.TypeA); got != nil {
			t.Fatalf("FAIL: synthesized %s for A at a CNAME owner (rcode=%d, AD=%v); the CNAME exists and must be resolved",
				"NODATA", got.Header.Flags.RCODE, got.Header.Flags.AD)
		}
	})

	t.Run("CNAME bit set: no NODATA for AAAA or MX either", func(t *testing.T) {
		nc := cnameNSECFixture(t, []uint16{protocol.TypeCNAME, protocol.TypeRRSIG, protocol.TypeNSEC})
		for _, qt := range []uint16{protocol.TypeAAAA, protocol.TypeMX, protocol.TypeTXT} {
			if got := nc.Lookup("alias.example.com.", qt); got != nil {
				t.Errorf("FAIL: synthesized NODATA for type %d at a CNAME owner", qt)
			}
		}
	})

	t.Run("CNAME bit set but the query is for the CNAME itself", func(t *testing.T) {
		nc := cnameNSECFixture(t, []uint16{protocol.TypeCNAME, protocol.TypeRRSIG, protocol.TypeNSEC})
		if got := nc.Lookup("alias.example.com.", protocol.TypeCNAME); got != nil {
			t.Fatalf("a CNAME is in the bitmap, there is nothing to deny: got %+v", got)
		}
	})

	t.Run("a CNAME owner does not break the NXDOMAIN proof it covers", func(t *testing.T) {
		nc := cnameNSECFixture(t, []uint16{protocol.TypeCNAME, protocol.TypeRRSIG, protocol.TypeNSEC})
		got := nc.Lookup("beta.example.com.", protocol.TypeA)
		if got == nil || got.Header.Flags.RCODE != protocol.RcodeNameError {
			t.Fatalf("beta.example.com. lies between alias and gamma and must still be denied, got %+v", got)
		}
	})
}
