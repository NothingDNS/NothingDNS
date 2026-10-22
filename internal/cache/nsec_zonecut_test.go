package cache

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// zoneCutNSECFixture caches the proof of an NXDOMAIN in example.com. whose
// covering NSEC is owned by `owner` and points at `next`, with the given type
// bitmap. The response's SOA is the example.com. SOA, as a real response from
// the parent zone's server carries.
func zoneCutNSECFixture(t *testing.T, owner, next string, bitmap []uint16) *NSECCache {
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
		Name: mustName(owner), Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataNSEC{NextDomain: mustName(next), TypeBitMap: bitmap},
	}
	// The wildcard-denial NSEC a real NXDOMAIN response carries (RFC 4035
	// §5.3.4): without it the cache never synthesizes an NXDOMAIN at all, so
	// the fixture must supply it for the "is denied" controls to mean anything.
	// It is owned by the apex and covers "*.example.com." up to the zone's first
	// real name, and has NO bearing on the names the tests below probe.
	wildcard := &protocol.ResourceRecord{
		Name: mustName("example.com."), Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataNSEC{NextDomain: mustName("aaa.example.com."), TypeBitMap: apexBitmap},
	}
	nc.AddFromResponse(&protocol.Message{
		Header:      protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeNameError)},
		Authorities: []*protocol.ResourceRecord{soa, covering, wildcard},
	}, true)
	return nc
}

var (
	// An ancestor delegation: NS set, SOA clear (RFC 6840 §4.1).
	delegationBitmap = []uint16{protocol.TypeNS, protocol.TypeRRSIG, protocol.TypeNSEC}
	// A zone apex: NS and SOA both set.
	apexBitmap = []uint16{protocol.TypeNS, protocol.TypeSOA, protocol.TypeRRSIG, protocol.TypeNSEC}
	// An ordinary owner.
	plainBitmap = []uint16{protocol.TypeA, protocol.TypeRRSIG, protocol.TypeNSEC}
	// A DNAME owner.
	dnameBitmap = []uint16{protocol.TypeDNAME, protocol.TypeRRSIG, protocol.TypeNSEC}
)

// RFC 6840 §4.1: "Ancestor delegation NSEC or NSEC3 RRs MUST NOT be used to
// assume nonexistence of any RRs below that zone cut, which include all RRs at
// that (original) owner name other than DS RRs, and all RRs below that owner
// name regardless of type." An NSEC owned by a delegation point describes the
// PARENT's view of the cut; the child zone's names and its apex data are not in
// it, so it can neither deny names beneath the cut nor deny types at the cut.
func TestNSECCacheDoesNotUseAncestorDelegationNSECBelowTheCut(t *testing.T) {
	t.Run("control: ordinary owner, name in range is denied", func(t *testing.T) {
		nc := zoneCutNSECFixture(t, "sub.example.com.", "zzz.example.com.", plainBitmap)
		got := nc.Lookup("tt.example.com.", protocol.TypeA)
		if got == nil || got.Header.Flags.RCODE != protocol.RcodeNameError {
			t.Fatalf("control: expected a synthesized NXDOMAIN, got %+v", got)
		}
	})

	t.Run("control: an NSEC with both NS and SOA set (apex-like) still denies names in its range", func(t *testing.T) {
		nc := zoneCutNSECFixture(t, "aaa.example.com.", "gamma.example.com.", apexBitmap)
		got := nc.Lookup("beta.example.com.", protocol.TypeA)
		if got == nil || got.Header.Flags.RCODE != protocol.RcodeNameError {
			t.Fatalf("control: an NS+SOA NSEC is not an ancestor delegation; expected NXDOMAIN, got %+v", got)
		}
	})

	t.Run("name below a delegation is not denied", func(t *testing.T) {
		nc := zoneCutNSECFixture(t, "sub.example.com.", "zzz.example.com.", delegationBitmap)
		if got := nc.Lookup("x.sub.example.com.", protocol.TypeA); got != nil {
			t.Fatalf("FAIL: synthesized rcode=%d (AD=%v) for x.sub.example.com. from an NSEC owned by the delegation sub.example.com.; the child zone's names are not in the parent's NSEC",
				got.Header.Flags.RCODE, got.Header.Flags.AD)
		}
	})

	t.Run("a deeper name below a delegation is not denied either", func(t *testing.T) {
		nc := zoneCutNSECFixture(t, "sub.example.com.", "zzz.example.com.", delegationBitmap)
		if got := nc.Lookup("a.b.sub.example.com.", protocol.TypeAAAA); got != nil {
			t.Fatalf("FAIL: synthesized rcode=%d for a name two labels below the cut", got.Header.Flags.RCODE)
		}
	})

	t.Run("types at the delegation owner other than DS are not denied", func(t *testing.T) {
		nc := zoneCutNSECFixture(t, "sub.example.com.", "zzz.example.com.", delegationBitmap)
		for _, qt := range []uint16{protocol.TypeA, protocol.TypeAAAA, protocol.TypeMX, protocol.TypeSOA, protocol.TypeDNSKEY} {
			if got := nc.Lookup("sub.example.com.", qt); got != nil {
				t.Errorf("FAIL: synthesized NODATA for type %d at the delegation owner; those RRs live in the child zone", qt)
			}
		}
	})

	t.Run("DS at the delegation owner IS answered by the parent's NSEC", func(t *testing.T) {
		nc := zoneCutNSECFixture(t, "sub.example.com.", "zzz.example.com.", delegationBitmap)
		got := nc.Lookup("sub.example.com.", protocol.TypeDS)
		if got == nil || got.Header.Flags.RCODE != protocol.RcodeSuccess || len(got.Answers) != 0 {
			t.Fatalf("an insecure-delegation proof (no DS) is exactly what the parent NSEC is for, got %+v", got)
		}
	})

	t.Run("a name in range that is NOT below the cut is still denied", func(t *testing.T) {
		// The covering NSEC is owned by the delegation, but the name sorts after
		// the cut's whole subtree: "tt.example.com." is not below sub.example.com.
		nc := zoneCutNSECFixture(t, "sub.example.com.", "zzz.example.com.", delegationBitmap)
		got := nc.Lookup("tt.example.com.", protocol.TypeA)
		if got == nil || got.Header.Flags.RCODE != protocol.RcodeNameError {
			t.Fatalf("a sibling of the delegation is outside the cut and must still be denied, got %+v", got)
		}
	})
}

// RFC 6840 §4.1: "An NSEC or NSEC3 RR with the DNAME bit set MUST NOT be used to
// assume the nonexistence of any subdomain of that NSEC/NSEC3 RR's (original)
// owner name." Names under a DNAME owner are synthesized from the DNAME, they
// do not exist as nodes, so "no name between owner and next" says nothing.
func TestNSECCacheDoesNotUseDNAMENSECBelowTheOwner(t *testing.T) {
	t.Run("name below a DNAME owner is not denied", func(t *testing.T) {
		nc := zoneCutNSECFixture(t, "dn.example.com.", "zzz.example.com.", dnameBitmap)
		if got := nc.Lookup("x.dn.example.com.", protocol.TypeA); got != nil {
			t.Fatalf("FAIL: synthesized rcode=%d (AD=%v) for x.dn.example.com. from the NSEC of the DNAME owner dn.example.com.",
				got.Header.Flags.RCODE, got.Header.Flags.AD)
		}
	})

	t.Run("a sibling of the DNAME owner is still denied", func(t *testing.T) {
		nc := zoneCutNSECFixture(t, "dn.example.com.", "zzz.example.com.", dnameBitmap)
		got := nc.Lookup("tt.example.com.", protocol.TypeA)
		if got == nil || got.Header.Flags.RCODE != protocol.RcodeNameError {
			t.Fatalf("tt.example.com. is not a subdomain of the DNAME owner and must be denied, got %+v", got)
		}
	})

	t.Run("a type missing at the DNAME owner itself is still NODATA", func(t *testing.T) {
		nc := zoneCutNSECFixture(t, "dn.example.com.", "zzz.example.com.", dnameBitmap)
		got := nc.Lookup("dn.example.com.", protocol.TypeA)
		if got == nil || got.Header.Flags.RCODE != protocol.RcodeSuccess {
			t.Fatalf("a DNAME does not redirect its own owner; NODATA for A is valid, got %+v", got)
		}
	})
}

// RFC 6840 §4.1 calls an NSEC an ancestor delegation only when, besides NS set
// and SOA clear, its signer is SHORTER than its owner — i.e. the parent signed
// it. A zone's own apex NSEC is signed by the zone and is not a cut, even when
// its bitmap is NS-without-SOA (a trimmed bitmap, as in the handler tests). It
// must keep denying names in its range and below.
//
// zoneCutNSECFixture is not used here: it always adds its own apex-owned
// wildcard-denial NSEC, which would overwrite the apex entry under test.
func TestNSECCacheApexNSECIsNotAnAncestorDelegation(t *testing.T) {
	soa := &protocol.ResourceRecord{
		Name: mustName("example.com."), Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataSOA{
			MName: mustName("ns1.example.com."), RName: mustName("admin.example.com."),
			Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300,
		},
	}
	trimmed := []uint16{protocol.TypeNS, protocol.TypeRRSIG, protocol.TypeNSEC} // NS set, SOA clear
	// Covering NSEC for beta/x.beta: a -> z. The apex NSEC (example.com. -> a) is
	// both the zone's own record and the wildcard-denial proof.
	covering := &protocol.ResourceRecord{
		Name: mustName("a.example.com."), Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataNSEC{NextDomain: mustName("z.example.com."), TypeBitMap: []uint16{protocol.TypeA}},
	}
	apex := &protocol.ResourceRecord{
		Name: mustName("example.com."), Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataNSEC{NextDomain: mustName("a.example.com."), TypeBitMap: trimmed},
	}
	nc := NewNSECCache(100)
	nc.AddFromResponse(&protocol.Message{
		Header:      protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeNameError)},
		Authorities: []*protocol.ResourceRecord{soa, covering, apex},
	}, true)
	if nc.Size() != 2 {
		t.Fatalf("fixture: cached %d entries, want 2", nc.Size())
	}

	if got := nc.Lookup("beta.example.com.", protocol.TypeA); got == nil || got.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Fatalf("the apex NSEC supplies the wildcard denial and must not be treated as a cut; expected NXDOMAIN, got %+v", got)
	}

	// Control: the same record at a name BELOW the zone IS an ancestor delegation.
	cut := &protocol.ResourceRecord{
		Name: mustName("sub.example.com."), Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataNSEC{NextDomain: mustName("zzz.example.com."), TypeBitMap: trimmed},
	}
	nc2 := NewNSECCache(100)
	nc2.AddFromResponse(&protocol.Message{
		Header:      protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeNameError)},
		Authorities: []*protocol.ResourceRecord{soa, cut},
	}, true)
	if got := nc2.Lookup("x.sub.example.com.", protocol.TypeA); got != nil {
		t.Fatalf("control: the same bitmap on a name strictly below the zone is a cut and must not deny below it, got %+v", got)
	}
}
