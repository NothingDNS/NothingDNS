// Round-008 proof: the RFC 8198 aggressive NSEC cache answers across zones.
//
// The cache is GLOBAL: `entries` is keyed by the NSEC owner name alone
// (nsec.go:25) and `Lookup` (nsec.go:142) iterates every cached entry
// regardless of which zone it came from. `nameInNSECRange` (nsec.go:178)
// then decides a match with a pure canonical-order comparison and NO
// zone check.
//
// An NSEC record only proves non-existence for names inside its OWN zone
// (RFC 4034 §4.1.1, RFC 8198 §5.3/§5.4). Using one to deny a name in a
// different zone is cross-zone confusion: the resolver synthesizes an
// NXDOMAIN for a name it has no evidence about, and stamps AD=1 on it.
//
// Canonical order (RFC 4034 §6.1, right-to-left, a proper suffix sorts
// first) makes example.com. the SMALLEST name in its zone, so every NSEC
// chain ends with a wrap record whose NextDomain is the apex. The wrap
// branch of nameInNSECRange is `cmpOwner > 0 || cmpNext < 0` — and for a
// name in a totally different zone that sorts below the apex,
// CompareNames(evil.com., example.com.) == -1 makes cmpNext < 0 true.
// So the wrap record happily "proves" evil.com. absent.
//
// The zone is seeded below with a real two-record chain:
//
//	example.com.   -> bbb.example.com.   (apex -> first gap)
//	zzz.example.com. -> example.com.      (last owner -> apex, wrap)
//
// CLAIM 1: evil.com. (different zone) must return nil — no evidence.
// CLAIM 2: zzzz.bbb.com. (different zone) must return nil.
// CONTROL 1: aaa.example.com. — same zone, inside the apex->bbb gap — must
//
//	still be denied, so the fix cannot just disable NSEC caching.
//
// CONTROL 2: the same cross-zone check for a second zone (aaa.com.).
package cache

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func mustNameRound008(t *testing.T, s string) *protocol.Name {
	t.Helper()
	n, err := protocol.ParseName(s)
	if err != nil {
		t.Fatalf("ParseName(%q): %v", s, err)
	}
	return n
}

// round008Seed caches a validated NXDOMAIN carrying `chain` (owner/next
// pairs) for `zone`, plus the zone's SOA.
func round008Seed(t *testing.T, zone string, chain [][2]string) *NSECCache {
	t.Helper()
	nc := NewNSECCache(100)

	auths := []*protocol.ResourceRecord{{
		Name:  mustNameRound008(t, zone+"."),
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   3600,
		Data: &protocol.RDataSOA{
			MName:   mustNameRound008(t, "ns1."+zone+"."),
			RName:   mustNameRound008(t, "hostmaster."+zone+"."),
			Minimum: 300,
		},
	}}
	for _, e := range chain {
		auths = append(auths, &protocol.ResourceRecord{
			Name:  mustNameRound008(t, e[0]),
			Type:  protocol.TypeNSEC,
			Class: protocol.ClassIN,
			TTL:   3600,
			Data: &protocol.RDataNSEC{
				NextDomain: mustNameRound008(t, e[1]),
				TypeBitMap: []uint16{protocol.TypeA, protocol.TypeNSEC},
			},
		})
	}

	nc.AddFromResponse(&protocol.Message{
		Header:      protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeNameError)},
		Authorities: auths,
	}, true)

	if got := nc.Size(); got != len(chain) {
		t.Fatalf("setup: cached %d NSEC records, want %d", got, len(chain))
	}
	return nc
}

// round008ExampleZone seeds the example.com. chain described above.
func round008ExampleZone(t *testing.T) *NSECCache {
	t.Helper()
	return round008Seed(t, "example.com.", [][2]string{
		{"example.com.", "bbb.example.com."}, // apex -> first gap
		{"zzz.example.com.", "example.com."}, // last owner -> apex (wrap)
	})
}

func rcodeOf(m *protocol.Message) string {
	return protocol.RcodeString(int(m.Header.Flags.RCODE))
}

// TestNSECCache_DoesNotDenyAcrossZones_SortsBelowApex is CLAIM 1.
func TestNSECCache_DoesNotDenyAcrossZones_SortsBelowApex(t *testing.T) {
	nc := round008ExampleZone(t)
	if got := nc.Lookup("evil.com.", protocol.TypeA); got != nil {
		t.Fatalf("cross-zone denial: Lookup(evil.com.) returned %s using example.com.'s NSEC. "+
			"An NSEC only proves non-existence within its own zone (RFC 4034 §4.1.1 / RFC 8198 §5.3); "+
			"answering hands a false AD=1 NXDOMAIN for a name the resolver knows nothing about.",
			rcodeOf(got))
	}
}

// TestNSECCache_DoesNotDenyAcrossZones_SortsAboveZone is CLAIM 2.
func TestNSECCache_DoesNotDenyAcrossZones_SortsAboveZone(t *testing.T) {
	nc := round008ExampleZone(t)
	if got := nc.Lookup("zzzz.bbb.com.", protocol.TypeA); got != nil {
		t.Fatalf("cross-zone denial: Lookup(zzzz.bbb.com.) returned %s using example.com.'s NSEC; "+
			"zzzz.bbb.com. belongs to a different zone entirely", rcodeOf(got))
	}
}

// TestNSECCache_StillDeniesSameZone is CONTROL 1: aaa.example.com. is in
// zone example.com. and sits inside the apex->bbb.example.com. gap, so
// the aggressive denial is correct and must survive the fix.
func TestNSECCache_StillDeniesSameZone(t *testing.T) {
	nc := round008ExampleZone(t)
	got := nc.Lookup("aaa.example.com.", protocol.TypeA)
	if got == nil {
		t.Fatalf("control: Lookup(aaa.example.com.) = nil; the example.com. NSEC " +
			"example.com. -> bbb.example.com. legitimately proves it absent")
	}
	if got.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Fatalf("control: rcode = %s, want NXDOMAIN", rcodeOf(got))
	}
}

// TestNSECCache_StillDeniesSameZone_SecondZone is CONTROL 2: the same
// in-zone denial must keep working for a different zone's chain, so the
// fix is not special-cased to one zone.
func TestNSECCache_StillDeniesSameZone_SecondZone(t *testing.T) {
	nc := round008Seed(t, "aaa.com.", [][2]string{
		{"aaa.com.", "nnn.aaa.com."},
		{"zzz.aaa.com.", "aaa.com."},
	})
	if got := nc.Lookup("mmm.aaa.com.", protocol.TypeA); got == nil {
		t.Fatalf("control: Lookup(mmm.aaa.com.) = nil; aaa.com.'s NSEC " +
			"aaa.com. -> nnn.aaa.com. legitimately proves it absent")
	}
	// And the cross-zone name that sorts above this zone must be ignored.
	if got := nc.Lookup("zzzz.bbb.com.", protocol.TypeA); got != nil {
		t.Fatalf("cross-zone denial: Lookup(zzzz.bbb.com.) returned %s using aaa.com.'s NSEC",
			rcodeOf(got))
	}
}
