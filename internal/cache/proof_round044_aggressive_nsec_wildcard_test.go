// Round-044 proof: aggressive NXDOMAIN synthesis must not deny a name a
// wildcard would answer.
//
// CONTRACT. RFC 8198 §5.3 lets a resolver answer from cached NSEC RRs only when
// it can determine "that a name would not exist without the wildcard match",
// per RFC 4035 §5.3.4 / RFC 5155 §8.8. A cached NSEC that merely *covers* the
// query name is not enough: it proves no name exists inside its range, and says
// nothing about whether a wildcard at the closest encloser would have matched
// the query. Synthesizing NXDOMAIN from the covering NSEC alone therefore turns
// a name that has an answer into an authoritative-looking AD=1 denial.
//
// DEFECT. `lookupAt` goes straight from `nameInNSECRange` to
// `synthesizeNXDOMAIN`, with no wildcard check. The covering NSEC in a real
// NXDOMAIN response can be the NSEC *whose owner is the wildcard itself*: with
// `*.sub.example.com.` in the zone, the chain is
// `example.com.` < `*.sub.example.com.` < `sub.example.com.`, so the record
// (owner `*.sub.example.com.`, next `example.com.`) is exactly what a server
// uses to deny an unrelated name such as `zzz.example.com.`. Caching it and
// then querying `a.sub.example.com.` — a name the wildcard answers — produced a
// synthesized NXDOMAIN, because the range comparison sees `a.sub.example.com.`
// after the owner.
//
// FIX. Before synthesizing NXDOMAIN, require the RFC 4035 §5.3.4 wildcard
// denial: an NSEC in the same zone whose range strictly covers the wildcard at
// the query name's closest encloser. The closest encloser is the deepest
// ancestor of the query name that the covering NSEC does not itself cover. When
// no such proof is cached the synthesis is refused (fail closed) — the query
// then resolves normally instead of being denied.
package cache

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// rr044NXDOMAIN builds a validated NXDOMAIN response carrying the given NSEC
// records in its authority section, as a DNSSEC-validating resolver would
// receive it.
func rr044NXDOMAIN(t *testing.T, zone string, nsecs []struct {
	owner string
	next  string
	types []uint16
}) *protocol.Message {
	t.Helper()

	zoneName, err := protocol.ParseName(zone)
	if err != nil {
		t.Fatalf("ParseName(%q): %v", zone, err)
	}
	mname, _ := protocol.ParseName("ns1." + zone)
	rname, _ := protocol.ParseName("hostmaster." + zone)

	resp := &protocol.Message{
		Header: protocol.Header{ID: 1, QDCount: 1, NSCount: uint16(1 + len(nsecs))},
		Authorities: []*protocol.ResourceRecord{{
			Name:  zoneName,
			Type:  protocol.TypeSOA,
			Class: protocol.ClassIN,
			TTL:   3600,
			Data: &protocol.RDataSOA{
				MName: mname, RName: rname, Serial: 2026010101,
				Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 300,
			},
		}},
	}
	resp.Header.Flags.RCODE = protocol.RcodeNameError

	for _, n := range nsecs {
		owner, err := protocol.ParseName(n.owner)
		if err != nil {
			t.Fatalf("ParseName(%q): %v", n.owner, err)
		}
		next, err := protocol.ParseName(n.next)
		if err != nil {
			t.Fatalf("ParseName(%q): %v", n.next, err)
		}
		resp.Authorities = append(resp.Authorities, &protocol.ResourceRecord{
			Name:  owner,
			Type:  protocol.TypeNSEC,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataNSEC{NextDomain: next, TypeBitMap: n.types},
		})
	}
	return resp
}

type rr044NSEC = struct {
	owner string
	next  string
	types []uint16
}

// TestRound044AggressiveNXDOMAINDoesNotDenyWildcardMatch is the defect case:
// the cached NSEC that covers the query name is the NSEC owned by the wildcard,
// so the wildcard exists and `a.sub.example.com.` has an answer. The cache must
// not synthesize a denial for it.
func TestRound044AggressiveNXDOMAINDoesNotDenyWildcardMatch(t *testing.T) {
	nc := NewNSECCache(100)

	// A real NXDOMAIN for zzz.example.com.: the denial proof for that name is
	// the NSEC owned by the wildcard (canonical order puts `*.sub.example.com.`
	// before `example.com.`, so its wrap-around range covers zzz.example.com.).
	nc.AddFromResponse(rr044NXDOMAIN(t, "example.com.", []rr044NSEC{
		{"*.sub.example.com.", "example.com.", []uint16{protocol.TypeNS, protocol.TypeRRSIG, protocol.TypeNSEC}},
	}), true)

	if nc.Size() == 0 {
		t.Fatal("NSEC entry was not cached; the fixture or AddFromResponse is broken")
	}

	got := nc.Lookup("a.sub.example.com.", protocol.TypeA)
	if got != nil {
		t.Fatalf("aggressive synthesis denied a wildcard-matched name: Lookup(a.sub.example.com., A) "+
			"returned rcode=%d AD=%v from a cached NSEC (owner *.sub.example.com., next example.com.). "+
			"That NSEC's owner IS the wildcard `*.sub.example.com.`, which answers "+
			"a.sub.example.com. — RFC 8198 §5.3 requires the resolver to establish that the name "+
			"would not exist WITHOUT the wildcard match (RFC 4035 §5.3.4), and a covering NSEC "+
			"alone cannot establish that. The name is served as an AD=1 denial instead of the "+
			"wildcard answer, so it stays unresolvable until the entry expires.",
			got.Header.Flags.RCODE, got.Header.Flags.AD)
	}
}

// TestRound044AggressiveNXDOMAINControls pins the cases that must keep working.
func TestRound044AggressiveNXDOMAINControls(t *testing.T) {
	t.Run("wildcard denial present: synthesis still happens", func(t *testing.T) {
		nc := NewNSECCache(100)

		// Zone with no wildcard: the chain is example.com. < a.example.com.
		// The NSEC owned by a.example.com. covers both zzz.example.com. and the
		// wildcard `*.example.com.`, so the RFC 4035 §5.3.4 denial is present.
		nc.AddFromResponse(rr044NXDOMAIN(t, "example.com.", []rr044NSEC{
			{"a.example.com.", "example.com.", []uint16{protocol.TypeA, protocol.TypeRRSIG, protocol.TypeNSEC}},
			{"example.com.", "a.example.com.", []uint16{protocol.TypeNS, protocol.TypeSOA, protocol.TypeRRSIG, protocol.TypeNSEC}},
		}), true)

		got := nc.Lookup("zzz.example.com.", protocol.TypeA)
		if got == nil {
			t.Fatal("a genuine non-existent name with a cached wildcard denial must still be denied " +
				"aggressively — the fix must not disable the feature")
		}
		if got.Header.Flags.RCODE != protocol.RcodeNameError {
			t.Errorf("rcode = %d, want NXDOMAIN", got.Header.Flags.RCODE)
		}
	})

	t.Run("deep name under an existing node", func(t *testing.T) {
		nc := NewNSECCache(100)
		nc.AddFromResponse(rr044NXDOMAIN(t, "example.com.", []rr044NSEC{
			{"a.example.com.", "example.com.", []uint16{protocol.TypeA, protocol.TypeRRSIG, protocol.TypeNSEC}},
			{"example.com.", "a.example.com.", []uint16{protocol.TypeNS, protocol.TypeSOA, protocol.TypeRRSIG, protocol.TypeNSEC}},
		}), true)

		// a.example.com. exists (it owns an NSEC), so the closest encloser is
		// a.example.com. and the wildcard to deny is *.a.example.com., which
		// the same covering NSEC covers.
		got := nc.Lookup("x.a.example.com.", protocol.TypeA)
		if got == nil {
			t.Fatal("x.a.example.com. is covered and its wildcard is denied; synthesis must still happen")
		}
	})

	t.Run("NODATA from an owner-matching NSEC is unaffected", func(t *testing.T) {
		nc := NewNSECCache(100)
		nc.AddFromResponse(rr044NXDOMAIN(t, "example.com.", []rr044NSEC{
			{"mail.example.com.", "example.com.", []uint16{protocol.TypeMX, protocol.TypeRRSIG, protocol.TypeNSEC}},
			{"example.com.", "mail.example.com.", []uint16{protocol.TypeNS, protocol.TypeSOA, protocol.TypeRRSIG, protocol.TypeNSEC}},
		}), true)

		// mail.example.com. exists with MX but no A: the exact-owner path must
		// still prove NODATA.
		got := nc.Lookup("mail.example.com.", protocol.TypeA)
		if got == nil {
			t.Fatal("owner-matching NSEC without the qtype must still prove NODATA")
		}
		if got.Header.Flags.RCODE != protocol.RcodeSuccess {
			t.Errorf("NODATA rcode = %d, want NOERROR", got.Header.Flags.RCODE)
		}
	})
}
