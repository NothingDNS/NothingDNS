// Round-007 proof: the empty-non-terminal (ENT) index goes stale when a
// mutation preserves the number of record owners.
//
// ensureENTIndex (zone.go:1201) decides the index is fresh with
// `z.entBuiltFor == len(z.Records)`. That compares an owner COUNT, not
// identity: a mutation that removes one owner and adds another leaves
// len(Records) unchanged while completely changing which names are empty
// non-terminals. entNames/entBuiltFor are written only in
// rebuildENTIndexLocked — no mutation path invalidates them — so the stale
// set survives and DNSSEC negative proofs are computed from it.
//
// Contract, from the file's own header (nsec.go):
//
//	"The proof is computed per query from the live zone rather than from a
//	 cached ordering. A stale NSEC chain is worse than a slow one: it would
//	 deny a name that exists, and an RFC 8198 resolver caches that denial and
//	 stops asking."
//
// CLAIM:  after removing a.b.example.com. (which retired "b.example.com." as
//
//	an ENT) and adding y.c.example.com., "b.example.com." no longer
//	exists as a node, so ClosestEncloser must report the origin. The
//	stale index still lists it and reports the retired name.
//
// CONTROL: "c.example.com." is an ENT before and after, so it must keep
//
//	resolving to itself.
package zone

import (
	"testing"
	"time"
)

func round007Zone(t *testing.T) (*Manager, *Zone) {
	t.Helper()
	m := NewManager()
	soa := &SOARecord{
		MName: "ns1.example.com.", RName: "hostmaster.example.com.",
		Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 300,
	}
	if err := m.CreateZone("example.com.", 300, soa, []NSRecord{{NSDName: "ns1.example.com."}}); err != nil {
		t.Fatalf("CreateZone: %v", err)
	}
	// a.b.example.com. makes "b.example.com." an empty non-terminal;
	// x.c.example.com. makes "c.example.com." one.
	if err := m.AddRecord("example.com.", Record{Name: "a.b.example.com.", Type: "A", TTL: 300, Class: "IN", RData: "1.1.1.1"}); err != nil {
		t.Fatalf("AddRecord a.b: %v", err)
	}
	if err := m.AddRecord("example.com.", Record{Name: "x.c.example.com.", Type: "A", TTL: 300, Class: "IN", RData: "2.2.2.2"}); err != nil {
		t.Fatalf("AddRecord x.c: %v", err)
	}
	z, ok := m.Get("example.com.")
	if !ok {
		t.Fatal("zone not found after CreateZone")
	}
	return m, z
}

// TestENTIndexStaleness_CountPreservingMutation is the CLAIM: the index must
// reflect the live zone, not a snapshot whose owner count happens to match.
func TestENTIndexStaleness_CountPreservingMutation(t *testing.T) {
	m, z := round007Zone(t)

	// Warm the index: "b.example.com." is an ENT right now, so this is true
	// and it also builds entNames/entBuiltFor for the current owner count.
	if got, ok := z.ClosestEncloser("b.example.com."); !ok || got != "b.example.com." {
		t.Fatalf("setup: ClosestEncloser(b.example.com.) = (%q, %v), want (b.example.com., true)", got, ok)
	}

	// A mutation pair that preserves len(Records): drop a.b.example.com.
	// (retires "b.example.com." as an ENT) and add y.c.example.com.
	// (one owner out, one owner in).
	if err := m.DeleteRecord("example.com.", "a.b.example.com.", "A"); err != nil {
		t.Fatalf("DeleteRecord a.b: %v", err)
	}
	if err := m.AddRecord("example.com.", Record{Name: "y.c.example.com.", Type: "A", TTL: 300, Class: "IN", RData: "3.3.3.3"}); err != nil {
		t.Fatalf("AddRecord y.c: %v", err)
	}

	// "b.example.com." now has no records and no descendants: it is not a node.
	got, ok := z.ClosestEncloser("b.example.com.")
	if ok && got == "b.example.com." {
		t.Fatalf("ENT index is stale: ClosestEncloser(b.example.com.) = %q, but a.b.example.com. "+
			"was deleted so b.example.com. is no longer a node and the closest encloser is the origin "+
			"(%q). ensureENTIndex trusted entBuiltFor == len(Records) even though the owner set changed.", got, "example.com.")
	}
	if ok && got != "example.com." {
		t.Fatalf("ClosestEncloser(b.example.com.) = %q, want example.com.", got)
	}
}

// TestENTIndexStaleness_Control is the CONTROL: an ENT that is untouched by
// the mutation must still resolve to itself, both before and after. It passes
// with or without the fix, so a broken harness cannot masquerade as the bug.
func TestENTIndexStaleness_Control(t *testing.T) {
	m, z := round007Zone(t)

	if got, ok := z.ClosestEncloser("c.example.com."); !ok || got != "c.example.com." {
		t.Fatalf("control: before mutation ClosestEncloser(c.example.com.) = (%q, %v), want (c.example.com., true)", got, ok)
	}

	if err := m.DeleteRecord("example.com.", "a.b.example.com.", "A"); err != nil {
		t.Fatalf("DeleteRecord a.b: %v", err)
	}
	if err := m.AddRecord("example.com.", Record{Name: "y.c.example.com.", Type: "A", TTL: 300, Class: "IN", RData: "3.3.3.3"}); err != nil {
		t.Fatalf("AddRecord y.c: %v", err)
	}

	if got, ok := z.ClosestEncloser("c.example.com."); !ok || got != "c.example.com." {
		t.Fatalf("control: after mutation ClosestEncloser(c.example.com.) = (%q, %v), want (c.example.com., true)", got, ok)
	}
}

// TestENTIndexStaleness_ApentStillFound guards the mirror case: a name that
// BECOMES an empty non-terminal (its new child was just added) must be
// reported as an existing node, not missed by a stale index.
func TestENTIndexStaleness_ApentStillFound(t *testing.T) {
	m, z := round007Zone(t)
	_ = m
	_ = z

	// Warm with a zone that has no y.c. child yet: "d.e.example.com." is not
	// an ENT, and nothing depends on that for this assertion.
	if got, ok := z.ClosestEncloser("d.e.example.com."); !ok || got != "example.com." {
		t.Fatalf("setup: ClosestEncloser(d.e.example.com.) = (%q, %v), want (example.com., true)", got, ok)
	}

	// Adding p.d.e.example.com. makes "d.e.example.com." an ENT (one new
	// owner, so the count DOES change here — this is the branch the current
	// check happens to catch). It must now be reported as a node.
	if err := m.AddRecord("example.com.", Record{Name: "p.d.e.example.com.", Type: "A", TTL: 300, Class: "IN", RData: "4.4.4.4"}); err != nil {
		t.Fatalf("AddRecord p.d.e: %v", err)
	}
	got, ok := z.ClosestEncloser("d.e.example.com.")
	if !ok || got != "d.e.example.com." {
		t.Fatalf("ClosestEncloser(d.e.example.com.) = (%q, %v) after gaining a child, want (d.e.example.com., true)", got, ok)
	}
	_ = time.Second
}
