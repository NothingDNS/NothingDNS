package zone

import (
	"sort"
	"testing"
)

// TestCanonicalNameOrder pins RFC 4034 §6.1 — the exact ordering from the
// example in that section. Everything about an NSEC chain rests on it: a name
// sorted wrongly produces a proof that denies a name which exists.
func TestCanonicalNameOrder(t *testing.T) {
	unsorted := []string{
		"a.example.", "yljkjljk.a.example.", "Z.a.example.", "zABC.a.EXAMPLE.",
		"z.example.", "\001.z.example.", "*.z.example.", "\200.z.example.",
		"example.",
	}
	want := []string{
		"example.", "a.example.", "yljkjljk.a.example.", "Z.a.example.",
		"zABC.a.EXAMPLE.", "z.example.", "\001.z.example.", "*.z.example.",
		"\200.z.example.",
	}

	got := append([]string(nil), unsorted...)
	sort.SliceStable(got, func(i, j int) bool { return canonicalNameLess(got[i], got[j]) })

	for i := range want {
		if compareCanonicalName(got[i], want[i]) != 0 {
			t.Fatalf("position %d: got %q, want %q\nfull order: %q", i, got[i], want[i], got)
		}
	}
}

func TestCanonicalNameOrder_CaseInsensitive(t *testing.T) {
	if compareCanonicalName("WWW.Example.COM.", "www.example.com.") != 0 {
		t.Error("names differing only in case must compare equal")
	}
}

func nsecTestZone() *Zone {
	z := NewZone("nsec.test.")
	z.DefaultTTL = 300
	add := func(name, rrtype, rdata string) {
		z.Records[name] = append(z.Records[name], Record{
			Name: name, Type: rrtype, TTL: 300, Class: "IN", RData: rdata,
		})
	}
	add("nsec.test.", "SOA", "ns1.nsec.test. admin.nsec.test. 1 3600 600 86400 300")
	add("nsec.test.", "NS", "ns1.nsec.test.")
	add("ns1.nsec.test.", "A", "192.0.2.1")
	add("www.nsec.test.", "A", "192.0.2.10")
	add("www.nsec.test.", "AAAA", "2001:db8::10")
	add("deep.ent.nsec.test.", "A", "192.0.2.20") // makes ent.nsec.test. an ENT
	return z
}

// TestNSECForName_TypeBitmap: the bitmap is the NODATA proof, so it must list
// exactly the types present — plus NSEC and RRSIG, which every name in a
// signed zone owns (RFC 4035 §2.3).
func TestNSECForName_TypeBitmap(t *testing.T) {
	z := nsecTestZone()

	data, ok := z.NSECForName("www.nsec.test.")
	if !ok {
		t.Fatal("no NSEC for an existing name")
	}
	if data.Owner != "www.nsec.test." {
		t.Errorf("owner = %q", data.Owner)
	}
	want := map[string]bool{"A": true, "AAAA": true, "NSEC": true, "RRSIG": true}
	if len(data.Types) != len(want) {
		t.Fatalf("types = %v, want exactly %v", data.Types, want)
	}
	for _, tp := range data.Types {
		if !want[tp] {
			t.Errorf("unexpected type %q in the bitmap", tp)
		}
	}
}

// TestNSECForName_EmptyNonTerminal is the regression for an ENT whose bitmap
// claimed no types at all — not even its own NSEC. Validators went looking for
// a delegation that is not there and reported a broken trust chain instead of
// a proven NODATA.
func TestNSECForName_EmptyNonTerminal(t *testing.T) {
	z := nsecTestZone()

	data, ok := z.NSECForName("ent.nsec.test.")
	if !ok {
		t.Fatal("no NSEC for an empty non-terminal")
	}
	var hasNSEC, hasRRSIG bool
	for _, tp := range data.Types {
		switch tp {
		case "NSEC":
			hasNSEC = true
		case "RRSIG":
			hasRRSIG = true
		default:
			t.Errorf("empty non-terminal claims type %q", tp)
		}
	}
	if !hasNSEC || !hasRRSIG {
		t.Errorf("ENT bitmap = %v, want NSEC and RRSIG", data.Types)
	}
}

// TestNSECCovering_ProvesNonExistence: the returned record must actually
// bracket the queried name, or it proves nothing.
func TestNSECCovering_ProvesNonExistence(t *testing.T) {
	z := nsecTestZone()

	for _, missing := range []string{
		"aaa.nsec.test.", "mmm.nsec.test.", "zzz.nsec.test.", "b.ent.nsec.test.",
	} {
		data, ok := z.NSECCovering(missing)
		if !ok {
			t.Errorf("%s: no covering NSEC", missing)
			continue
		}
		// Owner < missing, and either Next > missing or Next wrapped to the
		// apex (the end of the chain).
		if !canonicalNameLess(data.Owner, missing) {
			t.Errorf("%s: owner %q does not sort before it", missing, data.Owner)
		}
		wrapped := compareCanonicalName(data.Next, z.Origin) == 0
		if !wrapped && !canonicalNameLess(missing, data.Next) {
			t.Errorf("%s: next %q does not sort after it", missing, data.Next)
		}
	}
}

func TestNSECCovering_ExistingNameIsNotCoveredByItself(t *testing.T) {
	z := nsecTestZone()
	data, ok := z.NSECCovering("www.nsec.test.")
	if !ok {
		t.Fatal("no covering NSEC")
	}
	if data.Owner == "www.nsec.test." {
		t.Error("a name cannot be proven absent by its own NSEC")
	}
}

// TestClosestEncloser walks up to the deepest existing ancestor, counting
// empty non-terminals as existing.
func TestClosestEncloser(t *testing.T) {
	z := nsecTestZone()

	tests := map[string]string{
		"www.nsec.test.":      "www.nsec.test.", // exists itself
		"x.www.nsec.test.":    "www.nsec.test.", // parent exists
		"a.b.ent.nsec.test.":  "ent.nsec.test.", // ENT is the encloser
		"deep.ent.nsec.test.": "deep.ent.nsec.test.",
		"nothing.nsec.test.":  "nsec.test.", // falls back to the apex
		"a.b.c.d.nsec.test.":  "nsec.test.",
	}
	for name, want := range tests {
		got, ok := z.ClosestEncloser(name)
		if !ok {
			t.Errorf("%s: no closest encloser", name)
			continue
		}
		if got != want {
			t.Errorf("ClosestEncloser(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestClosestEncloser_OutsideZone(t *testing.T) {
	z := nsecTestZone()
	if _, ok := z.ClosestEncloser("example.org."); ok {
		t.Error("a name outside the zone has no closest encloser here")
	}
}

// TestNSECChain_IsClosed: following Next from the apex must reach every node
// and come back to the apex. A gap is a name that can never be proven present
// or absent.
func TestNSECChain_IsClosed(t *testing.T) {
	z := nsecTestZone()
	wantNodes := []string{
		"nsec.test.", "deep.ent.nsec.test.", "ent.nsec.test.",
		"ns1.nsec.test.", "www.nsec.test.",
	}

	visited := map[string]bool{}
	current := z.Origin
	for i := 0; i <= len(wantNodes); i++ {
		data, ok := z.NSECForName(current)
		if !ok {
			t.Fatalf("node %q has no NSEC", current)
		}
		visited[data.Owner] = true
		current = data.Next
		if compareCanonicalName(current, z.Origin) == 0 {
			break
		}
	}
	if compareCanonicalName(current, z.Origin) != 0 {
		t.Fatalf("chain did not close; stopped at %q", current)
	}
	for _, n := range wantNodes {
		if !visited[n] {
			t.Errorf("node %q is not on the chain", n)
		}
	}
}
