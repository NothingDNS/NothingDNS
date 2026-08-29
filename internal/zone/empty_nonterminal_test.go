package zone

import "testing"

// entTestZone models the shape that exposes empty non-terminals and wildcard
// scoping at the same time:
//
//	auth.test.                    apex (SOA)
//	  entb.auth.test.             ENT
//	    enta.entb.auth.test.      ENT
//	      host.enta.entb...       has an A
//	  wild.auth.test.             ENT
//	    *.wild.auth.test.         wildcard
//	    sub.wild.auth.test.       ENT
//	      deep.sub.wild...        has an A
func entTestZone() *Zone {
	z := NewZone("auth.test.")
	z.DefaultTTL = 300
	add := func(name, rrtype, rdata string) {
		z.Records[name] = append(z.Records[name], Record{
			Name: name, Type: rrtype, TTL: 300, Class: "IN", RData: rdata,
		})
	}
	add("auth.test.", "SOA", "ns1.auth.test. admin.auth.test. 1 3600 600 86400 300")
	add("host.enta.entb.auth.test.", "A", "192.0.2.40")
	add("*.wild.auth.test.", "A", "192.0.2.30")
	add("deep.sub.wild.auth.test.", "A", "192.0.2.31")
	return z
}

// TestNodeExists_EmptyNonTerminals is the regression for answering NXDOMAIN at
// an empty non-terminal. NXDOMAIN asserts that nothing at or below the name
// exists; RFC 8020 resolvers take that literally, so a cached NXDOMAIN for
// "entb.auth.test." makes them refuse "host.enta.entb.auth.test." — a name
// this very zone serves.
func TestNodeExists_EmptyNonTerminals(t *testing.T) {
	z := entTestZone()

	tests := []struct {
		name string
		want bool
		why  string
	}{
		{"host.enta.entb.auth.test.", true, "owns an A record"},
		{"enta.entb.auth.test.", true, "empty non-terminal"},
		{"entb.auth.test.", true, "empty non-terminal"},
		{"wild.auth.test.", true, "empty non-terminal (parent of the wildcard)"},
		{"sub.wild.auth.test.", true, "empty non-terminal"},
		{"auth.test.", true, "zone apex"},
		{"nothere.auth.test.", false, "no records, no descendants"},
		{"a.b.nothere.auth.test.", false, "no records, no descendants"},
		{"host.enta.entb.auth.test.extra.", false, "outside the zone"},
	}
	for _, tc := range tests {
		if got := z.NodeExists(tc.name); got != tc.want {
			t.Errorf("NodeExists(%q) = %v, want %v (%s)", tc.name, got, tc.want, tc.why)
		}
	}
}

// TestNodeExists_IndexRefreshesAfterMutation: Records is an exported field that
// the transfer and DDNS paths write to directly, so the derived index must not
// go stale behind them.
func TestNodeExists_IndexRefreshesAfterMutation(t *testing.T) {
	z := entTestZone()

	if z.NodeExists("new.branch.auth.test.") {
		t.Fatal("name should not exist yet")
	}

	z.Records["leaf.new.branch.auth.test."] = []Record{
		{Name: "leaf.new.branch.auth.test.", Type: "A", TTL: 300, Class: "IN", RData: "192.0.2.99"},
	}

	if !z.NodeExists("new.branch.auth.test.") {
		t.Error("new empty non-terminal not seen after a direct Records write")
	}
	if !z.NodeExists("branch.auth.test.") {
		t.Error("new empty non-terminal (2 levels up) not seen")
	}

	delete(z.Records, "leaf.new.branch.auth.test.")
	if z.NodeExists("new.branch.auth.test.") {
		t.Error("empty non-terminal still reported after its only descendant was removed")
	}
}

// TestLookupWildcard_StopsAtClosestEncloser is the regression for wildcard
// synthesis reaching past an existing ancestor. RFC 4592 §2.2.1 puts the
// source of synthesis at the closest encloser and nowhere else; the search
// used to climb until it found any "*.ancestor", so "*.wild.auth.test."
// answered for names under the populated "deep.sub.wild.auth.test." — the
// zone manufactured answers for names it does not cover.
func TestLookupWildcard_StopsAtClosestEncloser(t *testing.T) {
	z := entTestZone()

	tests := []struct {
		query     string
		wantFound bool
		wantWild  string
		why       string
	}{
		{"any.wild.auth.test.", true, "*.wild.auth.test.", "closest encloser is wild.auth.test."},
		{"x.deep.sub.wild.auth.test.", false, "", "closest encloser deep.sub.wild has no wildcard"},
		{"y.x.deep.sub.wild.auth.test.", false, "", "same closest encloser, deeper query"},
		{"foo.sub.wild.auth.test.", false, "", "closest encloser sub.wild (an ENT) has no wildcard"},
		{"anything.auth.test.", false, "", "closest encloser is the apex, which has no wildcard"},
	}
	for _, tc := range tests {
		recs, wild, found := z.LookupWildcard(tc.query, "A")
		if found != tc.wantFound {
			t.Errorf("LookupWildcard(%q): found = %v, want %v (%s)", tc.query, found, tc.wantFound, tc.why)
			continue
		}
		if found && wild != tc.wantWild {
			t.Errorf("LookupWildcard(%q): wildcard = %q, want %q", tc.query, wild, tc.wantWild)
		}
		if found && len(recs) == 0 {
			t.Errorf("LookupWildcard(%q): matched but returned no records", tc.query)
		}
	}
}

// TestLookupWildcard_NoDataAtWildcard: a wildcard that exists but holds no
// record of the requested type is a wildcard NODATA, not an NXDOMAIN.
func TestLookupWildcard_NoDataAtWildcard(t *testing.T) {
	z := entTestZone()

	recs, wild, found := z.LookupWildcard("any.wild.auth.test.", "MX")
	if !found {
		t.Fatal("wildcard name exists; this must be NODATA, not NXDOMAIN")
	}
	if wild != "*.wild.auth.test." {
		t.Errorf("wildcard = %q", wild)
	}
	if len(recs) != 0 {
		t.Errorf("got %d MX records from an A-only wildcard", len(recs))
	}
}
