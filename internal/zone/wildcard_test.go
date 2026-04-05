package zone

import (
	"testing"
)

// newTestZone creates a zone with the given origin and records for testing.
func newTestZone(origin string, records map[string][]Record) *Zone {
	z := NewZone(origin)
	for name, recs := range records {
		z.Records[canonicalize(name)] = recs
	}
	return z
}

func TestNameExists(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"www.example.com.": {{Name: "www.example.com.", Type: "A", RData: "1.2.3.4"}},
		"example.com.":     {{Name: "example.com.", Type: "SOA", RData: "ns1.example.com. admin.example.com. 1 3600 600 86400 300"}},
	})

	if !z.NameExists("www.example.com.") {
		t.Error("expected www.example.com. to exist")
	}
	if !z.NameExists("WWW.EXAMPLE.COM.") {
		t.Error("expected case-insensitive match")
	}
	if z.NameExists("nonexistent.example.com.") {
		t.Error("expected nonexistent.example.com. to not exist")
	}
}

func TestLookupWildcardBasic(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"example.com.":   {{Name: "example.com.", Type: "SOA", RData: "ns1 admin 1 3600 600 86400 300"}},
		"*.example.com.": {{Name: "*.example.com.", Type: "A", TTL: 300, RData: "10.0.0.1"}},
	})

	// Query for a name that doesn't exist → should match wildcard
	recs, wcName, found := z.LookupWildcard("anything.example.com.", "A")
	if !found {
		t.Fatal("expected wildcard match")
	}
	if wcName != "*.example.com." {
		t.Errorf("wildcard name = %q, want *.example.com.", wcName)
	}
	if len(recs) != 1 || recs[0].RData != "10.0.0.1" {
		t.Errorf("unexpected records: %+v", recs)
	}
}

func TestLookupWildcardDeepSubdomain(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"example.com.":   {{Name: "example.com.", Type: "SOA", RData: "ns1 admin 1 3600 600 86400 300"}},
		"*.example.com.": {{Name: "*.example.com.", Type: "A", TTL: 300, RData: "10.0.0.1"}},
	})

	// Deep subdomain should also match the wildcard
	recs, _, found := z.LookupWildcard("a.b.c.example.com.", "A")
	if !found {
		t.Fatal("expected wildcard match for deep subdomain")
	}
	if len(recs) != 1 {
		t.Errorf("expected 1 record, got %d", len(recs))
	}
}

func TestLookupWildcardSubzoneWildcard(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"example.com.":       {{Name: "example.com.", Type: "SOA", RData: "ns1 admin 1 3600 600 86400 300"}},
		"*.example.com.":     {{Name: "*.example.com.", Type: "A", TTL: 300, RData: "10.0.0.1"}},
		"*.sub.example.com.": {{Name: "*.sub.example.com.", Type: "A", TTL: 300, RData: "10.0.0.2"}},
		"sub.example.com.":   {{Name: "sub.example.com.", Type: "A", TTL: 300, RData: "10.0.0.3"}},
	})

	// foo.sub.example.com. should match *.sub.example.com. (more specific)
	recs, wcName, found := z.LookupWildcard("foo.sub.example.com.", "A")
	if !found {
		t.Fatal("expected wildcard match for *.sub.example.com.")
	}
	if wcName != "*.sub.example.com." {
		t.Errorf("wildcard name = %q, want *.sub.example.com.", wcName)
	}
	if len(recs) != 1 || recs[0].RData != "10.0.0.2" {
		t.Errorf("expected 10.0.0.2, got %+v", recs)
	}
}

func TestLookupWildcardNODATA(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"example.com.":   {{Name: "example.com.", Type: "SOA", RData: "ns1 admin 1 3600 600 86400 300"}},
		"*.example.com.": {{Name: "*.example.com.", Type: "A", TTL: 300, RData: "10.0.0.1"}},
	})

	// Query for AAAA → wildcard exists but no AAAA records → found=true, empty records
	recs, _, found := z.LookupWildcard("anything.example.com.", "AAAA")
	if !found {
		t.Fatal("expected found=true for wildcard NODATA")
	}
	if len(recs) != 0 {
		t.Errorf("expected 0 records for NODATA, got %d", len(recs))
	}
}

func TestLookupWildcardNoMatch(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"example.com.": {{Name: "example.com.", Type: "SOA", RData: "ns1 admin 1 3600 600 86400 300"}},
	})

	// No wildcard records exist → not found
	_, _, found := z.LookupWildcard("anything.example.com.", "A")
	if found {
		t.Error("expected no wildcard match when no wildcard records exist")
	}
}

func TestLookupWildcardOutOfZone(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"*.example.com.": {{Name: "*.example.com.", Type: "A", TTL: 300, RData: "10.0.0.1"}},
	})

	// Query for a name outside the zone → not found
	_, _, found := z.LookupWildcard("www.other.com.", "A")
	if found {
		t.Error("expected no match for out-of-zone query")
	}
}

func TestLookupWildcardCaseInsensitive(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"*.example.com.": {{Name: "*.example.com.", Type: "A", TTL: 300, RData: "10.0.0.1"}},
	})

	recs, _, found := z.LookupWildcard("FOO.EXAMPLE.COM.", "A")
	if !found {
		t.Fatal("expected case-insensitive wildcard match")
	}
	if len(recs) != 1 {
		t.Errorf("expected 1 record, got %d", len(recs))
	}
}

func TestFindDelegationBasic(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"example.com.": {
			{Name: "example.com.", Type: "SOA", RData: "ns1 admin 1 3600 600 86400 300"},
			{Name: "example.com.", Type: "NS", RData: "ns1.example.com."},
		},
		"sub.example.com.": {
			{Name: "sub.example.com.", Type: "NS", TTL: 86400, RData: "ns1.sub.example.com."},
			{Name: "sub.example.com.", Type: "NS", TTL: 86400, RData: "ns2.sub.example.com."},
		},
		"ns1.sub.example.com.": {
			{Name: "ns1.sub.example.com.", Type: "A", TTL: 86400, RData: "192.0.2.1"},
		},
		"ns2.sub.example.com.": {
			{Name: "ns2.sub.example.com.", Type: "A", TTL: 86400, RData: "192.0.2.2"},
		},
	})

	// Query below delegation point
	nsRecs, delegation, found := z.FindDelegation("www.sub.example.com.")
	if !found {
		t.Fatal("expected delegation at sub.example.com.")
	}
	if delegation != "sub.example.com." {
		t.Errorf("delegation = %q, want sub.example.com.", delegation)
	}
	if len(nsRecs) != 2 {
		t.Errorf("expected 2 NS records, got %d", len(nsRecs))
	}
}

func TestFindDelegationAtExactPoint(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"sub.example.com.": {
			{Name: "sub.example.com.", Type: "NS", TTL: 86400, RData: "ns1.sub.example.com."},
		},
	})

	// Query exactly at the delegation point — this is NOT a delegation
	// (the delegation applies to names BELOW the cut, the cut itself
	// belongs to the parent zone)
	_, _, found := z.FindDelegation("sub.example.com.")
	if found {
		t.Error("expected no delegation for query exactly at delegation point")
	}
}

func TestFindDelegationApexNS(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"example.com.": {
			{Name: "example.com.", Type: "NS", RData: "ns1.example.com."},
			{Name: "example.com.", Type: "NS", RData: "ns2.example.com."},
		},
	})

	// Apex NS records are NOT a delegation
	_, _, found := z.FindDelegation("www.example.com.")
	if found {
		t.Error("apex NS records should not be treated as delegation")
	}
}

func TestFindDelegationNone(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"www.example.com.": {{Name: "www.example.com.", Type: "A", RData: "1.2.3.4"}},
	})

	_, _, found := z.FindDelegation("www.example.com.")
	if found {
		t.Error("expected no delegation when no NS at intermediate names")
	}
}

func TestFindDelegationDeepQuery(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"sub.example.com.": {
			{Name: "sub.example.com.", Type: "NS", TTL: 86400, RData: "ns1.sub.example.com."},
		},
	})

	// Deep subdomain below delegation
	_, delegation, found := z.FindDelegation("a.b.c.sub.example.com.")
	if !found {
		t.Fatal("expected delegation for deep subdomain below zone cut")
	}
	if delegation != "sub.example.com." {
		t.Errorf("delegation = %q, want sub.example.com.", delegation)
	}
}

func TestFindGlue(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"ns1.sub.example.com.": {
			{Name: "ns1.sub.example.com.", Type: "A", TTL: 86400, RData: "192.0.2.1"},
			{Name: "ns1.sub.example.com.", Type: "AAAA", TTL: 86400, RData: "2001:db8::1"},
			{Name: "ns1.sub.example.com.", Type: "TXT", TTL: 86400, RData: "should not be returned"},
		},
	})

	glue := z.FindGlue("ns1.sub.example.com.")
	if len(glue) != 2 {
		t.Errorf("expected 2 glue records (A + AAAA), got %d", len(glue))
	}

	types := map[string]bool{}
	for _, g := range glue {
		types[g.Type] = true
	}
	if !types["A"] || !types["AAAA"] {
		t.Errorf("expected A and AAAA glue, got types: %v", types)
	}
}

func TestFindGlueEmpty(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{})

	glue := z.FindGlue("ns1.other.com.")
	if len(glue) != 0 {
		t.Errorf("expected 0 glue for out-of-zone NS, got %d", len(glue))
	}
}

func TestFindDelegationOriginQuery(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"example.com.": {
			{Name: "example.com.", Type: "NS", RData: "ns1.example.com."},
		},
	})

	// Query exactly at origin → no delegation possible
	_, _, found := z.FindDelegation("example.com.")
	if found {
		t.Error("expected no delegation for query at zone origin")
	}
}

func TestLookupWildcardMultipleTypes(t *testing.T) {
	z := newTestZone("example.com.", map[string][]Record{
		"*.example.com.": {
			{Name: "*.example.com.", Type: "A", TTL: 300, RData: "10.0.0.1"},
			{Name: "*.example.com.", Type: "AAAA", TTL: 300, RData: "2001:db8::1"},
			{Name: "*.example.com.", Type: "MX", TTL: 300, RData: "10 mail.example.com."},
		},
	})

	// Query A → should only return A records
	recs, _, found := z.LookupWildcard("foo.example.com.", "A")
	if !found {
		t.Fatal("expected wildcard match")
	}
	if len(recs) != 1 || recs[0].Type != "A" {
		t.Errorf("expected 1 A record, got %+v", recs)
	}

	// Query MX → should only return MX records
	recs, _, found = z.LookupWildcard("foo.example.com.", "MX")
	if !found {
		t.Fatal("expected wildcard match for MX")
	}
	if len(recs) != 1 || recs[0].Type != "MX" {
		t.Errorf("expected 1 MX record, got %+v", recs)
	}
}
