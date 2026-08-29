package zone

import "testing"

// TestLookup_ANYReturnsEveryType is the regression for an exact-name ANY
// query matching nothing. recordTypeMatches compared the query type to the
// record type as plain strings, so QTYPE=ANY (RFC 1035 §3.2.3, "a request for
// all records") matched no record at all and the caller concluded the name
// held no data. LookupWildcard already special-cased ANY, so the wildcard and
// exact-match paths disagreed about the same query.
func TestLookup_ANYReturnsEveryType(t *testing.T) {
	z := NewZone("example.com.")
	z.Records["www.example.com."] = []Record{
		{Name: "www.example.com.", Type: "A", TTL: 300, Class: "IN", RData: "192.0.2.1"},
		{Name: "www.example.com.", Type: "AAAA", TTL: 300, Class: "IN", RData: "2001:db8::1"},
		{Name: "www.example.com.", Type: "TXT", TTL: 300, Class: "IN", RData: "\"hello\""},
	}

	got := z.Lookup("www.example.com.", "ANY")
	if len(got) != 3 {
		t.Fatalf("Lookup ANY returned %d records, want 3", len(got))
	}

	seen := map[string]bool{}
	for _, r := range got {
		seen[r.Type] = true
	}
	for _, want := range []string{"A", "AAAA", "TXT"} {
		if !seen[want] {
			t.Errorf("ANY result is missing the %s record", want)
		}
	}
}

func TestLookup_ANYIsCaseInsensitive(t *testing.T) {
	z := NewZone("example.com.")
	z.Records["www.example.com."] = []Record{
		{Name: "www.example.com.", Type: "A", TTL: 300, Class: "IN", RData: "192.0.2.1"},
	}
	if got := z.Lookup("www.example.com.", "any"); len(got) != 1 {
		t.Fatalf("lowercase 'any' returned %d records, want 1", len(got))
	}
}

// TestLookup_SpecificTypeStillFilters guards the fix from over-reaching: a
// concrete QTYPE must still return only its own records.
func TestLookup_SpecificTypeStillFilters(t *testing.T) {
	z := NewZone("example.com.")
	z.Records["www.example.com."] = []Record{
		{Name: "www.example.com.", Type: "A", TTL: 300, Class: "IN", RData: "192.0.2.1"},
		{Name: "www.example.com.", Type: "AAAA", TTL: 300, Class: "IN", RData: "2001:db8::1"},
	}

	got := z.Lookup("www.example.com.", "A")
	if len(got) != 1 || got[0].Type != "A" {
		t.Fatalf("Lookup A returned %v, want exactly the A record", got)
	}
	if got := z.Lookup("www.example.com.", "MX"); len(got) != 0 {
		t.Fatalf("Lookup MX returned %d records, want 0", len(got))
	}
}

// TestLookupWildcard_ANYUnchanged pins the behaviour the exact-match path was
// brought into line with.
func TestLookupWildcard_ANYUnchanged(t *testing.T) {
	z := NewZone("example.com.")
	z.Records["*.example.com."] = []Record{
		{Name: "*.example.com.", Type: "A", TTL: 300, Class: "IN", RData: "192.0.2.1"},
		{Name: "*.example.com.", Type: "TXT", TTL: 300, Class: "IN", RData: "\"wild\""},
	}

	recs, _, found := z.LookupWildcard("anything.example.com.", "ANY")
	if !found || len(recs) != 2 {
		t.Fatalf("wildcard ANY: found=%v records=%d, want true/2", found, len(recs))
	}
}
