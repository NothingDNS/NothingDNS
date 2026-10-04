// Regression: WriteZone must serialize a record's stored TTL verbatim, because
// an explicit TTL of 0 is a meaningful value (RFC 2181 §8 "do not cache"), not
// an absent one.
//
// DEFECT. WriteZone replaced every record TTL of 0 with z.DefaultTTL:
//
//	if ttl == 0 { ttl = z.DefaultTTL }
//
// applied in the apex-NS loop and in the main record loop (writer.go:54-57 and
// :91-94). The parser deliberately keeps the distinction: parseRecordOwned
// assigns DefaultTTL only when the record line carried no TTL field, and its
// own comment states that an explicit TTL of 0 "is a deliberate value and must
// be preserved, not silently replaced by $TTL". The writer undid exactly that,
// so a record the operator marked "do not cache" came back with the zone
// default after any export/re-import cycle. WriteZone is not export-only: it
// backs Manager.ExportZone, Manager.WriteZoneFile (on-disk zone persistence)
// and Cluster.snapshotZones (every zone shipped to raft followers as BIND text
// and re-parsed there), so the rewrite silently changed live records.
//
// The controls pin the paths that must NOT change: a non-zero TTL is written
// verbatim, a record with no TTL field still comes back with the zone default,
// and a programmatically built NSRecord with TTL 0 still falls back to the
// zone default (that struct has no "explicitly zero" convention).
package zone

import (
	"strings"
	"testing"
)

const rr039ZoneText = `$ORIGIN example.com.
$TTL 3600
@	0	IN	NS	ns1
@	IN	SOA	ns1 hostmaster ( 2024010101 3600 900 604800 86400 )
ns1	IN	A	192.0.2.1
www	0	IN	A	192.0.2.2
keep	300	IN	A	192.0.2.3
noTTL	IN	A	192.0.2.4
`

// rr039TTL parses rr039ZoneText, writes it back out with WriteZone and parses
// the result again, returning the second-generation zone.
func rr039RoundTrip(t *testing.T) *Zone {
	t.Helper()
	first, err := ParseFile("-", strings.NewReader(rr039ZoneText))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	text, err := WriteZone(first)
	if err != nil {
		t.Fatalf("WriteZone: %v", err)
	}
	second, err := ParseFile("-", strings.NewReader(text))
	if err != nil {
		t.Fatalf("re-parsing the written zone failed: %v\nwritten zone:\n%s", err, text)
	}
	return second
}

// TestRound039WriteZonePreservesExplicitTTLZero is the defect case: a record
// whose line carried an explicit TTL of 0 must still have TTL 0 after the
// zone is written out and parsed again.
func TestRound039WriteZonePreservesExplicitTTLZero(t *testing.T) {
	z := rr039RoundTrip(t)

	tests := []struct {
		owner string
		rtype string
		want  uint32
		why   string
	}{
		{"www.example.com.", "A", 0, "explicit TTL 0 (RFC 2181 §8: do not cache)"},
		{"example.com.", "NS", 0, "apex NS written with an explicit TTL 0"},
	}
	for _, tc := range tests {
		t.Run(tc.owner+"/"+tc.rtype, func(t *testing.T) {
			recs := z.Lookup(tc.owner, tc.rtype)
			if len(recs) != 1 {
				t.Fatalf("Lookup(%q, %q) returned %d records, want 1", tc.owner, tc.rtype, len(recs))
			}
			if got := recs[0].TTL; got != tc.want {
				t.Errorf("TTL of %s %s after WriteZone round-trip = %d, want %d (%s): "+
					"the writer replaced a deliberate TTL 0 with the zone default, so every "+
					"export/re-import and every cluster zone snapshot silently changed the record",
					tc.owner, tc.rtype, got, tc.want, tc.why)
			}
		})
	}
}

// TestRound039WriteZoneKeepsOtherTTLs pins the unaffected paths.
func TestRound039WriteZoneKeepsOtherTTLs(t *testing.T) {
	z := rr039RoundTrip(t)

	tests := []struct {
		owner string
		rtype string
		want  uint32
		why   string
	}{
		{"keep.example.com.", "A", 300, "explicit non-zero TTL is written verbatim"},
		{"noTTL.example.com.", "A", 3600, "no TTL field on the line: the parser's $TTL default must survive"},
		{"example.com.", "SOA", 3600, "SOA TTL from the zone default"},
	}
	for _, tc := range tests {
		t.Run(tc.owner+"/"+tc.rtype, func(t *testing.T) {
			recs := z.Lookup(tc.owner, tc.rtype)
			if len(recs) != 1 {
				t.Fatalf("Lookup(%q, %q) returned %d records, want 1", tc.owner, tc.rtype, len(recs))
			}
			if got := recs[0].TTL; got != tc.want {
				t.Errorf("TTL of %s %s = %d, want %d (%s)", tc.owner, tc.rtype, got, tc.want, tc.why)
			}
		})
	}
}

// TestRound039WriteZoneProgrammaticNSStillUsesDefaultTTL pins the retained
// behaviour for a hand-built NSRecord, whose zero TTL means "unset" rather
// than "explicitly zero" — the fix must not change that path.
func TestRound039WriteZoneProgrammaticNSStillUsesDefaultTTL(t *testing.T) {
	z := NewZone("example.com.")
	z.DefaultTTL = 3600
	z.SOA = &SOARecord{Name: "example.com.", TTL: 3600, MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 1, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 300}
	z.NS = []NSRecord{{Name: "example.com.", TTL: 0, NSDName: "ns1.example.com."}}

	text, err := WriteZone(z)
	if err != nil {
		t.Fatalf("WriteZone: %v", err)
	}
	if !strings.Contains(text, "@\t3600\tIN\tNS\tns1.example.com.") {
		t.Errorf("a programmatically built NSRecord with TTL 0 must still be written with the "+
			"zone default (that struct has no explicit-zero convention); got:\n%s", text)
	}
}
