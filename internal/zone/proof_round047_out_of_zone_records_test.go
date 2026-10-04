// CONTRACT. A zone's data set holds only names at or below the zone origin.
// That is what the package's own predicate expresses — nameInZone(name, origin)
// (internal/zone/zone.go:199) is `name == origin || HasSuffix(name, "."+origin)`
// — and what the rest of the package assumes: Records is keyed by in-zone owner
// names, the empty-non-terminal index walks ancestors only until they leave the
// origin (rebuildENTIndexLocked), and the lookup tests assert that an
// out-of-zone *query* must not match a zone (wildcard_test.go:122,
// coverage_test.go:2111, :3281). The zone's data set is also what leaves the
// process: WriteZone writes it to disk, AXFR/IXFR ship it to secondaries,
// SignZone builds the NSEC/NSEC3 denial chain over it and ZONEMD digests it.
// BIND treats out-of-zone data in a zone as invalid for the same reason.
//
// DEFECT. The mutation entry points never check it. Manager.AddRecord
// (internal/zone/manager.go:531-570) validates RDATA control characters, then
// qualifyName()s the owner — makeAbsolute() returns an absolute name unchanged
// (zone.go:215-217) — and stores it in z.Records. Manager.UpdateRecord
// (:634-695) does the same for the replacement record, which is stored under
// the looked-up key while carrying its own Name. Nothing in internal/zone or
// internal/api rejects an out-of-zone owner, and the REST path hands the
// request record straight to the manager (internal/api/api_zones.go:353, and
// the bulk paths at :712/:738), so `POST /zones/example.com./records` with
// {"name":"evil.other.com."} puts a foreign name inside the zone — and from
// there into the zone file, the transfers and the signed denial chain.
//
// The tests below pin the rejection plus the controls that must keep working:
// relative names still qualify into the zone, in-zone absolute and deep names
// still work, and a suffix look-alike ("notexample.com.") is not in-zone.
package zone

import (
	"strings"
	"testing"
)

func rr047Manager(t *testing.T) (*Manager, *Zone) {
	t.Helper()
	z := NewZone("example.com.")
	z.SOA = &SOARecord{
		Name: "example.com.", TTL: 3600,
		MName: "ns1.example.com.", RName: "hostmaster.example.com.",
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400,
	}
	z.NS = []NSRecord{{Name: "example.com.", TTL: 3600, NSDName: "ns1.example.com."}}

	m := NewManager()
	m.LoadZone(z, "")
	return m, z
}

// rr047Owners lists the zone's data-set owner names (what WriteZone/AXFR/SignZone
// consume) so the assertion is about the stored data, not about an error string.
func rr047Owners(z *Zone) []string {
	z.RLock()
	defer z.RUnlock()
	owners := make([]string, 0, len(z.Records))
	for owner, recs := range z.Records {
		if len(recs) > 0 {
			owners = append(owners, owner)
		}
	}
	return owners
}

func rr047HasOwner(z *Zone, owner string) bool {
	for _, got := range rr047Owners(z) {
		if got == owner {
			return true
		}
	}
	return false
}

// TestRound047AddRecordRejectsOutOfZoneOwner is the defect case.
func TestRound047AddRecordRejectsOutOfZoneOwner(t *testing.T) {
	cases := []struct {
		name string
		why  string
	}{
		{"evil.other.com.", "a foreign zone entirely"},
		{"www.other.com.", "a foreign zone entirely"},
		{"notexample.com.", "a suffix look-alike: the label boundary before \"example.com.\" is \"t\", not \".\""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, z := rr047Manager(t)

			err := m.AddRecord("example.com.", Record{
				Name: tc.name, TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.66",
			})
			if err == nil {
				t.Errorf("AddRecord accepted owner %q (%s) into zone example.com.: the zone's "+
					"data set must contain only names at or below its origin, because that set "+
					"is written to the zone file, shipped by AXFR/IXFR and signed into the "+
					"NSEC/NSEC3 denial chain. Owner names now stored: %v",
					tc.name, tc.why, rr047Owners(z))
			}
			if rr047HasOwner(z, tc.name) {
				t.Errorf("zone data set contains the out-of-zone owner %q even though the "+
					"mutation was rejected; owners: %v", tc.name, rr047Owners(z))
			}
		})
	}
}

// TestRound047AddRecordControls pins the in-zone paths the guard must not break.
func TestRound047AddRecordControls(t *testing.T) {
	cases := []struct {
		given string
		want  string
		why   string
	}{
		{"api", "api.example.com.", "a relative name qualifies against the origin"},
		{"www.example.com.", "www.example.com.", "an in-zone absolute name is kept"},
		{"a.b.example.com.", "a.b.example.com.", "a deep in-zone name is allowed"},
		{"@", "example.com.", "@ is the apex"},
		{"example.com.", "example.com.", "the apex itself is in-zone"},
	}
	for _, tc := range cases {
		t.Run(tc.given, func(t *testing.T) {
			m, z := rr047Manager(t)

			if err := m.AddRecord("example.com.", Record{
				Name: tc.given, TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.1",
			}); err != nil {
				t.Fatalf("AddRecord(%q) = %v, want success (%s)", tc.given, err, tc.why)
			}
			if !rr047HasOwner(z, tc.want) {
				t.Errorf("AddRecord(%q) did not store owner %q; owners: %v",
					tc.given, tc.want, rr047Owners(z))
			}
		})
	}
}

// TestRound047UpdateRecordRejectsOutOfZoneReplacement covers the second path:
// the replacement record carries its own Name, which is what gets stored.
func TestRound047UpdateRecordRejectsOutOfZoneReplacement(t *testing.T) {
	m, z := rr047Manager(t)
	if err := m.AddRecord("example.com.", Record{
		Name: "www", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.1",
	}); err != nil {
		t.Fatalf("seed AddRecord: %v", err)
	}

	err := m.UpdateRecord("example.com.", "www", "A", "192.0.2.1", Record{
		Name: "evil.other.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.66",
	})
	if err == nil {
		t.Errorf("UpdateRecord accepted a replacement record owned by %q inside zone "+
			"example.com.; the stored record now carries a foreign owner", "evil.other.com.")
	}
	for _, owner := range rr047Owners(z) {
		if strings.EqualFold(owner, "evil.other.com.") {
			t.Errorf("zone data set contains the out-of-zone owner %q after the update; owners: %v",
				owner, rr047Owners(z))
		}
	}
	// The in-zone record must be untouched by the rejected update.
	recs, err := m.GetRecords("example.com.", "www")
	if err != nil {
		t.Fatalf("GetRecords(www): %v", err)
	}
	for _, r := range recs {
		if !strings.EqualFold(r.Name, "www.example.com.") {
			t.Errorf("stored record owner = %q, want www.example.com.", r.Name)
		}
	}

	// Control: an in-zone update still succeeds.
	if err := m.UpdateRecord("example.com.", "www", "A", "192.0.2.1", Record{
		Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.9",
	}); err != nil {
		t.Fatalf("in-zone UpdateRecord failed: %v", err)
	}
	recs, err = m.GetRecords("example.com.", "www")
	if err != nil {
		t.Fatalf("GetRecords(www) after control update: %v", err)
	}
	if len(recs) != 1 || recs[0].RData != "192.0.2.9" {
		t.Errorf("control update did not apply: %+v", recs)
	}
}
