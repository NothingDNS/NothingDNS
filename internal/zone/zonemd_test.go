package zone

// Round-4/25 regression guard: collectZoneRRsets kept a record whose RDATA
// fails the protocol parser (e.g. an A record whose RData is not an IP —
// storable via the API, since ValidateRecordData only rejects control
// characters) by serializing it as an EMPTY-RDATA RR: serializeRecordData
// returned nil, buildCanonicalRRset wrote rdlen=0, and ComputeZoneMD silently
// digested the garbage instead of reporting the malformed record.

import (
	"testing"
)

func TestCollectZoneRRsetsRejectsUnparseableRData(t *testing.T) {
	z := NewZone("example.com.")
	z.Records["www.example.com."] = []Record{{
		Name:  "www.example.com.",
		Type:  "A",
		Class: "IN",
		TTL:   300,
		RData: "not-an-ip",
	}}

	_, err := collectZoneRRsets(z)
	if err == nil {
		t.Fatalf("FAIL: a record with unparseable RDATA was silently included in the ZONEMD RRset collection (the digest covers garbage)")
	}
}
