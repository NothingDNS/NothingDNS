package zone

import (
	"bytes"
	"testing"
)

// TestSerializeRecordData_SRVIsWireNotPresentation verifies that a type which
// used to fall through to the presentation-bytes default (SRV) is now emitted
// as canonical wire RDATA.
func TestSerializeRecordData_SRVIsWireNotPresentation(t *testing.T) {
	rec := Record{Type: "SRV", RData: "10 20 5060 sip.example.com."}
	got := serializeRecordData(rec)

	// Wire SRV RDATA starts priority(2) weight(2) port(2): 10, 20, 5060.
	want := []byte{0x00, 0x0A, 0x00, 0x14, 0x13, 0xC4}
	if len(got) < 6 || !bytes.Equal(got[:6], want) {
		t.Fatalf("SRV serialized to %v, want a wire prefix of %v (not presentation bytes)", got, want)
	}
	if bytes.Equal(got, []byte(rec.RData)) {
		t.Fatal("SRV still serialized as raw presentation text")
	}
}

// TestSerializeRecordData_RRSIGTypeCoveredIsWire verifies that an RRSIG's first
// two serialized bytes are its wire Type Covered field — the invariant the
// "exclude RRSIG covering ZONEMD" check in collectZoneRRsets relies on. Before
// the wire rework, serializeRecordData returned the presentation string, so
// those two bytes were ASCII (e.g. 'Z','O') and the exclusion never fired.
func TestSerializeRecordData_RRSIGTypeCoveredIsWire(t *testing.T) {
	// RRSIG covering ZONEMD (type 63): "<covered> <algo> <labels> <ttl> <exp>
	// <inc> <keytag> <signer> <base64sig>".
	rec := Record{Type: "RRSIG", RData: "ZONEMD 13 2 3600 20260101000000 20250101000000 12345 example.com. AAAAAAAA"}
	got := serializeRecordData(rec)
	if len(got) < 2 {
		t.Fatalf("RRSIG serialized to %d bytes, want wire form", len(got))
	}
	covered := uint16(got[0])<<8 | uint16(got[1])
	if covered != 63 {
		t.Fatalf("RRSIG Type Covered serialized as %d, want 63 (ZONEMD); exclusion check would misread presentation bytes", covered)
	}
}

// TestComputeZoneMD_ExcludesRRSIGCoveringZONEMD confirms end-to-end that the
// digest changes when a non-ZONEMD-covering RRSIG is added but is unaffected by
// adding/removing an RRSIG that covers ZONEMD (which must be excluded).
func TestComputeZoneMD_ExcludesRRSIGCoveringZONEMD(t *testing.T) {
	base := func() *Zone {
		z := NewZone("example.com.")
		z.DefaultTTL = 3600
		z.SOA = &SOARecord{MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 1, TTL: 3600}
		z.Records["www.example.com."] = []Record{{Name: "www.example.com.", Type: "A", TTL: 3600, RData: "192.0.2.1"}}
		return z
	}

	z1 := base()
	d1, err := ComputeZoneMD(z1, ZONEMDSHA384)
	if err != nil {
		t.Fatalf("ComputeZoneMD z1: %v", err)
	}

	// Add an RRSIG that covers ZONEMD — it MUST be excluded, so the digest is
	// unchanged.
	z2 := base()
	z2.Records["example.com."] = append(z2.Records["example.com."],
		Record{Name: "example.com.", Type: "RRSIG", TTL: 3600, RData: "ZONEMD 13 2 3600 20260101000000 20250101000000 12345 example.com. AAAAAAAA"})
	d2, err := ComputeZoneMD(z2, ZONEMDSHA384)
	if err != nil {
		t.Fatalf("ComputeZoneMD z2: %v", err)
	}
	if !bytes.Equal(d1.Hash, d2.Hash) {
		t.Error("adding an RRSIG that covers ZONEMD changed the digest — it should be excluded")
	}

	// Add an RRSIG covering A — it must be INCLUDED, so the digest changes.
	z3 := base()
	z3.Records["www.example.com."] = append(z3.Records["www.example.com."],
		Record{Name: "www.example.com.", Type: "RRSIG", TTL: 3600, RData: "A 13 3 3600 20260101000000 20250101000000 12345 example.com. AAAAAAAA"})
	d3, err := ComputeZoneMD(z3, ZONEMDSHA384)
	if err != nil {
		t.Fatalf("ComputeZoneMD z3: %v", err)
	}
	if bytes.Equal(d1.Hash, d3.Hash) {
		t.Error("adding an RRSIG that covers A did not change the digest — it should be included")
	}
}
