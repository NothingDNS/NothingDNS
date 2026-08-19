package dnssec

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// mustParseNameTest parses a name, failing the test on error.
func mustParseNameTest(t *testing.T, s string) *protocol.Name {
	t.Helper()
	n, err := protocol.ParseName(s)
	if err != nil {
		t.Fatalf("ParseName(%q): %v", s, err)
	}
	return n
}

// nsec3RecordForOwner returns the generated NSEC3 record whose hashed owner
// name corresponds to the given original owner name, or nil.
func nsec3RecordForOwner(t *testing.T, s *Signer, records []*protocol.ResourceRecord, original string) *protocol.ResourceRecord {
	t.Helper()
	hash, err := NSEC3Hash(original, s.config.NSEC3Algorithm, s.config.NSEC3Iterations, s.config.NSEC3Salt)
	if err != nil {
		t.Fatalf("NSEC3Hash(%q): %v", original, err)
	}
	wantOwner := protocol.Base32Encode(hash) + "." + s.zone
	for _, rr := range records {
		if rr == nil || rr.Name == nil {
			continue
		}
		if rr.Name.String() == wantOwner {
			return rr
		}
	}
	return nil
}

// TestGenerateNSEC3_OptOutClassification verifies the opt-out flag is set
// exactly for unsigned delegations (RFC 5155 §6.1.1):
//   - zone apex (has SOA): never opt-out
//   - delegation with DS (signed child): never opt-out
//   - delegation with only NS (+RRSIG over the delegation NS RRset, which a
//     signed parent always carries): opt-out
//
// Regression: RRSIG records used to set the "has secure records" flag, so
// every delegation in a signed zone was classified as secure and the
// OptOut flag never engaged.
func TestGenerateNSEC3_OptOutClassification(t *testing.T) {
	cfg := DefaultSignerConfig()
	cfg.NSEC3Enabled = true
	cfg.NSEC3OptOut = true
	s := NewSigner("example.com.", cfg)

	apex := mustParseNameTest(t, "example.com.")
	child := mustParseNameTest(t, "child.example.com.")
	signedChild := mustParseNameTest(t, "signed.example.com.")
	nsData := &protocol.RDataNS{NSDName: mustParseNameTest(t, "ns1.child.example.com.")}

	records := []*protocol.ResourceRecord{
		// Apex: SOA + NS — must never be opt-out.
		{Name: apex, Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 3600, Data: &protocol.RDataSOA{}},
		{Name: apex, Type: protocol.TypeNS, Class: protocol.ClassIN, TTL: 3600, Data: nsData},
		// Unsigned delegation: NS + the RRSIG that a signed parent always
		// adds over the delegation NS RRset. No DS → opt-out eligible.
		{Name: child, Type: protocol.TypeNS, Class: protocol.ClassIN, TTL: 3600, Data: nsData},
		{Name: child, Type: protocol.TypeRRSIG, Class: protocol.ClassIN, TTL: 3600, Data: &protocol.RDataRRSIG{TypeCovered: protocol.TypeNS}},
		// Signed delegation: NS + DS → never opt-out.
		{Name: signedChild, Type: protocol.TypeNS, Class: protocol.ClassIN, TTL: 3600, Data: nsData},
		{Name: signedChild, Type: protocol.TypeDS, Class: protocol.ClassIN, TTL: 3600, Data: &protocol.RDataDS{}},
	}

	got := s.generateNSEC3(records)

	// Apex — no opt-out flag.
	apexRR := nsec3RecordForOwner(t, s, got, "example.com.")
	if apexRR == nil {
		t.Fatal("missing NSEC3 for apex")
	}
	apexNSEC3, ok := apexRR.Data.(*protocol.RDataNSEC3)
	if !ok {
		t.Fatalf("apex NSEC3 has wrong data type %T", apexRR.Data)
	}
	if apexNSEC3.Flags&protocol.NSEC3FlagOptOut != 0 {
		t.Error("apex NSEC3 must not have the opt-out flag set")
	}

	// Signed delegation — no opt-out flag.
	signedRR := nsec3RecordForOwner(t, s, got, "signed.example.com.")
	if signedRR == nil {
		t.Fatal("missing NSEC3 for signed delegation")
	}
	signedNSEC3, ok := signedRR.Data.(*protocol.RDataNSEC3)
	if !ok {
		t.Fatalf("signed delegation NSEC3 has wrong data type %T", signedRR.Data)
	}
	if signedNSEC3.Flags&protocol.NSEC3FlagOptOut != 0 {
		t.Error("signed delegation (with DS) NSEC3 must not have the opt-out flag set")
	}

	// Unsigned delegation — opt-out flag set, empty bitmap.
	childRR := nsec3RecordForOwner(t, s, got, "child.example.com.")
	if childRR == nil {
		t.Fatal("missing NSEC3 for unsigned delegation")
	}
	childNSEC3, ok := childRR.Data.(*protocol.RDataNSEC3)
	if !ok {
		t.Fatalf("unsigned delegation NSEC3 has wrong data type %T", childRR.Data)
	}
	if childNSEC3.Flags&protocol.NSEC3FlagOptOut == 0 {
		t.Error("unsigned delegation NSEC3 must have the opt-out flag set")
	}
	if len(childNSEC3.TypeBitMap) != 0 {
		t.Errorf("opt-out NSEC3 must have an empty type bitmap, got %v", childNSEC3.TypeBitMap)
	}
}

// TestGenerateNSEC3_NoOptOutWithoutConfig verifies that the opt-out flag is
// never set when NSEC3OptOut is disabled, regardless of delegation shape.
func TestGenerateNSEC3_NoOptOutWithoutConfig(t *testing.T) {
	cfg := DefaultSignerConfig()
	cfg.NSEC3Enabled = true
	cfg.NSEC3OptOut = false
	s := NewSigner("example.com.", cfg)

	child := mustParseNameTest(t, "child.example.com.")
	nsData := &protocol.RDataNS{NSDName: mustParseNameTest(t, "ns1.child.example.com.")}

	records := []*protocol.ResourceRecord{
		{Name: mustParseNameTest(t, "example.com."), Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 3600, Data: &protocol.RDataSOA{}},
		{Name: child, Type: protocol.TypeNS, Class: protocol.ClassIN, TTL: 3600, Data: nsData},
	}

	got := s.generateNSEC3(records)
	childRR := nsec3RecordForOwner(t, s, got, "child.example.com.")
	if childRR == nil {
		t.Fatal("missing NSEC3 for delegation")
	}
	childNSEC3, ok := childRR.Data.(*protocol.RDataNSEC3)
	if !ok {
		t.Fatalf("delegation NSEC3 has wrong data type %T", childRR.Data)
	}
	if childNSEC3.Flags&protocol.NSEC3FlagOptOut != 0 {
		t.Error("opt-out flag must not be set when NSEC3OptOut is disabled")
	}
}

// TestGenerateNSEC3_TypeBitmapExcludesNSEC3 verifies RFC 5155 §3.2.1: the
// NSEC3 type itself must never appear in an NSEC3 record's type bit maps
// (NSEC3 records live at hashed owner names, never at the original name).
func TestGenerateNSEC3_TypeBitmapExcludesNSEC3(t *testing.T) {
	cfg := DefaultSignerConfig()
	cfg.NSEC3Enabled = true
	s := NewSigner("example.com.", cfg)

	records := []*protocol.ResourceRecord{
		{Name: mustParseNameTest(t, "example.com."), Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 3600, Data: &protocol.RDataSOA{}},
		{Name: mustParseNameTest(t, "www.example.com."), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}}},
	}

	got := s.generateNSEC3(records)
	if len(got) == 0 {
		t.Fatal("expected NSEC3 records")
	}
	for _, rr := range got {
		nsec3, ok := rr.Data.(*protocol.RDataNSEC3)
		if !ok {
			t.Fatalf("unexpected record type %T", rr.Data)
		}
		if nsec3.HasType(protocol.TypeNSEC3) {
			t.Errorf("NSEC3 type must not appear in its own type bitmap: %v", nsec3.TypeBitMap)
		}
	}
}
