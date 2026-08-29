package protocol

import "testing"

// packRRWithTTL builds a minimal wire-format message carrying one A record
// with the given raw TTL, so the test exercises the real Unpack path rather
// than a struct literal.
func packRRWithTTL(t *testing.T, ttl uint32) *Message {
	t.Helper()
	m := &Message{
		Header:    Header{ID: 1, Flags: NewResponseFlags(RcodeSuccess)},
		Questions: []*Question{{Name: NewName([]string{"www", "example", "com"}, true), QType: TypeA, QClass: ClassIN}},
	}
	m.AddAnswer(&ResourceRecord{
		Name:  NewName([]string{"www", "example", "com"}, true),
		Type:  TypeA,
		Class: ClassIN,
		TTL:   ttl,
		Data:  &RDataA{Address: [4]byte{192, 0, 2, 1}},
	})

	buf := make([]byte, m.WireLength())
	n, err := m.Pack(buf)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	got, err := UnpackMessage(buf[:n])
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	return got
}

// TestUnpack_TTLMostSignificantBitIsZeroed covers RFC 2181 §8:
// "Implementations should treat TTL values received with the most significant
// bit set as if the entire value received was zero."
//
// Passed through, a TTL of 0xFFFFFFFF instructs every downstream cache to hold
// the record for ~136 years, so a single bad or hostile answer becomes a
// permanent one.
func TestUnpack_TTLMostSignificantBitIsZeroed(t *testing.T) {
	tests := []struct {
		name string
		in   uint32
		want uint32
	}{
		{"zero", 0, 0},
		{"ordinary", 300, 300},
		{"largest legal", 0x7FFFFFFF, 0x7FFFFFFF},
		{"msb set", 0x80000000, 0},
		{"all ones", 0xFFFFFFFF, 0},
		{"msb set with payload", 0x8000012C, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := packRRWithTTL(t, tc.in)
			if len(msg.Answers) != 1 {
				t.Fatalf("expected 1 answer, got %d", len(msg.Answers))
			}
			if got := msg.Answers[0].TTL; got != tc.want {
				t.Errorf("TTL 0x%08X unpacked as %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// TestUnpack_OPTTTLFieldIsNotClamped guards the exemption: the OPT
// pseudo-record's "TTL" field is not a TTL (RFC 6891 §6.1.3 packs the extended
// RCODE, EDNS version, DO bit and Z into it), so zeroing it on a high extended
// RCODE would silently strip the DO bit and the client's EDNS state.
func TestUnpack_OPTTTLFieldIsNotClamped(t *testing.T) {
	m := &Message{
		Header:    Header{ID: 1, Flags: NewResponseFlags(RcodeSuccess)},
		Questions: []*Question{{Name: NewName([]string{"www", "example", "com"}, true), QType: TypeA, QClass: ClassIN}},
	}
	// Extended RCODE 0x80 sets the most significant bit of the OPT TTL field,
	// alongside DO=1.
	optTTL := BuildEDNSTTL(0x80, 0, true, 0)
	m.AddAdditional(&ResourceRecord{
		Name:  NewName(nil, true),
		Type:  TypeOPT,
		Class: 1232,
		TTL:   optTTL,
		Data:  &RDataOPT{},
	})

	buf := make([]byte, m.WireLength())
	n, err := m.Pack(buf)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	got, err := UnpackMessage(buf[:n])
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}

	opt := got.GetOPT()
	if opt == nil {
		t.Fatal("OPT record missing after round-trip")
	}
	if opt.TTL != optTTL {
		t.Fatalf("OPT TTL field = 0x%08X, want 0x%08X (it is not a TTL)", opt.TTL, optTTL)
	}
	hdr := ParseEDNS0Header(opt)
	if hdr == nil || !hdr.DO {
		t.Error("DO bit lost from the OPT record")
	}
	if hdr.ExtendedRCODE != 0x80 {
		t.Errorf("extended RCODE = 0x%02X, want 0x80", hdr.ExtendedRCODE)
	}
}
