package protocol

import "testing"

// TestUnpackMessage_ReconstructsExtendedRCODE verifies RFC 6891 §6.1.3
// reconstruction: the OPT record's TTL carries the EDNS EXTENDED-RCODE in its
// upper 8 bits, and the full response code is (EXTENDED-RCODE << 4) | header
// nibble. Without reconstruction an upstream BADCOOKIE (23) or BADVERS (16)
// response unpacks as its low nibble (7, 0) — e.g. BADVERS misreads as
// NOERROR, which resolvers and stubs would treat as a successful empty
// answer instead of a failure.
func TestUnpackMessage_ReconstructsExtendedRCODE(t *testing.T) {
	tests := []struct {
		name      string
		extRC     uint8
		nibble    uint8
		wantRCODE uint8
	}{
		{"BADCOOKIE 23", 1, 7, 23},
		{"BADVERS 16", 1, 0, 16},
		{"zero extended byte stays nibble", 0, 7, 7},
		{"plain NOERROR untouched", 0, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, err := NewQuestion("example.com.", TypeA, ClassIN)
			if err != nil {
				t.Fatalf("NewQuestion: %v", err)
			}
			root, err := ParseName(".")
			if err != nil {
				t.Fatalf("ParseName: %v", err)
			}
			msg := &Message{
				Header: Header{
					ID:      0x1234,
					Flags:   NewResponseFlags(tt.nibble),
					QDCount: 1,
					ARCount: 1,
				},
				Questions: []*Question{q},
				Additionals: []*ResourceRecord{{
					// RFC 6891 §6.1.1: the OPT owner is the root, CLASS is
					// the requestor's UDP payload size, and the TTL packs
					// EXTENDED-RCODE | VERSION | DO | Z.
					Name:  root,
					Type:  TypeOPT,
					Class: 1232,
					TTL:   BuildEDNSTTL(tt.extRC, 0, false, 0),
					Data:  &RDataOPT{},
				}},
			}

			wire := make([]byte, msg.WireLength())
			if _, err := msg.Pack(wire); err != nil {
				t.Fatalf("Pack: %v", err)
			}
			got, err := UnpackMessage(wire)
			if err != nil {
				t.Fatalf("UnpackMessage: %v", err)
			}
			defer got.Release()

			if got.Header.Flags.RCODE != tt.wantRCODE {
				t.Errorf("RCODE = %d, want %d", got.Header.Flags.RCODE, tt.wantRCODE)
			}
		})
	}
}
