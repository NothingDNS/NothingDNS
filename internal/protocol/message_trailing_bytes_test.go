package protocol

import "testing"

func TestUnpackMessageRejectsTrailingBytes_F818(t *testing.T) {
	query, err := NewQuery(0x1234, "example.com.", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, query.WireLength())
	n, err := query.Pack(wire)
	if err != nil {
		t.Fatal(err)
	}
	wire = wire[:n]

	msg, err := UnpackMessage(wire)
	if err != nil {
		t.Fatalf("exact-length control rejected: %v", err)
	}
	msg.Release()

	for _, suffix := range [][]byte{{0}, {0xde, 0xad, 0xbe, 0xef}} {
		malformed := append(append([]byte(nil), wire...), suffix...)
		if got, err := UnpackMessage(malformed); err == nil {
			got.Release()
			t.Fatalf("message with %d trailing bytes accepted", len(suffix))
		}
	}
}

func TestUnpackMessageDSOBodyIsNotTrailingData_F818(t *testing.T) {
	h := Header{Flags: Flags{Opcode: OpcodeDSO}}
	wire := make([]byte, HeaderLen+3)
	if err := h.Pack(wire); err != nil {
		t.Fatal(err)
	}
	copy(wire[HeaderLen:], []byte{0, 1, 2})
	msg, err := UnpackMessage(wire)
	if err != nil {
		t.Fatalf("DSO body rejected as trailing data: %v", err)
	}
	defer msg.Release()
	if len(msg.RawBody) != 3 {
		t.Fatalf("DSO RawBody length = %d, want 3", len(msg.RawBody))
	}
}
