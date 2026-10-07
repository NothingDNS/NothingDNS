package protocol

import "testing"

// buildUpdateWire returns an UPDATE (or other opcode) message for zone
// example.com with the given prerequisite (AN) and update (NS) records.
func buildUpdateWire(t *testing.T, opcode uint8, prereq, update []*ResourceRecord) []byte {
	t.Helper()
	zone, err := ParseName("example.com.")
	if err != nil {
		t.Fatal(err)
	}
	var b []byte
	b = append(b, 0x12, 0x34, byte(opcode<<3), 0, 0, 1,
		0, byte(len(prereq)), 0, byte(len(update)), 0, 0)
	b = append(b, zone.wire...)
	b = append(b, 0, byte(TypeSOA), 0, byte(ClassIN))
	for _, rr := range append(append([]*ResourceRecord{}, prereq...), update...) {
		b = append(b, rr.Name.wire...)
		b = append(b, byte(rr.Type>>8), byte(rr.Type), byte(rr.Class>>8), byte(rr.Class), 0, 0, 0, 0, 0, 0)
	}
	return b
}

// TestUnpackUpdateEmptyRDataClassANYNONE (F122): RFC 2136 delete-RRset
// (§2.5.2) and RRset-exists / RRset-not-exists prerequisites (§2.4.1,
// §2.4.3) carry CLASS ANY/NONE with RDLENGTH 0 for typed RRs such as A or
// MX. The typed RDATA parsers rejected the empty RDATA, so every such
// UPDATE failed to parse.
func TestUnpackUpdateEmptyRDataClassANYNONE(t *testing.T) {
	owner, err := ParseName("host.example.com.")
	if err != nil {
		t.Fatal(err)
	}
	prereq := []*ResourceRecord{
		{Name: owner, Type: TypeA, Class: ClassANY},
		{Name: owner, Type: TypeAAAA, Class: ClassNONE},
	}
	update := []*ResourceRecord{
		{Name: owner, Type: TypeA, Class: ClassANY},
		{Name: owner, Type: TypeMX, Class: ClassANY},
	}
	wire := buildUpdateWire(t, OpcodeUpdate, prereq, update)
	msg, err := UnpackMessage(wire)
	if err != nil {
		t.Fatalf("UnpackMessage(UPDATE with RDLENGTH 0 CLASS ANY/NONE) = %v, want success", err)
	}
	defer msg.Release()
	for i, rr := range append(append([]*ResourceRecord{}, msg.Answers...), msg.Authorities...) {
		if rr.Data == nil || rr.Data.Len() != 0 {
			t.Fatalf("record %d: want empty non-nil RDATA, got %#v", i, rr.Data)
		}
	}
	if msg.Authorities[1].Type != TypeMX || msg.Authorities[1].Class != ClassANY {
		t.Fatalf("delete-RRset MX lost type/class: %s", msg.Authorities[1])
	}
	buf := make([]byte, 512)
	n, err := msg.Pack(buf)
	if err != nil {
		t.Fatalf("re-pack: %v", err)
	}
	again, err := UnpackMessage(buf[:n])
	if err != nil {
		t.Fatalf("re-unpack: %v", err)
	}
	again.Release()

	// Outside UPDATE the strict per-type RDATA validation still applies.
	query := buildUpdateWire(t, OpcodeQuery, []*ResourceRecord{{Name: owner, Type: TypeA, Class: ClassANY}}, nil)
	if m, err := UnpackMessage(query); err == nil {
		m.Release()
		t.Fatal("QUERY with CLASS ANY A RDLENGTH 0 parsed; want rejection")
	}
}
