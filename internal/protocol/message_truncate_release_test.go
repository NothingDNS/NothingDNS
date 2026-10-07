package protocol

import (
	"runtime/debug"
	"testing"
)

// packedLenForTest returns the packed (compressed) wire length of m, the size
// the transports actually send and compare against their payload limit.
func packedLenForTest(m *Message) int {
	buf := make([]byte, m.WireLength())
	n, err := m.Pack(buf)
	if err != nil {
		return -1
	}
	return n
}

// TestTruncateBudgetsAgainstCompressedSize is the F102 regression: Truncate
// used the uncompressed WireLength, so a response whose packed form only
// needed one glue record dropped instead lost most of its answers and got
// TC=1 (RFC 2181 §9: TC only when required data is omitted).
func TestTruncateBudgetsAgainstCompressedSize(t *testing.T) {
	owner, err := ParseName("www.compressible-example-zone.example.")
	if err != nil {
		t.Fatal(err)
	}
	glue, err := ParseName("ns1.compressible-example-zone.example.")
	if err != nil {
		t.Fatal(err)
	}
	a := func(n *Name, octet byte) *ResourceRecord {
		return &ResourceRecord{Name: n, Type: TypeA, Class: ClassIN, TTL: 300,
			Data: &RDataA{Address: [4]byte{192, 0, 2, octet}}}
	}
	build := func() *Message {
		m := NewMessage(Header{ID: 1, Flags: NewResponseFlags(RcodeSuccess)})
		m.AddQuestion(&Question{Name: owner, QType: TypeA, QClass: ClassIN})
		for i := 0; i < 20; i++ {
			m.AddAnswer(a(owner, byte(i)))
		}
		m.AddAdditional(a(glue, 99))
		m.SetEDNS0(1232, false)
		return m
	}

	full := packedLenForTest(build())
	t.Run("dropping glue suffices", func(t *testing.T) {
		m := build()
		m.Truncate(full - 1)
		if len(m.Answers) != 20 || m.Header.Flags.TC {
			t.Fatalf("answers=%d TC=%v, want 20 answers and TC=false", len(m.Answers), m.Header.Flags.TC)
		}
		if m.GetOPT() == nil || len(m.Additionals) != 1 {
			t.Fatalf("additionals=%d, want only the OPT", len(m.Additionals))
		}
		if got := packedLenForTest(m); got > full-1 {
			t.Fatalf("packed %d > budget %d", got, full-1)
		}
	})
	t.Run("answers removed only as needed", func(t *testing.T) {
		m := build()
		budget := full - 40 // glue alone (~20 bytes) is not enough
		m.Truncate(budget)
		got := packedLenForTest(m)
		if got > budget || !m.Header.Flags.TC {
			t.Fatalf("packed=%d budget=%d TC=%v", got, budget, m.Header.Flags.TC)
		}
		if len(m.Answers) < 17 {
			t.Fatalf("answers=%d: over-truncated (each compressed answer is 16 bytes)", len(m.Answers))
		}
	})
}

// TestMessageDoubleReleaseDoesNotAliasPool is the F103 regression: a second
// Release of the same *Message Put it into messagePool twice, so two later
// UnpackMessage calls (two unrelated requests) shared one *Message.
func TestMessageDoubleReleaseDoesNotAliasPool(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))

	q, err := NewQuery(7, "double.example.", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, 512)
	n, err := q.Pack(wire)
	if err != nil {
		t.Fatal(err)
	}
	wire = wire[:n]

	m, err := UnpackMessage(wire)
	if err != nil {
		t.Fatal(err)
	}
	m.Release()
	m.Release()

	seen := make(map[*Message]bool)
	for i := 0; i < 4; i++ {
		got, err := UnpackMessage(wire)
		if err != nil {
			t.Fatal(err)
		}
		if seen[got] {
			t.Fatalf("UnpackMessage returned the same *Message twice after a double Release")
		}
		seen[got] = true
	}
	acquired := AcquireMessage()
	if seen[acquired] {
		t.Fatal("AcquireMessage returned a *Message still held by an UnpackMessage caller")
	}
}
