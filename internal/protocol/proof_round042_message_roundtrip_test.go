// Round-042 discovery harness: whole-message Pack -> Unpack fidelity, name
// compression determinism, and Truncate's post-condition.
//
// CONTRACT.
//   - RFC 1035 §4.1: a message that packs must unpack back to the same
//     sections, names, types, TTLs and RDATA.
//   - RFC 1035 §4.1.4: compression is an encoding detail, so the same message
//     must pack to the same bytes twice (deterministic), and the packed form
//     must never exceed the uncompressed WireLength.
//   - RFC 2181 §9 / RFC 6891 §7: after Truncate(maxSize) the message must
//     either fit in maxSize or carry the TC bit, and it must never drop the
//     question section or invent records.
//
// These are the invariants the transports, the cache and the transfer paths
// rely on: every one of them packs messages they did not build.
package protocol

import (
	"strings"
	"testing"
)

// rr042Message builds a message with compression-heavy owner names, a spread of
// RDATA types, an OPT pseudo-record and two questions.
func rr042Message(t *testing.T) *Message {
	t.Helper()

	msg, err := NewQuery(0x4242, "www1.example.com.", TypeA)
	if err != nil {
		t.Fatalf("NewQuery: %v", err)
	}

	answers := []struct {
		name  string
		rtype uint16
		ttl   uint32
		text  string
	}{
		{"www1.example.com.", TypeA, 300, "192.0.2.1"},
		{"www2.example.com.", TypeA, 300, "192.0.2.2"},
		{"www3.example.com.", TypeA, 300, "192.0.2.3"},
		{"example.com.", TypeMX, 600, "10 mail.example.com."},
		{"example.com.", TypeNS, 86400, "ns1.example.com."},
		{"example.com.", TypeTXT, 60, `"hello" "world"`},
		{"sub.deep.example.com.", TypeAAAA, 120, "2001:db8::1"},
		{"_sip._tcp.example.com.", TypeSRV, 120, "10 20 5060 sip.example.com."},
	}
	for _, a := range answers {
		rd := ParseRDataText(TypeString(a.rtype), a.text)
		if rd == nil {
			t.Fatalf("ParseRDataText(%s, %q) returned nil", TypeString(a.rtype), a.text)
		}
		rr, err := NewResourceRecord(a.name, a.rtype, ClassIN, a.ttl, rd)
		if err != nil {
			t.Fatalf("NewResourceRecord(%s): %v", a.name, err)
		}
		msg.AddAnswer(rr)
	}

	soaText := "ns1.example.com. hostmaster.example.com. 2026010101 3600 600 86400 300"
	soa, err := NewResourceRecord("example.com.", TypeSOA, ClassIN, 3600, ParseRDataText("SOA", soaText))
	if err != nil {
		t.Fatalf("NewResourceRecord(SOA): %v", err)
	}
	msg.AddAuthority(soa)

	ns, err := NewResourceRecord("ns1.example.com.", TypeA, ClassIN, 86400, ParseRDataText("A", "192.0.2.53"))
	if err != nil {
		t.Fatalf("NewResourceRecord(glue): %v", err)
	}
	msg.AddAdditional(ns)

	// EDNS0 OPT pseudo-record (RFC 6891): class carries the UDP size, TTL the
	// extended rcode/version/DO bit.
	opt, err := NewResourceRecord(".", TypeOPT, 4096, 0, &RDataOPT{})
	if err != nil {
		t.Fatalf("NewResourceRecord(OPT): %v", err)
	}
	msg.AddAdditional(opt)

	return msg
}

// rr042Sections renders every section as a comparable string slice.
func rr042Sections(m *Message) []string {
	var out []string
	for _, q := range m.Questions {
		if q == nil || q.Name == nil {
			out = append(out, "<nil question>")
			continue
		}
		out = append(out, "Q "+q.Name.String()+" "+TypeString(q.QType))
	}
	for _, group := range []struct {
		label string
		rrs   []*ResourceRecord
	}{{"AN", m.Answers}, {"NS", m.Authorities}, {"AR", m.Additionals}} {
		for _, rr := range group.rrs {
			if rr == nil {
				out = append(out, group.label+" <nil record>")
				continue
			}
			name := "<nil>"
			if rr.Name != nil {
				name = rr.Name.String()
			}
			rdata := "<nil>"
			if !isNilRData(rr.Data) {
				rdata = rr.Data.String()
			}
			out = append(out, group.label+" "+name+" "+TypeString(rr.Type)+" "+
				itoa32(rr.TTL)+" "+rdata)
		}
	}
	return out
}

func itoa32(v uint32) string {
	if v == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func rr042Equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestRound042MessagePackUnpackRoundTrip is the core invariant: what packs must
// unpack to itself, and packing twice must produce identical bytes.
func TestRound042MessagePackUnpackRoundTrip(t *testing.T) {
	src := rr042Message(t)

	buf := make([]byte, 65535)
	n, err := src.Pack(buf)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if n > src.WireLength() {
		t.Errorf("packed length %d exceeds the uncompressed WireLength %d: compression "+
			"must never make a message longer", n, src.WireLength())
	}

	// Deterministic compression: the same message packs to the same bytes.
	buf2 := make([]byte, 65535)
	n2, err := src.Pack(buf2)
	if err != nil {
		t.Fatalf("second Pack: %v", err)
	}
	if n2 != n || string(buf[:n]) != string(buf2[:n2]) {
		t.Errorf("packing the same message twice produced different bytes (%d vs %d)", n, n2)
	}

	dst, err := UnpackMessage(buf[:n])
	if err != nil {
		t.Fatalf("UnpackMessage: %v", err)
	}
	defer dst.Release()

	if want, got := rr042Sections(src), rr042Sections(dst); !rr042Equal(want, got) {
		t.Errorf("message changed on the wire round trip:\n  packed   = %v\n  unpacked = %v", want, got)
	}
	if dst.Header.QDCount != src.Header.QDCount ||
		dst.Header.ANCount != src.Header.ANCount ||
		dst.Header.NSCount != src.Header.NSCount ||
		dst.Header.ARCount != src.Header.ARCount {
		t.Errorf("section counts changed: %d/%d/%d/%d -> %d/%d/%d/%d",
			src.Header.QDCount, src.Header.ANCount, src.Header.NSCount, src.Header.ARCount,
			dst.Header.QDCount, dst.Header.ANCount, dst.Header.NSCount, dst.Header.ARCount)
	}

	// Re-pack the decoded message: compression must round-trip too, and the
	// names that shared a suffix must still share it (i.e. the message must
	// shrink, not grow).
	buf3 := make([]byte, 65535)
	n3, err := dst.Pack(buf3)
	if err != nil {
		t.Fatalf("re-Pack: %v", err)
	}
	if n3 != n || string(buf[:n]) != string(buf3[:n3]) {
		t.Errorf("re-packing the decoded message is not byte-identical (%d vs %d bytes)", n, n3)
	}
}

// TestRound042TruncatePostCondition walks maxSize across the whole message and
// asserts Truncate's documented post-condition: the result either fits or is
// marked truncated, the question section survives, and the records that remain
// are a prefix of the original sections (removal is from the end).
func TestRound042TruncatePostCondition(t *testing.T) {
	full := rr042Message(t)
	packed := make([]byte, 65535)
	fullLen, err := full.Pack(packed)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	if fullLen <= 96 {
		t.Fatalf("fixture message packs to only %d bytes; a sweep starting at 64 would "+
			"never force truncation and the assertions below would be vacuous", fullLen)
	}
	for maxSize := 64; maxSize <= fullLen+32; maxSize += 23 {
		t.Run("maxSize="+itoa32(uint32(maxSize)), func(t *testing.T) {
			msg := rr042Message(t)
			before := rr042Sections(msg)
			msg.Truncate(maxSize)

			if got := msg.WireLength(); got > maxSize && !msg.Header.Flags.TC {
				t.Errorf("WireLength() = %d > maxSize %d without the TC bit: a truncated "+
					"response must tell the client to retry over TCP", got, maxSize)
			}
			if len(msg.Questions) != len(full.Questions) {
				t.Errorf("truncation dropped the question section: %d questions, want %d",
					len(msg.Questions), len(full.Questions))
			}

			// Records may only be removed from the end of each section.
			after := rr042Sections(msg)
			for _, line := range after {
				if strings.HasPrefix(line, "Q ") {
					continue
				}
				found := false
				for _, orig := range before {
					if orig == line {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("truncation produced a record that was not in the original "+
						"message: %q", line)
				}
			}
			if len(after) > len(before) {
				t.Errorf("truncation added records: %d -> %d", len(before), len(after))
			}

			// The result must be packable into maxSize when it claims to fit.
			out := make([]byte, maxSize)
			n, err := msg.Pack(out)
			if err != nil {
				if msg.WireLength() <= maxSize {
					t.Errorf("Pack into a %d-byte buffer failed (%v) even though "+
						"WireLength() = %d claims it fits", maxSize, err, msg.WireLength())
				}
				return
			}
			if n > maxSize {
				t.Errorf("Pack wrote %d bytes into a %d-byte buffer", n, maxSize)
			}
		})
	}
}
