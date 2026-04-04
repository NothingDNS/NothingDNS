package protocol

import (
	"testing"
)

// buildTestMessage creates a realistic DNS response for benchmarking.
func buildTestMessage() *Message {
	qname, _ := ParseName("www.example.com.")
	ns, _ := ParseName("ns1.example.com.")
	mbox, _ := ParseName("admin.example.com.")

	return &Message{
		Header: Header{
			ID: 0x1234,
			Flags: Flags{
				QR:     true,
				Opcode: OpcodeQuery,
				AA:     true,
				RD:     true,
				RA:     true,
				RCODE:  RcodeSuccess,
			},
			QDCount: 1,
			ANCount: 2,
			NSCount: 1,
		},
		Questions: []*Question{
			{Name: qname, QType: TypeA, QClass: ClassIN},
		},
		Answers: []*ResourceRecord{
			{
				Name:  qname,
				Type:  TypeA,
				Class: ClassIN,
				TTL:   300,
				Data:  &RDataA{Address: [4]byte{93, 184, 216, 34}},
			},
			{
				Name:  qname,
				Type:  TypeAAAA,
				Class: ClassIN,
				TTL:   300,
				Data:  &RDataAAAA{Address: [16]byte{0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01, 0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46}},
			},
		},
		Authorities: []*ResourceRecord{
			{
				Name:  qname,
				Type:  TypeSOA,
				Class: ClassIN,
				TTL:   3600,
				Data: &RDataSOA{
					MName:   ns,
					RName:   mbox,
					Serial:  2024010101,
					Refresh: 3600,
					Retry:   900,
					Expire:  604800,
					Minimum: 86400,
				},
			},
		},
	}
}

func BenchmarkMessagePack(b *testing.B) {
	msg := buildTestMessage()
	buf := make([]byte, 512)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = msg.Pack(buf)
	}
}

func BenchmarkMessageUnpack(b *testing.B) {
	msg := buildTestMessage()
	buf := make([]byte, 512)
	n, err := msg.Pack(buf)
	if err != nil {
		b.Fatalf("pack: %v", err)
	}
	wire := buf[:n]

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = UnpackMessage(wire)
	}
}

func BenchmarkMessagePackUnpackRoundTrip(b *testing.B) {
	msg := buildTestMessage()
	buf := make([]byte, 512)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		n, _ := msg.Pack(buf)
		_, _ = UnpackMessage(buf[:n])
	}
}

func BenchmarkPackName(b *testing.B) {
	name, _ := ParseName("www.example.com.")
	buf := make([]byte, 256)
	compression := make(map[string]int)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		compression["www.example.com."] = 0
		_, _ = PackName(name, buf, 0, compression)
	}
}

func BenchmarkPackNameNoCompression(b *testing.B) {
	name, _ := ParseName("www.example.com.")
	buf := make([]byte, 256)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = PackName(name, buf, 0, nil)
	}
}

func BenchmarkUnpackName(b *testing.B) {
	name, _ := ParseName("www.example.com.")
	buf := make([]byte, 256)
	n, _ := PackName(name, buf, 0, nil)
	wire := buf[:n]

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, _ = UnpackName(wire, 0)
	}
}

func BenchmarkCanonicalWireName(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = CanonicalWireName("www.example.com.")
	}
}

func BenchmarkCanonicalWireName_Long(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = CanonicalWireName("very.long.subdomain.deep.nesting.example.co.uk.")
	}
}

func BenchmarkParseName(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = ParseName("www.example.com.")
	}
}

func BenchmarkHeaderPack(b *testing.B) {
	h := &Header{
		ID: 0x1234,
		Flags: Flags{
			QR: true, Opcode: OpcodeQuery, AA: true,
			RD: true, RA: true, RCODE: RcodeSuccess,
		},
		QDCount: 1,
		ANCount: 1,
	}
	buf := make([]byte, HeaderLen)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.Pack(buf)
	}
}

func BenchmarkHeaderUnpack(b *testing.B) {
	h := &Header{
		ID: 0x1234,
		Flags: Flags{
			QR: true, Opcode: OpcodeQuery, AA: true,
			RD: true, RA: true, RCODE: RcodeSuccess,
		},
		QDCount: 1,
		ANCount: 1,
	}
	buf := make([]byte, HeaderLen)
	h.Pack(buf)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var hdr Header
		hdr.Unpack(buf)
	}
}
