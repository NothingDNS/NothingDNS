// Round-041 discovery harness: every RData type the wire codec supports must
// survive a Pack -> Unpack round trip.
//
// CONTRACT. RFC 1035 §3.3 / §4.1.3: RDATA is defined by the wire format of its
// type, and `Len()` must equal the number of bytes `Pack` emits. Anything that
// fails to reproduce itself through Pack/Unpack breaks the paths that go
// through the wire: AXFR/IXFR (both directions), upstream forwarding, the
// cache's stored messages, and the zone-file round trip (text -> RData ->
// wire -> RData).
//
// The harness is deliberately a discovery tool, not a single-case proof: it
// walks a table of presentation forms, parses each with ParseRDataText, packs
// it, unpacks it into a fresh instance of the same type, and compares the type
// code, the declared length and the presentation form. A mismatch is a real
// defect — the record does not survive the wire — and the harness prints
// enough detail to localise it.
package protocol

import (
	"strings"
	"testing"
)

type rr041Case struct {
	rtype string
	text  string
}

var rr041Cases = []rr041Case{
	{"A", "192.0.2.1"},
	{"AAAA", "2001:db8::1"},
	{"CNAME", "target.example.com."},
	{"NS", "ns1.example.com."},
	{"PTR", "host.example.com."},
	{"DNAME", "other.example.net."},
	{"MX", "10 mail.example.com."},
	{"TXT", `"first" "second"`},
	{"SPF", `"v=spf1 -all"`},
	{"HINFO", `"Intel" "Linux"`},
	{"RP", "mbox.example.com. txt.example.com."},
	{"AFSDB", "1 afs.example.com."},
	{"KX", "10 kx.example.com."},
	{"SOA", "ns1.example.com. hostmaster.example.com. 2026010101 3600 600 86400 300"},
	{"SRV", "10 20 5060 sip.example.com."},
	{"CAA", `0 issue "ca.example.com"`},
	{"NAPTR", `100 10 "U" "E2U+sip" "!^.*$!sip:info@example.com!" .`},
	{"URI", `10 1 "https://example.com/"`},
	{"LOC", "37 46 29.000 N 122 25 10.000 W 10.00m 1m 10000m 10m"},
	{"SSHFP", "2 1 0123456789abcdef0123456789abcdef01234567"},
	{"DS", "12345 8 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
	{"CDS", "12345 8 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
	{"TA", "12345 8 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
	{"TLSA", "3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
	{"DNSKEY", "256 3 8 AwEAAcExampleKeyMaterialAwEAAcExampleKeyMaterial"},
	{"CDNSKEY", "256 3 8 AwEAAcExampleKeyMaterialAwEAAcExampleKeyMaterial"},
	{"KEY", "256 3 8 AwEAAcExampleKeyMaterialAwEAAcExampleKeyMaterial"},
	{"RRSIG", "A 8 3 300 20260101000000 20250101000000 12345 example.com. AwEAAcExampleKeyMaterial"},
	{"SIG", "A 8 3 300 20260101000000 20250101000000 12345 example.com. AwEAAcExampleKeyMaterial"},
	{"NSEC", "next.example.com. A NS SOA RRSIG NSEC DNSKEY"},
	{"NSEC3", "1 0 10 AABBCCDD 0123456789ABCDEF0123456789ABCDEF A NS"},
	{"NSEC3PARAM", "1 0 10 AABBCCDD"},
	{"CERT", "1 12345 8 AwEAAcExampleKeyMaterial"},
	{"APL", "1:192.0.2.0/24"},
	{"HIP", "2 200100107B1A74DF365639CC39F1D578 AwEAAcExampleKeyMaterial"},
	{"IPSECKEY", "10 1 2 192.0.2.38 AwEAAcExampleKeyMaterial"},
	{"DHCID", "AwEAAcExampleKeyMaterial"},
	{"OPENPGPKEY", "AwEAAcExampleKeyMaterial"},
	{"ZONEMD", "1 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
	{"SVCB", `1 svc.example.com. alpn="h2"`},
	{"HTTPS", `1 . alpn="h2"`},
	// ── Boundary forms: empty, maximum-length and root-name inputs ──
	{"TXT", `""`},
	{"TXT", `"` + strings.Repeat("x", 255) + `"`},
	{"TXT", strings.Repeat("y", 256)},
	{"HINFO", `"" ""`},
	{"CNAME", "."},
	{"MX", "0 ."},
	{"SRV", "0 0 0 ."},
	{"AAAA", "::ffff:192.0.2.1"},
	{"SOA", "ns1.example.com. hostmaster.example.com. 4294967295 0 0 0 0"},
	{"NSEC3PARAM", "1 0 10 -"},
	{"NSEC3", "1 0 10 - 0123456789ABCDEF0123456789ABCDEF A"},
	// An NSEC with no type bitmap has no legal presentation form (the parser
	// rejects it); its WIRE path is covered by TestRound041NSECEmptyBitmapWirePath.
	{"SVCB", "1 svc.example.com."},
	{"APL", "2:2001:db8::/32"},
	{"HIP", "2 200100107B1A74DF365639CC39F1D578 AwEAAcExampleKeyMaterial"},
	{"LOC", "0 0 0.000 N 0 0 0.000 E -100000.00m"},
	{"ZONEMD", "1 1 2 " + strings.Repeat("ab", 64)},
}

// TestRound041RDataPackUnpackRoundTrip walks the table and reports every type
// whose wire round trip changes the record.
func TestRound041RDataPackUnpackRoundTrip(t *testing.T) {
	for _, tc := range rr041Cases {
		t.Run(tc.rtype, func(t *testing.T) {
			typeCode, ok := StringToType[strings.ToUpper(tc.rtype)]
			if !ok {
				t.Fatalf("StringToType has no entry for %q — the type is not addressable by name", tc.rtype)
			}

			src := ParseRDataText(tc.rtype, tc.text)
			if src == nil {
				t.Fatalf("ParseRDataText(%q, %q) returned nil: the presentation form of a "+
					"supported type does not parse, so a zone-file line of this type cannot "+
					"be served", tc.rtype, tc.text)
			}

			buf := make([]byte, 65535)
			n, err := src.Pack(buf, 0)
			if err != nil {
				t.Fatalf("Pack(%q) failed: %v", tc.rtype, err)
			}
			if n != src.Len() {
				t.Errorf("Len() = %d but Pack wrote %d bytes: Len is used to size buffers "+
					"(WireLength/Truncate), so a mismatch under- or over-allocates the message",
					src.Len(), n)
			}

			dst := createRData(typeCode)
			if dst == nil {
				t.Fatalf("createRData(%d) returned nil for a type ParseRDataText supports", typeCode)
			}
			nn, err := dst.Unpack(buf[:n], 0, uint16(n))
			if err != nil {
				t.Fatalf("Unpack(%q) of the bytes Pack just wrote failed: %v", tc.rtype, err)
			}
			if nn != n {
				t.Errorf("Unpack consumed %d bytes but Pack wrote %d", nn, n)
			}
			if got := dst.String(); got != src.String() {
				t.Errorf("round trip changed the record:\n  packed   = %s\n  unpacked = %s",
					src.String(), got)
			}
			if dst.Type() != src.Type() {
				t.Errorf("round trip changed the type: %d -> %d", src.Type(), dst.Type())
			}
		})
	}
}

// TestRound041NSECEmptyBitmapWirePath covers the shape the presentation parser
// rejects: an NSEC whose Type Bit Maps field is empty. It can still arrive on
// the wire — from an upstream, or from a cached message that is re-packed — so
// Pack, Len and Unpack must agree on it and the record must survive unchanged.
func TestRound041NSECEmptyBitmapWirePath(t *testing.T) {
	next, err := ParseName("next.example.com.")
	if err != nil {
		t.Fatalf("ParseName: %v", err)
	}

	src := &RDataNSEC{NextDomain: next}
	buf := make([]byte, 512)
	n, err := src.Pack(buf, 0)
	if err != nil {
		t.Fatalf("Pack of an NSEC with an empty type bitmap failed: %v", err)
	}
	if n != src.Len() {
		t.Errorf("Len() = %d but Pack wrote %d: Len sizes the enclosing message, "+
			"so a mismatch under- or over-allocates it", src.Len(), n)
	}

	dst := &RDataNSEC{}
	nn, err := dst.Unpack(buf[:n], 0, uint16(n))
	if err != nil {
		t.Fatalf("Unpack of the bytes Pack just wrote failed: %v", err)
	}
	if nn != n {
		t.Errorf("Unpack consumed %d bytes but Pack wrote %d", nn, n)
	}
	if len(dst.TypeBitMap) != 0 {
		t.Errorf("an empty type bitmap became %v on the wire round trip", dst.TypeBitMap)
	}
	if dst.NextDomain == nil || dst.NextDomain.String() != next.String() {
		t.Errorf("next domain changed on the wire round trip: %v -> %v", next, dst.NextDomain)
	}

	buf2 := make([]byte, 512)
	n2, err := dst.Pack(buf2, 0)
	if err != nil {
		t.Fatalf("re-Pack failed: %v", err)
	}
	if n2 != n || string(buf[:n]) != string(buf2[:n2]) {
		t.Errorf("re-packing the decoded record is not byte-identical: %d bytes vs %d", n, n2)
	}
}
