package resolver

import (
	"net"
	"testing"
)

// RDNSS option wire layout, RFC 8106 §5.1:
//
//	+0-1  OPTION-CODE (2 octets) = 31
//	+2    OPTION-LENGTH (1 octet)
//	+3-4  RESERVED (2 octets)
//	+5-8  LIFETIME (4 octets)
//	+9..  NORMALIZED VALIDATOR ADDRESSES (16 octets each; Validate admits IPv6)
//
// OPTION-LENGTH counts the option DATA — everything after OPTION-LENGTH
// itself — namely RESERVED + LIFETIME = 6 octets, padded with zeroes up to the
// next 8-byte boundary (an 8-octet header), then the addresses. Since 16n is
// always a multiple of 8, the encoded length is (8 + 16n)/8 == 1 + 2n.

// TestRDNSSLengthUnitsHeader pins the RFC 8106 §5.1 encoded length. The
// original formula was "1 (type) + 1 (length) + 4 (lifetime) + 16n", which
// counted OPTION-CODE as one octet and omitted RESERVED entirely, so every
// result came out one 8-byte unit short and ParseRDNSSOption rejected
// conformant RAs (one address encodes Length=3, not 2).
func TestRDNSSLengthUnitsHeader(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4, 5, 8, 16} {
		want := (8 + 16*n) / 8
		if got := rdnssOptionLengthUnits(n); got != want {
			t.Errorf("rdnssOptionLengthUnits(%d) = %d, want %d (8-octet padded header)",
				n, got, want)
		}
	}
}

// TestRDNSSLengthUnitsMatchesDNSSLHeader pins RDNSS to the same header size the
// sibling DNSSL option in this file already uses correctly, so the two RFC 8020
// options cannot drift apart again.
func TestRDNSSLengthUnitsMatchesDNSSLHeader(t *testing.T) {
	// DNSSL with one short domain: 8 (header) + (1+7 "example") + 1
	// (terminator) = 17 octets, padded to 24 -> 3 units.
	if got := dnsslOptionLengthUnits([]string{"example"}); got != 3 {
		t.Fatalf("dnsslOptionLengthUnits([example]) = %d, want 3", got)
	}
	// Same 8-octet header, one IPv6 address: 8 + 16 = 24 octets -> 3 units.
	if got, want := rdnssOptionLengthUnits(1), 3; got != want {
		t.Errorf("rdnssOptionLengthUnits(1) = %d, want %d", got, want)
	}
}

// TestRDNSSRoundtripPreservesOption is the neighbouring valid path: an option
// we serialize must parse back, and a length computed from the RFC formula must
// be accepted by the parser.
func TestRDNSSRoundtripPreservesOption(t *testing.T) {
	opt := &RDNSSOption{
		Lifetime: 3600,
		Servers:  []net.IP{net.ParseIP("2001:db8::1")},
	}

	tlv := opt.ToTLV()
	parsed, err := ParseRDNSSOption(tlv)
	if err != nil {
		t.Fatalf("self round-trip failed: %v", err)
	}
	if parsed.Lifetime != opt.Lifetime || len(parsed.Servers) != 1 {
		t.Fatalf("round-trip lost data: lifetime=%d servers=%v", parsed.Lifetime, parsed.Servers)
	}

	// A conformant RDNSS option carrying one IPv6 address encodes 24 octets of
	// option data -> Length=3.
	conforming := &RDNSSOptionTLV{
		Type:      31,
		Length:    3,
		Lifetime:  3600,
		Addresses: []net.IP{net.ParseIP("2001:db8::1")},
	}
	if _, err := ParseRDNSSOption(conforming); err != nil {
		t.Fatalf("rejected an RFC-conforming RDNSS option (Length=3): %v", err)
	}
}
