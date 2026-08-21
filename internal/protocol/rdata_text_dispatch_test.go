// NothingDNS - dispatch-level tests for ParseRDataText.
//
// ParseRDataText is the master presentation-format parser shared by the
// server (zone files, DDNS), zone transfers, and dnsctl. The pre-existing
// rdata_text_test.go round-trips five DNSSEC types; this suite walks every
// case label in the dispatcher (including aliases), the inline error
// branches for A/AAAA/name/MX, and the unknown-type default.

package protocol

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseRDataText_DispatchTable(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte("test-key-material-for-parser-tests"))

	tests := []struct {
		rtype    string
		rdata    string
		wantType uint16
	}{
		// Inline cases.
		{"A", "192.0.2.1", TypeA},
		{"AAAA", "2001:db8::1", TypeAAAA},
		{"CNAME", "target.example.com.", TypeCNAME},
		{"DNAME", "target.example.com.", TypeDNAME},
		{"NS", "ns1.example.com.", TypeNS},
		{"PTR", "host.example.com.", TypePTR},
		{"MX", "10 mail.example.com.", TypeMX},
		// Delegated cases (one valid input each; format per parser docs).
		{"TXT", "\"part one\" \"part two\"", TypeTXT},
		{"DKIM", "v=DKIM1; k=rsa", TypeTXT},        // DKIM alias -> TXT
		{"SPF", "v=spf1 mx -all", TypeTXT},         // SPF alias -> TXT
		{"HINFO", "\"Xeon\" \"Linux\"", TypeHINFO}, // `cpu os` (quoted)
		{"RP", "admin.example.com. info.example.com.", TypeRP},
		{"AFSDB", "1 afsdb.example.com.", TypeAFSDB},                                             // `subtype hostname`
		{"SIG", "A 13 2 300 20250101000000 20241201000000 12345 example.com. " + b64, TypeRRSIG}, // SIG alias -> RRSIG
		{"KEY", "257 3 13 " + b64, TypeDNSKEY},                                                   // KEY alias -> DNSKEY
		{"LOC", "42 21 54.000 N 71 06 18.000 W -10m", TypeLOC},
		{"SOA", "ns1.example.com. admin.example.com. 2026082101 7200 900 1209600 3600", TypeSOA},
		{"SRV", "10 60 5060 bigbox.example.com.", TypeSRV},
		{"KX", "10 kx.example.com.", TypeKX},
		{"CERT", "1 2 3 " + b64, TypeCERT},
		{"APL", "1:192.0.2.0/24", TypeAPL},
		{"CAA", "0 issue letsencrypt.org", TypeCAA},
		{"URI", "10 20 \"https://example.com\"", TypeURI},
		{"NAPTR", "100 10 \"S\" \"SIP+D2U\" \"!^.*$!sip:info@bar.com!i\" .", TypeNAPTR},
		{"SSHFP", "2 1 " + strings.Repeat("ab", 20), TypeSSHFP},
		{"HIP", "2 " + strings.Repeat("cd", 16) + " " + b64, TypeHIP},
		{"IPSECKEY", "10 1 2 192.0.2.38 " + b64, TypeIPSECKEY},
		{"TLSA", "3 1 1 " + strings.Repeat("ef", 32), TypeTLSA},
		{"DHCID", b64, TypeDHCID},
		{"DS", "12345 13 2 " + strings.Repeat("9f", 20), TypeDS},
		{"CDS", "12345 13 2 " + strings.Repeat("9f", 20), TypeDS}, // CDS alias -> DS
		{"TA", "12345 13 2 " + strings.Repeat("9f", 20), TypeDS},  // TA alias -> DS
		{"DNSKEY", "257 3 13 " + b64, TypeDNSKEY},
		{"CDNSKEY", "257 3 13 " + b64, TypeDNSKEY}, // CDNSKEY alias -> DNSKEY
		{"OPENPGPKEY", base64.StdEncoding.EncodeToString([]byte("01234567")), TypeOPENPGPKEY},
		{"RRSIG", "A 13 2 300 20250101000000 20241201000000 12345 example.com. " + b64, TypeRRSIG},
		{"ZONEMD", "2018081402 1 1 " + strings.Repeat("aa", 32), TypeZONEMD},
		{"NSEC", "host.example.com. A MX RRSIG NSEC", TypeNSEC},
		{"NSEC3", "1 0 5 abcdef 2t7b4g4vsa5smi47k61mv5bv1a22bojr A RRSIG", TypeNSEC3},
		{"NSEC3PARAM", "1 0 5 abcdef", TypeNSEC3PARAM},
		{"SVCB", "1 svc.example.com.", TypeSVCB},
		{"HTTPS", "1 svc.example.com.", TypeHTTPS},
	}

	for _, tt := range tests {
		t.Run(tt.rtype, func(t *testing.T) {
			rd := ParseRDataText(tt.rtype, tt.rdata)
			if rd == nil {
				t.Fatalf("ParseRDataText(%q, %q) = nil, want %s RData", tt.rtype, tt.rdata, TypeToString[tt.wantType])
			}
			if got := rd.Type(); got != tt.wantType {
				t.Errorf("ParseRDataText(%q) type = %d (%s), want %d (%s)",
					tt.rtype, got, TypeToString[got], tt.wantType, TypeToString[tt.wantType])
			}
			// Every returned RData must be packable: a parse that yields a
			// struct the wire encoder rejects is worse than no parse.
			buf := make([]byte, rd.Len())
			if _, err := rd.Pack(buf, 0); err != nil {
				t.Errorf("parsed %s RData does not pack: %v", tt.rtype, err)
			}
		})
	}
}

// TestParseRDataText_InlineErrorBranches pins the fall-through paths that
// live inside ParseRDataText itself (rather than in the delegated parsers).
func TestParseRDataText_InlineErrorBranches(t *testing.T) {
	tests := []struct {
		name  string
		rtype string
		rdata string
	}{
		{"A with IPv6 literal rejected", "A", "2001:db8::1"}, // To4()==nil
		{"A with garbage rejected", "A", "not-an-ip"},
		{"AAAA with garbage rejected", "AAAA", "not-an-ip"},
		{"CNAME with invalid name rejected", "CNAME", "!.example.com."},
		{"DNAME with invalid name rejected", "DNAME", "!.example.com."},
		{"NS with invalid name rejected", "NS", "!.example.com."},
		{"PTR with invalid name rejected", "PTR", "!.example.com."},
		{"MX with one field rejected", "MX", "mail.example.com"},
		{"MX with non-numeric preference rejected", "MX", "ten mail.example.com."},
		{"MX with invalid exchange rejected", "MX", "10 !.example.com."},
		{"TXT with empty input still parses", "TXT", ""}, // parseTXTRData fallback
		{"unknown type rejected", "FUTURE", "whatever"},
		{"empty type rejected", "", "whatever"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rd := ParseRDataText(tt.rtype, tt.rdata)
			if tt.name == "TXT with empty input still parses" {
				if rd == nil {
					t.Fatal("empty TXT must still parse (verbatim fallback)")
				}
				return
			}
			if rd != nil {
				t.Errorf("ParseRDataText(%q, %q) = %T, want nil", tt.rtype, tt.rdata, rd)
			}
		})
	}
}

// TestParseRDataText_CaseInsensitive: type mnemonics are matched
// case-insensitively (strings.ToUpper in the dispatcher).
func TestParseRDataText_CaseInsensitive(t *testing.T) {
	for _, rtype := range []string{"a", "aaaa", "mx", "soA", "srv", "Txt", "caA"} {
		var rdata string
		switch strings.ToUpper(rtype) {
		case "A":
			rdata = "192.0.2.1"
		case "AAAA":
			rdata = "2001:db8::1"
		case "MX":
			rdata = "10 mail.example.com."
		case "SOA":
			rdata = "ns1.example.com. admin.example.com. 1 2 3 4 5"
		case "SRV":
			rdata = "10 60 5060 bigbox.example.com."
		case "TXT":
			rdata = "hello"
		case "CAA":
			rdata = "0 issue ca.example.net"
		}
		if rd := ParseRDataText(rtype, rdata); rd == nil {
			t.Errorf("ParseRDataText(%q, ...) = nil, want parse (case-insensitive)", rtype)
		}
	}
}
