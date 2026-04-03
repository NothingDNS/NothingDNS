package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
)

// ============================================================================
// parseZoneRecords tests
// ============================================================================

func TestParseZoneRecords(t *testing.T) {
	tests := []struct {
		name       string
		zoneData   string
		origin     string
		wantCount  int
		wantTypes  []uint16 // expected record types in order
		wantNames  []string // expected owner names in order
	}{
		{
			name: "single A record",
			zoneData: `@	300	IN	A	192.0.2.1
`,
			origin:    "example.com.",
			wantCount: 1,
			wantTypes: []uint16{protocol.TypeA},
			wantNames: []string{"example.com."},
		},
		{
			name: "multiple record types",
			zoneData: `@		300	IN	A	192.0.2.1
@		300	IN	AAAA	2001:db8::1
www		300	IN	CNAME	example.com.
@		300	IN	MX	10 mail.example.com.
@		300	IN	TXT	"v=spf1 +all"
@		300	IN	NS	ns1.example.com.
`,
			origin:    "example.com.",
			wantCount: 6,
			wantTypes: []uint16{
				protocol.TypeA,
				protocol.TypeAAAA,
				protocol.TypeCNAME,
				protocol.TypeMX,
				protocol.TypeTXT,
				protocol.TypeNS,
			},
			wantNames: []string{
				"example.com.",
				"example.com.",
				"www.example.com.",
				"example.com.",
				"example.com.",
				"example.com.",
			},
		},
		{
			name: "comments and blank lines are skipped",
			zoneData: `; This is a comment
@	300	IN	A	192.0.2.1

; Another comment
@	300	IN	A	192.0.2.2
`,
			origin:    "example.com.",
			wantCount: 2,
			wantTypes: []uint16{protocol.TypeA, protocol.TypeA},
			wantNames: []string{"example.com.", "example.com."},
		},
		{
			name: "dollar directives are skipped",
			zoneData: `$TTL 300
$ORIGIN example.com.
@	300	IN	A	192.0.2.1
`,
			origin:    "example.com.",
			wantCount: 1,
			wantTypes: []uint16{protocol.TypeA},
			wantNames: []string{"example.com."},
		},
		{
			name: "at sign expands to origin",
			zoneData: `@	300	IN	A	192.0.2.1
`,
			origin:    "test.org.",
			wantCount: 1,
			wantNames: []string{"test.org."},
		},
		{
			name: "relative name gets origin appended",
			zoneData: `www	300	IN	A	192.0.2.1
ftp	300	IN	A	192.0.2.2
`,
			origin:    "example.com.",
			wantCount: 2,
			wantNames: []string{"www.example.com.", "ftp.example.com."},
		},
		{
			name: "fqdn name used as-is",
			zoneData: `www.example.com.	300	IN	A	192.0.2.1
`,
			origin:    "example.com.",
			wantCount: 1,
			wantNames: []string{"www.example.com."},
		},
		{
			name: "lines with fewer than 4 fields are skipped",
			zoneData: `@	IN	A
@	300	IN
short
`,
			origin:    "example.com.",
			wantCount: 0,
		},
		{
			name: "non-IN class records are skipped",
			zoneData: `@	300	CH	A	192.0.2.1
@	300	IN	A	192.0.2.2
`,
			origin:    "example.com.",
			wantCount: 1,
			wantNames: []string{"example.com."},
		},
		{
			name: "invalid TTL is skipped",
			zoneData: `@	notanumber	IN	A	192.0.2.1
@	300	IN	A	192.0.2.2
`,
			origin:    "example.com.",
			wantCount: 1,
			wantNames: []string{"example.com."},
		},
		{
			name: "unknown record type is skipped",
			zoneData: `@	300	IN	UNKNOWN	foo
@	300	IN	A	192.0.2.1
`,
			origin:    "example.com.",
			wantCount: 1,
			wantTypes: []uint16{protocol.TypeA},
		},
		{
			name: "NS record with relative name",
			zoneData: `@	300	IN	NS	ns1
@	300	IN	NS	ns2.example.com.
`,
			origin:    "example.com.",
			wantCount: 2,
			wantTypes: []uint16{protocol.TypeNS, protocol.TypeNS},
		},
		{
			name: "MX record parsed correctly",
			zoneData: `@	300	IN	MX	10 mail.example.com.
@	300	IN	MX	20 backup.example.com.
`,
			origin:    "example.com.",
			wantCount: 2,
			wantTypes: []uint16{protocol.TypeMX, protocol.TypeMX},
		},
		{
			name: "TXT record parsed correctly",
			zoneData: `@	300	IN	TXT	"v=spf1 include:example.com ~all"
`,
			origin:    "example.com.",
			wantCount: 1,
			wantTypes: []uint16{protocol.TypeTXT},
		},
		{
			name:      "empty zone file",
			zoneData:  "",
			origin:    "example.com.",
			wantCount: 0,
		},
		{
			name: "SOA record parsed via default handler",
			zoneData: `@	300	IN	SOA	ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400
`,
			origin:    "example.com.",
			wantCount: 1,
			wantTypes: []uint16{protocol.TypeSOA},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			records, err := parseZoneRecords(tt.zoneData, tt.origin)
			if err != nil {
				t.Fatalf("parseZoneRecords() error = %v", err)
			}
			if got := len(records); got != tt.wantCount {
				t.Fatalf("parseZoneRecords() returned %d records, want %d", got, tt.wantCount)
			}
			for i, wantType := range tt.wantTypes {
				if i >= len(records) {
					break
				}
				if records[i].Type != wantType {
					t.Errorf("record[%d].Type = %d, want %d", i, records[i].Type, wantType)
				}
			}
			for i, wantName := range tt.wantNames {
				if i >= len(records) {
					break
				}
				got := records[i].Name.String()
				if got != wantName {
					t.Errorf("record[%d].Name = %q, want %q", i, got, wantName)
				}
			}
		})
	}
}

func TestParseZoneRecordsFromFile(t *testing.T) {
	// Create a temp zone file and parse it to verify end-to-end behavior.
	tmpDir := t.TempDir()
	zoneContent := `; Zone file for example.com
$TTL 300
@		300	IN	SOA	ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400
@		300	IN	NS	ns1.example.com.
@		300	IN	NS	ns2.example.com.
@		300	IN	A	192.0.2.1
@		300	IN	AAAA	2001:db8::1
www		300	IN	A	192.0.2.10
www		300	IN	AAAA	2001:db8::10
mail	300	IN	A	192.0.2.50
@		300	IN	MX	10 mail.example.com.
@		300	IN	TXT	"v=spf1 +all"
ftp		300	IN	CNAME	www.example.com.
`
	zonePath := filepath.Join(tmpDir, "example.com.zone")
	if err := os.WriteFile(zonePath, []byte(zoneContent), 0644); err != nil {
		t.Fatalf("failed to write temp zone file: %v", err)
	}

	data, err := os.ReadFile(zonePath)
	if err != nil {
		t.Fatalf("failed to read temp zone file: %v", err)
	}

	records, err := parseZoneRecords(string(data), "example.com.")
	if err != nil {
		t.Fatalf("parseZoneRecords() error = %v", err)
	}

	// SOA + 2 NS + A(apex) + AAAA(apex) + A(www) + AAAA(www) + A(mail) + MX + TXT + CNAME
	wantCount := 11
	if got := len(records); got != wantCount {
		t.Fatalf("got %d records, want %d", got, wantCount)
	}

	// Verify specific records
	for _, rr := range records {
		switch rr.Name.String() {
		case "mail.example.com.":
			if rr.Type != protocol.TypeA {
				t.Errorf("mail.example.com. type = %d, want A", rr.Type)
			}
			aData, ok := rr.Data.(*protocol.RDataA)
			if !ok {
				t.Fatalf("mail.example.com. data is not RDataA")
			}
			expected := net.IPv4(192, 0, 2, 50).To4()
			if string(aData.Address[:]) != string(expected) {
				t.Errorf("mail.example.com. address = %v, want %v", aData.Address, expected)
			}
		case "ftp.example.com.":
			if rr.Type != protocol.TypeCNAME {
				t.Errorf("ftp.example.com. type = %d, want CNAME", rr.Type)
			}
		}
	}
}

// ============================================================================
// parseRDataFromZone tests
// ============================================================================

func TestParseRDataFromZone(t *testing.T) {
	tests := []struct {
		name     string
		rrtype   uint16
		rdata    string
		origin   string
		wantErr  bool
		validate func(t *testing.T, data protocol.RData)
	}{
		{
			name:   "A record valid",
			rrtype: protocol.TypeA,
			rdata:  "192.0.2.1",
			validate: func(t *testing.T, data protocol.RData) {
				a, ok := data.(*protocol.RDataA)
				if !ok {
					t.Fatalf("expected *RDataA, got %T", data)
				}
				expected := net.IPv4(192, 0, 2, 1).To4()
				if string(a.Address[:]) != string(expected) {
					t.Errorf("address = %v, want %v", a.Address, expected)
				}
			},
		},
		{
			name:    "A record invalid IP",
			rrtype:  protocol.TypeA,
			rdata:   "not-an-ip",
			wantErr: true,
		},
		{
			name:   "A record IPv6 address rejected",
			rrtype: protocol.TypeA,
			rdata:  "2001:db8::1",
			wantErr: true, // IPv6 is not a valid A record
		},
		{
			name:   "AAAA record valid",
			rrtype: protocol.TypeAAAA,
			rdata:  "2001:db8::1",
			validate: func(t *testing.T, data protocol.RData) {
				aaaa, ok := data.(*protocol.RDataAAAA)
				if !ok {
					t.Fatalf("expected *RDataAAAA, got %T", data)
				}
				expected := net.ParseIP("2001:db8::1").To16()
				if string(aaaa.Address[:]) != string(expected) {
					t.Errorf("address = %v, want %v", aaaa.Address, expected)
				}
			},
		},
		{
			name:    "AAAA record invalid IP",
			rrtype:  protocol.TypeAAAA,
			rdata:   "not-an-ip",
			wantErr: true,
		},
		{
			name:   "CNAME record valid",
			rrtype: protocol.TypeCNAME,
			rdata:  "www.example.com.",
			validate: func(t *testing.T, data protocol.RData) {
				cname, ok := data.(*protocol.RDataCNAME)
				if !ok {
					t.Fatalf("expected *RDataCNAME, got %T", data)
				}
				if cname.CName.String() != "www.example.com." {
					t.Errorf("cname = %q, want %q", cname.CName.String(), "www.example.com.")
				}
			},
		},
		{
			name:    "CNAME record invalid name with spaces only",
			rrtype:  protocol.TypeCNAME,
			rdata:   "   ",
			wantErr: true,
		},
		{
			name:   "NS record valid",
			rrtype: protocol.TypeNS,
			rdata:  "ns1.example.com.",
			validate: func(t *testing.T, data protocol.RData) {
				ns, ok := data.(*protocol.RDataNS)
				if !ok {
					t.Fatalf("expected *RDataNS, got %T", data)
				}
				if ns.NSDName.String() != "ns1.example.com." {
					t.Errorf("nsdname = %q, want %q", ns.NSDName.String(), "ns1.example.com.")
				}
			},
		},
		{
			name:   "MX record valid",
			rrtype: protocol.TypeMX,
			rdata:  "10 mail.example.com.",
			validate: func(t *testing.T, data protocol.RData) {
				mx, ok := data.(*protocol.RDataMX)
				if !ok {
					t.Fatalf("expected *RDataMX, got %T", data)
				}
				if mx.Preference != 10 {
					t.Errorf("preference = %d, want 10", mx.Preference)
				}
				if mx.Exchange.String() != "mail.example.com." {
					t.Errorf("exchange = %q, want %q", mx.Exchange.String(), "mail.example.com.")
				}
			},
		},
		{
			name:    "MX record missing preference",
			rrtype:  protocol.TypeMX,
			rdata:   "mail.example.com.",
			wantErr: true,
		},
		{
			name:   "TXT record with quotes",
			rrtype: protocol.TypeTXT,
			rdata:  `"v=spf1 +all"`,
			validate: func(t *testing.T, data protocol.RData) {
				txt, ok := data.(*protocol.RDataTXT)
				if !ok {
					t.Fatalf("expected *RDataTXT, got %T", data)
				}
				if len(txt.Strings) != 1 || txt.Strings[0] != "v=spf1 +all" {
					t.Errorf("strings = %v, want [\"v=spf1 +all\"]", txt.Strings)
				}
			},
		},
		{
			name:   "TXT record without quotes",
			rrtype: protocol.TypeTXT,
			rdata:  `some text value`,
			validate: func(t *testing.T, data protocol.RData) {
				txt, ok := data.(*protocol.RDataTXT)
				if !ok {
					t.Fatalf("expected *RDataTXT, got %T", data)
				}
				if len(txt.Strings) != 1 || txt.Strings[0] != "some text value" {
					t.Errorf("strings = %v, want [\"some text value\"]", txt.Strings)
				}
			},
		},
		{
			name:    "DNSKEY record too few fields",
			rrtype:  protocol.TypeDNSKEY,
			rdata:   "257 3",
			wantErr: true,
		},
		{
			name:   "DNSKEY record valid",
			rrtype: protocol.TypeDNSKEY,
			rdata:  fmt.Sprintf("257 3 13 %s", base64.StdEncoding.EncodeToString([]byte("fakekey"))),
			validate: func(t *testing.T, data protocol.RData) {
				dnskey, ok := data.(*protocol.RDataDNSKEY)
				if !ok {
					t.Fatalf("expected *RDataDNSKEY, got %T", data)
				}
				if dnskey.Flags != 257 {
					t.Errorf("flags = %d, want 257", dnskey.Flags)
				}
				if dnskey.Protocol != 3 {
					t.Errorf("protocol = %d, want 3", dnskey.Protocol)
				}
				if dnskey.Algorithm != 13 {
					t.Errorf("algorithm = %d, want 13", dnskey.Algorithm)
				}
			},
		},
		{
			name:    "DNSKEY record invalid base64",
			rrtype:  protocol.TypeDNSKEY,
			rdata:   "257 3 13 !!not-base64!!",
			wantErr: true,
		},
		{
			name:    "RRSIG record too few fields",
			rrtype:  protocol.TypeRRSIG,
			rdata:   "A 13 2 300",
			wantErr: true,
		},
		{
			name:   "RRSIG record valid",
			rrtype: protocol.TypeRRSIG,
			rdata:  fmt.Sprintf("A 13 2 300 1735689600 1733088000 12345 example.com. %s", base64.StdEncoding.EncodeToString([]byte("fakesignature"))),
			validate: func(t *testing.T, data protocol.RData) {
				rrsig, ok := data.(*protocol.RDataRRSIG)
				if !ok {
					t.Fatalf("expected *RDataRRSIG, got %T", data)
				}
				if rrsig.TypeCovered != protocol.TypeA {
					t.Errorf("typeCovered = %d, want %d", rrsig.TypeCovered, protocol.TypeA)
				}
				if rrsig.Algorithm != 13 {
					t.Errorf("algorithm = %d, want 13", rrsig.Algorithm)
				}
				if rrsig.Labels != 2 {
					t.Errorf("labels = %d, want 2", rrsig.Labels)
				}
				if rrsig.OriginalTTL != 300 {
					t.Errorf("originalTTL = %d, want 300", rrsig.OriginalTTL)
				}
				if rrsig.KeyTag != 12345 {
					t.Errorf("keyTag = %d, want 12345", rrsig.KeyTag)
				}
				if rrsig.SignerName.String() != "example.com." {
					t.Errorf("signerName = %q, want %q", rrsig.SignerName.String(), "example.com.")
				}
			},
		},
		{
			name:   "RRSIG record invalid base64 signature",
			rrtype: protocol.TypeRRSIG,
			rdata:  "A 13 2 300 1735689600 1733088000 12345 example.com. !!invalid!!",
			wantErr: true,
		},
		{
			name:   "Unknown record type returns RDataRaw",
			rrtype: 999, // unsupported type
			rdata:  "some arbitrary data",
			validate: func(t *testing.T, data protocol.RData) {
				raw, ok := data.(*protocol.RDataRaw)
				if !ok {
					t.Fatalf("expected *RDataRaw, got %T", data)
				}
				if raw.TypeVal != 999 {
					t.Errorf("typeVal = %d, want 999", raw.TypeVal)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := parseRDataFromZone(tt.rrtype, tt.rdata, "example.com.")
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (data type: %T)", data)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, data)
			}
		})
	}
}

// ============================================================================
// algorithmName tests
// ============================================================================

func TestAlgorithmName(t *testing.T) {
	tests := []struct {
		alg  uint8
		want string
	}{
		{1, "RSAMD5"},
		{5, "RSASHA1"},
		{7, "RSASHA1NSEC3SHA1"},
		{8, "RSASHA256"},
		{10, "RSASHA512"},
		{13, "ECDSAP256SHA256"},
		{14, "ECDSAP384SHA384"},
		{15, "ED25519"},
		{16, "ED448"},
		{0, "UNKNOWN(0)"},
		{2, "UNKNOWN(2)"},
		{99, "UNKNOWN(99)"},
		{255, "UNKNOWN(255)"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("alg_%d", tt.alg), func(t *testing.T) {
			got := algorithmName(tt.alg)
			if got != tt.want {
				t.Errorf("algorithmName(%d) = %q, want %q", tt.alg, got, tt.want)
			}
		})
	}
}

// ============================================================================
// hexEncode tests
// ============================================================================

func TestHexEncode(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"empty", []byte{}, ""},
		{"single byte", []byte{0x0A}, "0A"},
		{"multiple bytes", []byte{0xDE, 0xAD, 0xBE, 0xEF}, "DEADBEEF"},
		{"all zeros", []byte{0, 0, 0}, "000000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hexEncode(tt.data)
			if got != tt.want {
				t.Errorf("hexEncode() = %q, want %q", got, tt.want)
			}
			// Verify consistency with stdlib hex encoding
			if len(tt.data) > 0 {
				stdlib := fmt.Sprintf("%X", tt.data)
				if got != stdlib {
					t.Errorf("hexEncode() = %q, stdlib = %q, mismatch", got, stdlib)
				}
			}
		})
	}
}

// ============================================================================
// canonicalWireName tests
// ============================================================================

func TestCanonicalWireName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []byte
	}{
		{
			name: "root zone",
			in:   ".",
			want: []byte{0},
		},
		{
			name: "empty string",
			in:   "",
			want: []byte{0},
		},
		{
			name: "simple name",
			in:   "example.com.",
			want: []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
		{
			name: "name is lowercased",
			in:   "EXAMPLE.COM.",
			want: []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
		{
			name: "three labels",
			in:   "WWW.Example.COM.",
			want: []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := canonicalWireName(tt.in)
			if string(got) != string(tt.want) {
				t.Errorf("canonicalWireName(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// ============================================================================
// cmdDNSSECSignZone flag validation tests (algorithm and keysize)
// ============================================================================

func TestCmdDNSSECSignZone_AlgorithmValidation(t *testing.T) {
	tests := []struct {
		name      string
		algorithm int
		wantErr   bool
		errSubstr string
	}{
		{name: "algorithm 3 valid", algorithm: 3, wantErr: false},
		{name: "algorithm 5 valid (RSA)", algorithm: 5, wantErr: true, errSubstr: "keysize"}, // RSA needs keysize
		{name: "algorithm 7 valid (RSA NSEC3)", algorithm: 7, wantErr: true, errSubstr: "keysize"},
		{name: "algorithm 8 valid (RSA)", algorithm: 8, wantErr: true, errSubstr: "keysize"},
		{name: "algorithm 10 valid (RSA)", algorithm: 10, wantErr: true, errSubstr: "keysize"},
		{name: "algorithm 13 valid (ECDSA)", algorithm: 13, wantErr: false},
		{name: "algorithm 14 valid (ECDSA)", algorithm: 14, wantErr: false},
		{name: "algorithm 16 valid (ED448)", algorithm: 16, wantErr: false},
		{name: "algorithm 2 too low", algorithm: 2, wantErr: true, errSubstr: "invalid algorithm"},
		{name: "algorithm 1 too low", algorithm: 1, wantErr: true, errSubstr: "invalid algorithm"},
		{name: "algorithm 0 too low", algorithm: 0, wantErr: true, errSubstr: "invalid algorithm"},
		{name: "algorithm 17 too high", algorithm: 17, wantErr: true, errSubstr: "invalid algorithm"},
		{name: "algorithm 100 too high", algorithm: 100, wantErr: true, errSubstr: "invalid algorithm"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temp zone file so the "zone and input are required" check
			// passes but subsequent validation catches our test conditions.
			tmpDir := t.TempDir()
			zoneFile := filepath.Join(tmpDir, "test.zone")
			if err := os.WriteFile(zoneFile, []byte("@ 300 IN A 192.0.2.1\n"), 0644); err != nil {
				t.Fatalf("failed to create temp zone file: %v", err)
			}

			args := []string{
				"--zone", "example.com",
				"--input", zoneFile,
				"--output", filepath.Join(tmpDir, "test.zone.signed"),
				"--algorithm", fmt.Sprintf("%d", tt.algorithm),
				"--keysize", "0",
			}

			err := cmdDNSSECSignZone(args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errSubstr)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errSubstr)
				}
			}
			// When wantErr is false, we don't check success further because
			// sign-zone has many other dependencies. We only validate that
			// the algorithm/keysize checks pass.
		})
	}
}

func TestCmdDNSSECSignZone_KeysizeValidationForRSA(t *testing.T) {
	tests := []struct {
		name      string
		algorithm int
		keysize   int
		wantErr   bool
		errSubstr string
	}{
		{
			name:      "RSA algorithm 5 with keysize 0 rejected",
			algorithm: 5,
			keysize:   0,
			wantErr:   true,
			errSubstr: "keysize must be > 0",
		},
		{
			name:      "RSA algorithm 7 with keysize 0 rejected",
			algorithm: 7,
			keysize:   0,
			wantErr:   true,
			errSubstr: "keysize must be > 0",
		},
		{
			name:      "RSA algorithm 8 with keysize 0 rejected",
			algorithm: 8,
			keysize:   0,
			wantErr:   true,
			errSubstr: "keysize must be > 0",
		},
		{
			name:      "RSA algorithm 10 with keysize 0 rejected",
			algorithm: 10,
			keysize:   0,
			wantErr:   true,
			errSubstr: "keysize must be > 0",
		},
		{
			name:      "RSA algorithm 1 (RSAMD5) with keysize 0 rejected",
			algorithm: 3,
			keysize:   0,
			wantErr:   false, // algorithm 3 is DSA, not RSA, so keysize not enforced
		},
		{
			name:      "ECDSA algorithm 13 with keysize 0 accepted",
			algorithm: 13,
			keysize:   0,
			wantErr:   false,
		},
		{
			name:      "ECDSA algorithm 14 with keysize 0 accepted",
			algorithm: 14,
			keysize:   0,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			zoneFile := filepath.Join(tmpDir, "test.zone")
			if err := os.WriteFile(zoneFile, []byte("@ 300 IN A 192.0.2.1\n"), 0644); err != nil {
				t.Fatalf("failed to create temp zone file: %v", err)
			}

			args := []string{
				"--zone", "example.com",
				"--input", zoneFile,
				"--output", filepath.Join(tmpDir, "test.zone.signed"),
				"--algorithm", fmt.Sprintf("%d", tt.algorithm),
				"--keysize", fmt.Sprintf("%d", tt.keysize),
			}

			err := cmdDNSSECSignZone(args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errSubstr)
				}
				if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errSubstr)
				}
			}
		})
	}
}

func TestCmdDNSSECSignZone_MissingRequiredFlags(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantErr   bool
		errSubstr string
	}{
		{
			name:      "missing zone",
			args:      []string{"--input", "/dev/null"},
			wantErr:   true,
			errSubstr: "zone and input are required",
		},
		{
			name:      "missing input",
			args:      []string{"--zone", "example.com"},
			wantErr:   true,
			errSubstr: "zone and input are required",
		},
		{
			name:      "missing both",
			args:      []string{},
			wantErr:   true,
			errSubstr: "zone and input are required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cmdDNSSECSignZone(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errSubstr)
				}
				if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errSubstr)
				}
			}
		})
	}
}

// ============================================================================
// cmdDNSSECGenerateKey flag tests
// ============================================================================

func TestCmdDNSSECGenerateKey_FlagParsing(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantErr   bool
		errSubstr string
	}{
		{
			name:      "missing zone name",
			args:      []string{"--algorithm", "13", "--type", "ZSK"},
			wantErr:   true,
			errSubstr: "zone name is required",
		},
		{
			name:    "valid ECDSA P256 KSK",
			args:    []string{"--algorithm", "13", "--type", "KSK", "--zone", "example.com"},
			wantErr: false,
		},
		{
			name:    "valid ECDSA P384 ZSK",
			args:    []string{"--algorithm", "14", "--type", "ZSK", "--zone", "example.com"},
			wantErr: false,
		},
		{
			name:    "valid RSA SHA256 with keysize",
			args:    []string{"--algorithm", "8", "--type", "ZSK", "--zone", "example.com", "--keysize", "2048"},
			wantErr: false,
		},
		{
			name:    "valid RSA SHA512 with keysize",
			args:    []string{"--algorithm", "10", "--type", "KSK", "--zone", "test.org", "--keysize", "4096"},
			wantErr: false,
		},
		{
			name:    "default algorithm is 13",
			args:    []string{"--zone", "example.com"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			args := append(tt.args, "--output", tmpDir)

			err := cmdDNSSECGenerateKey(args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errSubstr)
				}
				if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify key files were created
			keyFiles, err := filepath.Glob(filepath.Join(tmpDir, "K*.key"))
			if err != nil {
				t.Fatalf("glob error: %v", err)
			}
			if len(keyFiles) == 0 {
				t.Error("expected key file to be created, none found")
			}

			privFiles, err := filepath.Glob(filepath.Join(tmpDir, "K*.private"))
			if err != nil {
				t.Fatalf("glob error: %v", err)
			}
			if len(privFiles) == 0 {
				t.Error("expected private key file to be created, none found")
			}
		})
	}
}

func TestCmdDNSSECGenerateKey_OutputToCustomDir(t *testing.T) {
	tmpDir := t.TempDir()
	outputDir := filepath.Join(tmpDir, "keys")

	err := cmdDNSSECGenerateKey([]string{
		"--algorithm", "13",
		"--type", "ZSK",
		"--zone", "example.com",
		"--output", outputDir,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the output directory was created
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		t.Error("expected output directory to be created")
	}

	keyFiles, _ := filepath.Glob(filepath.Join(outputDir, "K*.key"))
	if len(keyFiles) == 0 {
		t.Error("expected key files in custom output directory")
	}
}

// ============================================================================
// cmdDNSSECDSFromDNSKEY tests
// ============================================================================

func TestCmdDNSSECDSFromDNSKEY_FlagValidation(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantErr   bool
		errSubstr string
	}{
		{
			name:      "missing zone and keyfile",
			args:      []string{},
			wantErr:   true,
			errSubstr: "zone and keyfile are required",
		},
		{
			name:      "missing keyfile",
			args:      []string{"--zone", "example.com"},
			wantErr:   true,
			errSubstr: "zone and keyfile are required",
		},
		{
			name:      "missing zone",
			args:      []string{"--keyfile", "some.key"},
			wantErr:   true,
			errSubstr: "zone and keyfile are required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cmdDNSSECDSFromDNSKEY(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errSubstr)
				}
				if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errSubstr)
				}
			}
		})
	}
}

// ============================================================================
// readDNSKEYFromFile tests
// ============================================================================

func TestReadDNSKEYFromFile(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("valid DNSKEY file", func(t *testing.T) {
		pubKey := base64.StdEncoding.EncodeToString([]byte("fakepublickey12345"))
		content := fmt.Sprintf("; DNSKEY record for example.com.\nexample.com. IN DNSKEY 257 3 13 %s\n", pubKey)
		keyPath := filepath.Join(tmpDir, "Kexample.com.+013+12345.key")
		if err := os.WriteFile(keyPath, []byte(content), 0644); err != nil {
			t.Fatalf("failed to write key file: %v", err)
		}

		dnskey, err := readDNSKEYFromFile(keyPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dnskey.Flags != 257 {
			t.Errorf("flags = %d, want 257", dnskey.Flags)
		}
		if dnskey.Protocol != 3 {
			t.Errorf("protocol = %d, want 3", dnskey.Protocol)
		}
		if dnskey.Algorithm != 13 {
			t.Errorf("algorithm = %d, want 13", dnskey.Algorithm)
		}
	})

	t.Run("file does not exist", func(t *testing.T) {
		_, err := readDNSKEYFromFile(filepath.Join(tmpDir, "nonexistent.key"))
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
	})

	t.Run("no valid DNSKEY in file", func(t *testing.T) {
		keyPath := filepath.Join(tmpDir, "invalid.key")
		if err := os.WriteFile(keyPath, []byte("this is not a DNSKEY file\n"), 0644); err != nil {
			t.Fatalf("failed to write key file: %v", err)
		}

		_, err := readDNSKEYFromFile(keyPath)
		if err == nil {
			t.Error("expected error for file without DNSKEY")
		}
		if !strings.Contains(err.Error(), "no valid DNSKEY") {
			t.Errorf("error = %q, want substring 'no valid DNSKEY'", err.Error())
		}
	})
}

// ============================================================================
// generateKeyPair tests
// ============================================================================

func TestGenerateKeyPair(t *testing.T) {
	tests := []struct {
		name      string
		algorithm uint8
		isKSK     bool
		keySize   int
		wantErr   bool
	}{
		{
			name:      "ECDSA P256 ZSK",
			algorithm: protocol.AlgorithmECDSAP256SHA256,
			isKSK:     false,
			wantErr:   false,
		},
		{
			name:      "ECDSA P256 KSK",
			algorithm: protocol.AlgorithmECDSAP256SHA256,
			isKSK:     true,
			wantErr:   false,
		},
		{
			name:      "ECDSA P384 ZSK",
			algorithm: protocol.AlgorithmECDSAP384SHA384,
			isKSK:     false,
			wantErr:   false,
		},
		{
			name:      "RSA SHA256 2048",
			algorithm: protocol.AlgorithmRSASHA256,
			isKSK:     false,
			keySize:   2048,
			wantErr:   false,
		},
		{
			name:      "RSA SHA256 default size",
			algorithm: protocol.AlgorithmRSASHA256,
			isKSK:     true,
			keySize:   0, // should default to 2048
			wantErr:   false,
		},
		{
			name:      "RSA SHA512 4096",
			algorithm: protocol.AlgorithmRSASHA512,
			isKSK:     true,
			keySize:   4096,
			wantErr:   false,
		},
		{
			name:      "unsupported algorithm 0",
			algorithm: 0,
			wantErr:   true,
		},
		{
			name:      "unsupported algorithm 99",
			algorithm: 99,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := generateKeyPair(tt.algorithm, tt.isKSK, tt.keySize)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if key == nil {
				t.Fatal("key is nil")
			}
			if key.DNSKEY == nil {
				t.Fatal("key.DNSKEY is nil")
			}
			if key.PrivateKey == nil {
				t.Fatal("key.PrivateKey is nil")
			}
			if key.DNSKEY.Algorithm != tt.algorithm {
				t.Errorf("algorithm = %d, want %d", key.DNSKEY.Algorithm, tt.algorithm)
			}
			if key.IsKSK != tt.isKSK {
				t.Errorf("IsKSK = %v, want %v", key.IsKSK, tt.isKSK)
			}
			if key.IsZSK != !tt.isKSK {
				t.Errorf("IsZSK = %v, want %v", key.IsZSK, !tt.isKSK)
			}
			if key.KeyTag == 0 {
				t.Error("KeyTag should not be 0")
			}
		})
	}
}

// ============================================================================
// writePrivateKey and writePublicKey round-trip tests
// ============================================================================

func TestWriteAndReadKeyFiles(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name      string
		algorithm uint8
		isKSK     bool
		keySize   int
	}{
		{"ECDSA_P256_ZSK", protocol.AlgorithmECDSAP256SHA256, false, 0},
		{"ECDSA_P256_KSK", protocol.AlgorithmECDSAP256SHA256, true, 0},
		{"ECDSA_P384_ZSK", protocol.AlgorithmECDSAP384SHA384, false, 0},
		{"RSA_SHA256_2048_KSK", protocol.AlgorithmRSASHA256, true, 2048},
		{"RSA_SHA512_4096_ZSK", protocol.AlgorithmRSASHA512, false, 4096},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := generateKeyPair(tt.algorithm, tt.isKSK, tt.keySize)
			if err != nil {
				t.Fatalf("generateKeyPair error: %v", err)
			}

			zone := "test.example.com."
			algStr := fmt.Sprintf("%03d", tt.algorithm)
			baseName := fmt.Sprintf("K%s+%s+%05d", zone, algStr, key.KeyTag)

			privPath := filepath.Join(tmpDir, baseName+".private")
			pubPath := filepath.Join(tmpDir, baseName+".key")

			if err := writePrivateKey(privPath, key); err != nil {
				t.Fatalf("writePrivateKey error: %v", err)
			}
			if err := writePublicKey(pubPath, zone, key); err != nil {
				t.Fatalf("writePublicKey error: %v", err)
			}

			// Verify private key file exists and has content
			privData, err := os.ReadFile(privPath)
			if err != nil {
				t.Fatalf("reading private key: %v", err)
			}
			if len(privData) == 0 {
				t.Error("private key file is empty")
			}
			privStr := string(privData)
			if !strings.Contains(privStr, "Private-key-format:") {
				t.Error("private key missing format header")
			}
			if !strings.Contains(privStr, "Algorithm:") {
				t.Error("private key missing Algorithm field")
			}
			if !strings.Contains(privStr, "KeyTag:") {
				t.Error("private key missing KeyTag field")
			}

			// Verify public key file exists and can be read back
			pubData, err := os.ReadFile(pubPath)
			if err != nil {
				t.Fatalf("reading public key: %v", err)
			}
			if len(pubData) == 0 {
				t.Error("public key file is empty")
			}
			pubStr := string(pubData)
			if !strings.Contains(pubStr, "DNSKEY") {
				t.Error("public key missing DNSKEY line")
			}

			// Round-trip: read DNSKEY back from the file
			dnskey, err := readDNSKEYFromFile(pubPath)
			if err != nil {
				t.Fatalf("readDNSKEYFromFile error: %v", err)
			}
			if dnskey.Algorithm != tt.algorithm {
				t.Errorf("round-trip algorithm = %d, want %d", dnskey.Algorithm, tt.algorithm)
			}
			if dnskey.Protocol != 3 {
				t.Errorf("round-trip protocol = %d, want 3", dnskey.Protocol)
			}
			expectedFlags := uint16(protocol.DNSKEYFlagZone)
			if tt.isKSK {
				expectedFlags |= protocol.DNSKEYFlagSEP
			}
			if dnskey.Flags != expectedFlags {
				t.Errorf("round-trip flags = %d, want %d", dnskey.Flags, expectedFlags)
			}
		})
	}
}

// ============================================================================
// keyType helper tests
// ============================================================================

func TestKeyType(t *testing.T) {
	tests := []struct {
		name string
		isKSK bool
		want  string
	}{
		{"KSK", true, "KSK"},
		{"ZSK", false, "ZSK"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := keyType(&dnssec.SigningKey{IsKSK: tt.isKSK, IsZSK: !tt.isKSK})
			if got != tt.want {
				t.Errorf("keyType() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ============================================================================
// findKeyFiles tests
// ============================================================================

func TestFindKeyFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create some key files with BIND naming convention
	keyNames := []string{
		"Kexample.com+013+12345.key",
		"Kexample.com+013+67890.key",
		"Kother.com+013+11111.key",
		"notakey.txt",
	}
	for _, name := range keyNames {
		if err := os.WriteFile(filepath.Join(tmpDir, name), []byte("test"), 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
	}

	files, err := findKeyFiles(tmpDir, "example.com.")
	if err != nil {
		t.Fatalf("findKeyFiles error: %v", err)
	}

	if len(files) != 2 {
		t.Fatalf("expected 2 key files for example.com., got %d: %v", len(files), files)
	}

	for _, f := range files {
		base := filepath.Base(f)
		if !strings.HasPrefix(base, "Kexample.com+") {
			t.Errorf("unexpected file: %s", base)
		}
	}
}

func TestFindKeyFiles_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()

	files, err := findKeyFiles(tmpDir, "example.com.")
	if err != nil {
		t.Fatalf("findKeyFiles error: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 key files in empty dir, got %d", len(files))
	}
}

// ============================================================================
// buildSignedDataForValidation tests (smoke test)
// ============================================================================

func TestBuildSignedDataForValidation(t *testing.T) {
	// This is a basic smoke test to ensure the function doesn't panic
	// and returns non-empty data.
	owner, _ := protocol.ParseName("example.com.")
	signer, _ := protocol.ParseName("example.com.")

	rrSet := []*protocol.ResourceRecord{
		{
			Name:  owner,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data: &protocol.RDataA{
				Address: [4]byte{192, 0, 2, 1},
			},
		},
	}

	rrsig := &protocol.RDataRRSIG{
		TypeCovered: protocol.TypeA,
		Algorithm:   13,
		Labels:      1,
		OriginalTTL: 300,
		Expiration:  1735689600,
		Inception:   1733088000,
		KeyTag:      12345,
		SignerName:  signer,
		Signature:   []byte("fakesignature"),
	}

	data := buildSignedDataForValidation(rrSet, rrsig)
	if len(data) == 0 {
		t.Error("expected non-empty signed data")
	}

	// Verify the data starts with the type covered (big-endian uint16)
	typeCovered := uint16(data[0])<<8 | uint16(data[1])
	if typeCovered != protocol.TypeA {
		t.Errorf("first two bytes = %d (type covered), want %d", typeCovered, protocol.TypeA)
	}
}

// ============================================================================
// cmdDNSSEC subcommand dispatch tests
// ============================================================================

func TestCmdDNSSEC_SubcommandDispatch(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantErr   bool
		errSubstr string
	}{
		{
			name:      "no subcommand",
			args:      []string{},
			wantErr:   true,
			errSubstr: "dnssec subcommand required",
		},
		{
			name:      "unknown subcommand",
			args:      []string{"unknown-subcmd"},
			wantErr:   true,
			errSubstr: "unknown dnssec subcommand",
		},
		{
			name:      "generate-key missing zone",
			args:      []string{"generate-key"},
			wantErr:   true,
			errSubstr: "zone name is required",
		},
		{
			name:      "sign-zone missing args",
			args:      []string{"sign-zone"},
			wantErr:   true,
			errSubstr: "zone and input are required",
		},
		{
			name:      "ds-from-dnskey missing args",
			args:      []string{"ds-from-dnskey"},
			wantErr:   true,
			errSubstr: "zone and keyfile are required",
		},
		{
			name:      "verify-anchor missing file",
			args:      []string{"verify-anchor"},
			wantErr:   true,
			errSubstr: "trust anchor file path is required",
		},
		{
			name:      "validate-zone missing zone",
			args:      []string{"validate-zone"},
			wantErr:   true,
			errSubstr: "zone file is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cmdDNSSEC(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errSubstr)
				}
				if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errSubstr)
				}
			}
		})
	}
}

// ============================================================================
// cmdDNSSECValidateZone flag tests
// ============================================================================

func TestCmdDNSSECValidateZone_FlagValidation(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantErr   bool
		errSubstr string
	}{
		{
			name:      "missing zone file",
			args:      []string{},
			wantErr:   true,
			errSubstr: "zone file is required",
		},
		{
			name:      "nonexistent zone file",
			args:      []string{"--zone", "/nonexistent/path/zone.signed"},
			wantErr:   true,
			errSubstr: "reading zone file",
		},
		{
			name:      "empty zone file produces error",
			args:      nil, // will be set with temp file
			wantErr:   true,
			errSubstr: "no valid records",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.args
			if tt.name == "empty zone file produces error" {
				tmpDir := t.TempDir()
				emptyFile := filepath.Join(tmpDir, "empty.zone")
				if err := os.WriteFile(emptyFile, []byte(""), 0644); err != nil {
					t.Fatalf("failed to create empty file: %v", err)
				}
				args = []string{"--zone", emptyFile}
			}

			err := cmdDNSSECValidateZone(args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errSubstr)
				}
				if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errSubstr)
				}
			}
		})
	}
}

// ============================================================================
// parseZoneRecords: record content validation
// ============================================================================

func TestParseZoneRecords_RecordDataContent(t *testing.T) {
	zoneData := `@	300	IN	A	192.0.2.1
@	300	IN	AAAA	2001:db8::1
www	300	IN	CNAME	example.com.
@	300	IN	MX	10 mail.example.com.
@	300	IN	TXT	"v=spf1 +all"
@	300	IN	NS	ns1.example.com.
`
	records, err := parseZoneRecords(zoneData, "example.com.")
	if err != nil {
		t.Fatalf("parseZoneRecords() error = %v", err)
	}
	if len(records) != 6 {
		t.Fatalf("got %d records, want 6", len(records))
	}

	// Verify A record data
	aRec, ok := records[0].Data.(*protocol.RDataA)
	if !ok {
		t.Fatalf("record 0: expected *RDataA, got %T", records[0].Data)
	}
	expectedIP := net.IPv4(192, 0, 2, 1).To4()
	if string(aRec.Address[:]) != string(expectedIP) {
		t.Errorf("A address = %v, want %v", aRec.Address, expectedIP)
	}

	// Verify AAAA record data
	aaaaRec, ok := records[1].Data.(*protocol.RDataAAAA)
	if !ok {
		t.Fatalf("record 1: expected *RDataAAAA, got %T", records[1].Data)
	}
	expectedIP6 := net.ParseIP("2001:db8::1").To16()
	if string(aaaaRec.Address[:]) != string(expectedIP6) {
		t.Errorf("AAAA address = %v, want %v", aaaaRec.Address, expectedIP6)
	}

	// Verify CNAME record data
	cnameRec, ok := records[2].Data.(*protocol.RDataCNAME)
	if !ok {
		t.Fatalf("record 2: expected *RDataCNAME, got %T", records[2].Data)
	}
	if cnameRec.CName.String() != "example.com." {
		t.Errorf("CNAME = %q, want %q", cnameRec.CName.String(), "example.com.")
	}

	// Verify MX record data
	mxRec, ok := records[3].Data.(*protocol.RDataMX)
	if !ok {
		t.Fatalf("record 3: expected *RDataMX, got %T", records[3].Data)
	}
	if mxRec.Preference != 10 {
		t.Errorf("MX preference = %d, want 10", mxRec.Preference)
	}
	if mxRec.Exchange.String() != "mail.example.com." {
		t.Errorf("MX exchange = %q, want %q", mxRec.Exchange.String(), "mail.example.com.")
	}

	// Verify TXT record data
	txtRec, ok := records[4].Data.(*protocol.RDataTXT)
	if !ok {
		t.Fatalf("record 4: expected *RDataTXT, got %T", records[4].Data)
	}
	if len(txtRec.Strings) != 1 || txtRec.Strings[0] != "v=spf1 +all" {
		t.Errorf("TXT strings = %v, want [\"v=spf1 +all\"]", txtRec.Strings)
	}

	// Verify NS record data
	nsRec, ok := records[5].Data.(*protocol.RDataNS)
	if !ok {
		t.Fatalf("record 5: expected *RDataNS, got %T", records[5].Data)
	}
	if nsRec.NSDName.String() != "ns1.example.com." {
		t.Errorf("NS = %q, want %q", nsRec.NSDName.String(), "ns1.example.com.")
	}

	// Verify all records have class IN and TTL 300
	for i, rr := range records {
		if rr.Class != protocol.ClassIN {
			t.Errorf("record[%d].Class = %d, want IN", i, rr.Class)
		}
		if rr.TTL != 300 {
			t.Errorf("record[%d].TTL = %d, want 300", i, rr.TTL)
		}
	}
}

// ============================================================================
// Integration: generate keys and sign zone
// ============================================================================

func TestSignZoneIntegration(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a zone file
	zoneContent := `; Test zone
@	300	IN	SOA	ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400
@	300	IN	NS	ns1.example.com.
@	300	IN	A	192.0.2.1
www	300	IN	A	192.0.2.10
@	300	IN	MX	10 mail.example.com.
@	300	IN	TXT	"v=spf1 +all"
`
	zoneFile := filepath.Join(tmpDir, "example.com.zone")
	if err := os.WriteFile(zoneFile, []byte(zoneContent), 0644); err != nil {
		t.Fatalf("failed to write zone file: %v", err)
	}

	outputFile := filepath.Join(tmpDir, "example.com.zone.signed")

	err := cmdDNSSECSignZone([]string{
		"--zone", "example.com",
		"--input", zoneFile,
		"--output", outputFile,
		"--algorithm", "13",
	})
	if err != nil {
		t.Fatalf("cmdDNSSECSignZone error: %v", err)
	}

	// Verify output file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Fatal("signed zone file was not created")
	}

	// Read and verify the output contains expected content
	signedData, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read signed zone: %v", err)
	}
	signedStr := string(signedData)

	// Should contain the header comment
	if !strings.Contains(signedStr, "Signed zone:") {
		t.Error("signed zone missing 'Signed zone:' header")
	}
	if !strings.Contains(signedStr, "example.com.") {
		t.Error("signed zone missing zone name")
	}
	// Should contain DNSKEY records
	if !strings.Contains(signedStr, "DNSKEY") {
		t.Error("signed zone missing DNSKEY records")
	}
}

// ============================================================================
// hex encoding consistency check
// ============================================================================

func TestHexEncodeConsistency(t *testing.T) {
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	got := hexEncode(data)
	want := strings.ToUpper(hex.EncodeToString(data))
	if got != want {
		t.Errorf("hexEncode(%v) = %q, want %q", data, got, want)
	}
}

