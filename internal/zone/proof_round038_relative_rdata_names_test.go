// Regression: domain names inside RDATA that are not terminated by a dot are
// relative to the current origin (RFC 1035 §5.1), exactly like the owner name.
//
// DEFECT. parseRecordOwned resolved the owner name with makeAbsolute but stored
// the RDATA text verbatim, so a zone line `www IN CNAME target` was kept as
// "target". Record.RData is the text protocol.ParseRDataText turns into the
// served wire record, and that parser has no origin: it read "target" as the
// root-relative name "target.", so the authoritative answer was
// "www.example.com. CNAME target." — a name in the root zone — instead of
// target.example.com. The same applied to NS, MX, SRV, SOA, PTR, DNAME, SVCB
// targets, and to NAPTR/HIP/IPSECKEY name fields.
//
// The controls below pin the unaffected paths: already-absolute names, the
// root name ".", and RDATA of types that carry no domain name (TXT/A/AAAA) must
// come through byte-identical, so the fix cannot rewrite non-name fields.
package zone

import (
	"os"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

const rr038ZoneText = `$ORIGIN example.com.
$TTL 3600
@	IN SOA	ns1 hostmaster ( 2024010101 3600 900 604800 86400 )
@	IN NS	ns1
ns1	IN A	192.0.2.1
www	IN CNAME	target
alias	IN DNAME	target2
mail	IN MX	10 mx1
_sip._tcp	IN SRV	0 0 5060 sipserver
4.3.2.1	IN PTR	host
svc	IN SVCB	1 backend
sig	IN RRSIG	A 8 2 3600 20300101000000 20200101000000 12345 signer abc
hip	IN HIP	2 00112233445566778899aabbccddeeff AAAA rvs1 rvs2
naptr	IN NAPTR	100 10 u E2U+sip !^.*$!sip:info@example.com! .
; controls: must not be rewritten
abs	IN CNAME	target.example.com.
root	IN CNAME	.
txt	IN TXT	"a b.example.com"
host6	IN AAAA	2001:db8::1
svcroot	IN SVCB	1 .
`

// rr038Lookup returns the single record of the given type at owner.
func rr038Lookup(t *testing.T, z *Zone, owner, rrtype string) Record {
	t.Helper()
	recs := z.Lookup(owner, rrtype)
	if len(recs) != 1 {
		t.Fatalf("Lookup(%q, %q) returned %d records, want 1", owner, rrtype, len(recs))
	}
	return recs[0]
}

func TestRound038RelativeRDataNamesResolvedAgainstOrigin(t *testing.T) {
	z, err := ParseFile("-", strings.NewReader(rr038ZoneText))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	tests := []struct {
		owner string
		rtype string
		want  string
	}{
		{"example.com.", "NS", "ns1.example.com."},
		{"www.example.com.", "CNAME", "target.example.com."},
		{"alias.example.com.", "DNAME", "target2.example.com."},
		{"mail.example.com.", "MX", "10 mx1.example.com."},
		{"_sip._tcp.example.com.", "SRV", "0 0 5060 sipserver.example.com."},
		{"4.3.2.1.example.com.", "PTR", "host.example.com."},
		{"svc.example.com.", "SVCB", "1 backend.example.com."},
		{"sig.example.com.", "RRSIG", "A 8 2 3600 20300101000000 20200101000000 12345 signer.example.com. abc"},
		{"hip.example.com.", "HIP", "2 00112233445566778899aabbccddeeff AAAA rvs1.example.com. rvs2.example.com."},
		{"naptr.example.com.", "NAPTR", "100 10 u E2U+sip !^.*$!sip:info@example.com! ."},
		{"example.com.", "SOA", "ns1.example.com. hostmaster.example.com. 2024010101 3600 900 604800 86400"},
		// Controls: absolute names, the root name, and name-free RDATA.
		{"abs.example.com.", "CNAME", "target.example.com."},
		{"root.example.com.", "CNAME", "."},
		{"svcroot.example.com.", "SVCB", "1 ."},
		// Round 040: character-string RDATA is stored in its canonical quoted
		// form; the name inside it is still resolved against the origin.
		{"txt.example.com.", "TXT", `"a b.example.com"`},
		{"host6.example.com.", "AAAA", "2001:db8::1"},
	}
	for _, tc := range tests {
		t.Run(tc.rtype+"/"+tc.owner, func(t *testing.T) {
			rec := rr038Lookup(t, z, tc.owner, tc.rtype)
			if rec.RData != tc.want {
				t.Errorf("stored RDATA for %s %s = %q, want %q (RFC 1035 §5.1: a name "+
					"not ending in a dot is relative to the origin)",
					tc.owner, tc.rtype, rec.RData, tc.want)
			}
		})
	}
}

// TestRound038ServedRDataCarriesAbsoluteTarget is the user-visible half: the
// stored text is what the authoritative handler converts with
// protocol.ParseRDataText, so the served record must point at the in-zone name.
func TestRound038ServedRDataCarriesAbsoluteTarget(t *testing.T) {
	z, err := ParseFile("-", strings.NewReader(rr038ZoneText))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	cname := rr038Lookup(t, z, "www.example.com.", "CNAME")
	rd := protocol.ParseRDataText(cname.Type, cname.RData)
	if rd == nil {
		t.Fatalf("ParseRDataText(%q, %q) returned nil", cname.Type, cname.RData)
	}
	served, ok := rd.(*protocol.RDataCNAME)
	if !ok {
		t.Fatalf("ParseRDataText returned %T, want *protocol.RDataCNAME", rd)
	}
	if got := served.CName.String(); got != "target.example.com." {
		t.Errorf("served CNAME target = %q, want %q — the answer points outside the zone",
			got, "target.example.com.")
	}

	mx := rr038Lookup(t, z, "mail.example.com.", "MX")
	mxRD, ok := protocol.ParseRDataText(mx.Type, mx.RData).(*protocol.RDataMX)
	if !ok {
		t.Fatalf("ParseRDataText(%q, %q) did not return *protocol.RDataMX", mx.Type, mx.RData)
	}
	if got := mxRD.Exchange.String(); got != "mx1.example.com." {
		t.Errorf("served MX exchange = %q, want %q", got, "mx1.example.com.")
	}

	srv := rr038Lookup(t, z, "_sip._tcp.example.com.", "SRV")
	srvRD, ok := protocol.ParseRDataText(srv.Type, srv.RData).(*protocol.RDataSRV)
	if !ok {
		t.Fatalf("ParseRDataText(%q, %q) did not return *protocol.RDataSRV", srv.Type, srv.RData)
	}
	if got := srvRD.Target.String(); got != "sipserver.example.com." {
		t.Errorf("served SRV target = %q, want %q", got, "sipserver.example.com.")
	}
}

// TestRound038RelativeRDataIncludedZoneUsesIncludeOrigin pins the same rule for
// records pulled in through $INCLUDE: the included file's records are parsed
// with the including zone's origin, so their relative RDATA names resolve there.
func TestRound038RelativeRDataIncludedZoneUsesIncludeOrigin(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/included.zone", []byte("child\tIN CNAME\tleaf\n"), 0o644); err != nil {
		t.Fatalf("writing include file: %v", err)
	}
	mainText := "$ORIGIN example.com.\n$TTL 300\n@ IN SOA ns1 hostmaster ( 1 3600 900 604800 86400 )\n$INCLUDE included.zone\n"
	mainPath := dir + "/main.zone"
	if err := os.WriteFile(mainPath, []byte(mainText), 0o644); err != nil {
		t.Fatalf("writing main zone file: %v", err)
	}
	f, err := os.Open(mainPath)
	if err != nil {
		t.Fatalf("open main zone file: %v", err)
	}
	defer f.Close()

	z, err := ParseFile(mainPath, f)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	rec := rr038Lookup(t, z, "child.example.com.", "CNAME")
	if rec.RData != "leaf.example.com." {
		t.Errorf("included record RDATA = %q, want %q", rec.RData, "leaf.example.com.")
	}
}
