package transfer

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// Character-string RDATA is case-sensitive: an RFC 2136 delete of one RR (and a
// value-dependent prerequisite) must not match an RR that differs only in case.
// updateRDataEqual exempted TXT only, so SPF, CAA, URI and the other
// character-string types matched case-insensitively and a delete removed both.
func TestDDNSRDataMatchIsCaseSensitiveForCharacterStrings(t *testing.T) {
	newZone := func() *zone.Zone {
		z := zone.NewZone("example.com.")
		z.Records["x.example.com."] = []zone.Record{
			{Name: "x.example.com.", Type: "SPF", TTL: 300, RData: `"V=spf1 -all"`},
			{Name: "x.example.com.", Type: "SPF", TTL: 300, RData: `"v=spf1 -all"`},
		}
		return z
	}

	z := newZone()
	zoneDeleteRecord(z, "x.example.com.", protocol.TypeSPF, `"v=spf1 -all"`)
	got := z.Records["x.example.com."]
	if len(got) != 1 || got[0].RData != `"V=spf1 -all"` {
		t.Fatalf("FAIL: deleting %q left %+v, want only the differently-cased RR", `"v=spf1 -all"`, got)
	}

	z = newZone()
	z.Records["x.example.com."] = z.Records["x.example.com."][:1] // only the upper-case RR
	if zoneRecordExists(z, "x.example.com.", protocol.TypeSPF, `"v=spf1 -all"`) {
		t.Fatal("FAIL: prerequisite for the lower-case SPF matched the upper-case RR")
	}

	// Control: domain names in RDATA still match regardless of case.
	z = zone.NewZone("example.com.")
	z.Records["www.example.com."] = []zone.Record{{Name: "www.example.com.", Type: "CNAME", TTL: 300, RData: "Target.Example.com."}}
	if !zoneRecordExists(z, "www.example.com.", protocol.TypeCNAME, "target.example.com.") {
		t.Fatal("control: CNAME target compared case-sensitively")
	}
}
