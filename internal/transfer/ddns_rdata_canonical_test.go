package transfer

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// F694: the zone parser stores RDATA as written ("2001:0DB8:0:0:0:0:0:0001",
// upper-case hex) while an UPDATE carries wire RDATA rendered by String()
// ("2001:db8::1"). Comparing the raw text meant a zone-file record could not
// be deleted, matched by a prerequisite, or de-duplicated by DDNS.
func TestDDNSMatchesRDataByValueNotSpelling(t *testing.T) {
	cases := []struct {
		name   string
		rrType uint16
		typ    string
		stored string
		wire   string
	}{
		{"aaaa", protocol.TypeAAAA, "AAAA", "2001:0DB8:0:0:0:0:0:0001", "2001:db8::1"},
		{"tlsa", protocol.TypeTLSA, "TLSA", "3 1 1 ABCD", "3 1 1 abcd"},
		{"sshfp", protocol.TypeSSHFP, "SSHFP", "1 1 ABCDEF", "1 1 abcdef"},
		{"control-a", protocol.TypeA, "A", "192.0.2.1", "192.0.2.1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mk := func() *zone.Zone {
				z := zone.NewZone("example.com.")
				z.Records["h.example.com."] = []zone.Record{{Name: "h.example.com.", Type: c.typ, TTL: 60, Class: "IN", RData: c.stored}}
				return z
			}
			if !zoneRecordExists(mk(), "h.example.com.", c.rrType, c.wire) {
				t.Errorf("prerequisite: %q not matched by %q", c.stored, c.wire)
			}
			z := mk()
			if err := ApplyUpdate(z, &UpdateRequest{ZoneName: "example.com.", Updates: []UpdateOperation{
				{Name: "h.example.com.", Type: c.rrType, TTL: 60, RData: c.wire, Operation: UpdateOpDelete},
			}}); err != nil {
				t.Fatal(err)
			}
			if n := len(z.Records["h.example.com."]); n != 0 {
				t.Errorf("delete: %d records left", n)
			}
			z = mk()
			if err := ApplyUpdate(z, &UpdateRequest{ZoneName: "example.com.", Updates: []UpdateOperation{
				{Name: "h.example.com.", Type: c.rrType, TTL: 120, RData: c.wire, Operation: UpdateOpAdd},
			}}); err != nil {
				t.Fatal(err)
			}
			if n := len(z.Records["h.example.com."]); n != 1 {
				t.Errorf("add: duplicate RR, %d records", n)
			}
		})
	}
}
