package transfer

import (
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// A TXT record a slave received must survive being written to its zone file
// and read back: strings holding ';', parentheses or a backslash, and empty
// strings, were written bare and came back altered (F765).
func TestTXTSurvivesZoneFileRoundTrip(t *testing.T) {
	for _, strs := range [][]string{{"a;b"}, {"(x)"}, {"a\\b"}, {""}, {"", "x"}, {"v=DKIM1; k=rsa; p=abc"}, {"plain"}} {
		name, _ := protocol.ParseName("t.e.test.")
		rr := &protocol.ResourceRecord{Name: name, Type: protocol.TypeTXT, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataTXT{Strings: strs}}
		z := zone.NewZone("e.test.")
		z.SOA = &zone.SOARecord{Name: "e.test.", TTL: 300, MName: "n.e.test.", RName: "h.e.test.", Serial: 1, Refresh: 1, Retry: 1, Expire: 1, Minimum: 1}
		z.Records["t.e.test."] = []zone.Record{recordFromRR(rr)}
		text, err := zone.WriteZone(z)
		if err != nil {
			t.Fatalf("%q: WriteZone: %v", strs, err)
		}
		back, err := zone.ParseFile("t", strings.NewReader(text))
		if err != nil {
			t.Fatalf("%q: reparse: %v\n%s", strs, err, text)
		}
		recs := back.Lookup("t.e.test.", "TXT")
		if len(recs) != 1 {
			t.Fatalf("%q: %d TXT records after reparse\n%s", strs, len(recs), text)
		}
		got := protocol.ParseRDataText("TXT", recs[0].RData)
		want := (&protocol.RDataTXT{Strings: strs}).String()
		if got == nil || protocol.ParseRDataText("TXT", want).String() != got.String() {
			t.Errorf("%q came back as %v", strs, got)
		}
		if txt, ok := got.(*protocol.RDataTXT); !ok || strings.Join(txt.Strings, "\x00") != strings.Join(strs, "\x00") {
			t.Errorf("%q came back as %#v", strs, got)
		}
	}
}
