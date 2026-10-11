package transfer

// F685: a TXT string holding a NUL octet survives slave store -> WriteZone -> reload
// (the writer drops raw control characters, so the text form must escape them).

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// A slave stores wire TXT via recordFromRR, persists the zone with WriteZone,
// reloads it: the served bytes must equal the transferred bytes.
func slaveTXTPersisted(t *testing.T, s string) []byte {
	rd := append([]byte{byte(len(s))}, s...)
	wire := append([]byte{0, 0, 16, 0, 1, 0, 0, 0, 60, 0, byte(len(rd))}, rd...)
	rr, _, err := protocol.UnpackResourceRecord(wire, 0)
	if err != nil {
		t.Fatalf("%v", err)
	}
	rec := recordFromRR(rr)
	rec.Name = "r.example.com."
	rec.Class = "IN"
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{MName: "ns1.example.com.", RName: "h.example.com.", Serial: 1, Refresh: 1, Retry: 1, Expire: 1, Minimum: 1}
	z.Records["example.com."] = []zone.Record{
		{Name: "example.com.", Type: "SOA", Class: "IN", TTL: 60, RData: "ns1.example.com. h.example.com. 1 1 1 1 1"},
		{Name: "example.com.", Type: "NS", Class: "IN", TTL: 60, RData: "ns1.example.com."},
	}
	z.Records["r.example.com."] = []zone.Record{rec}
	out, err := zone.WriteZone(z)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	z2, err := zone.ParseFile("z", strings.NewReader(out))
	if err != nil {
		t.Fatalf("reparse: %v\n%s", err, out)
	}
	recs := z2.Records["r.example.com."]
	if len(recs) != 1 {
		return nil
	}
	d := protocol.ParseRDataText(recs[0].Type, recs[0].RData)
	if d == nil {
		return nil
	}
	buf := make([]byte, 512)
	n, _ := d.Pack(buf, 0)
	return append([]byte(nil), buf[:n]...)
}

func TestSlaveTXTControlOctetsSurvivePersistence(t *testing.T) {
	for _, s := range []string{"plain", "with space", `q"uote`} { // controls
		if got := slaveTXTPersisted(t, s); !bytes.Equal(got, append([]byte{byte(len(s))}, s...)) {
			t.Fatalf("control %q: %x", s, got)
		}
	}
	bad := 0
	for _, s := range []string{"a\x00b", "a\nb", "a\rb", "x\x01y", "\x00"} {
		want := append([]byte{byte(len(s))}, s...)
		if got := slaveTXTPersisted(t, s); !bytes.Equal(got, want) {
			bad++
			t.Errorf("%q: got %x, want %x", s, got, want)
		}
	}
	if bad > 0 {
		t.Fatalf("%d cases changed across persistence", bad)
	}
}
