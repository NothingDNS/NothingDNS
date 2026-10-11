package zone

// F688: a zone file may use TYPE<n> and the generic `\# <len> <hex>` RDATA.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestZoneFileGenericRecords(t *testing.T) {
	z, err := ParseFile("z", strings.NewReader("$ORIGIN example.com.\n$TTL 60\n@ IN SOA ns1 h 1 2 3 4 5\n@ NS ns1\nx1 IN TYPE65280 \\# 4 01020304\nx2 TYPE999 \\# 0\nx3 IN A \\# 4 c0000201\nx4 IN TYPE1 192.0.2.7\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]byte{
		"x1.example.com.": {1, 2, 3, 4},
		"x2.example.com.": {},
		"x3.example.com.": {192, 0, 2, 1},
		"x4.example.com.": {192, 0, 2, 7},
	}
	for name, w := range want {
		recs := z.Records[name]
		if len(recs) != 1 {
			t.Fatalf("%s: %d records", name, len(recs))
		}
		d := protocol.ParseRDataText(recs[0].Type, recs[0].RData)
		if d == nil {
			t.Errorf("%s %s %q: not parseable", name, recs[0].Type, recs[0].RData)
			continue
		}
		buf := make([]byte, 64)
		n, _ := d.Pack(buf, 0)
		if !bytes.Equal(buf[:n], w) {
			t.Errorf("%s: wire %x, want %x", name, buf[:n], w)
		}
	}
	if got := z.Records["x4.example.com."][0].Type; got != "A" {
		t.Errorf("TYPE1 stored as %q, want A", got)
	}
	for _, bad := range []string{"TYPE", "TYPE0", "TYPE70000", "TYPEx"} {
		if isType(bad) {
			t.Errorf("isType(%q) = true", bad)
		}
	}
	// WriteZone output reads back.
	out, err := WriteZone(z)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseFile("z2", strings.NewReader(out)); err != nil {
		t.Fatalf("re-parse written zone: %v\n%s", err, out)
	}
}
