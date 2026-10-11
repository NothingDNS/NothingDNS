package zone

// F683: quoted RDATA fields in a zone file reach the served wire record
// intact — \DDD octets, non-UTF-8 bytes, and spaces inside HINFO, URI and
// NAPTR character-strings — and a zone written by WriteZone parses back to the
// same wire bytes.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func zoneFileWire(t *testing.T, src string) map[string][]byte {
	t.Helper()
	z, err := ParseFile("z", strings.NewReader("$ORIGIN example.com.\n$TTL 60\n@ IN SOA ns1 h 1 2 3 4 5\n@ IN NS ns1\n"+src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	out := map[string][]byte{}
	for name, recs := range z.Records {
		for _, rec := range recs {
			if rec.Type == "SOA" || rec.Type == "NS" {
				continue
			}
			d := protocol.ParseRDataText(rec.Type, rec.RData)
			if d == nil {
				out[name+" "+rec.Type] = nil
				continue
			}
			buf := make([]byte, 4096)
			n, err := d.Pack(buf, 0)
			if err != nil {
				t.Fatalf("pack %s %s: %v", name, rec.Type, err)
			}
			out[name+" "+rec.Type] = buf[:n]
		}
	}
	return out
}

func TestZoneFileQuotedRDataWire(t *testing.T) {
	ls := func(parts ...string) []byte {
		var b []byte
		for _, p := range parts {
			b = append(b, byte(len(p)))
			b = append(b, p...)
		}
		return b
	}
	cases := []struct {
		rtype, text string
		want        []byte
	}{
		{"TXT", `"plain" "two"`, ls("plain", "two")},
		{"TXT", `"c\"d"`, ls(`c"d`)},
		{"TXT", `"\065\066"`, ls("AB")},
		{"TXT", `"a\255b"`, ls("a\xffb")},
		{"TXT", `"a\010b"`, ls("a\nb")},
		{"TXT", "\"a\xffb\"", ls("a\xffb")},
		{"HINFO", `cpu os`, ls("cpu", "os")},
		{"HINFO", `"a b" "c"`, ls("a b", "c")},
		{"CAA", `0 issue "ca.example.net"`, append([]byte{0, 5}, "issueca.example.net"...)},
		{"URI", `10 1 "http://x/a b"`, append([]byte{0, 10, 0, 1}, "http://x/a b"...)},
		{"NAPTR", `100 10 "u" "E2U+sip" "!^.*$!sip:a b!" .`, append(append([]byte{0, 100, 0, 10}, ls("u", "E2U+sip", "!^.*$!sip:a b!")...), 0)},
	}
	for _, c := range cases {
		got := zoneFileWire(t, "r IN "+c.rtype+" "+c.text+"\n")["r.example.com. "+c.rtype]
		if !bytes.Equal(got, c.want) {
			t.Errorf("%s %q: wire %x, want %x", c.rtype, c.text, got, c.want)
		}
	}
}

func TestZoneFileQuotedRDataWriteRoundTrip(t *testing.T) {
	src := "t IN TXT \"\\065\\255\" \"a\\\"b\" \"x\\010y\"\nh IN HINFO \"a b\" \"c\\\\d\"\nn IN NAPTR 1 2 \"u\" \"E2U\" \"!a b!c!\" .\n"
	first := zoneFileWire(t, src)
	z, err := ParseFile("z", strings.NewReader("$ORIGIN example.com.\n$TTL 60\n@ IN SOA ns1 h 1 2 3 4 5\n@ IN NS ns1\n"+src))
	if err != nil {
		t.Fatal(err)
	}
	text, err := WriteZone(z)
	if err != nil {
		t.Fatalf("WriteZone: %v", err)
	}
	z2, err := ParseFile("z2", strings.NewReader(text))
	if err != nil {
		t.Fatalf("re-parse: %v\n%s", err, text)
	}
	for name, recs := range z2.Records {
		for _, rec := range recs {
			want, ok := first[name+" "+rec.Type]
			if !ok {
				continue
			}
			d := protocol.ParseRDataText(rec.Type, rec.RData)
			b := make([]byte, 4096)
			n, _ := d.Pack(b, 0)
			if !bytes.Equal(b[:n], want) {
				t.Errorf("%s %s changed across WriteZone: %x -> %x\n%s", name, rec.Type, want, b[:n], text)
			}
		}
	}
}
