package protocol

import "testing"

// TestParseRDataText_QuotedEscapesAndOctets pins F107/F108: quoted
// character-strings decode RFC 1035 §5.1 \DDD escapes to the octet they name
// and keep non-UTF-8 octets byte-for-byte (they were rewritten as U+FFFD).
func TestParseRDataText_QuotedEscapesAndOctets(t *testing.T) {
	txtCases := []struct{ in, want string }{
		{`"v=DKIM1\059 k=rsa"`, "v=DKIM1; k=rsa"},
		{`"a\032b"`, "a b"},
		{`"\000\255"`, "\x00\xff"},
		{`"a\256b"`, "a256b"}, // out-of-range \DDD keeps the old \X meaning
		{`"a\05"`, "a05"},     // short \DD keeps the old \X meaning
		{`"a\"b"`, `a"b`},
		{`"a\\065"`, `a\065`},
		{"\"\xff\"", "\xff"},
		{"\"a b\x80c\"", "a b\x80c"},
		{"\"café\"", "café"},
	}
	for _, c := range txtCases {
		rd, ok := ParseRDataText("TXT", c.in).(*RDataTXT)
		if !ok || len(rd.Strings) != 1 || rd.Strings[0] != c.want {
			t.Errorf("TXT %q = %#v, want single string %q", c.in, rd, c.want)
		}
	}

	h, ok := ParseRDataText("HINFO", "\"x\\032y\" \"os\xfe\"").(*RDataHINFO)
	if !ok || h.CPU != "x y" || h.OS != "os\xfe" {
		t.Errorf("HINFO = %#v, want CPU %q OS %q", h, "x y", "os\xfe")
	}
	caa, ok := ParseRDataText("CAA", `0 issue "ca.example\059 account=1"`).(*RDataCAA)
	if !ok || caa.Value != "ca.example; account=1" {
		t.Errorf("CAA = %#v, want value %q", caa, "ca.example; account=1")
	}
}
