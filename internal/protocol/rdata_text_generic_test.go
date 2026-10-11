package protocol

// F688: RFC 3597 §5 generic RDATA (`\# <len> <hex>`) parses for any type. A
// slave stores a type it does not model as that text, and it used to be
// dropped when the zone was served.

import (
	"bytes"
	"testing"
)

func packRD(t *testing.T, d RData) []byte {
	t.Helper()
	buf := make([]byte, 4096)
	n, err := d.Pack(buf, 0)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return buf[:n]
}

func TestParseRDataTextGeneric(t *testing.T) {
	cases := []struct {
		rtype, text string
		want        []byte
	}{
		{"TYPE65280", `\# 4 01020304`, []byte{1, 2, 3, 4}},
		{"TYPE999", `\# 0`, []byte{}},
		{"TYPE999", `\# 3 0a 0b 0C`, []byte{0x0a, 0x0b, 0x0c}},
		{"A", `\# 4 c0000201`, []byte{192, 0, 2, 1}},
		{"TXT", `\# 4 03616263`, []byte{3, 'a', 'b', 'c'}},
		{"type61", `\# 2 abcd`, []byte{0xab, 0xcd}},
	}
	for _, c := range cases {
		d := ParseRDataText(c.rtype, c.text)
		if d == nil {
			t.Errorf("%s %q: nil", c.rtype, c.text)
			continue
		}
		if got := packRD(t, d); !bytes.Equal(got, c.want) {
			t.Errorf("%s %q: wire %x, want %x", c.rtype, c.text, got, c.want)
		}
	}
	for _, bad := range [][2]string{
		{"TYPE999", `\# 4 0102`},   // length mismatch
		{"TYPE999", `\# 2 zz00`},   // not hex
		{"TYPE999", `\# 70000 00`}, // length > 65535
		{"TYPE999", `\# `},         // no length
		{"A", `\# 3 c00002`},       // typed rdata that does not unpack
		{"NOSUCHTYPE", `\# 1 00`},  // unknown mnemonic
		{"TYPE999", `\# -1 00`},
	} {
		if d := ParseRDataText(bad[0], bad[1]); d != nil {
			t.Errorf("%s %q parsed, want nil", bad[0], bad[1])
		}
	}
	// What RDataRaw prints reads back.
	raw := &RDataRaw{TypeVal: 4242, Data: []byte{0, 255, 16}}
	if d := ParseRDataText("TYPE4242", raw.String()); d == nil || !bytes.Equal(packRD(t, d), raw.Data) {
		t.Errorf("RDataRaw.String() %q does not read back", raw.String())
	}
	if d := ParseRDataText("TYPE4242", (&RDataRaw{TypeVal: 4242}).String()); d == nil {
		t.Errorf("empty RDataRaw text does not read back")
	}
}
