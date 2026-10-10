package protocol

// F682: CAA and NAPTR String() wrote raw quotes/backslashes/control octets between quotes and the
// CAA parser collapsed whitespace, so such values changed through the text form (DDNS, zone
// transfer, reload). Same class as F680.

import (
	"bytes"
	"testing"
)

func caaNaptrRT(t *testing.T, name string, wire []byte) (bool, string) {
	d1 := createRData(RecordTypeFromText(name))
	if _, err := d1.Unpack(wire, 0, uint16(len(wire))); err != nil {
		t.Fatalf("INVALID PROOF: unpack %s: %v", name, err)
	}
	w1 := make([]byte, 4096)
	n1, err := d1.Pack(w1, 0)
	if err != nil {
		t.Fatalf("INVALID PROOF: pack: %v", err)
	}
	text := d1.String()
	d2 := ParseRDataText(name, text)
	if d2 == nil {
		return false, text
	}
	w2 := make([]byte, 4096)
	n2, err := d2.Pack(w2, 0)
	return err == nil && bytes.Equal(w1[:n1], w2[:n2]), text
}

func caaWire(v string) []byte { return append([]byte{0, 5, 'i', 's', 's', 'u', 'e'}, v...) }

func naptrWire(regexp string) []byte {
	b := []byte{0, 1, 0, 2, 1, 'u', 3, 'x', 'y', 'z', byte(len(regexp))}
	b = append(b, regexp...)
	return append(b, 0)
}

func TestCAANAPTRString_RoundTripsThroughParseRDataText(t *testing.T) {
	for b := 0; b < 256; b++ {
		for _, pre := range []string{"", " "} {
			v := "a" + pre + string([]byte{byte(b)}) + "c"
			if ok, txt := caaNaptrRT(t, "CAA", caaWire(v)); !ok {
				t.Fatalf("CAA octet %#02x pre=%q: text %q", b, pre, txt)
			}
			if ok, txt := caaNaptrRT(t, "NAPTR", naptrWire(v)); !ok {
				t.Fatalf("NAPTR regexp octet %#02x pre=%q: text %q", b, pre, txt)
			}
			// flags and service fields too
			w := []byte{0, 1, 0, 2, byte(len(v))}
			w = append(w, v...)
			w = append(w, byte(len(v)))
			w = append(w, v...)
			w = append(w, 1, 'x', 0)
			if ok, txt := caaNaptrRT(t, "NAPTR", w); !ok {
				t.Fatalf("NAPTR flags/service octet %#02x pre=%q: text %q", b, pre, txt)
			}
		}
	}
	if got := ParseRDataText("CAA", `0 issue "ca.example.net"`).String(); got != `0 issue "ca.example.net"` {
		t.Fatalf("plain CAA rendered as %q", got)
	}
	if got := ParseRDataText("CAA", `0 issue ca.example.net`).String(); got != `0 issue "ca.example.net"` {
		t.Fatalf("unquoted CAA rendered as %q", got)
	}
}
