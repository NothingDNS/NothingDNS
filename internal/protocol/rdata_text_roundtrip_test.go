package protocol

// F680: String() of TXT, HINFO and URI used Go escapes (\n, \xNN, \uNNNN) that ParseRDataText
// reads back as plain letters, so DDNS-added and AXFR-transferred values changed once stored
// as text and parsed again for serving or zone-file reload. Presentation form is RFC 1035 \DDD.

import (
	"bytes"
	"testing"
)

// rdataTextRoundTrip unpacks wire RDATA, renders it with String() (what DDNS
// parseUpdates and the AXFR/IXFR slave store), parses that text back with
// ParseRDataText (what serving and zone-file reload do) and compares the wire.
func rdataTextRoundTrip(t *testing.T, name string, wire []byte) (same bool, text string) {
	typ := RecordTypeFromText(name)
	d1 := createRData(typ)
	if _, err := d1.Unpack(wire, 0, uint16(len(wire))); err != nil {
		t.Fatalf("INVALID PROOF: unpack %s: %v", name, err)
	}
	w1 := make([]byte, 4096)
	n1, err := d1.Pack(w1, 0)
	if err != nil {
		t.Fatalf("INVALID PROOF: pack %s: %v", name, err)
	}
	text = d1.String()
	d2 := ParseRDataText(name, text)
	if d2 == nil {
		return false, text
	}
	w2 := make([]byte, 4096)
	n2, err := d2.Pack(w2, 0)
	if err != nil {
		return false, text
	}
	return bytes.Equal(w1[:n1], w2[:n2]), text
}

func TestRDataString_RoundTripsThroughParseRDataText(t *testing.T) {
	// every octet value, alone and next to a space (which forces quoting), in each type
	for b := 0; b < 256; b++ {
		for _, sp := range []bool{false, true} {
			inner := []byte{'a', byte(b), 'c'}
			if sp {
				inner = []byte{'a', ' ', byte(b), 'c'}
			}
			wires := map[string][]byte{
				"TXT":   append([]byte{byte(len(inner))}, inner...),
				"SPF":   append([]byte{byte(len(inner))}, inner...),
				"HINFO": append(append([]byte{byte(len(inner))}, inner...), 2, 'x', byte(b)),
				"URI":   append([]byte{0, 1, 0, 2}, inner...),
			}
			for n, w := range wires {
				if ok, txt := rdataTextRoundTrip(t, n, w); !ok {
					t.Fatalf("%s octet %#02x (space=%v): text %q does not round-trip", n, b, sp, txt)
				}
			}
		}
	}
	// multi-string TXT, empty-free: quotes and backslashes together with controls
	multi := []byte{4, 'a', '"', '\\', '\n', 3, 'x', ' ', 'y'}
	if ok, txt := rdataTextRoundTrip(t, "TXT", multi); !ok {
		t.Fatalf("multi-string TXT %q does not round-trip", txt)
	}
	// plain values keep their old, readable form
	d := ParseRDataText("TXT", `v=spf1 mx -all`)
	if got := d.String(); got != `"v=spf1 mx -all"` {
		t.Fatalf("TXT with spaces rendered as %q", got)
	}
	if got := ParseRDataText("TXT", `plain`).String(); got != `plain` {
		t.Fatalf("plain TXT rendered as %q", got)
	}
}
