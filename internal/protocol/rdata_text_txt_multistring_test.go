package protocol

// F684: a TXT RDATA with several character-strings keeps its string
// boundaries through String() and ParseRDataText. Bare `a b` reads back as the
// single string "a b", so a DKIM/SPF value split across strings gained a space
// at every boundary after an AXFR/IXFR or a DDNS update.

import (
	"bytes"
	"math/rand"
	"testing"
)

func txtMultiWire(strs []string) []byte {
	var b []byte
	for _, s := range strs {
		b = append(b, byte(len(s)))
		b = append(b, s...)
	}
	return b
}

func txtMultiRoundTrip(t *testing.T, strs []string) {
	t.Helper()
	wire := txtMultiWire(strs)
	d := &RDataTXT{}
	if _, err := d.Unpack(wire, 0, uint16(len(wire))); err != nil {
		t.Fatalf("unpack %q: %v", strs, err)
	}
	text := d.String()
	back := ParseRDataText("TXT", text)
	if back == nil {
		t.Fatalf("%q: text %q does not parse", strs, text)
	}
	buf := make([]byte, 2048)
	n, err := back.Pack(buf, 0)
	if err != nil {
		t.Fatalf("%q: pack: %v", strs, err)
	}
	if !bytes.Equal(buf[:n], wire) {
		t.Errorf("%q: text %q read back as wire %x, want %x", strs, text, buf[:n], wire)
	}
}

func TestTXTMultiStringTextRoundTrip(t *testing.T) {
	for _, c := range [][]string{
		{"single"}, {"v=spf1 -all"}, {`say "hi"`}, // one string: bare or quoted as before
		{"a", "b"}, {"v=DKIM1;k=rsa;p=MIIB", "IjANBgkq"}, {"", "x"}, {"x", ""}, {"", ""},
		{"a b", "c"}, {`q"`, `\`}, {"x\ny", "z"},
	} {
		txtMultiRoundTrip(t, c)
	}
	// The single-string text is unchanged (no quotes added to a plain value).
	if got := (&RDataTXT{Strings: []string{"plain"}}).String(); got != "plain" {
		t.Errorf("single plain string = %q, want plain", got)
	}
}

func TestTXTMultiStringTextRoundTripRandom(t *testing.T) {
	rnd := rand.New(rand.NewSource(684))
	alphabet := []byte("ab =;\"\\.\n\t\x00\xff")
	for it := 0; it < 3000; it++ {
		strs := make([]string, 1+rnd.Intn(4))
		for i := range strs {
			b := make([]byte, rnd.Intn(8))
			for j := range b {
				b[j] = alphabet[rnd.Intn(len(alphabet))]
			}
			strs[i] = string(b)
		}
		if len(strs) == 1 && strs[0] == "" {
			continue
		}
		txtMultiRoundTrip(t, strs)
	}
}
