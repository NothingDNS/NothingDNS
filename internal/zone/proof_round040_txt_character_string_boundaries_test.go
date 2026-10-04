// Regression: TXT/SPF/DKIM character-string boundaries must survive the zone
// parser, so the served RDATA keeps the string count the operator wrote.
//
// CONTRACT. RFC 1035 §3.3.14: TXT-DATA is <character-string>+ — the record
// carries a SEQUENCE of strings, not one string. A zone file expresses that
// sequence as adjacent quoted fields: `txt IN TXT "first" "second"` is a
// two-string record, while `txt IN TXT "first second"` is a one-string record
// whose value contains a space. RFC 6376 §3.6.1 (DKIM key records) and
// RFC 7208 (SPF) rely on this: long values are split across strings and the
// reader concatenates them, so a space injected at a string boundary changes
// the published value.
//
// DEFECT. parseRecordOwned stores the RDATA text of every type by joining the
// presentation fields with a single space and dropping the quotes. For the
// character-string types that join is lossy in two ways: the string count is
// lost (`"first" "second"` and `"first second"` both become `first second`),
// and an extra space is injected at every boundary. protocol.ParseRDataText
// then packs the stored text as ONE character-string, so the served record
// differs from the zone file — for the DKIM multi-line form the served value
// even carries the injected space inside the base64.
//
// FIX. For the character-string types the parser re-quotes each presentation
// field (escaping `\` and `"`), so the stored RDATA keeps the boundary
// information and the existing quoted-form branch of the RDATA parser packs
// the strings the operator wrote.
//
// The controls pin the cases that must not move: a single quoted value keeps
// its embedded space, an unquoted single token stays one string, an escaped
// quote stays one string, and an API-style unquoted value (the stored form the
// REST layer writes) still serves as one string.
package zone

import (
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

const rr040ZoneText = `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1 hostmaster ( 1 3600 900 604800 86400 )
@ IN NS ns1
ns1 IN A 192.0.2.1
two 300 IN TXT "first" "second"
one 300 IN TXT "first second"
esc 300 IN TXT "quote\"inside"
raw 300 IN TXT plain-token
`

func rr040Names(z *Zone) []string {
	out := make([]string, 0, len(z.Records))
	for k := range z.Records {
		out = append(out, k)
	}
	return out
}

// rr040ServedStrings parses the zone text and returns the character-strings
// protocol.ParseRDataText packs for the TXT record of name — the exact value
// the server puts on the wire.
func rr040ServedStrings(t *testing.T, z *Zone, name string) []string {
	t.Helper()
	for _, rec := range z.Records[name] {
		if rec.Type != "TXT" {
			continue
		}
		rd := protocol.ParseRDataText("TXT", rec.RData)
		if rd == nil {
			t.Fatalf("ParseRDataText(TXT, %q) returned nil", rec.RData)
		}
		txt, ok := rd.(*protocol.RDataTXT)
		if !ok || txt == nil {
			t.Fatalf("ParseRDataText(TXT, %q) returned %T, want *protocol.RDataTXT", rec.RData, rd)
		}
		return txt.Strings
	}
	t.Fatalf("no TXT record stored for %q (stored keys: %v)", name, rr040Names(z))
	return nil
}

func rr040Parse(t *testing.T) *Zone {
	t.Helper()
	z, err := ParseFile("txt.example.com.zone", strings.NewReader(rr040ZoneText))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	return z
}

// TestRound040TXTCharacterStringBoundaries is the defect case: adjacent quoted
// fields are two character-strings and must be served as two.
func TestRound040TXTCharacterStringBoundaries(t *testing.T) {
	z := rr040Parse(t)

	got := rr040ServedStrings(t, z, "two.example.com.")
	want := []string{"first", "second"}
	if len(got) != len(want) {
		t.Fatalf("TXT %q served as %d character-string(s) %q, want %d %q: "+
			"the zone file declares two strings and RFC 1035 §3.3.14 keeps them "+
			"separate; collapsing them also injects a space at the boundary, which "+
			"changes the published value (RFC 6376 §3.6.1 / RFC 7208)",
			`"first" "second"`, len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("character-string %d = %q, want %q (served %q)", i, got[i], want[i], got)
		}
	}
}

// TestRound040TXTBoundariesSurviveWriteZoneRoundTrip pins the export /
// persistence / cluster-snapshot path: a zone written by WriteZone and read
// back must still declare the same number of character-strings.
func TestRound040TXTBoundariesSurviveWriteZoneRoundTrip(t *testing.T) {
	z := rr040Parse(t)

	text, err := WriteZone(z)
	if err != nil {
		t.Fatalf("WriteZone: %v", err)
	}
	z2, err := ParseFile("txt.example.com.zone", strings.NewReader(text))
	if err != nil {
		t.Fatalf("ParseFile(WriteZone output): %v\n%s", err, text)
	}

	got := rr040ServedStrings(t, z2, "two.example.com.")
	if len(got) != 2 {
		t.Fatalf("after a WriteZone round trip the TXT record serves %d "+
			"character-string(s) %q, want 2 — exported and persisted zones must "+
			"keep the string count", len(got), got)
	}
	if got[0] != "first" || got[1] != "second" {
		t.Errorf("after a WriteZone round trip the strings are %q, want [first second]", got)
	}
}

// TestRound040TXTControls pins the neighbouring cases that must not move.
func TestRound040TXTControls(t *testing.T) {
	z := rr040Parse(t)

	tests := []struct {
		name   string
		owner  string
		want   []string
		reason string
	}{
		{
			name:   "single quoted value keeps its space",
			owner:  "one.example.com.",
			want:   []string{"first second"},
			reason: `"first second" is ONE character-string containing a space`,
		},
		{
			name:   "escaped quote stays one string",
			owner:  "esc.example.com.",
			want:   []string{`quote"inside`},
			reason: `an escaped quote is content, not a boundary`,
		},
		{
			name:   "unquoted single token",
			owner:  "raw.example.com.",
			want:   []string{"plain-token"},
			reason: "an unquoted character-string is still one string",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := rr040ServedStrings(t, z, tc.owner)
			if len(got) != len(tc.want) {
				t.Fatalf("%s: served %q, want %q (%s)", tc.owner, got, tc.want, tc.reason)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("%s: string %d = %q, want %q (%s)", tc.owner, i, got[i], tc.want[i], tc.reason)
				}
			}
		})
	}

	// The REST layer stores RDATA unquoted; such a value must still serve as
	// one string, not be split on its spaces.
	z2 := NewZone("example.com.")
	z2.DefaultTTL = 300
	z2.Records["api.example.com."] = []Record{{
		Name: "api.example.com.", TTL: 300, Class: "IN", Type: "TXT",
		RData: "v=spf1 include:_spf.example.com -all",
	}}
	got := rr040ServedStrings(t, z2, "api.example.com.")
	if len(got) != 1 || got[0] != "v=spf1 include:_spf.example.com -all" {
		t.Errorf("API-style unquoted RDATA served as %q, want one string "+
			"[v=spf1 include:_spf.example.com -all] — an unquoted stored value "+
			"must not be split on whitespace", got)
	}
}
