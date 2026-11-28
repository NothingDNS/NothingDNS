package protocol

import "testing"

// Regression tests for CanonicalWireName's handling of RFC 1035 §5.1
// presentation escapes.
//
// CanonicalWireName is the shared canonical name encoder used by DNSSEC
// signing/validation (internal/dnssec), ZONEMD serialization (internal/zone)
// and `dnsctl dnssec validate-zone`. Its input is presentation-format text,
// so it must decode RFC 1035 §5.1 escapes (`\X` quotes the next character,
// `\DDD` is a decimal octet) before splitting labels and lowercasing —
// otherwise a legal name like `my\.host.example.` is encoded as the three
// labels `my\`, `host`, `example` (with a literal backslash byte), which no
// other DNSSEC implementation accepts as the same name.

func TestCanonicalWireNameDecodesEscapedDot(t *testing.T) {
	// `my\.host.example.` is ONE label "my.host" (7 bytes), not `my\`+`host`.
	want := []byte{7, 'm', 'y', '.', 'h', 'o', 's', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0}
	got := CanonicalWireName(`my\.host.example.`)
	if string(got) != string(want) {
		t.Fatalf("CanonicalWireName(`my\\.host.example.`) = %v, want %v", got, want)
	}
}

func TestCanonicalWireNameDecodesDecimalEscape(t *testing.T) {
	// `my\032host.example.` — \032 is a space octet inside one label (9 bytes).
	want := []byte{7, 'm', 'y', ' ', 'h', 'o', 's', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0}
	got := CanonicalWireName(`my\032host.example.`)
	if string(got) != string(want) {
		t.Fatalf("CanonicalWireName(`my\\032host.example.`) = %v, want %v", got, want)
	}
}

func TestCanonicalWireNameTrailingEscapedDotIsALabel(t *testing.T) {
	// `a\.` is the single label "a." (RFC 1035 §5.1: \. quotes the dot), so
	// the wire form is len=2 'a' '.' root — the trailing dot must NOT be
	// stripped as a root separator, and no backslash may leak into the wire.
	want := []byte{2, 'a', '.', 0}
	got := CanonicalWireName(`a\.`)
	if string(got) != string(want) {
		t.Fatalf("CanonicalWireName(`a\\.`) = %v, want %v", got, want)
	}
}

func TestCanonicalWireNameTrailingUnescapedDotStillTrimmed(t *testing.T) {
	// Control: an unescaped trailing dot is still the root separator, and an
	// even number of backslashes before it leaves it unescaped (`a\\` is the
	// label "a\", then the unescaped dot ends the name).
	for _, name := range []string{"a.", `a\\.`, `a\\\.`} {
		var want []byte
		switch name {
		case "a.":
			want = []byte{1, 'a', 0}
		case `a\\.`:
			want = []byte{2, 'a', '\\', 0}
		case `a\\\.`:
			// a, literal \ (\\), escaped dot (\.): one label "a\." plus root.
			want = []byte{3, 'a', '\\', '.', 0}
		}
		got := CanonicalWireName(name)
		if string(got) != string(want) {
			t.Fatalf("CanonicalWireName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestCanonicalWireNameDecodesEscapedBackslash(t *testing.T) {
	// `a\\b.example.` — \\ quotes one backslash: label is a,\,b (3 bytes).
	want := []byte{3, 'a', '\\', 'b', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0}
	got := CanonicalWireName(`a\\b.example.`)
	if string(got) != string(want) {
		t.Fatalf("CanonicalWireName(`a\\\\b.example.`) = %v, want %v", got, want)
	}
}

func TestCanonicalWireNameLowercasesEscapedAndPlainLetters(t *testing.T) {
	want := []byte{7, 'm', 'y', '.', 'h', 'o', 's', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0}
	got := CanonicalWireName(`MY\.HOST.EXAMPLE.`)
	if string(got) != string(want) {
		t.Fatalf("CanonicalWireName(`MY\\.HOST.EXAMPLE.`) = %v, want %v", got, want)
	}
}

func TestCanonicalWireNameEscapesYieldValidWireLabels(t *testing.T) {
	// The produced wire form must decode back to exactly the two labels the
	// escaped presentation text denotes.
	wire := CanonicalWireName(`my\.host.example.`)
	var labels []string
	forEachWireLabel(wire, func(label []byte) bool {
		labels = append(labels, string(label))
		return true
	})
	if len(labels) != 2 || labels[0] != "my.host" || labels[1] != "example" {
		t.Fatalf("wire labels = %q, want [my.host example]", labels)
	}
}

// Controls: unaffected inputs must keep their pre-fix canonical encodings.
func TestCanonicalWireNameControls(t *testing.T) {
	tests := []struct {
		in   string
		want []byte
	}{
		{".", []byte{0}},
		{"", []byte{0}},
		{"EXAMPLE.COM.", []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}},
		{"www.Example.COM.", []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}},
		{"a.b.c.", []byte{1, 'a', 1, 'b', 1, 'c', 0}},
	}
	for _, tt := range tests {
		if got := CanonicalWireName(tt.in); string(got) != string(tt.want) {
			t.Errorf("CanonicalWireName(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
