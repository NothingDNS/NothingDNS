package zone

import (
	"fmt"
	"strings"
	"testing"
)

func TestGenerateBasic(t *testing.T) {
	input := `$ORIGIN example.com.
$TTL 300
$GENERATE 1-5 host$ A 10.0.0.$
`
	z, err := ParseFile("test.zone", strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	for i := 1; i <= 5; i++ {
		name := fqdn(t, "host%d", i)
		recs := z.Lookup(name, "A")
		if len(recs) == 0 {
			t.Errorf("missing record for %s", name)
			continue
		}
		want := rdata(t, "10.0.0.%d", i)
		if recs[0].RData != want {
			t.Errorf("%s RData = %q, want %q", name, recs[0].RData, want)
		}
	}
}

func TestGenerateStep(t *testing.T) {
	input := `$ORIGIN example.com.
$TTL 300
$GENERATE 0-10/5 host$ A 10.0.0.$
`
	z, err := ParseFile("test.zone", strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Should have records for 0, 5, 10
	expected := []int{0, 5, 10}
	for _, i := range expected {
		name := fqdn(t, "host%d", i)
		recs := z.Lookup(name, "A")
		if len(recs) == 0 {
			t.Errorf("missing record for %s", name)
		}
	}

	// Should NOT have records for 1, 2, 3, 4
	for i := 1; i <= 4; i++ {
		name := fqdn(t, "host%d", i)
		recs := z.Lookup(name, "A")
		if len(recs) != 0 {
			t.Errorf("unexpected record for %s", name)
		}
	}
}

func TestGeneratePTR(t *testing.T) {
	input := `$ORIGIN 0.168.192.in-addr.arpa.
$TTL 86400
$GENERATE 1-3 $ PTR host-$.example.com.
`
	z, err := ParseFile("test.zone", strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	for i := 1; i <= 3; i++ {
		name := intToStr(i) + ".0.168.192.in-addr.arpa."
		recs := z.Lookup(name, "PTR")
		if len(recs) == 0 {
			t.Errorf("missing PTR for %s", name)
			continue
		}
		want := "host-" + intToStr(i) + ".example.com."
		if recs[0].RData != want {
			t.Errorf("%s RData = %q, want %q", name, recs[0].RData, want)
		}
	}
}

func TestGenerateWithModifier(t *testing.T) {
	input := `$ORIGIN example.com.
$TTL 300
$GENERATE 1-3 host${0,3,d} A 10.0.0.$
`
	z, err := ParseFile("test.zone", strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// ${0,3,d} means offset=0, width=3, decimal => 001, 002, 003
	names := []string{
		"host001.example.com.",
		"host002.example.com.",
		"host003.example.com.",
	}
	for _, name := range names {
		recs := z.Lookup(name, "A")
		if len(recs) == 0 {
			t.Errorf("missing record for %s", name)
		}
	}
}

func TestGenerateWithOffset(t *testing.T) {
	input := `$ORIGIN example.com.
$TTL 300
$GENERATE 1-3 host$ A 10.0.${100,0,d}.$
`
	z, err := ParseFile("test.zone", strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// ${100,0,d} adds offset 100, so iter 1 -> 101, 2 -> 102, 3 -> 103
	tests := []struct {
		iter int
		want string
	}{
		{1, "10.0.101.1"},
		{2, "10.0.102.2"},
		{3, "10.0.103.3"},
	}
	for _, tt := range tests {
		name := fqdn(t, "host%d", tt.iter)
		recs := z.Lookup(name, "A")
		if len(recs) == 0 {
			t.Errorf("missing record for %s", name)
			continue
		}
		if recs[0].RData != tt.want {
			t.Errorf("%s RData = %q, want %q", name, recs[0].RData, tt.want)
		}
	}
}

func TestGenerateHexRadix(t *testing.T) {
	input := `$ORIGIN example.com.
$TTL 300
$GENERATE 10-12 host-${0,2,x} CNAME node-$.example.com.
`
	z, err := ParseFile("test.zone", strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// 10=0a, 11=0b, 12=0c
	names := []string{
		"host-0a.example.com.",
		"host-0b.example.com.",
		"host-0c.example.com.",
	}
	for _, name := range names {
		recs := z.Lookup(name, "CNAME")
		if len(recs) == 0 {
			t.Errorf("missing record for %s", name)
		}
	}
}

func TestGenerateOctalRadix(t *testing.T) {
	input := `$ORIGIN example.com.
$TTL 300
$GENERATE 8-10 host-${0,3,o} A 10.0.0.$
`
	z, err := ParseFile("test.zone", strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// 8=010, 9=011, 10=012
	names := []string{
		"host-010.example.com.",
		"host-011.example.com.",
		"host-012.example.com.",
	}
	for _, name := range names {
		recs := z.Lookup(name, "A")
		if len(recs) == 0 {
			t.Errorf("missing record for %s", name)
		}
	}
}

func TestGenerateErrorNoArgs(t *testing.T) {
	input := `$ORIGIN example.com.
$GENERATE
`
	_, err := ParseFile("test.zone", strings.NewReader(input))
	if err == nil {
		t.Error("expected error for $GENERATE with no arguments")
	}
}

func TestGenerateErrorBadRange(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"no dash", "$ORIGIN example.com.\n$GENERATE 10 host$ A 10.0.0.$\n"},
		{"bad start", "$ORIGIN example.com.\n$GENERATE abc-10 host$ A 10.0.0.$\n"},
		{"bad stop", "$ORIGIN example.com.\n$GENERATE 1-xyz host$ A 10.0.0.$\n"},
		{"start > stop", "$ORIGIN example.com.\n$GENERATE 10-5 host$ A 10.0.0.$\n"},
		{"bad step", "$ORIGIN example.com.\n$GENERATE 1-10/0 host$ A 10.0.0.$\n"},
		{"negative step", "$ORIGIN example.com.\n$GENERATE 1-10/-1 host$ A 10.0.0.$\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseFile("test.zone", strings.NewReader(tt.input))
			if err == nil {
				t.Errorf("expected error for %s", tt.name)
			}
		})
	}
}

func TestGenerateTooFewArgs(t *testing.T) {
	input := `$ORIGIN example.com.
$GENERATE 1-5 host$ A
`
	// 3 args after range: "host$" "A" — that's only lhs type, missing rhs
	// This should still attempt to parse and might produce records with empty rdata
	// or may error depending on parseRecord behavior
	_, err := ParseFile("test.zone", strings.NewReader(input))
	// Either way, it shouldn't panic
	_ = err
}

func TestGenerateLargeRange(t *testing.T) {
	input := `$ORIGIN example.com.
$TTL 60
$GENERATE 1-254 $ PTR host-$.example.com.
`
	z, err := ParseFile("test.zone", strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Verify first, middle, and last
	for _, i := range []int{1, 127, 254} {
		name := fqdn(t, "%d", i)
		recs := z.Lookup(name, "PTR")
		if len(recs) == 0 {
			t.Errorf("missing PTR for %s", name)
		}
	}
}

func TestParseGenerateRange(t *testing.T) {
	tests := []struct {
		input      string
		start, stop, step int
		wantErr    bool
	}{
		{"1-10", 1, 10, 1, false},
		{"0-255", 0, 255, 1, false},
		{"1-100/10", 1, 100, 10, false},
		{"5-5", 5, 5, 1, false},
		{"10-5", 0, 0, 0, true},
		{"abc-10", 0, 0, 0, true},
		{"1-abc", 0, 0, 0, true},
		{"1-10/0", 0, 0, 0, true},
		{"1-10/abc", 0, 0, 0, true},
		{"nope", 0, 0, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			start, stop, step, err := parseGenerateRange(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if start != tt.start || stop != tt.stop || step != tt.step {
					t.Errorf("got (%d,%d,%d), want (%d,%d,%d)",
						start, stop, step, tt.start, tt.stop, tt.step)
				}
			}
		})
	}
}

func TestExpandGenerate(t *testing.T) {
	tests := []struct {
		template string
		iter     int
		want     string
	}{
		{"host$", 5, "host5"},
		{"host$.example.com.", 42, "host42.example.com."},
		{"10.0.0.$", 100, "10.0.0.100"},
		{"${0,3,d}", 5, "005"},
		{"${10,0,d}", 5, "15"},
		{"${0,2,x}", 255, "ff"},
		{"${0,4,o}", 8, "0010"},
		{"host${0,3,d}.example.com.", 7, "host007.example.com."},
		{"no-dollar-here", 1, "no-dollar-here"},
		{"$$", 3, "33"},
	}
	for _, tt := range tests {
		t.Run(tt.template, func(t *testing.T) {
			got := expandGenerate(tt.template, tt.iter)
			if got != tt.want {
				t.Errorf("expandGenerate(%q, %d) = %q, want %q",
					tt.template, tt.iter, got, tt.want)
			}
		})
	}
}

func TestApplyGenerateModifier(t *testing.T) {
	tests := []struct {
		iter     int
		modifier string
		want     string
	}{
		{5, "0,0,d", "5"},
		{5, "10,0,d", "15"},
		{5, "0,3,d", "005"},
		{10, "0,2,x", "0a"},
		{8, "0,3,o", "010"},
		{1, ",,", "1"},
		{5, "", "5"},
	}
	for _, tt := range tests {
		t.Run(tt.modifier, func(t *testing.T) {
			got := applyGenerateModifier(tt.iter, tt.modifier)
			if got != tt.want {
				t.Errorf("applyGenerateModifier(%d, %q) = %q, want %q",
					tt.iter, tt.modifier, got, tt.want)
			}
		})
	}
}

// helpers

func fqdn(t *testing.T, format string, args ...interface{}) string {
	t.Helper()
	return strings.ToLower(fmt.Sprintf(format, args...) + ".example.com.")
}

func rdata(t *testing.T, format string, args ...interface{}) string {
	t.Helper()
	return fmt.Sprintf(format, args...)
}

func intToStr(v int) string {
	return fmt.Sprintf("%d", v)
}
