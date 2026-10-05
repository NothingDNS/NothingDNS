package idna

import (
	"strings"
	"testing"
)

func TestToASCIIMappedASCII(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"K.example", "k.example"},
		{"KK.example", "kk.example"},
		{"AKB.example", "akb.example"},
		{"K.münchen", "k.xn--mnchen-3ya"},
		{"Ké.example", "xn--k-bga.example"},
		{strings.Repeat("K", 63) + ".example", strings.Repeat("k", 63) + ".example"},
		{"Example.COM", "Example.COM"},
	} {
		got, err := ToASCII(tc.input)
		if err != nil || got != tc.want {
			t.Errorf("ToASCII(%q) = %q, %v; want %q", tc.input, got, err, tc.want)
		}
	}
	if _, err := ToASCII(strings.Repeat("K", 64) + ".example"); err != ErrLabelTooLong {
		t.Errorf("64 mapped ASCII bytes: error = %v, want %v", err, ErrLabelTooLong)
	}
}
