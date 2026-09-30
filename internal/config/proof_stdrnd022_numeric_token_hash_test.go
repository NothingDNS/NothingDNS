package config

import "testing"

func TestNumericTokenHashIsLiteral(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"int glued hash", "k: 123#abc\n", "123#abc"},
		{"float glued hash", "k: 1.5#x\n", "1.5#x"},
		{"signed glued hash", "k: -7#tag\n", "-7#tag"},
		{"signed plain", "k: -5353\n", "-5353"},
		{"int plain", "k: 5353\n", "5353"},
		{"hash after space", "k: 123 #n\n", "123"},
		{"bare dash scalar", "k: -abc\n", "-abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, err := NewParser(tc.in).ParseMapping()
			if err != nil {
				t.Fatalf("ParseMapping(%q): %v", tc.in, err)
			}
			if len(root.Children) < 2 {
				t.Fatalf("no value from %q", tc.in)
			}
			if got := root.Children[1].Value; got != tc.want {
				t.Errorf("value = %q, want %q", got, tc.want)
			}
		})
	}
}

// Controls: block sequences and nested maps must keep parsing.
func TestDashDispatchKeepsBlockSequences(t *testing.T) {
	root, err := NewParser("list:\n  - a\n  - b\n").ParseMapping()
	if err != nil {
		t.Fatalf("block sequence: %v", err)
	}
	l := root.Get("list")
	if l == nil || len(l.Children) != 2 {
		t.Fatalf("block sequence broken: %#v", l)
	}
	if l.Children[0].Value != "a" || l.Children[1].Value != "b" {
		t.Fatalf("items wrong: %q %q", l.Children[0].Value, l.Children[1].Value)
	}
}
