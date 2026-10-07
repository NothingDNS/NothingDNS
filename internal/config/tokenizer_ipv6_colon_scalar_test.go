package config

import (
	"strings"
	"testing"
)

// TestTokenizer_IPv6DoubleColonScalar covers F577: an unquoted IPv6 address
// ending in "::" ("::", "fe80::", "2001:db8::") must stay one plain scalar.
// The trailing colon used to be taken as a mapping indicator, so "- ::"
// became the mapping {":": null} and silently dropped out of server.bind.
// Ordinary mapping indicators must be unaffected.
func TestTokenizer_IPv6DoubleColonScalar(t *testing.T) {
	cases := []struct{ in, want string }{
		{"bind:\n  - ::\n", `{bind: ["::"]}`},
		{"bind: ::\n", `{bind: "::"}`},
		{"bind:\n  - 0.0.0.0\n  - ::\n  - fe80::\n  - 2001:db8::\n", `{bind: ["0.0.0.0", "::", "fe80::", "2001:db8::"]}`},
		{"bind:\n  - ::   # any\nport: 53\n", `{bind: ["::"], port: "53"}`},
		{"bind: [::, \"::1\", fe80::]\n", `{bind: ["::", "::1", "fe80::"]}`},
		{"m: {a: ::, b: c}\n", `{m: {a: "::", b: "c"}}`},
		{"a:\n  b: ::\n  c: 1\nd: x\n", `{a: {b: "::", c: "1"}, d: "x"}`},
		{"nets: [::/0, ::1, ::ffff:1.2.3.4]\n", `{nets: ["::/0", "::1", "::ffff:1.2.3.4"]}`},
		// unchanged mapping indicators
		{"key: value\nempty:\nn: {a: b}\nt: 10:30\n", `{key: "value", empty: "", n: {a: "b"}, t: "10:30"}`},
		{"a:\n  b:\nc: ::1\n", `{a: {b: ""}, c: "::1"}`},
	}
	for _, c := range cases {
		n, err := NewParser(c.in).ParseMapping()
		if err != nil {
			t.Errorf("%q: unexpected error %v", c.in, err)
			continue
		}
		if got := dumpTokenizerTestNode(n); got != c.want {
			t.Errorf("%q:\n got  %s\n want %s", c.in, got, c.want)
		}
	}
}

func TestUnmarshalYAML_BareIPv6AnyBind(t *testing.T) {
	for in, want := range map[string]string{
		"server:\n  bind:\n    - ::\n":                "::",
		"server:\n  bind: ::\n":                       "::",
		"server:\n  bind:\n    - 0.0.0.0\n    - ::\n": "0.0.0.0,::",
		"server:\n  bind: [::]\n":                     "::",
		"server:\n  bind:\n    - \"::\"\n":            "::",
		"server:\n  bind:\n    - \"[::]:53\"\n":       "[::]:53",
		"server:\n  bind:\n    - ::ffff:1.2.3.4\n":    "::ffff:1.2.3.4",
	} {
		cfg, err := UnmarshalYAML(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got := strings.Join(cfg.Server.Bind, ","); got != want {
			t.Errorf("%q: server.bind = %q, want %q", in, got, want)
		}
	}
}
