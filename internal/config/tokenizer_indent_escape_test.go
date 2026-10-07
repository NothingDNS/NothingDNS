package config

import (
	"fmt"
	"strings"
	"testing"
)

// dumpTokenizerTestNode renders a node tree compactly for comparison.
func dumpTokenizerTestNode(n *Node) string {
	if n == nil {
		return "<nil>"
	}
	switch n.Type {
	case NodeScalar:
		return fmt.Sprintf("%q", n.Value)
	case NodeSequence:
		parts := make([]string, 0, len(n.Children))
		for _, c := range n.Children {
			parts = append(parts, dumpTokenizerTestNode(c))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case NodeMapping:
		var parts []string
		for i := 0; i+1 < len(n.Children); i += 2 {
			parts = append(parts, n.Children[i].Value+": "+dumpTokenizerTestNode(n.Children[i+1]))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return "?"
}

// TestTokenizer_IndentationAndEscapes covers F182–F186: tabs in indentation,
// blank/comment lines holding tabs, the content column of a sequence item
// whose first key has a nested block value, YAML double-quoted escapes, and
// plain scalars with an inner sign. want "ERR" means the input must fail.
func TestTokenizer_IndentationAndEscapes(t *testing.T) {
	cases := []struct{ name, in, want string }{
		// F182: a tab-indented content line was silently re-nested.
		{"F182/tab after space-indented sibling", "server:\n  bind: [\"127.0.0.1\"]\n\tport: 5353\n", "ERR"},
		{"F182/tab as whole indentation", "server:\n\tport: 53\n", "ERR"},
		{"F182/control tab after dash", "a:\n  -\tx\n", `{a: ["x"]}`},
		// F183: blank and comment lines holding tabs are not content.
		{"F183/blank line with tab", "server:\n    port: 1\n  \t\n    bind: x\n", `{server: {port: "1", bind: "x"}}`},
		{"F183/tab-led comment", "server:\n    port: 1\n\t# note\n    bind: x\n", `{server: {port: "1", bind: "x"}}`},
		// F184: "- k:" + nested block, then the item's next key.
		{"F184/nested map then sibling", "r:\n  - k:\n      x: 1\n    m: n\n", `{r: [{k: {x: "1"}, m: "n"}]}`},
		{"F184/two items then parent sibling",
			"rules:\n  - records:\n      US: 1\n    domain: a\n  - domain: b\nacl: x\n",
			`{rules: [{records: {US: "1"}, domain: "a"}, {domain: "b"}], acl: "x"}`},
		{"F184/nested sequence then sibling", "r:\n  - k:\n      - 1\n    m: n\n", `{r: [{k: ["1"], m: "n"}]}`},
		{"F184/still rejects mapping mis-dedent", "a:\n    b: 1\n  c: 2\n", "ERR"},
		{"F184/still rejects stale item column", "x:\n  - k: 1\n  y:\n      n: 1\n    m: 2\n", "ERR"},
		// F185: YAML 1.2 double-quoted escapes.
		{"F185/unicode escapes", `a: "caf\u00e9 \x41 \U0001F600"`, `{a: "café A 😀"}`},
		{"F185/control escapes", `a: "\0\e\a\/\t\\\""`, `{a: "\x00\x1b\a/\t\\\""}`},
		{"F185/invalid escape rejected", `a: "C:\data"`, "ERR"},
		{"F185/surrogate rejected", `a: "\ud800"`, "ERR"},
		{"F185/single quotes keep backslash", `a: 'C:\data'`, `{a: "C:\\data"}`},
		// F186: an inner sign makes a plain scalar, not a split number.
		{"F186/date", "a: 2024-01-15\nb: 2\n", `{a: "2024-01-15", b: "2"}`},
		{"F186/range in flow", "a: [10-20, 3]\n", `{a: ["10-20", "3"]}`},
		{"F186/exponent still a number", "a: 5e-3\nb: -12\n", `{a: "5e-3", b: "-12"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n, err := NewParser(c.in).ParseMapping()
			got := dumpTokenizerTestNode(n)
			if err != nil {
				got = "ERR"
			}
			if got != c.want {
				t.Fatalf("input %q\nwant %s\ngot  %s (err=%v)", c.in, c.want, got, err)
			}
		})
	}
}

// TestUnmarshalYAML_GeoDNSRuleRecordsFirst is the config-level F184 shape:
// a geodns rule that lists its records map before its other keys.
func TestUnmarshalYAML_GeoDNSRuleRecordsFirst(t *testing.T) {
	cfg, err := UnmarshalYAML("geodns:\n  enabled: true\n  rules:\n    - records:\n        US: 192.0.2.1\n      domain: www.example.com\n      type: A\n      default: 192.0.2.9\n")
	if err != nil {
		t.Fatalf("UnmarshalYAML: %v", err)
	}
	r := cfg.GeoDNS.Rules
	if len(r) != 1 || r[0].Domain != "www.example.com" || r[0].Records["US"] != "192.0.2.1" || r[0].Default != "192.0.2.9" {
		t.Fatalf("rules = %+v", r)
	}
}
