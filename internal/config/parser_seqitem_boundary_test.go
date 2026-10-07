package config

import (
	"fmt"
	"strings"
	"testing"
)

func dumpNodeTree(n *Node) string {
	if n == nil {
		return "<nil>"
	}
	switch n.Type {
	case NodeScalar:
		return fmt.Sprintf("%q", n.Value)
	case NodeSequence:
		parts := make([]string, 0, len(n.Children))
		for _, c := range n.Children {
			parts = append(parts, dumpNodeTree(c))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case NodeMapping:
		parts := make([]string, 0, len(n.Children)/2)
		for i := 0; i+1 < len(n.Children); i += 2 {
			parts = append(parts, n.Children[i].Value+": "+dumpNodeTree(n.Children[i+1]))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return "?"
}

// TestParser_SequenceItemBoundaries pins where block-sequence item mappings
// and block sequences end. Each case used to parse silently into the wrong
// tree (or reject valid YAML):
//
//   - F177: a key after an item whose last value is a nested block mapping
//     was absorbed into the item (a top-level `acl:` after a geodns rule's
//     `records:` map vanished).
//   - F178: `key:` with an empty value followed by a sibling at the same
//     column nested the sibling under it; as the item's first key it was
//     rejected outright.
//   - F179: a non-key line inside an item mapping was silently dropped.
//   - F180: an inner sequence swallowed the enclosing sequence's next item.
//   - F181: `-` alone followed by the next item became a nested sequence.
func TestParser_SequenceItemBoundaries(t *testing.T) {
	tests := []struct {
		name, src, want string
	}{
		{"F177 top-level key after nested map", "servers:\n  - name: a\n    opts:\n      x: 1\nother: 2\n",
			`{servers: [{name: "a", opts: {x: "1"}}], other: "2"}`},
		{"F177 dash-newline item", "servers:\n  -\n    name: a\n    opts:\n      x: 1\nother: 2\n",
			`{servers: [{name: "a", opts: {x: "1"}}], other: "2"}`},
		{"F177 parent sibling", "a:\n  b:\n    - name: x\n      sub:\n        k: v\n  c: 3\n",
			`{a: {b: [{name: "x", sub: {k: "v"}}], c: "3"}}`},
		{"F177 item key after nested map", "a:\n  - k: v\n    s:\n      x: 1\n    m: 2\nb: 1\n",
			`{a: [{k: "v", s: {x: "1"}, m: "2"}], b: "1"}`},
		{"F177 misaligned item key", "a:\n  - k: v\n   m: n\nz: 1\n", "ERR"},
		{"F178 later empty key", "a:\n  - k: v\n    m:\n    n: 1\nz: 2\n",
			`{a: [{k: "v", m: "", n: "1"}], z: "2"}`},
		{"F178 first empty key", "a:\n  - k:\n    n: 1\nz: 2\n",
			`{a: [{k: "", n: "1"}], z: "2"}`},
		{"F178 first empty key then dedent", "a:\n  - k:\nz: 1\n", `{a: [{k: ""}], z: "1"}`},
		{"F178 first key nested map", "a:\n  - k:\n      x: 1\nz: 1\n", `{a: [{k: {x: "1"}}], z: "1"}`},
		{"F179 forgotten colon", "acl:\n  - name: deny-all\n    action deny\n", "ERR"},
		{"F180 inner sequence ends in nested map", "a:\n  -\n    - k: v\n      sub:\n        x: 1\n  - z\nb: 1\n",
			`{a: [[{k: "v", sub: {x: "1"}}], "z"], b: "1"}`},
		{"F181 empty middle item", "a:\n  - x\n  -\n  - y\nb: 1\n", `{a: ["x", "", "y"], b: "1"}`},
		{"control nested sequence", "a:\n  -\n    - x\n  - y\n", `{a: [["x"], "y"]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := NewParser(tt.src).ParseMapping()
			got := "ERR"
			if err == nil {
				got = dumpNodeTree(n)
			}
			if got != tt.want {
				t.Fatalf("parse mismatch\n got: %s\nwant: %s", got, tt.want)
			}
		})
	}
}

// TestUnmarshalYAML_ACLAfterGeoDNSRecordsMap is the config-level shape of
// F177: the ACL following a geodns rule's records map must not be lost.
func TestUnmarshalYAML_ACLAfterGeoDNSRecordsMap(t *testing.T) {
	src := "geodns:\n  enabled: true\n  rules:\n    - domain: geo.example.com.\n      type: A\n      records:\n        US: 192.0.2.20\n" +
		"acl:\n  - name: deny-all\n    networks:\n      - 0.0.0.0/0\n    action: deny\n"
	cfg, err := UnmarshalYAML(src)
	if err != nil {
		t.Fatalf("UnmarshalYAML: %v", err)
	}
	if len(cfg.ACL) != 1 || cfg.ACL[0].Action != "deny" {
		t.Fatalf("ACL = %+v, want one deny rule", cfg.ACL)
	}
	if len(cfg.GeoDNS.Rules) != 1 || cfg.GeoDNS.Rules[0].Records["US"] != "192.0.2.20" {
		t.Fatalf("GeoDNS rules = %+v", cfg.GeoDNS.Rules)
	}
}
