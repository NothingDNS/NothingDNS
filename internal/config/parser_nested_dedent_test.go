package config

import (
	"strings"
	"testing"
)

// TestParseMapping_KeyAfterNestedBlockSequence is the regression for a
// top-level section being swallowed into the wrong parent.
//
// The tokenizer pops its whole indent stack at once and only then emits one
// DEDENT per closed level, so the tokenizer's live indent already reads the
// final level while the first of several stacked DEDENTs is still being
// handled. parseMapping consumed exactly one DEDENT per frame and compared
// against that collapsed value, which came out right for one or two levels of
// nesting and wrong for three: a key returning to column 0 after a three-deep
// block sequence landed inside the section above it, and everything under it
// was silently dropped.
//
// `dnssec.signing.keys` is exactly that shape, so filling in the shipped
// example's signing keys lost whatever section followed `dnssec`.
func TestParseMapping_KeyAfterNestedBlockSequence(t *testing.T) {
	tests := []struct {
		name string
		src  []string
	}{
		{"sequence one level deep", []string{
			"items:",
			"  - a: 1",
			"    b: 2",
			"top: x",
		}},
		{"sequence two levels deep", []string{
			"outer:",
			"  items:",
			"    - a: 1",
			"      b: 2",
			"top: x",
		}},
		{"sequence three levels deep", []string{
			"outer:",
			"  mid:",
			"    items:",
			"      - a: 1",
			"        b: 2",
			"top: x",
		}},
		{"sequence four levels deep", []string{
			"o1:",
			"  o2:",
			"    o3:",
			"      items:",
			"        - a: 1",
			"          b: 2",
			"top: x",
		}},
		{"multiple items before the dedent", []string{
			"outer:",
			"  mid:",
			"    items:",
			"      - a: 1",
			"        b: 2",
			"      - a: 3",
			"        b: 4",
			"top: x",
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			node, err := NewParser(strings.Join(tc.src, "\n") + "\n").ParseMapping()
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if node.Get("top") == nil {
				t.Errorf("`top` is not at the document root; root keys = %v", node.Keys())
			}
			if v := node.GetString("top"); v != "x" {
				t.Errorf("top = %q, want \"x\"", v)
			}
		})
	}
}

// TestParseMapping_PartialDedentKeepsSibling: a key that dedents only part of
// the way belongs to the intermediate mapping, not the root.
func TestParseMapping_PartialDedentKeepsSibling(t *testing.T) {
	src := strings.Join([]string{
		"outer:",
		"  mid:",
		"    items:",
		"      - a: 1",
		"        b: 2",
		"  other: y",
		"top: x",
	}, "\n") + "\n"

	node, err := NewParser(src).ParseMapping()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if node.Get("top") == nil {
		t.Fatalf("`top` is not at the root; root keys = %v", node.Keys())
	}
	outer := node.Get("outer")
	if outer == nil {
		t.Fatal("`outer` missing")
	}
	if outer.GetString("other") != "y" {
		t.Errorf("`other` did not stay inside `outer`; outer keys = %v", outer.Keys())
	}
	if outer.Get("top") != nil {
		t.Error("`top` was absorbed into `outer`")
	}
}

// TestTokenizer_QuotedKeyColumn: a token's column is where it starts in the
// source. Reporting the first content character instead put a quoted key one
// column to the right of a plain key at the same indentation, which the
// column-based mapping boundary above would read as deeper nesting.
func TestTokenizer_QuotedKeyColumn(t *testing.T) {
	tk := NewTokenizer("\"quoted\": a\nplain: b\n")

	var cols []int
	for i := 0; i < 10; i++ {
		tok := tk.Next()
		if tok.Type == TokenEOF {
			break
		}
		if tok.Type == TokenString && (tok.Value == "quoted" || tok.Value == "plain") {
			cols = append(cols, tok.Col)
		}
	}
	if len(cols) != 2 {
		t.Fatalf("expected both keys, got columns %v", cols)
	}
	if cols[0] != cols[1] {
		t.Errorf("quoted key at column %d, plain key at column %d — same indentation must report the same column",
			cols[0], cols[1])
	}
}

// TestParseMapping_QuotedKeysStillParse guards the conformance case that the
// column change had to keep working.
func TestParseMapping_QuotedKeysStillParse(t *testing.T) {
	node, err := NewParser("\"complex:key\": value\nsimple: other\n").ParseMapping()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := node.GetString("complex:key"); got != "value" {
		t.Errorf("complex:key = %q, want \"value\"", got)
	}
	if got := node.GetString("simple"); got != "other" {
		t.Errorf("simple = %q, want \"other\"", got)
	}
}
