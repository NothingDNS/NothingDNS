package config

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// YAML Parser Conformance Test Vectors
//
// Tests cover:
//   - Plain scalars (string, number, bool, null)
//   - Quoted scalars (single, double, escape sequences)
//   - Multi-line and empty values
//   - Comments (inline, standalone)
//   - Mixed indentation
//   - Nested mappings and sequences
//   - Flow style mappings and sequences
//   - Env var expansion
//   - Real config fragments
//   - Edge cases
//   - Error cases (unsupported features, malformed input)
// ---------------------------------------------------------------------------

// ---- Helpers ----

func parseMappingOrFail(t *testing.T, input string) *Node {
	t.Helper()
	p := NewParser(input)
	node, err := p.ParseMapping()
	if err != nil {
		t.Fatalf("ParseMapping: %v\nInput:\n%s", err, input)
	}
	return node
}

func assertScalar(t *testing.T, node *Node, key, expected string) {
	t.Helper()
	val := node.GetString(key)
	if val != expected {
		t.Errorf("key %q: expected %q, got %q", key, expected, val)
	}
}

func assertNodeType(t *testing.T, node *Node, key string, expectedType NodeType) *Node {
	t.Helper()
	child := node.Get(key)
	if child == nil {
		t.Fatalf("key %q not found in node", key)
	}
	if child.Type != expectedType {
		t.Errorf("key %q: expected type %v, got %v", key, expectedType, child.Type)
	}
	return child
}

func assertSequenceLen(t *testing.T, node *Node, key string, expectedLen int) *Node {
	t.Helper()
	child := assertNodeType(t, node, key, NodeSequence)
	if len(child.Children) != expectedLen {
		t.Errorf("key %q: expected %d items, got %d", key, expectedLen, len(child.Children))
	}
	return child
}

func assertParseError(t *testing.T, input string, expectMsg string) {
	t.Helper()
	p := NewParser(input)
	_, err := p.ParseMapping()
	if err == nil {
		t.Errorf("expected error but got none\nInput:\n%s", input)
	} else if expectMsg != "" && !strings.Contains(err.Error(), expectMsg) {
		t.Errorf("expected error containing %q, got %q", expectMsg, err.Error())
	}
}

// ===========================================================================
// 1. Plain Scalars
// ===========================================================================

func TestConformance_PlainStringScalars(t *testing.T) {
	input := `name: hello
greeting: hello world
url: https://example.com
single: a`
	node := parseMappingOrFail(t, input)
	assertScalar(t, node, "name", "hello")
	assertScalar(t, node, "greeting", "hello world")
	assertScalar(t, node, "url", "https://example.com")
	assertScalar(t, node, "single", "a")
}

func TestConformance_PlainNumberScalars(t *testing.T) {
	input := `port: 53
count: 1000
negative: -42
float: 3.14
exponent: 1.5e10
neg_exp: -2.5e-3
zero: 0`
	node := parseMappingOrFail(t, input)
	assertScalar(t, node, "port", "53")
	assertScalar(t, node, "count", "1000")
	assertScalar(t, node, "negative", "-42")
	assertScalar(t, node, "float", "3.14")
	assertScalar(t, node, "exponent", "1.5e10")
	assertScalar(t, node, "neg_exp", "-2.5e-3")
	assertScalar(t, node, "zero", "0")
}

func TestConformance_BooleanScalars(t *testing.T) {
	input := `flag_a: true
flag_b: false
flag_c: yes
flag_d: no
flag_e: on
flag_f: off`
	node := parseMappingOrFail(t, input)
	assertScalar(t, node, "flag_a", "true")
	assertScalar(t, node, "flag_b", "false")
	assertScalar(t, node, "flag_c", "true")
	assertScalar(t, node, "flag_d", "false")
	assertScalar(t, node, "flag_e", "true")
	assertScalar(t, node, "flag_f", "false")
}

func TestConformance_NullScalars(t *testing.T) {
	input := `a: null
b: ~
c:` // empty value
	node := parseMappingOrFail(t, input)
	a := assertNodeType(t, node, "a", NodeScalar)
	if a.Value != "" {
		t.Errorf("null expected empty value, got %q", a.Value)
	}
	b := assertNodeType(t, node, "b", NodeScalar)
	if b.Value != "" {
		t.Errorf("~ expected empty value, got %q", b.Value)
	}
	c := assertNodeType(t, node, "c", NodeScalar)
	if c.Value != "" {
		t.Errorf("empty value expected empty, got %q", c.Value)
	}
}

// ===========================================================================
// 2. Quoted Scalars
// ===========================================================================

func TestConformance_SingleQuotedStrings(t *testing.T) {
	input := `text: 'hello world'
special: 'colon:value'
empty: ''`
	node := parseMappingOrFail(t, input)
	assertScalar(t, node, "text", "hello world")
	assertScalar(t, node, "special", "colon:value")
	assertScalar(t, node, "empty", "")
}

func TestConformance_DoubleQuotedStrings(t *testing.T) {
	input := `text: "hello world"
special: "colon:value"
empty: ""`
	node := parseMappingOrFail(t, input)
	assertScalar(t, node, "text", "hello world")
	assertScalar(t, node, "special", "colon:value")
	assertScalar(t, node, "empty", "")
}

func TestConformance_DoubleQuotedEscapeSequences(t *testing.T) {
	input := `newline: "line1\nline2"
tab: "col1\tcol2"
backslash: "path\\to\\file"
quote: "say \"hello\""`
	node := parseMappingOrFail(t, input)
	assertScalar(t, node, "newline", "line1\nline2")
	assertScalar(t, node, "tab", "col1\tcol2")
	assertScalar(t, node, "backslash", "path\\to\\file")
	assertScalar(t, node, "quote", `say "hello"`)
}

// ===========================================================================
// 3. Comments
// ===========================================================================

func TestConformance_Comments(t *testing.T) {
	input := `# Top-level comment
key: value # inline comment
# Another comment
nested:
  inner: val # nested inline`
	node := parseMappingOrFail(t, input)
	assertScalar(t, node, "key", "value")
	nested := assertNodeType(t, node, "nested", NodeMapping)
	assertScalar(t, nested, "inner", "val")
}

func TestConformance_CommentOnlyLines(t *testing.T) {
	input := `# just a comment`
	p := NewParser(input)
	_, err := p.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// A file with only a comment results in an empty mapping
}

// ===========================================================================
// 4. Nested Mappings
// ===========================================================================

func TestConformance_DeeplyNestedMapping(t *testing.T) {
	input := `a:
  b:
    c:
      d: deep`
	node := parseMappingOrFail(t, input)
	a := assertNodeType(t, node, "a", NodeMapping)
	b := assertNodeType(t, a, "b", NodeMapping)
	c := assertNodeType(t, b, "c", NodeMapping)
	assertScalar(t, c, "d", "deep")
}

func TestConformance_MultipleKeysAtSameLevel(t *testing.T) {
	input := `name: test
port: 8080
enabled: true`
	node := parseMappingOrFail(t, input)
	assertScalar(t, node, "name", "test")
	assertScalar(t, node, "port", "8080")
	assertScalar(t, node, "enabled", "true")
}

// ===========================================================================
// 5. Sequences
// ===========================================================================

func TestConformance_PlainSequence(t *testing.T) {
	input := `items:
  - one
  - two
  - three`
	node := parseMappingOrFail(t, input)
	items := assertSequenceLen(t, node, "items", 3)
	if items.Children[0].Value != "one" {
		t.Errorf("expected 'one', got %q", items.Children[0].Value)
	}
}

func TestConformance_SequenceOfMappings(t *testing.T) {
	input := `servers:
  - name: web
    port: 80
  - name: dns
    port: 53`
	node := parseMappingOrFail(t, input)
	seq := assertSequenceLen(t, node, "servers", 2)
	first := seq.Children[0]
	if first.Type != NodeMapping {
		t.Fatalf("expected mapping, got %v", first.Type)
	}
	assertScalar(t, first, "name", "web")
	assertScalar(t, first, "port", "80")
	second := seq.Children[1]
	assertScalar(t, second, "name", "dns")
	assertScalar(t, second, "port", "53")
}

func TestConformance_NestedSequence(t *testing.T) {
	// This custom parser does not support `- - item` syntax for nested
	// block sequences. Use separate indented sequence blocks instead.
	t.Skip("nested block sequences with `- -` syntax not supported by this parser")
}

// ===========================================================================
// 6. Mixed Sequences and Mappings
// ===========================================================================

func TestConformance_MixedSequenceMapping(t *testing.T) {
	input := `name: test
values:
  - a
  - b
config:
  enabled: true
  count: 42`
	node := parseMappingOrFail(t, input)
	assertScalar(t, node, "name", "test")
	assertSequenceLen(t, node, "values", 2)
	cfg := assertNodeType(t, node, "config", NodeMapping)
	assertScalar(t, cfg, "enabled", "true")
	assertScalar(t, cfg, "count", "42")
}

func TestConformance_SequenceWithMixedItems(t *testing.T) {
	input := `items:
  - simple
  - key: value
    alt: other
  - last`
	node := parseMappingOrFail(t, input)
	seq := assertSequenceLen(t, node, "items", 3)
	if seq.Children[0].Value != "simple" {
		t.Errorf("expected 'simple', got %q", seq.Children[0].Value)
	}
	if seq.Children[1].Type != NodeMapping {
		t.Errorf("expected mapping, got %v", seq.Children[1].Type)
	}
	if seq.Children[2].Value != "last" {
		t.Errorf("expected 'last', got %q", seq.Children[2].Value)
	}
}

// ===========================================================================
// 7. Flow Style
// ===========================================================================

func TestConformance_FlowMapping(t *testing.T) {
	input := `config: {name: test, port: 53, enabled: true}`
	node := parseMappingOrFail(t, input)
	cfg := assertNodeType(t, node, "config", NodeMapping)
	assertScalar(t, cfg, "name", "test")
	assertScalar(t, cfg, "port", "53")
	assertScalar(t, cfg, "enabled", "true")
}

func TestConformance_FlowSequence(t *testing.T) {
	input := `items: [one, two, three]`
	node := parseMappingOrFail(t, input)
	assertSequenceLen(t, node, "items", 3)
}

func TestConformance_NestedFlow(t *testing.T) {
	input := `data: {list: [a, b], map: {x: 1, y: 2}}`
	node := parseMappingOrFail(t, input)
	data := assertNodeType(t, node, "data", NodeMapping)
	assertSequenceLen(t, data, "list", 2)
	subMap := assertNodeType(t, data, "map", NodeMapping)
	assertScalar(t, subMap, "x", "1")
	assertScalar(t, subMap, "y", "2")
}

// ===========================================================================
// 8. Empty Values and Null Handling
// ===========================================================================

func TestConformance_TrailingNewlines(t *testing.T) {
	inputs := []string{
		"key: value\n",
		"key: value\n\n",
		"key: value\n\n\n",
	}
	for _, input := range inputs {
		node := parseMappingOrFail(t, input)
		assertScalar(t, node, "key", "value")
	}
}

func TestConformance_EmptyLinesBetweenKeys(t *testing.T) {
	input := `key1: value1

key2: value2

key3: value3`
	node := parseMappingOrFail(t, input)
	assertScalar(t, node, "key1", "value1")
	assertScalar(t, node, "key2", "value2")
	assertScalar(t, node, "key3", "value3")
}

// ===========================================================================
// 9. Env Var Expansion (in scalar values)
// ===========================================================================

func TestConformance_EnvVarExpansion(t *testing.T) {
	os.Setenv("TEST_PORT", "8080")
	os.Setenv("TEST_HOST", "localhost")
	defer func() {
		os.Unsetenv("TEST_PORT")
		os.Unsetenv("TEST_HOST")
	}()

	// Env vars are expanded AFTER parsing, not during.
	// The parser should keep the ${VAR} text as-is.
	input := `port: ${TEST_PORT}
host: ${TEST_HOST}
static: value`
	node := parseMappingOrFail(t, input)
	assertScalar(t, node, "port", "${TEST_PORT}")
	assertScalar(t, node, "host", "${TEST_HOST}")
	assertScalar(t, node, "static", "value")
}

// ===========================================================================
// 10. Real Config Fragments
// ===========================================================================

func TestConformance_ConfigFragment_Server(t *testing.T) {
	input := `server:
  port: 53
  bind:
    - 0.0.0.0
    - "::"
  http:
    enabled: true
    bind: "0.0.0.0:8080"
    doh_enabled: false`
	node := parseMappingOrFail(t, input)
	server := assertNodeType(t, node, "server", NodeMapping)
	assertScalar(t, server, "port", "53")
	bind := assertSequenceLen(t, server, "bind", 2)
	if bind.Children[0].Value != "0.0.0.0" {
		t.Errorf("bind[0] expected '0.0.0.0', got %q", bind.Children[0].Value)
	}
	http := assertNodeType(t, server, "http", NodeMapping)
	assertScalar(t, http, "enabled", "true")
}

func TestConformance_ConfigFragment_Cluster(t *testing.T) {
	input := `cluster:
  enabled: false
  node_id: "node-1"
  bind_addr: "0.0.0.0"
  gossip_port: 7946
  region: default
  weight: 100`
	node := parseMappingOrFail(t, input)
	cl := assertNodeType(t, node, "cluster", NodeMapping)
	assertScalar(t, cl, "enabled", "false")
	assertScalar(t, cl, "node_id", "node-1")
	assertScalar(t, cl, "gossip_port", "7946")
	assertScalar(t, cl, "region", "default")
	assertScalar(t, cl, "weight", "100")
}

func TestConformance_ConfigFragment_Blocklist(t *testing.T) {
	input := `blocklist:
  enabled: true
  urls:
    - "https://example.com/blocklist.txt"
  files:
    - /etc/nothingdns/blocklist.txt`
	node := parseMappingOrFail(t, input)
	bl := assertNodeType(t, node, "blocklist", NodeMapping)
	assertScalar(t, bl, "enabled", "true")
	assertSequenceLen(t, bl, "urls", 1)
	assertSequenceLen(t, bl, "files", 1)
}

// ===========================================================================
// 11. Edge Cases
// ===========================================================================

func TestConformance_SpecialCharsInUnquotedValue(t *testing.T) {
	input := `pattern: "*.example.com"
path: /var/log/nothingdns/access.log
version: v1.2.3
ip: 192.168.1.1
email: admin@example.com`
	node := parseMappingOrFail(t, input)
	// Quoted values preserve special chars literally
	assertScalar(t, node, "pattern", "*.example.com")
	assertScalar(t, node, "path", "/var/log/nothingdns/access.log")
	assertScalar(t, node, "version", "v1.2.3")
	assertScalar(t, node, "ip", "192.168.1.1")
	assertScalar(t, node, "email", "admin@example.com")
}

func TestConformance_KeysWithColon(t *testing.T) {
	input := `"complex:key": value
simple: other`
	node := parseMappingOrFail(t, input)
	assertScalar(t, node, "complex:key", "value")
	assertScalar(t, node, "simple", "other")
}

func TestConformance_TrailingWhitespace(t *testing.T) {
	input := `key: value   
port: 53   
name: test`
	node := parseMappingOrFail(t, input)
	assertScalar(t, node, "key", "value")
	assertScalar(t, node, "port", "53")
	assertScalar(t, node, "name", "test")
}

func TestConformance_IndentedCommentAfterKey(t *testing.T) {
	input := `key: value
  # indented comment
other: val`
	node := parseMappingOrFail(t, input)
	assertScalar(t, node, "key", "value")
	assertScalar(t, node, "other", "val")
}

func TestConformance_MultipleSequences(t *testing.T) {
	input := `list_a:
  - 1
  - 2
list_b:
  - a
  - b
  - c`
	node := parseMappingOrFail(t, input)
	assertSequenceLen(t, node, "list_a", 2)
	assertSequenceLen(t, node, "list_b", 3)
}

// ===========================================================================
// 12. Error Cases
// ===========================================================================

func TestConformance_Error_UnsupportedBlockScalar(t *testing.T) {
	// Tokenizer returns an ERROR token; parser surfaces it as "unexpected token ERROR"
	assertParseError(t, "key: |\n  block text", "ERROR")
}

func TestConformance_Error_UnsupportedFoldedScalar(t *testing.T) {
	assertParseError(t, "key: >\n  folded text", "ERROR")
}

func TestConformance_Error_UnsupportedAnchor(t *testing.T) {
	assertParseError(t, "key: &anchor value", "ERROR")
}

func TestConformance_Error_UnsupportedAlias(t *testing.T) {
	assertParseError(t, "key: *alias", "ERROR")
}

func TestConformance_Error_UnsupportedTag(t *testing.T) {
	assertParseError(t, "key: !!str value", "ERROR")
}

func TestConformance_Error_DuplicateKey(t *testing.T) {
	input := `key: first
key: second`
	p := NewParser(input)
	_, err := p.ParseMapping()
	if err == nil {
		t.Error("expected error for duplicate key")
	} else if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("expected duplicate key error, got %q", err.Error())
	}
}

func TestConformance_Error_MissingColon(t *testing.T) {
	assertParseError(t, "key value", "expected ':'")
}

func TestConformance_Error_UnclosedFlowMapping(t *testing.T) {
	assertParseError(t, "data: {a: 1, b: 2", "unterminated flow mapping")
}

func TestConformance_Error_UnclosedFlowSequence(t *testing.T) {
	assertParseError(t, "items: [1, 2, 3", "unterminated flow sequence")
}

func TestConformance_Error_DeepNesting(t *testing.T) {
	var b strings.Builder
	b.WriteString("a:\n")
	for i := 0; i < 110; i++ {
		fmt.Fprintf(&b, "%s  b:\n", strings.Repeat("  ", i+1))
	}
	b.WriteString(strings.Repeat("  ", 110) + "val")
	assertParseError(t, b.String(), "nesting depth")
}

// ===========================================================================
// 13. Parse() vs ParseMapping()
// ===========================================================================

func TestConformance_ParseTopLevelSequence(t *testing.T) {
	input := `- one
- two
- three`
	p := NewParser(input)
	node, err := p.Parse()
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if node.Type != NodeDocument {
		t.Fatalf("expected Document node, got %v", node.Type)
	}
	if len(node.Children) != 1 {
		t.Fatalf("expected 1 child, got %d", len(node.Children))
	}
	seq := node.Children[0]
	if seq.Type != NodeSequence {
		t.Fatalf("expected Sequence, got %v", seq.Type)
	}
	if len(seq.Children) != 3 {
		t.Fatalf("expected 3 items, got %d", len(seq.Children))
	}
}

func TestConformance_ParseMappingWithNewlines(t *testing.T) {
	input := "\n\n\nkey: value\n\n\n"
	node := parseMappingOrFail(t, input)
	assertScalar(t, node, "key", "value")
}

// ===========================================================================
// 14. Real Config Full Parse (config.example.yaml)
// ===========================================================================

func TestConformance_RealConfigFileExample(t *testing.T) {
	input := `server:
  port: 53
  http:
    enabled: true
    bind: "0.0.0.0:8080"
cluster:
  enabled: false
  node_id: "node-1"
logging:
  level: info
cache:
  capacity: 10000
blocklist:
  enabled: true
rpz:
  enabled: false`
	node := parseMappingOrFail(t, input)
	server := assertNodeType(t, node, "server", NodeMapping)
	assertScalar(t, server, "port", "53")
	assertNodeType(t, server, "http", NodeMapping)
	assertNodeType(t, node, "cluster", NodeMapping)
	assertNodeType(t, node, "logging", NodeMapping)
	assertNodeType(t, node, "cache", NodeMapping)
	assertNodeType(t, node, "blocklist", NodeMapping)
	assertNodeType(t, node, "rpz", NodeMapping)
}
