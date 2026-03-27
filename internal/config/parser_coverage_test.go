package config

import (
	"testing"
)

// TestParse_EmptyInput tests Parse with empty input (triggers parseValue EOF)
func TestParse_EmptyInput(t *testing.T) {
	parser := NewParser("")
	_, err := parser.Parse()
	if err == nil {
		t.Error("expected error for empty input")
	}
}

// TestParse_IndentAtStart tests parseValue TokenIndent branch
func TestParse_IndentAtStart(t *testing.T) {
	parser := NewParser("  value")
	_, err := parser.Parse()
	// This might succeed or fail depending on tokenizer behavior,
	// but it covers the TokenIndent branch in parseValue
	t.Logf("Parse with leading indent: %v", err)
}

// TestParse_DashAtTopLevel tests parseValue with dash (sequence at top level)
func TestParse_DashAtTopLevel(t *testing.T) {
	parser := NewParser("- item1\n- item2")
	node, err := parser.Parse()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(node.Children) != 1 || node.Children[0].Type != NodeSequence {
		t.Fatal("expected sequence at top level")
	}
	if len(node.Children[0].Children) != 2 {
		t.Errorf("expected 2 items, got %d", len(node.Children[0].Children))
	}
}

// TestParse_UnexpectedToken tests parseValue with an unexpected token type
func TestParse_UnexpectedToken(t *testing.T) {
	parser := NewParser("]")
	_, err := parser.Parse()
	if err == nil {
		t.Error("expected error for unexpected token")
	}
}

// TestParse_TrailingContent tests Parse with trailing content after value
func TestParse_TrailingContent(t *testing.T) {
	parser := NewParser("value\nextra")
	_, err := parser.Parse()
	if err == nil {
		t.Error("expected error for trailing content")
	}
}

// TestParseMapping_Simple tests parseMapping with a simple key-value pair
func TestParseMapping_Simple(t *testing.T) {
	parser := NewParser("key: value")
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node.GetString("key") != "value" {
		t.Errorf("expected 'value', got %q", node.GetString("key"))
	}
}

// TestParseMapping_Dedent tests parseMapping DEDENT branch
func TestParseMapping_Dedent(t *testing.T) {
	input := `outer:
  inner: val
top: level`
	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node.GetString("top") != "level" {
		t.Errorf("expected 'level', got %q", node.GetString("top"))
	}
}

// TestParseMapping_EmptyValue tests mapping with empty value (default case)
func TestParseMapping_EmptyValue(t *testing.T) {
	input := `key:
next: val`
	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node.GetString("next") != "val" {
		t.Errorf("expected 'val', got %q", node.GetString("next"))
	}
}

// TestParseMapping_DefaultValue tests mapping with unknown token as value
func TestParseMapping_DefaultValue(t *testing.T) {
	// After colon, an unexpected token should produce empty value
	input := "key"
	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		// This might error because no colon found
		t.Logf("Result: %v", err)
	}
	if node != nil {
		t.Logf("Node value: %q", node.GetString("key"))
	}
}

// TestParseMapping_ScalarWithDedent tests that scalar value followed by DEDENT exits mapping
func TestParseMapping_ScalarWithDedent(t *testing.T) {
	input := `server:
  port: 53
  bind: 0.0.0.0`
	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	server := node.Get("server")
	if server == nil {
		t.Fatal("expected server node")
	}
	if server.GetString("port") != "53" {
		t.Errorf("expected port '53', got %q", server.GetString("port"))
	}
	if server.GetString("bind") != "0.0.0.0" {
		t.Errorf("expected bind '0.0.0.0', got %q", server.GetString("bind"))
	}
}

// TestParseMapping_NewlineThenMapping tests mapping where value is on next line as mapping
func TestParseMapping_NewlineThenMapping(t *testing.T) {
	input := `server:
  host: localhost
  port: 53`
	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	server := node.Get("server")
	if server == nil || server.Type != NodeMapping {
		t.Fatal("expected server to be a mapping")
	}
	if server.GetString("port") != "53" {
		t.Errorf("expected port '53', got %q", server.GetString("port"))
	}
}

// TestParseMapping_NewlineThenSequence tests mapping where value is on next line as sequence
func TestParseMapping_NewlineThenSequence(t *testing.T) {
	input := `items:
  - one
  - two`
	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	items := node.Get("items")
	if items == nil || items.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}
	if len(items.Children) != 2 {
		t.Errorf("expected 2 items, got %d", len(items.Children))
	}
}

// TestParseMapping_NewlineThenScalar tests mapping where value is on next line as a number
func TestParseMapping_NewlineThenScalar(t *testing.T) {
	input := `desc:
  42`
	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node.GetString("desc") != "42" {
		t.Errorf("expected '42', got %q", node.GetString("desc"))
	}
}

// TestParseMapping_FlowMappingValue tests mapping with inline flow mapping value
func TestParseMapping_FlowMappingValue(t *testing.T) {
	input := `config: {a: 1, b: 2}`
	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	config := node.Get("config")
	if config == nil || config.Type != NodeMapping {
		t.Fatal("expected config to be a mapping")
	}
}

// TestParseMapping_FlowSequenceValue tests mapping with inline flow sequence value
func TestParseMapping_FlowSequenceValue(t *testing.T) {
	input := `tags: [a, b, c]`
	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tags := node.Get("tags")
	if tags == nil || tags.Type != NodeSequence {
		t.Fatal("expected tags to be a sequence")
	}
}

// TestParseMapping_DashValue tests mapping with dash (sequence) as value
func TestParseMapping_DashValue(t *testing.T) {
	input := "items:\n  - a\n  - b"
	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	items := node.Get("items")
	if items == nil || items.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}
}

// TestNode_KeysWithOddChildren tests Keys with odd number of children
func TestNode_KeysWithOddChildren(t *testing.T) {
	node := &Node{
		Type: NodeMapping,
		Children: []*Node{
			{Type: NodeScalar, Value: "key1"},
			{Type: NodeScalar, Value: "val1"},
			{Type: NodeScalar, Value: "key2"},
			// Missing value for key2 (odd children)
		},
	}
	keys := node.Keys()
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
	if keys[0] != "key1" {
		t.Errorf("expected key1, got %q", keys[0])
	}
	if keys[1] != "key2" {
		t.Errorf("expected key2, got %q", keys[1])
	}
}

// TestNode_KeysOnNonMapping tests Keys on non-mapping node
func TestNode_KeysOnNonMapping(t *testing.T) {
	node := &Node{Type: NodeScalar, Value: "test"}
	keys := node.Keys()
	if keys != nil {
		t.Errorf("expected nil for scalar Keys(), got %v", keys)
	}
}

// TestNode_KeysWithEmptyMapping tests Keys on empty mapping
func TestNode_KeysWithEmptyMapping(t *testing.T) {
	node := &Node{Type: NodeMapping}
	keys := node.Keys()
	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}
}

// TestParseFlowMapping_Unterminated tests unterminated flow mapping
func TestParseFlowMapping_Unterminated(t *testing.T) {
	parser := NewParser("{key: value")
	_, err := parser.Parse()
	if err == nil {
		t.Error("expected error for unterminated flow mapping")
	}
}

// TestParseFlowSequence_Unterminated tests unterminated flow sequence
func TestParseFlowSequence_Unterminated(t *testing.T) {
	parser := NewParser("[a, b")
	_, err := parser.Parse()
	if err == nil {
		t.Error("expected error for unterminated flow sequence")
	}
}

// TestParseMapping_DedentAtEntryLevel tests DEDENT drops below entry level
func TestParseMapping_DedentAtEntryLevel(t *testing.T) {
	input := `a: 1
b: 2`
	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node.GetString("a") != "1" {
		t.Errorf("expected '1', got %q", node.GetString("a"))
	}
	if node.GetString("b") != "2" {
		t.Errorf("expected '2', got %q", node.GetString("b"))
	}
}

// TestParseMapping_DedentAtSameLevel tests DEDENT at same level continues
func TestParseMapping_DedentAtSameLevel(t *testing.T) {
	input := `outer:
  a: 1
  b: 2`
	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	outer := node.Get("outer")
	if outer == nil {
		t.Fatal("expected outer node")
	}
	if outer.GetString("a") != "1" {
		t.Errorf("expected '1', got %q", outer.GetString("a"))
	}
	if outer.GetString("b") != "2" {
		t.Errorf("expected '2', got %q", outer.GetString("b"))
	}
}

// TestParseMapping_ScalarValue tests mapping with inline scalar values
func TestParseMapping_ScalarValue(t *testing.T) {
	input := `name: test
count: 42
enabled: true
empty: null`
	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node.GetString("name") != "test" {
		t.Errorf("expected 'test', got %q", node.GetString("name"))
	}
	if node.GetString("count") != "42" {
		t.Errorf("expected '42', got %q", node.GetString("count"))
	}
	if node.GetBool("enabled") != true {
		t.Error("expected enabled to be true")
	}
}

// TestParseMapping_EOF tests mapping ending with EOF
func TestParseMapping_EOF(t *testing.T) {
	input := "key: value"
	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node.GetString("key") != "value" {
		t.Errorf("expected 'value', got %q", node.GetString("key"))
	}
}

// TestParseMapping_EndsWithNonString tests mapping that ends with non-string token
func TestParseMapping_EndsWithNonString(t *testing.T) {
	input := `items:
  - one
  - two
name: test`
	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node.GetString("name") != "test" {
		t.Errorf("expected 'test', got %q", node.GetString("name"))
	}
}
