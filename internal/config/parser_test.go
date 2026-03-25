package config

import (
	"testing"
)

func TestParserSimpleMapping(t *testing.T) {
	input := `key: value`
	parser := NewParser(input)
	node, err := parser.ParseMapping()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if node.Type != NodeMapping {
		t.Errorf("expected Mapping node, got %v", node.Type)
	}

	if value := node.GetString("key"); value != "value" {
		t.Errorf("expected 'value', got %q", value)
	}
}

func TestParserNestedMapping(t *testing.T) {
	input := `server:
  port: 53
  bind: 0.0.0.0`

	parser := NewParser(input)
	node, err := parser.ParseMapping()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	serverNode := node.Get("server")
	if serverNode == nil {
		t.Fatal("expected 'server' key")
	}

	if serverNode.Type != NodeMapping {
		t.Errorf("expected server to be Mapping, got %v", serverNode.Type)
	}

	if port := serverNode.GetString("port"); port != "53" {
		t.Errorf("expected port '53', got %q", port)
	}

	if bind := serverNode.GetString("bind"); bind != "0.0.0.0" {
		t.Errorf("expected bind '0.0.0.0', got %q", bind)
	}
}

func TestParserSequence(t *testing.T) {
	input := `items:
  - one
  - two
  - three`

	parser := NewParser(input)
	node, err := parser.ParseMapping()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	itemsNode := node.Get("items")
	if itemsNode == nil {
		t.Fatal("expected 'items' key")
	}

	if itemsNode.Type != NodeSequence {
		t.Errorf("expected Sequence node, got %v", itemsNode.Type)
	}

	if len(itemsNode.Children) != 3 {
		t.Errorf("expected 3 items, got %d", len(itemsNode.Children))
	}

	for i, child := range itemsNode.Children {
		if child.Type != NodeScalar {
			t.Errorf("item %d: expected Scalar, got %v", i, child.Type)
		}
	}
}

func TestParserFlowMapping(t *testing.T) {
	input := `{key1: value1, key2: value2}`
	parser := NewParser(input)
	node, err := parser.ParseMapping()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if node.Type != NodeMapping {
		t.Errorf("expected Mapping node, got %v", node.Type)
	}

	if value := node.GetString("key1"); value != "value1" {
		t.Errorf("expected 'value1', got %q", value)
	}

	if value := node.GetString("key2"); value != "value2" {
		t.Errorf("expected 'value2', got %q", value)
	}
}

func TestParserFlowSequence(t *testing.T) {
	input := `[one, two, three]`
	parser := NewParser(input)
	node, err := parser.Parse()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(node.Children) != 1 {
		t.Fatalf("expected 1 child, got %d", len(node.Children))
	}

	seqNode := node.Children[0]
	if seqNode.Type != NodeSequence {
		t.Errorf("expected Sequence node, got %v", seqNode.Type)
	}

	if len(seqNode.Children) != 3 {
		t.Errorf("expected 3 items, got %d", len(seqNode.Children))
	}
}

func TestParserMixedContent(t *testing.T) {
	input := `name: test
values:
  - a
  - b
  - c
config:
  enabled: true
  count: 42`

	parser := NewParser(input)
	node, err := parser.ParseMapping()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if name := node.GetString("name"); name != "test" {
		t.Errorf("expected name 'test', got %q", name)
	}

	valuesNode := node.Get("values")
	if valuesNode == nil || valuesNode.Type != NodeSequence {
		t.Error("expected 'values' to be a sequence")
	}

	configNode := node.Get("config")
	if configNode == nil || configNode.Type != NodeMapping {
		t.Error("expected 'config' to be a mapping")
	}
}

func TestParserDeepNesting(t *testing.T) {
	input := `level1:
  level2:
    level3:
      deep: value`

	parser := NewParser(input)
	node, err := parser.ParseMapping()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	level1 := node.Get("level1")
	if level1 == nil {
		t.Fatal("expected 'level1'")
	}

	level2 := level1.Get("level2")
	if level2 == nil {
		t.Fatal("expected 'level2'")
	}

	level3 := level2.Get("level3")
	if level3 == nil {
		t.Fatal("expected 'level3'")
	}

	if deep := level3.GetString("deep"); deep != "value" {
		t.Errorf("expected 'value', got %q", deep)
	}
}

func TestParserErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "unterminated string",
			input: `"unterminated`,
		},
		{
			name:  "invalid flow mapping",
			input: `{key}`,
		},
		{
			name:  "unterminated flow mapping",
			input: `{key: value`,
		},
		{
			name:  "unterminated flow sequence",
			input: `[a, b`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser(tt.input)
			_, err := parser.Parse()
			if err == nil {
				t.Error("expected an error but got none")
			}
		})
	}
}

func TestNodeMethods(t *testing.T) {
	input := `server:
  port: 53
  enabled: true
tags:
  - one
  - two`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test Get
	serverNode := node.Get("server")
	if serverNode == nil {
		t.Fatal("expected 'server' node")
	}

	// Test GetString
	if port := serverNode.GetString("port"); port != "53" {
		t.Errorf("expected port '53', got %q", port)
	}

	// Test GetInt
	if port := serverNode.GetInt("port"); port != 53 {
		t.Errorf("expected port 53, got %d", port)
	}

	// Test GetBool
	if enabled := serverNode.GetBool("enabled"); !enabled {
		t.Error("expected enabled to be true")
	}

	// Test GetSlice
	tagsNode := node.Get("tags")
	if tagsNode == nil {
		t.Fatal("expected 'tags' node")
	}

	slice := tagsNode.GetSlice("")
	if len(slice) != 2 {
		t.Errorf("expected 2 tags, got %d", len(slice))
	}

	// Test Keys
	keys := serverNode.Keys()
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
}

func TestNodeIsMethods(t *testing.T) {
	tests := []struct {
		input    string
		isScalar bool
		isMapping bool
		isSequence bool
	}{
		{"value", true, false, false},
		{"{key: value}", false, true, false},
		{"[a, b, c]", false, false, true},
	}

	for _, tt := range tests {
		parser := NewParser(tt.input)
		node, err := parser.Parse()
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", tt.input, err)
		}

		if len(node.Children) == 0 {
			t.Fatalf("no children for %q", tt.input)
		}

		n := node.Children[0]
		if n.IsScalar() != tt.isScalar {
			t.Errorf("%q: IsScalar() = %v, want %v", tt.input, n.IsScalar(), tt.isScalar)
		}
		if n.IsMapping() != tt.isMapping {
			t.Errorf("%q: IsMapping() = %v, want %v", tt.input, n.IsMapping(), tt.isMapping)
		}
		if n.IsSequence() != tt.isSequence {
			t.Errorf("%q: IsSequence() = %v, want %v", tt.input, n.IsSequence(), tt.isSequence)
		}
	}
}

func TestNodeTypeString(t *testing.T) {
	tests := []struct {
		nt       NodeType
		expected string
	}{
		{NodeDocument, "Document"},
		{NodeMapping, "Mapping"},
		{NodeSequence, "Sequence"},
		{NodeScalar, "Scalar"},
		{NodeType(999), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.nt.String(); got != tt.expected {
			t.Errorf("NodeType(%d).String() = %q, want %q", tt.nt, got, tt.expected)
		}
	}
}
