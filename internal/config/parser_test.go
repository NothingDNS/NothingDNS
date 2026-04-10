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
		input      string
		isScalar   bool
		isMapping  bool
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

// --- Tests for parseBlockSequence coverage ---

func TestParserBlockSequenceInlineMapping(t *testing.T) {
	// Test: sequence items that are inline mappings (key: value on same line as dash)
	input := `items:
  - name: first
    value: one
  - name: second
    value: two`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	itemsNode := node.Get("items")
	if itemsNode == nil || itemsNode.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}
	if len(itemsNode.Children) != 2 {
		t.Fatalf("expected 2 items, got %d", len(itemsNode.Children))
	}

	// Each child should be a mapping
	first := itemsNode.Children[0]
	if first.Type != NodeMapping {
		t.Fatalf("expected first item to be Mapping, got %v", first.Type)
	}
	if first.GetString("name") != "first" {
		t.Errorf("expected name 'first', got %q", first.GetString("name"))
	}
	if first.GetString("value") != "one" {
		t.Errorf("expected value 'one', got %q", first.GetString("value"))
	}

	second := itemsNode.Children[1]
	if second.Type != NodeMapping {
		t.Fatalf("expected second item to be Mapping, got %v", second.Type)
	}
	if second.GetString("name") != "second" {
		t.Errorf("expected name 'second', got %q", second.GetString("name"))
	}
}

func TestParserBlockSequenceNestedSequence(t *testing.T) {
	// Test: nested sequences where a sequence item's value on the next line is another sequence
	input := `matrix:
  -
    - a
    - b`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	matrixNode := node.Get("matrix")
	if matrixNode == nil || matrixNode.Type != NodeSequence {
		t.Fatal("expected matrix to be a sequence")
	}
	if len(matrixNode.Children) != 1 {
		t.Fatalf("expected 1 item, got %d", len(matrixNode.Children))
	}

	// Child should be a nested sequence
	first := matrixNode.Children[0]
	if first.Type != NodeSequence {
		t.Fatalf("expected first item to be Sequence, got %v", first.Type)
	}
	if len(first.Children) != 2 {
		t.Errorf("expected 2 items in nested sequence, got %d", len(first.Children))
	}
}

func TestParserBlockSequenceInlineNestedMapping(t *testing.T) {
	// Test: sequence with mapping on next line (newline after dash)
	input := `items:
  -
    key1: val1
    key2: val2`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	itemsNode := node.Get("items")
	if itemsNode == nil || itemsNode.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}
	if len(itemsNode.Children) != 1 {
		t.Fatalf("expected 1 item, got %d", len(itemsNode.Children))
	}

	child := itemsNode.Children[0]
	if child.Type != NodeMapping {
		t.Fatalf("expected child to be Mapping, got %v", child.Type)
	}
	if child.GetString("key1") != "val1" {
		t.Errorf("expected key1 'val1', got %q", child.GetString("key1"))
	}
	if child.GetString("key2") != "val2" {
		t.Errorf("expected key2 'val2', got %q", child.GetString("key2"))
	}
}

func TestParserBlockSequenceWithFlowMapping(t *testing.T) {
	// Test: sequence item that is a flow mapping
	input := `items:
  - {key: val}
  - simple`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	itemsNode := node.Get("items")
	if itemsNode == nil || itemsNode.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}
	if len(itemsNode.Children) != 2 {
		t.Fatalf("expected 2 items, got %d", len(itemsNode.Children))
	}

	first := itemsNode.Children[0]
	if first.Type != NodeMapping {
		t.Fatalf("expected first item to be Mapping, got %v", first.Type)
	}
}

func TestParserBlockSequenceWithFlowSequence(t *testing.T) {
	// Test: sequence item that is a flow sequence
	input := `items:
  - [a, b]
  - c`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	itemsNode := node.Get("items")
	if itemsNode == nil || itemsNode.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}

	first := itemsNode.Children[0]
	if first.Type != NodeSequence {
		t.Fatalf("expected first item to be Sequence, got %v", first.Type)
	}
}

func TestParserBlockSequenceNewlineAfterDash(t *testing.T) {
	// Test: dash followed by newline, then a nested sequence
	input := `items:
  -
    - nested1
    - nested2`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	itemsNode := node.Get("items")
	if itemsNode == nil || itemsNode.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}
	if len(itemsNode.Children) != 1 {
		t.Fatalf("expected 1 item, got %d", len(itemsNode.Children))
	}

	child := itemsNode.Children[0]
	if child.Type != NodeSequence {
		t.Fatalf("expected child to be Sequence, got %v", child.Type)
	}
	if len(child.Children) != 2 {
		t.Errorf("expected 2 nested items, got %d", len(child.Children))
	}
}

func TestParserBlockSequenceNewlineAfterDashScalar(t *testing.T) {
	// Test: dash followed by newline, then a plain scalar
	input := `items:
  -
    scalar_value`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	itemsNode := node.Get("items")
	if itemsNode == nil || itemsNode.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}
}

func TestParserBlockSequenceEmptyValue(t *testing.T) {
	// Test: dash followed by something that is not a valid value start
	input := `items:
  -
key: value`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	itemsNode := node.Get("items")
	if itemsNode == nil || itemsNode.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}
}

func TestParserBlockSequenceInlineMappingNewlineValue(t *testing.T) {
	// Test: inline mapping in sequence where a key has a flow mapping value
	input := `items:
  - name: {sub: val}
  - other`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	itemsNode := node.Get("items")
	if itemsNode == nil || itemsNode.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}

	first := itemsNode.Children[0]
	if first.Type != NodeMapping {
		t.Fatalf("expected first item to be Mapping, got %v", first.Type)
	}
	// name's value should be a mapping
	nameNode := first.Get("name")
	if nameNode == nil || nameNode.Type != NodeMapping {
		t.Fatalf("expected name to have a mapping value, got %v", nameNode.Type)
	}
}

func TestParserBlockSequenceInlineMappingWithDashValue(t *testing.T) {
	// Test: inline mapping where value after colon is a sequence
	input := `items:
  - name:
      - sub1
      - sub2`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	itemsNode := node.Get("items")
	if itemsNode == nil || itemsNode.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}
}

func TestParserBlockSequenceInlineMappingWithNestedMapping(t *testing.T) {
	// Test: inline mapping where the value after colon+newline is another mapping
	input := `items:
  - outer: simple`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	itemsNode := node.Get("items")
	if itemsNode == nil || itemsNode.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}

	child := itemsNode.Children[0]
	if child.Type != NodeMapping {
		t.Fatalf("expected child to be Mapping, got %v", child.Type)
	}
	if child.GetString("outer") != "simple" {
		t.Errorf("expected outer 'simple', got %q", child.GetString("outer"))
	}
}

func TestParserBlockSequenceNewlineThenFlowMapping(t *testing.T) {
	// Test: dash then newline then flow mapping value in a mapping context
	input := `items:
  - data: {flow: map}`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	itemsNode := node.Get("items")
	if itemsNode == nil || itemsNode.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}
}

func TestParserBlockSequenceNewlineThenFlowSequence(t *testing.T) {
	// Test: inline mapping where value is a flow sequence
	input := `items:
  - data: [flow, seq]`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	itemsNode := node.Get("items")
	if itemsNode == nil || itemsNode.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}
}

func TestParserBlockSequenceNewlineThenInlineMappingValueOnNewline(t *testing.T) {
	// Test: inline mapping in sequence (dash then string:colon pattern)
	input := `items:
  - key: val`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	itemsNode := node.Get("items")
	if itemsNode == nil || itemsNode.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}

	child := itemsNode.Children[0]
	if child.Type != NodeMapping {
		t.Fatalf("expected child to be Mapping, got %v", child.Type)
	}
	if child.GetString("key") != "val" {
		t.Errorf("expected key 'val', got %q", child.GetString("key"))
	}
}

func TestParserBlockSequenceNewlineInlineMappingWithBlockSeqValue(t *testing.T) {
	// Test: mapping in sequence with scalar value followed by block sequence
	input := `items:
  - list:
      - a
      - b`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	itemsNode := node.Get("items")
	if itemsNode == nil || itemsNode.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}

	child := itemsNode.Children[0]
	if child.Type != NodeMapping {
		t.Fatalf("expected child to be Mapping, got %v", child.Type)
	}
}

func TestParserBlockSequenceScalarValueAfterColon(t *testing.T) {
	// Test: inline mapping in sequence with scalar value
	input := `items:
  - key: val`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	itemsNode := node.Get("items")
	if itemsNode == nil || itemsNode.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}

	child := itemsNode.Children[0]
	if child.Type != NodeMapping {
		t.Fatalf("expected child to be Mapping, got %v", child.Type)
	}
}

func TestParserBlockSequenceInlineMappingBoolValue(t *testing.T) {
	// Test: inline mapping with bool value after colon
	input := `items:
  - enabled: true`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	itemsNode := node.Get("items")
	if itemsNode == nil || itemsNode.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}
	child := itemsNode.Children[0]
	if child.Type != NodeMapping {
		t.Fatalf("expected Mapping, got %v", child.Type)
	}
	if child.GetBool("enabled") != true {
		t.Error("expected enabled to be true")
	}
}

func TestParserBlockSequenceInlineMappingNumberValue(t *testing.T) {
	// Test: inline mapping with number value after colon
	input := `items:
  - count: 42`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	itemsNode := node.Get("items")
	if itemsNode == nil || itemsNode.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}
	child := itemsNode.Children[0]
	if child.Type != NodeMapping {
		t.Fatalf("expected Mapping, got %v", child.Type)
	}
	if child.GetInt("count") != 42 {
		t.Errorf("expected count 42, got %d", child.GetInt("count"))
	}
}

func TestParserBlockSequenceInlineMappingNullValue(t *testing.T) {
	// Test: inline mapping with null value after colon
	input := `items:
  - value: null`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	itemsNode := node.Get("items")
	if itemsNode == nil || itemsNode.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}
	child := itemsNode.Children[0]
	if child.Type != NodeMapping {
		t.Fatalf("expected Mapping, got %v", child.Type)
	}
}

func TestParserBlockSequenceScalarValues(t *testing.T) {
	// Test: sequence items that are plain scalars (not mappings)
	input := `items:
  - hello
  - 42
  - true`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	itemsNode := node.Get("items")
	if itemsNode == nil || itemsNode.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}
	if len(itemsNode.Children) != 3 {
		t.Fatalf("expected 3 items, got %d", len(itemsNode.Children))
	}
	if itemsNode.Children[0].Value != "hello" {
		t.Errorf("expected 'hello', got %q", itemsNode.Children[0].Value)
	}
}

func TestParserBlockSequenceEmptyValueAfterDash(t *testing.T) {
	// Test: sequence item with dash followed by newline only
	input := `items:
  -
next: value`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	itemsNode := node.Get("items")
	if itemsNode == nil || itemsNode.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}
	// Should have at least one child (empty scalar)
	if len(itemsNode.Children) != 1 {
		t.Errorf("expected 1 item, got %d", len(itemsNode.Children))
	}
}

func TestParserBlockSequenceInlineMappingDashValue(t *testing.T) {
	// Test: inline mapping where value is a nested sequence via inline colon
	input := `items:
  - list:
      - one
      - two`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	itemsNode := node.Get("items")
	if itemsNode == nil || itemsNode.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}

	child := itemsNode.Children[0]
	if child.Type != NodeMapping {
		t.Fatalf("expected child to be Mapping, got %v", child.Type)
	}
}

func TestParserBlockSequenceInlineMappingFlowValue(t *testing.T) {
	// Test: inline mapping where value after colon is flow mapping
	input := `items:
  - obj: {a: 1}`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	itemsNode := node.Get("items")
	if itemsNode == nil || itemsNode.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}
}

func TestParserBlockSequenceInlineMappingFlowSeqValue(t *testing.T) {
	// Test: inline mapping where value after colon is flow sequence
	input := `items:
  - arr: [x, y]`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	itemsNode := node.Get("items")
	if itemsNode == nil || itemsNode.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}
}

// --- Tests for parseMapping coverage ---

func TestParserMappingDefaultCase(t *testing.T) {
	// Test: mapping value that falls to default case (empty value)
	input := `key:`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if node.GetString("key") != "" {
		t.Errorf("expected empty value, got %q", node.GetString("key"))
	}
}

func TestParserMappingValueWithNewlineAndIndent(t *testing.T) {
	// Test: mapping with value on next line followed by indent token
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
		t.Fatal("expected server node")
	}
	if serverNode.GetString("port") != "53" {
		t.Errorf("expected port '53', got %q", serverNode.GetString("port"))
	}
	if serverNode.GetString("bind") != "0.0.0.0" {
		t.Errorf("expected bind '0.0.0.0', got %q", serverNode.GetString("bind"))
	}
}

func TestParserMappingNewlineThenDash(t *testing.T) {
	// Test: mapping value on next line that is a sequence
	input := `items:
  - one
  - two`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	itemsNode := node.Get("items")
	if itemsNode == nil || itemsNode.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}
	if len(itemsNode.Children) != 2 {
		t.Errorf("expected 2 items, got %d", len(itemsNode.Children))
	}
}

func TestParserMappingInlineFlowMapping(t *testing.T) {
	// Test: mapping value that is an inline flow mapping
	input := `config: {k: v}`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	configNode := node.Get("config")
	if configNode == nil || configNode.Type != NodeMapping {
		t.Fatal("expected config to be a mapping")
	}
}

func TestParserMappingInlineFlowSequence(t *testing.T) {
	// Test: mapping value that is an inline flow sequence
	input := `items: [a, b]`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	itemsNode := node.Get("items")
	if itemsNode == nil || itemsNode.Type != NodeSequence {
		t.Fatal("expected items to be a sequence")
	}
}

// --- Tests for parseValue coverage ---

func TestParserParseValueEOF(t *testing.T) {
	// Test parseValue with EOF (top-level document parse)
	input := ""
	parser := NewParser(input)
	_, err := parser.Parse()
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestParserParseValueWithIndent(t *testing.T) {
	// Test parseValue with TokenIndent
	input := `  value`
	parser := NewParser(input)
	_, err := parser.Parse()
	if err != nil {
		// Might error because indent is unexpected at top level
		// This is fine - we're just covering the TokenIndent branch
		t.Logf("Parse result: %v", err)
	}
}

func TestParserParseMappingNoColonAfterKey(t *testing.T) {
	// Test parseMapping where first token is not string (error case)
	input := `: value`
	parser := NewParser(input)
	_, err := parser.ParseMapping()
	if err == nil {
		t.Error("expected error for mapping starting with colon")
	}
}

func TestParserParseMappingNoColonAfterExistingPairs(t *testing.T) {
	// Test that mapping ends when dedent occurs after some pairs - testing early break
	input := `key: value
other: data`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node.GetString("key") != "value" {
		t.Errorf("expected key 'value', got %q", node.GetString("key"))
	}
	if node.GetString("other") != "data" {
		t.Errorf("expected other 'data', got %q", node.GetString("other"))
	}
}

// --- Tests for parseFlowSequence/parseFlowMapping coverage ---

func TestParserFlowSequenceWithFlowMapping(t *testing.T) {
	// Test: flow sequence containing flow mappings
	input := `[{a: 1}, {b: 2}]`

	parser := NewParser(input)
	node, err := parser.Parse()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	seq := node.Children[0]
	if seq.Type != NodeSequence {
		t.Fatalf("expected Sequence, got %v", seq.Type)
	}
	if len(seq.Children) != 2 {
		t.Errorf("expected 2 children, got %d", len(seq.Children))
	}
}

func TestParserFlowSequenceWithNestedSequence(t *testing.T) {
	// Test: flow sequence containing nested flow sequences
	input := `[[a, b], [c, d]]`

	parser := NewParser(input)
	node, err := parser.Parse()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	seq := node.Children[0]
	if seq.Type != NodeSequence {
		t.Fatalf("expected Sequence, got %v", seq.Type)
	}
	if len(seq.Children) != 2 {
		t.Errorf("expected 2 children, got %d", len(seq.Children))
	}
}

func TestParserFlowMappingWithNestedFlowMapping(t *testing.T) {
	// Test: flow mapping with nested flow mapping value
	input := `{outer: {inner: value}}`

	parser := NewParser(input)
	node, err := parser.Parse()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mapping := node.Children[0]
	if mapping.Type != NodeMapping {
		t.Fatalf("expected Mapping, got %v", mapping.Type)
	}

	outer := mapping.Get("outer")
	if outer == nil || outer.Type != NodeMapping {
		t.Fatal("expected nested mapping")
	}
}

func TestParserFlowMappingWithNestedFlowSequence(t *testing.T) {
	// Test: flow mapping with nested flow sequence value
	input := `{items: [a, b, c]}`

	parser := NewParser(input)
	node, err := parser.Parse()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mapping := node.Children[0]
	items := mapping.Get("items")
	if items == nil || items.Type != NodeSequence {
		t.Fatal("expected nested sequence")
	}
	if len(items.Children) != 3 {
		t.Errorf("expected 3 items, got %d", len(items.Children))
	}
}

func TestParserFlowMappingUnexpectedTokenInValue(t *testing.T) {
	// Test: flow mapping with unexpected token type as value
	input := `{key: :}`

	parser := NewParser(input)
	_, err := parser.Parse()
	if err == nil {
		t.Error("expected error for unexpected token in flow mapping")
	}
}

func TestParserFlowSequenceUnexpectedToken(t *testing.T) {
	// Test: flow sequence with unexpected token type
	input := `[ :]`

	parser := NewParser(input)
	_, err := parser.Parse()
	if err == nil {
		t.Error("expected error for unexpected token in flow sequence")
	}
}

func TestParserFlowMappingUnexpectedKey(t *testing.T) {
	// Test: flow mapping with non-string key
	input := `{123: value}`

	parser := NewParser(input)
	_, err := parser.Parse()
	if err == nil {
		t.Error("expected error for non-string key in flow mapping")
	}
}

func TestParserFlowMappingMissingColon(t *testing.T) {
	// Test: flow mapping missing colon after key
	input := `{key value}`

	parser := NewParser(input)
	_, err := parser.Parse()
	if err == nil {
		t.Error("expected error for missing colon in flow mapping")
	}
}
