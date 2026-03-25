package config

import (
	"fmt"
	"testing"
)

func TestDebugMixedContent(t *testing.T) {
	input := `name: test
values:
  - a
  - b
  - c
config:
  enabled: true
  count: 42`

	fmt.Println("=== Tokens ===")
	tokenizer := NewTokenizer(input)
	tokens := tokenizer.TokenizeAll()
	for i, tok := range tokens {
		fmt.Printf("Token[%d]: Type=%s Value=%q Line=%d Col=%d\n", i, tok.Type, tok.Value, tok.Line, tok.Col)
	}
	fmt.Println("=============================")

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	fmt.Println("=== Parsed Node Structure ===")
	debugNode(node, 0)
	fmt.Println("=============================")

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
