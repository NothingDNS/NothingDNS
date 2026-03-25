package config

import (
	"testing"
	"fmt"
)

func TestDebugNestedMapping(t *testing.T) {
	input := `server:
  port: 53
  bind: 0.0.0.0`

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

func TestDebugFlowMapping(t *testing.T) {
	input := `{key1: value1, key2: value2}`

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
}
