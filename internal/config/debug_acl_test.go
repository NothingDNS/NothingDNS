package config

import (
	"fmt"
	"testing"
)

func TestDebugACL(t *testing.T) {
	input := `
acl:
  - name: local
    networks:
      - "127.0.0.1/32"
      - "10.0.0.0/8"
    types:
      - A
      - AAAA
    action: allow
`

	fmt.Println("=== Tokens ===")
	tokenizer := NewTokenizer(input)
	tokens := tokenizer.TokenizeAll()
	for i, tok := range tokens {
		fmt.Printf("Token[%d]: Type=%s Value=%q Line=%d Col=%d\n", i, tok.Type, tok.Value, tok.Line, tok.Col)
	}
	fmt.Println("=============================")

	// Try full unmarshal first with debug
	fmt.Println("=== Calling UnmarshalYAML ===")
	cfg, err := UnmarshalYAML(input)
	if err != nil {
		fmt.Printf("UnmarshalYAML error: %v\n", err)
	} else {
		fmt.Printf("UnmarshalYAML success: %d ACL rules\n", len(cfg.ACL))
	}

	fmt.Println("=== Calling ParseMapping ===")
	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	fmt.Println("=== Parsed Node Structure ===")
	debugNode(node, 0)
	fmt.Println("=============================")

	if len(cfg.ACL) != 1 {
		t.Errorf("expected 1 ACL rule, got %d", len(cfg.ACL))
	}
}
