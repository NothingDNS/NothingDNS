package config

import (
	"fmt"
	"testing"
)

func TestDebugBasic(t *testing.T) {
	input := `
server:
  port: 5353
  bind:
    - 127.0.0.1
upstream:
  strategy: round_robin
  servers:
    - 1.1.1.1:53
    - 8.8.8.8:53
`

	fmt.Println("=== Tokens ===")
	tokenizer := NewTokenizer(input)
	tokens := tokenizer.TokenizeAll()
	for i, tok := range tokens {
		fmt.Printf("Token[%d]: Type=%s Value=%q Line=%d Col=%d\n", i, tok.Type, tok.Value, tok.Line, tok.Col)
	}
	fmt.Println("=============================")

	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	fmt.Printf("Port: %d\n", cfg.Server.Port)
	fmt.Printf("Bind: %v\n", cfg.Server.Bind)
	fmt.Printf("Strategy: %q\n", cfg.Upstream.Strategy)
	fmt.Printf("Servers: %v\n", cfg.Upstream.Servers)

	if cfg.Upstream.Strategy != "round_robin" {
		t.Errorf("expected strategy 'round_robin', got %q", cfg.Upstream.Strategy)
	}
}
