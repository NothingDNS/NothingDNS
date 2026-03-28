package config

import (
	"fmt"
	"testing"
)

func TestDebugTokenizer(t *testing.T) {
	// Test: inline "- name:" followed by newline + value
	input := "items:\n  - name:\n      test\n  - end"
	t.Logf("Input:\n%s", input)
	tok := NewTokenizer(input)
	for {
		tok2 := tok.Next()
		fmt.Printf("Token: %-12s Value: %q Line: %d\n", tok2.Type, tok2.Value, tok2.Line)
		if tok2.Type == TokenEOF || tok2.Type == TokenError {
			break
		}
	}
}
