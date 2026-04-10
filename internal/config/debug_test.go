package config

import (
	"fmt"
	"testing"
)

func TestDebugComments(t *testing.T) {
	input := `# This is a comment
key: value # inline comment
# Another comment`

	tokenizer := NewTokenizer(input)
	tokens := tokenizer.TokenizeAll()

	for i, tok := range tokens {
		fmt.Printf("Token[%d]: Type=%s Value=%q Line=%d Col=%d\n", i, tok.Type, tok.Value, tok.Line, tok.Col)
	}
}
