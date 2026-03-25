package config

import (
	"testing"
)

func TestTokenizerBasic(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []TokenType
	}{
		{
			name:     "empty",
			input:    "",
			expected: []TokenType{TokenEOF},
		},
		{
			name:     "simple scalar",
			input:    "hello",
			expected: []TokenType{TokenString, TokenEOF},
		},
		{
			name:     "number",
			input:    "123",
			expected: []TokenType{TokenNumber, TokenEOF},
		},
		{
			name:     "negative number",
			input:    "-45",
			expected: []TokenType{TokenNumber, TokenEOF},
		},
		{
			name:     "float",
			input:    "3.14",
			expected: []TokenType{TokenNumber, TokenEOF},
		},
		{
			name:     "true bool",
			input:    "true",
			expected: []TokenType{TokenBool, TokenEOF},
		},
		{
			name:     "false bool",
			input:    "false",
			expected: []TokenType{TokenBool, TokenEOF},
		},
		{
			name:     "null",
			input:    "null",
			expected: []TokenType{TokenNull, TokenEOF},
		},
		{
			name:     "colon",
			input:    ":",
			expected: []TokenType{TokenColon, TokenEOF},
		},
		{
			name:     "dash",
			input:    "-",
			expected: []TokenType{TokenDash, TokenEOF},
		},
		{
			name:     "braces",
			input:    "{}",
			expected: []TokenType{TokenLBrace, TokenRBrace, TokenEOF},
		},
		{
			name:     "brackets",
			input:    "[]",
			expected: []TokenType{TokenLBracket, TokenRBracket, TokenEOF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenizer := NewTokenizer(tt.input)
			tokens := tokenizer.TokenizeAll()

			if len(tokens) != len(tt.expected) {
				t.Errorf("expected %d tokens, got %d", len(tt.expected), len(tokens))
				return
			}

			for i, tok := range tokens {
				if tok.Type != tt.expected[i] {
					t.Errorf("token %d: expected %v, got %v", i, tt.expected[i], tok.Type)
				}
			}
		})
	}
}

func TestTokenizerNewlines(t *testing.T) {
	input := `foo
bar
baz`
	tokenizer := NewTokenizer(input)
	tokens := tokenizer.TokenizeAll()

	expected := []TokenType{TokenString, TokenNewline, TokenString, TokenNewline, TokenString, TokenEOF}
	if len(tokens) != len(expected) {
		t.Fatalf("expected %d tokens, got %d", len(expected), len(tokens))
	}

	for i, tok := range tokens {
		if tok.Type != expected[i] {
			t.Errorf("token %d: expected %v, got %v", i, expected[i], tok.Type)
		}
	}
}

func TestTokenizerIndentation(t *testing.T) {
	input := `root:
  child1:
    grandchild: value
  child2: value2`

	tokenizer := NewTokenizer(input)
	tokens := tokenizer.TokenizeAll()

	// Collect token types
	var types []TokenType
	for _, tok := range tokens {
		types = append(types, tok.Type)
	}

	// Check that we have proper indentation tokens
	hasIndent := false
	hasDedent := false
	for _, tt := range types {
		if tt == TokenIndent {
			hasIndent = true
		}
		if tt == TokenDedent {
			hasDedent = true
		}
	}

	if !hasIndent {
		t.Error("expected at least one INDENT token")
	}
	if !hasDedent {
		t.Error("expected at least one DEDENT token")
	}
}

func TestTokenizerQuotedStrings(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "double quoted",
			input:    `"hello world"`,
			expected: "hello world",
		},
		{
			name:     "single quoted",
			input:    `'hello world'`,
			expected: "hello world",
		},
		{
			name:     "escaped newline",
			input:    `"hello\nworld"`,
			expected: "hello\nworld",
		},
		{
			name:     "escaped tab",
			input:    `"hello\tworld"`,
			expected: "hello\tworld",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenizer := NewTokenizer(tt.input)
			tok := tokenizer.Next()

			if tok.Type != TokenString {
				t.Errorf("expected STRING token, got %v", tok.Type)
			}
			if tok.Value != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, tok.Value)
			}
		})
	}
}

func TestTokenizerComments(t *testing.T) {
	input := `# This is a comment
key: value # inline comment
# Another comment`

	tokenizer := NewTokenizer(input)
	tokens := tokenizer.TokenizeAll()

	// Should have: key, :, value, EOF
	// Comments should be skipped or returned as Comment tokens
	var values []string
	for _, tok := range tokens {
		if tok.Type == TokenString || tok.Type == TokenComment {
			values = append(values, tok.Value)
		}
	}

	expected := []string{"This is a comment", "key", "value", "inline comment", "Another comment"}
	if len(values) != len(expected) {
		t.Errorf("expected %d values, got %d: %v", len(expected), len(values), values)
	} else {
		for i, exp := range expected {
			if values[i] != exp {
				t.Errorf("value %d: expected %q, got %q", i, exp, values[i])
			}
		}
	}
}

func TestTokenizerFlowStyle(t *testing.T) {
	input := `{key: value, list: [a, b, c]}`
	tokenizer := NewTokenizer(input)
	tokens := tokenizer.TokenizeAll()

	expected := []TokenType{
		TokenLBrace,
		TokenString, TokenColon, TokenString, TokenComma,
		TokenString, TokenColon,
		TokenLBracket, TokenString, TokenComma, TokenString, TokenComma, TokenString, TokenRBracket,
		TokenRBrace,
		TokenEOF,
	}

	if len(tokens) != len(expected) {
		t.Fatalf("expected %d tokens, got %d", len(expected), len(tokens))
	}

	for i, tok := range tokens {
		if tok.Type != expected[i] {
			t.Errorf("token %d: expected %v, got %v", i, expected[i], tok.Type)
		}
	}
}

func TestTokenTypeString(t *testing.T) {
	tests := []struct {
		tt       TokenType
		expected string
	}{
		{TokenEOF, "EOF"},
		{TokenError, "ERROR"},
		{TokenString, "STRING"},
		{TokenNumber, "NUMBER"},
		{TokenBool, "BOOL"},
		{TokenColon, "COLON"},
		{TokenDash, "DASH"},
		{TokenLBrace, "LBRACE"},
		{TokenRBrace, "RBRACE"},
	}

	for _, tt := range tests {
		if got := tt.tt.String(); got != tt.expected {
			t.Errorf("TokenType(%d).String() = %q, want %q", tt.tt, got, tt.expected)
		}
	}
}
