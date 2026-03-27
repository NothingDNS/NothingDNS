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

func TestTokenizerNumberExponent(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"positive exponent", "1e10", "1e10"},
		{"uppercase exponent", "1E10", "1E10"},
		{"negative exponent", "1e-5", "1e-5"},
		{"positive sign exponent", "1e+3", "1e+3"},
		{"float with exponent", "3.14e2", "3.14e2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenizer := NewTokenizer(tt.input)
			tok := tokenizer.Next()
			if tok.Type != TokenNumber {
				t.Errorf("expected NUMBER token, got %v (value: %q)", tok.Type, tok.Value)
			}
			if tok.Value != tt.expected {
				t.Errorf("expected value %q, got %q", tt.expected, tok.Value)
			}
		})
	}
}

func TestTokenizerPositiveNumber(t *testing.T) {
	// Test positive sign number (+ prefix)
	tokenizer := NewTokenizer("+42")
	tok := tokenizer.Next()
	if tok.Type != TokenNumber {
		t.Errorf("expected NUMBER token, got %v", tok.Type)
	}
}

func TestTokenizerNumberAtEOF(t *testing.T) {
	// Test number at end of input (readNumber reading digits until EOF)
	tokenizer := NewTokenizer("42")
	tok := tokenizer.Next()
	if tok.Type != TokenNumber {
		t.Errorf("expected NUMBER token, got %v", tok.Type)
	}
	if tok.Value != "42" {
		t.Errorf("expected value '42', got %q", tok.Value)
	}
}

func TestTokenizerQuotedStringEscapeBackslash(t *testing.T) {
	// Test escaped backslash in double-quoted string
	tokenizer := NewTokenizer(`"hello\\world"`)
	tok := tokenizer.Next()
	if tok.Type != TokenString {
		t.Errorf("expected STRING, got %v", tok.Type)
	}
	if tok.Value != `hello\world` {
		t.Errorf("expected 'hello\\world', got %q", tok.Value)
	}
}

func TestTokenizerQuotedStringEscapeQuote(t *testing.T) {
	// Test escaped quote in double-quoted string
	tokenizer := NewTokenizer(`"say \"hello\""`)
	tok := tokenizer.Next()
	if tok.Type != TokenString {
		t.Errorf("expected STRING, got %v", tok.Type)
	}
	if tok.Value != `say "hello"` {
		t.Errorf("expected 'say \"hello\"', got %q", tok.Value)
	}
}

func TestTokenizerQuotedStringEscapeUnknown(t *testing.T) {
	// Test unknown escape sequence (keeps the character)
	tokenizer := NewTokenizer(`"hello\aworld"`)
	tok := tokenizer.Next()
	if tok.Type != TokenString {
		t.Errorf("expected STRING, got %v", tok.Type)
	}
	if tok.Value != "helloaworld" {
		t.Errorf("expected 'helloaworld', got %q", tok.Value)
	}
}

func TestTokenizerQuotedStringEscapeReturn(t *testing.T) {
	// Test \r escape
	tokenizer := NewTokenizer(`"hello\rworld"`)
	tok := tokenizer.Next()
	if tok.Type != TokenString {
		t.Errorf("expected STRING, got %v", tok.Type)
	}
	if tok.Value != "hello\rworld" {
		t.Errorf("expected 'hello\\rworld', got %q", tok.Value)
	}
}

func TestTokenizerCRLF(t *testing.T) {
	// Test CRLF handling
	input := "key\r\nvalue"
	tokenizer := NewTokenizer(input)
	tokens := tokenizer.TokenizeAll()

	// Should have: key, newline, value, EOF
	if len(tokens) < 3 {
		t.Fatalf("expected at least 3 tokens, got %d", len(tokens))
	}
	if tokens[0].Type != TokenString {
		t.Errorf("expected STRING, got %v", tokens[0].Type)
	}
	if tokens[1].Type != TokenNewline {
		t.Errorf("expected NEWLINE, got %v", tokens[1].Type)
	}
}

func TestTokenizerScalarWithColonNotFollowedBySpace(t *testing.T) {
	// Test: scalar containing colon not followed by space (like URL)
	tokenizer := NewTokenizer("http://example.com:8080")
	tok := tokenizer.Next()
	if tok.Type != TokenString {
		t.Errorf("expected STRING, got %v (value: %q)", tok.Type, tok.Value)
	}
	if tok.Value != "http://example.com:8080" {
		t.Errorf("expected 'http://example.com:8080', got %q", tok.Value)
	}
}

func TestTokenizerEmptyInput(t *testing.T) {
	tokenizer := NewTokenizer("")
	tok := tokenizer.Next()
	if tok.Type != TokenEOF {
		t.Errorf("expected EOF, got %v", tok.Type)
	}
}

func TestTokenizerPipeToken(t *testing.T) {
	tokenizer := NewTokenizer("|")
	tok := tokenizer.Next()
	if tok.Type != TokenPipe {
		t.Errorf("expected PIPE, got %v", tok.Type)
	}
}

func TestTokenizerGreaterToken(t *testing.T) {
	tokenizer := NewTokenizer(">")
	tok := tokenizer.Next()
	if tok.Type != TokenGreater {
		t.Errorf("expected GREATER, got %v", tok.Type)
	}
}

func TestTokenizerIsNumberStartMultipleDots(t *testing.T) {
	// Test: value with multiple dots should not be treated as number (e.g., IP address)
	tokenizer := NewTokenizer("192.168.1.1")
	tok := tokenizer.Next()
	if tok.Type == TokenNumber {
		t.Errorf("IP address should not be tokenized as NUMBER, got %v (value: %q)", tok.Type, tok.Value)
	}
}

func TestTokenizerIsNumberStartDotNoDigit(t *testing.T) {
	// Test: digit followed by dot and non-digit (e.g., "1.x")
	tokenizer := NewTokenizer("1.x")
	tok := tokenizer.Next()
	if tok.Type == TokenNumber {
		t.Errorf("'1.x' should not be tokenized as NUMBER, got %v", tok.Type)
	}
}

func TestTokenizerNegativeDash(t *testing.T) {
	// Test: dash not followed by digit (should be DASH, not negative number)
	tokenizer := NewTokenizer("- item")
	tok := tokenizer.Next()
	if tok.Type != TokenDash {
		t.Errorf("expected DASH, got %v", tok.Type)
	}
}

func TestTokenizerBlankLine(t *testing.T) {
	// Test: blank line handling
	input := "key:\n\nvalue"
	tokenizer := NewTokenizer(input)
	tokens := tokenizer.TokenizeAll()

	if len(tokens) == 0 {
		t.Fatal("expected tokens")
	}
}

func TestTokenizerCommentOnlyLine(t *testing.T) {
	// Test: line with only a comment after newline
	input := "key:\n  # comment\n  value"
	tokenizer := NewTokenizer(input)
	tokens := tokenizer.TokenizeAll()

	if len(tokens) == 0 {
		t.Fatal("expected tokens")
	}
}
