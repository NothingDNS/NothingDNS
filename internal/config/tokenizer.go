package config

import (
	"fmt"
	"strings"
	"unicode"
)

// Tokenizer converts YAML input into a stream of tokens.
type Tokenizer struct {
	input string
	pos   int // current position in input
	line  int // current line (1-indexed)
	col   int // current column (1-indexed)

	// Indentation tracking
	indentStack   []int
	atLineStart   bool
	pendingTokens []Token // buffered DEDENT tokens for multi-level dedents
}

// NewTokenizer creates a new tokenizer for the given input.
func NewTokenizer(input string) *Tokenizer {
	return &Tokenizer{
		input:       input,
		pos:         0,
		line:        1,
		col:         1,
		indentStack: []int{0},
		atLineStart: true,
	}
}

// Next returns the next token from the input.
func (t *Tokenizer) Next() Token {
	// Return buffered DEDENT tokens first
	if len(t.pendingTokens) > 0 {
		tok := t.pendingTokens[0]
		t.pendingTokens = t.pendingTokens[1:]
		return tok
	}

	// Handle end of input
	if t.pos >= len(t.input) {
		return t.emitEOF()
	}

	// At line start, check for indentation changes BEFORE skipping spaces
	if t.atLineStart {
		if tok := t.checkIndent(); tok.Type != TokenEOF {
			return tok
		}
	}

	// Skip whitespace (but not newlines)
	t.skipSpaces()

	// Handle end of input after skipping spaces
	if t.pos >= len(t.input) {
		return t.emitEOF()
	}

	ch := t.peek()

	// Handle line breaks
	if ch == '\n' || ch == '\r' {
		return t.handleNewline()
	}

	// Skip comments
	if ch == '#' {
		return t.readComment()
	}

	// Handle structural characters
	switch ch {
	case ':':
		return t.emitChar(TokenColon)
	case '-':
		// Check if it's a number (negative) or dash
		if t.isNumberStart() {
			return t.readNumber()
		}
		return t.emitChar(TokenDash)
	case ',':
		return t.emitChar(TokenComma)
	case '{':
		return t.emitChar(TokenLBrace)
	case '}':
		return t.emitChar(TokenRBrace)
	case '[':
		return t.emitChar(TokenLBracket)
	case ']':
		return t.emitChar(TokenRBracket)
	case '|':
		return t.emitChar(TokenPipe)
	case '>':
		return t.emitChar(TokenGreater)
	case '!':
		return t.readTag()
	case '&':
		return t.readAnchor()
	case '*':
		return t.readAlias()
	case '"', '\'':
		return t.readQuotedString()
	}

	// Handle scalars (strings, numbers, booleans, null)
	if t.isNumberStart() {
		return t.readNumber()
	}

	return t.readScalar()
}

// TokenizeAll tokenizes the entire input and returns all tokens.
func (t *Tokenizer) TokenizeAll() []Token {
	var tokens []Token
	for {
		tok := t.Next()
		tokens = append(tokens, tok)
		if tok.Type == TokenEOF || tok.Type == TokenError {
			break
		}
	}
	return tokens
}

// peek returns the current character without consuming it.
func (t *Tokenizer) peek() byte {
	if t.pos >= len(t.input) {
		return 0
	}
	return t.input[t.pos]
}

// next consumes and returns the current character.
func (t *Tokenizer) next() byte {
	if t.pos >= len(t.input) {
		return 0
	}
	ch := t.input[t.pos]
	t.pos++
	if ch == '\n' {
		t.line++
		t.col = 1
	} else {
		t.col++
	}
	return ch
}

// skipSpaces skips spaces and tabs (but not newlines).
func (t *Tokenizer) skipSpaces() {
	for {
		ch := t.peek()
		if ch != ' ' && ch != '\t' {
			break
		}
		t.next()
	}
}

// emit creates a token with the given type and value.
func (t *Tokenizer) emit(tt TokenType, value string) Token {
	return Token{Type: tt, Value: value, Line: t.line, Col: t.col - len(value)}
}

// emitChar emits a single-character token.
func (t *Tokenizer) emitChar(tt TokenType) Token {
	ch := t.next()
	return t.emit(tt, string(ch))
}

// emitEOF emits EOF and any pending dedents.
func (t *Tokenizer) emitEOF() Token {
	// Pop remaining indent levels, emitting one DEDENT per level
	if len(t.indentStack) > 1 {
		popCount := len(t.indentStack) - 1
		for i := 1; i < popCount; i++ {
			t.pendingTokens = append(t.pendingTokens, t.emit(TokenDedent, ""))
		}
		t.indentStack = t.indentStack[:1]
		return t.emit(TokenDedent, "")
	}
	return t.emit(TokenEOF, "")
}

// handleNewline processes line breaks.
func (t *Tokenizer) handleNewline() Token {
	// Consume \r\n or just \n
	if t.peek() == '\r' {
		t.next()
	}
	if t.peek() == '\n' {
		t.next()
	}
	t.atLineStart = true
	return t.emit(TokenNewline, "\n")
}

// checkIndent checks for indentation changes at line start.
func (t *Tokenizer) checkIndent() Token {
	t.atLineStart = false

	// Count leading spaces
	indent := 0
	for t.peek() == ' ' {
		indent++
		t.next()
	}

	// Skip blank lines
	if t.peek() == '\n' || t.peek() == '\r' || t.peek() == '#' || t.peek() == 0 {
		return t.emit(TokenEOF, "") // Signal to continue
	}

	currentIndent := t.indentStack[len(t.indentStack)-1]

	if indent > currentIndent {
		// Increased indent
		t.indentStack = append(t.indentStack, indent)
		return t.emit(TokenIndent, "")
	} else if indent < currentIndent {
		// Decreased indent - emit one DEDENT per popped level
		popCount := 0
		for len(t.indentStack) > 1 && indent < t.indentStack[len(t.indentStack)-1] {
			t.indentStack = t.indentStack[:len(t.indentStack)-1]
			popCount++
		}
		if indent != t.indentStack[len(t.indentStack)-1] {
			return t.emit(TokenError, fmt.Sprintf("inconsistent indentation at line %d", t.line))
		}
		// Buffer extra DEDENTs beyond the first
		for i := 1; i < popCount; i++ {
			t.pendingTokens = append(t.pendingTokens, t.emit(TokenDedent, ""))
		}
		return t.emit(TokenDedent, "")
	}

	return t.emit(TokenEOF, "") // No change, signal to continue
}

// readComment reads a comment until end of line.
func (t *Tokenizer) readComment() Token {
	start := t.pos
	startCol := t.col
	t.next() // consume '#'

	for t.peek() != '\n' && t.peek() != '\r' && t.peek() != 0 {
		t.next()
	}

	value := t.input[start+1 : t.pos] // Don't include the #
	return Token{Type: TokenComment, Value: strings.TrimSpace(value), Line: t.line, Col: startCol}
}

// readTag reads a tag (!tag).
func (t *Tokenizer) readTag() Token {
	start := t.pos
	startCol := t.col
	t.next() // consume '!'

	for {
		ch := t.peek()
		if ch == 0 || ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
			break
		}
		t.next()
	}

	return Token{Type: TokenTag, Value: t.input[start:t.pos], Line: t.line, Col: startCol}
}

// readAnchor reads an anchor (&anchor).
func (t *Tokenizer) readAnchor() Token {
	start := t.pos
	startCol := t.col
	t.next() // consume '&'

	for {
		ch := t.peek()
		if ch == 0 || ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
			break
		}
		t.next()
	}

	return Token{Type: TokenAnchor, Value: t.input[start:t.pos], Line: t.line, Col: startCol}
}

// readAlias reads an alias (*alias).
func (t *Tokenizer) readAlias() Token {
	start := t.pos
	startCol := t.col
	t.next() // consume '*'

	for {
		ch := t.peek()
		if ch == 0 || ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
			break
		}
		t.next()
	}

	return Token{Type: TokenAlias, Value: t.input[start:t.pos], Line: t.line, Col: startCol}
}

// readQuotedString reads a single or double quoted string.
func (t *Tokenizer) readQuotedString() Token {
	quote := t.next()
	startLine := t.line
	startCol := t.col

	var value strings.Builder
	for {
		ch := t.peek()
		if ch == 0 {
			return t.emit(TokenError, "unterminated string")
		}

		if ch == quote {
			t.next()
			break
		}

		if ch == '\\' && quote == '"' {
			t.next()
			esch := t.next()
			switch esch {
			case 'n':
				value.WriteByte('\n')
			case 't':
				value.WriteByte('\t')
			case 'r':
				value.WriteByte('\r')
			case '\\':
				value.WriteByte('\\')
			case '"':
				value.WriteByte('"')
			default:
				value.WriteByte(esch)
			}
		} else {
			value.WriteByte(t.next())
		}
	}

	return Token{Type: TokenString, Value: value.String(), Line: startLine, Col: startCol}
}

// isNumberStart checks if current position starts a number.
func (t *Tokenizer) isNumberStart() bool {
	ch := t.peek()
	if ch == '-' || ch == '+' {
		// Look ahead
		if t.pos+1 < len(t.input) {
			next := t.input[t.pos+1]
			return unicode.IsDigit(rune(next)) || next == '.'
		}
		return false
	}
	if !unicode.IsDigit(rune(ch)) {
		return false
	}

	// Scan ahead to count dots in this token
	// Valid numbers have 0 or 1 dots. Multiple dots means IP/version.
	start := t.pos
	pos := start
	dotCount := 0

	// Skip the first digit(s)
	for pos < len(t.input) && unicode.IsDigit(rune(t.input[pos])) {
		pos++
	}

	// Continue scanning through the token
	for pos < len(t.input) {
		ch := t.input[pos]
		// Stop at whitespace or structural characters
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == ',' || ch == ']' || ch == '}' || ch == '#' || ch == 0 {
			break
		}
		// Colon followed by space is a separator
		if ch == ':' {
			next := pos + 1
			if next >= len(t.input) || t.input[next] == ' ' || t.input[next] == '\t' || t.input[next] == '\n' || t.input[next] == '\r' {
				break
			}
		}
		if ch == '.' {
			dotCount++
			// If we see a second dot, it's not a number
			if dotCount > 1 {
				return false
			}
			// Check if dot is followed by a digit (valid decimal) or something else
			if pos+1 < len(t.input) {
				next := t.input[pos+1]
				if !unicode.IsDigit(rune(next)) {
					// Dot not followed by digit (like "1.x"), not a number
					return false
				}
			}
		} else if !unicode.IsDigit(rune(ch)) && ch != 'e' && ch != 'E' && ch != '+' && ch != '-' {
			// Non-numeric character (other than exponent), not a simple number
			return false
		}
		pos++
	}

	return true
}

// readNumber reads an integer or float.
func (t *Tokenizer) readNumber() Token {
	start := t.pos
	startCol := t.col

	// Optional sign
	if t.peek() == '-' || t.peek() == '+' {
		t.next()
	}

	// Integer part
	for unicode.IsDigit(rune(t.peek())) {
		t.next()
	}

	// Decimal part
	if t.peek() == '.' {
		t.next()
		for unicode.IsDigit(rune(t.peek())) {
			t.next()
		}
	}

	// Exponent
	if t.peek() == 'e' || t.peek() == 'E' {
		t.next()
		if t.peek() == '-' || t.peek() == '+' {
			t.next()
		}
		for unicode.IsDigit(rune(t.peek())) {
			t.next()
		}
	}

	value := t.input[start:t.pos]
	return Token{Type: TokenNumber, Value: value, Line: t.line, Col: startCol}
}

// readScalar reads an unquoted scalar value.
func (t *Tokenizer) readScalar() Token {
	start := t.pos
	startCol := t.col

	for {
		ch := t.peek()
		if ch == 0 || ch == '\n' || ch == '\r' || ch == '#' {
			break
		}
		// Stop at structural characters
		if ch == ',' || ch == '[' || ch == ']' || ch == '{' || ch == '}' {
			break
		}
		// Stop at colon only if followed by whitespace (key separator)
		if ch == ':' {
			next := t.peekNext()
			if next == ' ' || next == '\t' || next == '\n' || next == '\r' || next == 0 {
				break
			}
		}
		t.next()
	}

	value := strings.TrimSpace(t.input[start:t.pos])

	// Check for special values
	switch strings.ToLower(value) {
	case "true", "yes", "on":
		return Token{Type: TokenBool, Value: "true", Line: t.line, Col: startCol}
	case "false", "no", "off":
		return Token{Type: TokenBool, Value: "false", Line: t.line, Col: startCol}
	case "null", "~", "":
		return Token{Type: TokenNull, Value: "", Line: t.line, Col: startCol}
	}

	return Token{Type: TokenString, Value: value, Line: t.line, Col: startCol}
}

// peekNext returns the next character after current without consuming anything.
func (t *Tokenizer) peekNext() byte {
	if t.pos+1 >= len(t.input) {
		return 0
	}
	return t.input[t.pos+1]
}

// CurrentIndent returns the current indentation level (depth of indentStack).
func (t *Tokenizer) CurrentIndent() int {
	return len(t.indentStack)
}
