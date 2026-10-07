package config

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
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

	// itemContentIndent maps the indentation of the most recent open line
	// that starts with a block-sequence dash to the indentation of the content
	// after that dash ("    - k: v" → 4 → 6). The item's later keys sit at
	// the content indentation, which never became an indent-stack level when
	// the item's first key had a nested block value (F184).
	itemContentIndent map[int]int
	lineIndent        int // indentation of the current line

	// Max string size limit
	maxStringSize int
}

const maxQuotedStringSize = 1024 * 1024 // 1MB limit for quoted strings

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
		// A colon is the mapping indicator only when followed by whitespace,
		// end of line, or a flow indicator; otherwise it starts a plain
		// scalar such as the IPv6 address "::1/128" (YAML 1.2 §7.3.3) or
		// "::" (readScalar keeps a colon run whole, F577).
		if next := t.peekNext(); !strings.ContainsRune(" \t\n\r,[]{}", rune(next)) && next != 0 {
			return t.readScalar()
		}
		return t.emitChar(TokenColon)
	case '-':
		// Check if it's a number (negative) or dash
		if t.isNumberStart() {
			return t.readNumber()
		}
		// A '-' at end of line or followed by white space is a block-sequence
		// marker, which the parser consumes structurally (TokenDash). A '-'
		// glued to a non-space character instead begins a plain scalar: "-abc"
		// is the string "-abc". Emitting TokenDash there yielded an empty
		// value, so read the scalar instead.
		if next := t.peekNext(); next != 0 && !isSpaceByte(next) {
			return t.readScalar()
		}
		t.recordItemContentIndent()
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
		t.next() // consume '|'
		return Token{Type: TokenError, Value: fmt.Sprintf("YAML block scalar (|) is not supported at line %d; use quoted strings instead", t.line), Line: t.line, Col: t.col - 1}
	case '>':
		t.next() // consume '>'
		return Token{Type: TokenError, Value: fmt.Sprintf("YAML folded scalar (>) is not supported at line %d; use quoted strings instead", t.line), Line: t.line, Col: t.col - 1}
	case '!':
		t.next() // consume '!'
		return Token{Type: TokenError, Value: fmt.Sprintf("YAML tags (!) are not supported at line %d", t.line), Line: t.line, Col: t.col - 1}
	case '&':
		t.next() // consume '&'
		return Token{Type: TokenError, Value: fmt.Sprintf("YAML anchors (&) are not supported at line %d", t.line), Line: t.line, Col: t.col - 1}
	case '*':
		// Could be an alias (*alias) or the start of a quoted string in flow style.
		// In block context, '*' at the start of a value is always an alias.
		t.next() // consume '*'
		return Token{Type: TokenError, Value: fmt.Sprintf("YAML aliases (*) are not supported at line %d", t.line), Line: t.line, Col: t.col - 1}
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

	// A tab in the leading white space does not count as indentation. On a
	// blank or comment-only line it is harmless separation (F183); on a
	// content line YAML forbids it, and counting it as nothing silently
	// re-nested the line under the wrong parent (F182).
	tabbed := false
	for t.peek() == ' ' || t.peek() == '\t' {
		if t.peek() == '\t' {
			tabbed = true
		}
		t.next()
	}

	// Skip blank lines
	if t.peek() == '\n' || t.peek() == '\r' || t.peek() == '#' || t.peek() == 0 {
		return t.emit(TokenEOF, "") // Signal to continue
	}

	if tabbed {
		return t.emit(TokenError, fmt.Sprintf("tab character in indentation at line %d; indent with spaces", t.line))
	}

	// This line replaces whatever line last opened this indentation; a dash
	// on it re-records the item content indentation.
	t.lineIndent = indent
	delete(t.itemContentIndent, indent)

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
		if top := t.indentStack[len(t.indentStack)-1]; indent != top {
			// Returning to the content column of the sequence item opened
			// at the new top level ("- k:" + nested block + "  m: v") is a
			// valid level that was never pushed: push it now (F184).
			if c, ok := t.itemContentIndent[top]; !ok || c != indent {
				return t.emit(TokenError, fmt.Sprintf("inconsistent indentation at line %d", t.line))
			}
			t.indentStack = append(t.indentStack, indent)
		}
		// Buffer extra DEDENTs beyond the first
		for i := 1; i < popCount; i++ {
			t.pendingTokens = append(t.pendingTokens, t.emit(TokenDedent, ""))
		}
		return t.emit(TokenDedent, "")
	}

	return t.emit(TokenEOF, "") // No change, signal to continue
}

// recordItemContentIndent remembers, for a block-sequence dash that is the
// first token of its line, the indentation of the content following it.
func (t *Tokenizer) recordItemContentIndent() {
	if t.col-1 != t.lineIndent {
		return // not the line's first token (e.g. a compact nested dash)
	}
	pos := t.pos + 1
	for pos < len(t.input) && (t.input[pos] == ' ' || t.input[pos] == '\t') {
		pos++
	}
	if pos >= len(t.input) || strings.ContainsRune("\n\r#", rune(t.input[pos])) {
		return // no content on the dash line
	}
	if t.itemContentIndent == nil {
		t.itemContentIndent = make(map[int]int)
	}
	t.itemContentIndent[t.lineIndent] = t.lineIndent + (pos - t.pos)
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

// readQuotedString reads a single or double quoted string.
func (t *Tokenizer) readQuotedString() Token {
	// Capture the position of the opening quote, not of the first content
	// character. A token's column is where it starts in the source, and the
	// parser uses key columns to decide which mapping a key belongs to — so
	// reporting `"key"` one column to the right of a plain `key` at the same
	// indentation made a quoted key look more deeply indented than it is.
	startLine := t.line
	startCol := t.col
	quote := t.next()

	limit := t.maxStringSize
	if limit == 0 {
		limit = maxQuotedStringSize
	}
	var value strings.Builder
	for {
		ch := t.peek()
		if ch == 0 {
			return t.emit(TokenError, "unterminated string")
		}

		if ch == quote {
			if quote == '\'' && t.peekNext() == '\'' {
				// YAML 1.2 §7.3.1: '' inside a single-quoted string is an
				// escaped literal quote — consume both, emit one.
				t.next()
				t.next()
				value.WriteByte('\'')
				continue
			}
			t.next()
			break
		}

		if value.Len() >= limit {
			return t.emit(TokenError, fmt.Sprintf("quoted string exceeds %d byte limit", limit))
		}

		if ch == '\\' && quote == '"' {
			t.next()
			if err := t.readEscape(&value); err != "" {
				return Token{Type: TokenError, Value: err, Line: t.line, Col: t.col}
			}
		} else {
			value.WriteByte(t.next())
		}
	}

	return Token{Type: TokenString, Value: value.String(), Line: startLine, Col: startCol}
}

// readEscape decodes one YAML 1.2 double-quoted escape sequence (§5.7), the
// backslash already consumed, into value. Escapes outside the YAML set are
// an error: silently dropping the backslash corrupted values such as
// "C:\data" into "C:data", and \x / \u / \U were decoded as literal
// letters (F185).
func (t *Tokenizer) readEscape(value *strings.Builder) string {
	esch := t.next()
	switch esch {
	case '0':
		value.WriteByte(0)
	case 'a':
		value.WriteByte('\a')
	case 'b':
		value.WriteByte('\b')
	case 't', '\t':
		value.WriteByte('\t')
	case 'n':
		value.WriteByte('\n')
	case 'v':
		value.WriteByte('\v')
	case 'f':
		value.WriteByte('\f')
	case 'r':
		value.WriteByte('\r')
	case 'e':
		value.WriteByte(0x1b)
	case ' ', '"', '/', '\\':
		value.WriteByte(esch)
	case 'N':
		value.WriteRune('\u0085')
	case '_':
		value.WriteRune('\u00a0')
	case 'L':
		value.WriteRune('\u2028')
	case 'P':
		value.WriteRune('\u2029')
	case 'x', 'u', 'U':
		n := map[byte]int{'x': 2, 'u': 4, 'U': 8}[esch]
		if t.pos+n > len(t.input) {
			return fmt.Sprintf("invalid escape \\%c in double-quoted string at line %d", esch, t.line)
		}
		code, err := strconv.ParseUint(t.input[t.pos:t.pos+n], 16, 32)
		if err != nil || !utf8.ValidRune(rune(code)) {
			return fmt.Sprintf("invalid escape \\%c%s in double-quoted string at line %d", esch, t.input[t.pos:t.pos+n], t.line)
		}
		for i := 0; i < n; i++ {
			t.next()
		}
		value.WriteRune(rune(code))
	case '\r', '\n':
		// Escaped line break: the break and the next line's leading white
		// space are dropped.
		if esch == '\r' {
			if t.peek() == '\n' {
				t.next()
			} else {
				t.line++ // next() only counts '\n'
				t.col = 1
			}
		}
		for t.peek() == ' ' || t.peek() == '\t' {
			t.next()
		}
	case 0:
		return "unterminated string"
	default:
		return fmt.Sprintf("invalid escape \\%c in double-quoted string at line %d", esch, t.line)
	}
	return ""
}

// isNumberStart checks if current position starts a number.
func (t *Tokenizer) isNumberStart() bool {
	ch := t.peek()
	hasSign := false
	if ch == '-' || ch == '+' {
		// A sign must be followed by a digit or dot. Do not return true here:
		// the rest of the token still has to be scanned, or "-7#tag" is read
		// as the number -7 and "#tag" is silently dropped as a comment.
		if t.pos+1 >= len(t.input) {
			return false
		}
		next := t.input[t.pos+1]
		if !unicode.IsDigit(rune(next)) && next != '.' {
			return false
		}
		hasSign = true
	} else if !unicode.IsDigit(rune(ch)) {
		return false
	}

	// Scan ahead to count dots in this token
	// Valid numbers have 0 or 1 dots. Multiple dots means IP/version.
	start := t.pos
	pos := start
	dotCount := 0

	// Skip an optional sign, then the first digit(s)
	if hasSign {
		pos++
	}
	for pos < len(t.input) && unicode.IsDigit(rune(t.input[pos])) {
		pos++
	}

	// Continue scanning through the token
	for pos < len(t.input) {
		ch := t.input[pos]
		// Stop at whitespace or structural characters
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == ',' || ch == ']' || ch == '}' || ch == 0 {
			break
		}
		// A '#' ends the number only when white space separates it (YAML
		// §7.3.1: a comment must be separated from the preceding token).
		// Glued to the digits it belongs to the token, so "123#abc" is a plain
		// scalar rather than the number 123 — return false and let readScalar
		// keep it whole.
		if ch == '#' {
			if isSpaceByte(t.input[pos-1]) {
				break
			}
			return false
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
		} else if (ch == '+' || ch == '-') && t.input[pos-1] != 'e' && t.input[pos-1] != 'E' {
			// A sign is numeric only as an exponent sign ("5e-3"); inside a
			// digit run it makes a plain scalar ("2024-01-15", "10-20") that
			// readNumber would otherwise split into several NUMBER tokens (F186).
			return false
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

// isSpaceByte reports whether b is a YAML white-space character. Used to
// decide whether a '#' begins a comment (it must be preceded by white space)
// rather than being part of the scalar itself.
func isSpaceByte(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// readScalar reads an unquoted scalar value.
func (t *Tokenizer) readScalar() Token {
	start := t.pos
	startCol := t.col
	inEnvBraced := false

	for {
		ch := t.peek()
		if ch == 0 || ch == '\n' || ch == '\r' {
			break
		}
		// '#' only starts a comment at the start of the scalar or when
		// preceded by whitespace (YAML §7.3.1: a comment must be separated
		// from the preceding token by white space). Breaking on every '#'
		// truncated any unquoted value containing one — "api_key: abc#def"
		// silently became "abc" with the remainder dropped as a comment.
		if ch == '#' && (t.pos == start || isSpaceByte(t.input[t.pos-1])) {
			break
		}
		if inEnvBraced {
			t.next()
			if ch == '}' {
				inEnvBraced = false
			}
			continue
		}
		if ch == '{' && t.pos > start && t.input[t.pos-1] == '$' {
			inEnvBraced = true
			t.next()
			continue
		}
		// Stop at structural characters
		if ch == ',' || ch == '[' || ch == ']' || ch == '{' || ch == '}' {
			break
		}
		// Stop at colon only if followed by whitespace (key separator).
		// Deliberate deviation from strict YAML (F577): a colon that directly
		// follows another colon is never a mapping indicator, so an IPv6
		// address ending in "::" ("::", "fe80::", "2001:db8::") stays one
		// scalar instead of becoming the mapping {"<addr>:": null}.
		if ch == ':' && (t.pos == start || t.input[t.pos-1] != ':') {
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
