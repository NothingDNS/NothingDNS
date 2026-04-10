package config

// TokenType represents the type of a YAML token.
type TokenType int

const (
	// Special tokens
	TokenEOF TokenType = iota
	TokenError

	// Structural tokens
	TokenIndent   // Indentation (tracked for block context)
	TokenDedent   // Decrease in indentation
	TokenNewline  // Line break
	TokenColon    // ':' key-value separator
	TokenDash     // '-' sequence item marker
	TokenComma    // ',' (for flow style)
	TokenLBrace   // '{' (flow mapping)
	TokenRBrace   // '}' (flow mapping)
	TokenLBracket // '[' (flow sequence)
	TokenRBracket // ']' (flow sequence)

	// Scalar tokens
	TokenString // Regular string/scalar
	TokenNumber // Integer or float
	TokenBool   // true/false
	TokenNull   // null, ~, empty

	// Special markers
	TokenComment // # comment
	TokenAnchor  // &anchor
	TokenAlias   // *alias
	TokenTag     // !tag
	TokenPipe    // | literal block scalar
	TokenGreater // > folded block scalar
)

// String returns the human-readable name of a token type.
func (t TokenType) String() string {
	switch t {
	case TokenEOF:
		return "EOF"
	case TokenError:
		return "ERROR"
	case TokenIndent:
		return "INDENT"
	case TokenDedent:
		return "DEDENT"
	case TokenNewline:
		return "NEWLINE"
	case TokenColon:
		return "COLON"
	case TokenDash:
		return "DASH"
	case TokenComma:
		return "COMMA"
	case TokenLBrace:
		return "LBRACE"
	case TokenRBrace:
		return "RBRACE"
	case TokenLBracket:
		return "LBRACKET"
	case TokenRBracket:
		return "RBRACKET"
	case TokenString:
		return "STRING"
	case TokenNumber:
		return "NUMBER"
	case TokenBool:
		return "BOOL"
	case TokenNull:
		return "NULL"
	case TokenComment:
		return "COMMENT"
	case TokenAnchor:
		return "ANCHOR"
	case TokenAlias:
		return "ALIAS"
	case TokenTag:
		return "TAG"
	case TokenPipe:
		return "PIPE"
	case TokenGreater:
		return "GREATER"
	default:
		return "UNKNOWN"
	}
}

// Token represents a single lexical token in YAML.
type Token struct {
	Type  TokenType
	Value string
	Line  int
	Col   int
}

// String returns a human-readable representation of the token.
func (t Token) String() string {
	if t.Type == TokenEOF {
		return "EOF"
	}
	if t.Type == TokenString || t.Type == TokenNumber || t.Type == TokenBool {
		return t.Type.String() + "(" + t.Value + ")"
	}
	return t.Type.String()
}
