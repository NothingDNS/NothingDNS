package config

import (
	"fmt"
)

// Maximum YAML nesting depth to prevent stack overflow DoS.
const maxYAMLDepth = 100

// Parser converts YAML tokens into a tree structure.
type Parser struct {
	tokenizer *Tokenizer
	current   Token
	peekToken Token
	hasPeek   bool
	depth     int // current recursion depth
}

// NewParser creates a new parser for the given input.
func NewParser(input string) *Parser {
	p := &Parser{
		tokenizer: NewTokenizer(input),
	}
	p.advance() // Load first token
	return p
}

// Parse parses the entire YAML document and returns the root node.
func (p *Parser) Parse() (*Node, error) {
	// Skip initial newlines
	for p.current.Type == TokenNewline {
		p.advance()
	}

	// Parse the document content
	node, err := p.parseValue()
	if err != nil {
		return nil, err
	}

	// Skip trailing newlines
	for p.current.Type == TokenNewline {
		p.advance()
	}

	if p.current.Type != TokenEOF {
		return nil, fmt.Errorf("unexpected token %s at line %d", p.current.Type, p.current.Line)
	}

	return &Node{
		Type:     NodeDocument,
		Children: []*Node{node},
		Line:     1,
		Col:      1,
	}, nil
}

// ParseMapping parses a mapping specifically (for config root).
func (p *Parser) ParseMapping() (*Node, error) {
	// Skip initial newlines
	for p.current.Type == TokenNewline {
		p.advance()
	}

	var node *Node
	var err error

	// Handle both block mappings and flow mappings
	if p.current.Type == TokenLBrace {
		node, err = p.parseFlowMapping()
	} else {
		node, err = p.parseMapping(0)
	}

	if err != nil {
		return nil, err
	}

	// Skip trailing newlines
	for p.current.Type == TokenNewline {
		p.advance()
	}

	if p.current.Type != TokenEOF {
		return nil, fmt.Errorf("unexpected token %s at line %d", p.current.Type, p.current.Line)
	}

	return node, nil
}

// advance moves to the next token, skipping comment tokens.
func (p *Parser) advance() {
	for {
		if p.hasPeek {
			p.current = p.peekToken
			p.hasPeek = false
		} else {
			p.current = p.tokenizer.Next()
		}
		if p.current.Type != TokenComment {
			break
		}
	}
}

// peek returns the next non-comment token without consuming it.
func (p *Parser) peek() Token {
	if !p.hasPeek {
		for {
			p.peekToken = p.tokenizer.Next()
			if p.peekToken.Type != TokenComment {
				break
			}
		}
		p.hasPeek = true
	}
	return p.peekToken
}

// expect checks that the current token is of the expected type and advances.
func (p *Parser) expect(tt TokenType) error {
	if p.current.Type != tt {
		return fmt.Errorf("expected %s but got %s at line %d", tt, p.current.Type, p.current.Line)
	}
	p.advance()
	return nil
}

// parseValue parses any YAML value.
func (p *Parser) parseValue() (*Node, error) {
	if p.depth > maxYAMLDepth {
		return nil, fmt.Errorf("yaml nesting depth exceeds maximum (%d levels) at line %d", maxYAMLDepth, p.current.Line)
	}
	switch p.current.Type {
	case TokenLBrace:
		return p.parseFlowMapping()
	case TokenLBracket:
		return p.parseFlowSequence()
	case TokenDash:
		return p.parseBlockSequence(0)
	case TokenString, TokenNumber, TokenBool, TokenNull:
		return p.parseScalar()
	case TokenIndent:
		p.advance()
		return p.parseValue()
	case TokenEOF:
		return nil, fmt.Errorf("unexpected EOF")
	default:
		return nil, fmt.Errorf("unexpected token %s at line %d", p.current.Type, p.current.Line)
	}
}

// parseScalar parses a scalar value.
func (p *Parser) parseScalar() (*Node, error) {
	node := &Node{
		Type:  NodeScalar,
		Value: p.current.Value,
		Line:  p.current.Line,
		Col:   p.current.Col,
	}
	p.advance()
	return node, nil
}

// parseMapping parses a block mapping.
func (p *Parser) parseMapping(indent int) (*Node, error) {
	if p.depth > maxYAMLDepth {
		return nil, fmt.Errorf("yaml nesting depth exceeds maximum (%d levels) at line %d", maxYAMLDepth, p.current.Line)
	}
	p.depth++
	defer func() { p.depth-- }()
	node := &Node{
		Type: NodeMapping,
		Line: p.current.Line,
		Col:  p.current.Col,
	}
	seenKeys := make(map[string]struct{})

	// Column of this mapping's first key. Every later key of the same mapping
	// sits at that column; anything shallower belongs to an enclosing one.
	//
	// This used to be decided from the tokenizer's live indent level instead,
	// which cannot work: when a deeply indented block closes, the tokenizer
	// pops its whole indent stack at once and only then emits one DEDENT per
	// closed level, so CurrentIndent() already reads the final level while the
	// first of several stacked DEDENTs is still being handled. Each nested
	// parseMapping consumed exactly one DEDENT and compared against that same
	// collapsed value, which happened to come out right for one or two levels
	// of nesting and wrong for three. A key returning to column 0 after a
	// three-deep block sequence — `logging:` after `dnssec.signing.keys:`,
	// exactly the shape of the shipped example — was attached to the wrong
	// parent, and the whole section was silently dropped.
	//
	// Columns do not have that problem: they are a property of the source
	// text, not of tokenizer state, and parseBlockSequence already decides
	// its own boundaries the same way.
	keyCol := 0

	for {
		// Skip newlines at current level
		for p.current.Type == TokenNewline {
			p.advance()
		}

		// Check for end of mapping
		if p.current.Type == TokenEOF {
			break
		}

		// On DEDENT, absorb the whole run — how many there are says nothing
		// about which mapping they close — and let the column check below
		// decide whether the next key is still ours.
		if p.current.Type == TokenDedent {
			for p.current.Type == TokenDedent {
				p.advance()
			}
			continue
		}

		// Expect a key (string scalar)
		if p.current.Type != TokenString {
			if len(node.Children) > 0 {
				// We've already parsed some pairs, this is the end
				break
			}
			return nil, fmt.Errorf("expected mapping key but got %s at line %d", p.current.Type, p.current.Line)
		}

		// A key to the left of ours closes this mapping. Leaving it as the
		// current token lets the enclosing parser claim it.
		if keyCol > 0 && p.current.Col < keyCol {
			break
		}
		if keyCol == 0 {
			keyCol = p.current.Col
		}

		key := &Node{
			Type:  NodeScalar,
			Value: p.current.Value,
			Line:  p.current.Line,
			Col:   p.current.Col,
		}
		p.advance()

		// Expect colon
		if p.current.Type != TokenColon {
			return nil, fmt.Errorf("expected ':' after key but got %s at line %d", p.current.Type, p.current.Line)
		}
		p.advance()

		// Parse value
		var value *Node
		var err error

		// Skip spaces after colon
		for p.current.Type == TokenIndent {
			p.advance()
		}

		switch p.current.Type {
		case TokenNewline:
			// Value is on next line with increased indent
			p.advance()
			for p.current.Type == TokenNewline {
				p.advance()
			}
			if p.current.Type == TokenIndent {
				p.advance()
				// Parse indented content - could be mapping, sequence, or scalar
				if p.current.Type == TokenDash {
					value, err = p.parseBlockSequence(indent + 1)
				} else if p.current.Type == TokenString {
					// Could be a mapping or a scalar - try mapping first
					value, err = p.parseMapping(indent + 1)
				} else {
					value, err = p.parseValue()
				}
			} else if p.current.Type == TokenDash {
				value, err = p.parseBlockSequence(indent + 1)
			} else {
				// Empty value or inline
				value = &Node{Type: NodeScalar, Value: ""}
			}
		case TokenIndent:
			p.advance()
			value, err = p.parseValue()
		case TokenLBrace:
			value, err = p.parseFlowMapping()
		case TokenLBracket:
			value, err = p.parseFlowSequence()
		case TokenDash:
			value, err = p.parseBlockSequence(indent + 1)
		case TokenString, TokenNumber, TokenBool, TokenNull:
			value, err = p.parseScalar()
			// After scalar, if we see DEDENT, consume it (it's the end of current block)
			if err == nil && p.current.Type == TokenDedent {
				p.advance()
			}
		default:
			// Empty value after a colon is valid YAML (e.g. "key:").
			// But an unexpected token means silent data loss — surface as error.
			if p.current.Type == TokenNewline || p.current.Type == TokenEOF {
				value = &Node{Type: NodeScalar, Value: ""}
			} else {
				return nil, fmt.Errorf("unexpected token %s after key at line %d", p.current.Type, p.current.Line)
			}
		}

		if err != nil {
			return nil, err
		}

		if err := addMappingPair(node, seenKeys, key, value); err != nil {
			return nil, err
		}

		// Check for end of mapping after a pair
		for p.current.Type == TokenNewline {
			p.advance()
		}

		// A DEDENT after a value is handled at the top of the loop, where the
		// run is absorbed and the next key's column decides whether this
		// mapping continues. Breaking here on a tokenizer indent comparison
		// would re-introduce the miscount this mapping's keyCol replaced.
	}

	return node, nil
}

// parseBlockSequence parses a block sequence (list with - items).
func (p *Parser) parseBlockSequence(indent int) (*Node, error) {
	if p.depth > maxYAMLDepth {
		return nil, fmt.Errorf("yaml nesting depth exceeds maximum (%d levels) at line %d", maxYAMLDepth, p.current.Line)
	}
	p.depth++
	defer func() { p.depth-- }()
	node := &Node{
		Type: NodeSequence,
		Line: p.current.Line,
		Col:  p.current.Col,
	}

	// Column of the FIRST dash. Subsequent items must be at this same
	// column to belong to this sequence; a dash at a shallower column
	// belongs to an enclosing sequence (terminator for ours).
	sequenceDashCol := p.current.Col

	for {
		// Expect dash
		if p.current.Type != TokenDash {
			break
		}
		p.advance()

		// Parse item value
		var value *Node
		var err error

		// Skip spaces after dash
		for p.current.Type == TokenIndent {
			p.advance()
		}

		switch p.current.Type {
		case TokenNewline:
			p.advance()
			for p.current.Type == TokenNewline {
				p.advance()
			}
			if p.current.Type == TokenIndent {
				p.advance()
			}
			if p.current.Type == TokenDash {
				// Nested sequence
				value, err = p.parseBlockSequence(indent + 1)
			} else if p.current.Type == TokenString {
				// Check if this is a mapping
				savedKey := &Node{
					Type:  NodeScalar,
					Value: p.current.Value,
					Line:  p.current.Line,
					Col:   p.current.Col,
				}
				next := p.peek()
				if next.Type == TokenColon {
					// It's a mapping - consume the peeked token
					p.hasPeek = false
					// Parse it manually since we consumed the first key via peek
					p.current = next // Now at COLON
					p.advance()      // Consume colon
					// Parse value after colon
					var valNode *Node
					switch p.current.Type {
					case TokenNewline:
						p.advance()
						for p.current.Type == TokenNewline {
							p.advance()
						}
						if p.current.Type == TokenIndent {
							p.advance()
						}
						if p.current.Type == TokenDash {
							valNode, err = p.parseBlockSequence(indent + 1)
						} else if p.current.Type == TokenString {
							// Check if nested mapping
							next2 := p.peek()
							if next2.Type == TokenColon {
								p.hasPeek = false
								p.current = next2
								valNode, err = p.parseMapping(indent + 1)
							} else {
								valNode = &Node{Type: NodeScalar, Value: p.current.Value}
								p.advance()
							}
						} else {
							valNode, err = p.parseValue()
						}
					case TokenIndent:
						p.advance()
						valNode, err = p.parseValue()
					case TokenLBrace:
						valNode, err = p.parseFlowMapping()
					case TokenLBracket:
						valNode, err = p.parseFlowSequence()
					case TokenDash:
						valNode, err = p.parseBlockSequence(indent + 1)
					case TokenString, TokenNumber, TokenBool, TokenNull:
						valNode, err = p.parseScalar()
					default:
						valNode = &Node{Type: NodeScalar, Value: ""}
					}
					if err != nil {
						return nil, err
					}
					value = &Node{
						Type: NodeMapping,
						Line: savedKey.Line,
						Col:  savedKey.Col,
					}
					seenItemKeys := make(map[string]struct{})
					if err := addMappingPair(value, seenItemKeys, savedKey, valNode); err != nil {
						return nil, err
					}
					// Continue parsing rest of mapping if more keys
					// Parse additional key-value pairs that belong to THIS
					// sequence-item mapping. After a DEDENT, peek the
					// next significant token: if it's at or beyond the
					// item's first-key column, the dedent is internal
					// (closure of a nested seq / map) and we continue.
					// Otherwise it crossed the item boundary — break
					// and let the enclosing parser see the dedent.
					itemCol := savedKey.Col
					for {
						for p.current.Type == TokenNewline || p.current.Type == TokenIndent {
							p.advance()
						}
						if p.current.Type == TokenEOF {
							break
						}
						if p.current.Type == TokenDedent {
							next := p.peek()
							if next.Type == TokenString && next.Col >= itemCol {
								// Internal dedent — absorb and continue.
								p.advance()
								continue
							}
							// Crossed the item boundary; leave dedent
							// for the enclosing parser.
							break
						}
						if p.current.Type != TokenString {
							break
						}
						k := &Node{
							Type:  NodeScalar,
							Value: p.current.Value,
							Line:  p.current.Line,
							Col:   p.current.Col,
						}
						p.advance()
						if p.current.Type != TokenColon {
							break
						}
						p.advance()
						var v *Node
						switch p.current.Type {
						case TokenNewline:
							p.advance()
							for p.current.Type == TokenNewline {
								p.advance()
							}
							if p.current.Type == TokenIndent {
								p.advance()
							}
							if p.current.Type == TokenDash {
								v, err = p.parseBlockSequence(indent + 1)
							} else if p.current.Type == TokenString && p.peek().Type == TokenColon {
								v, err = p.parseMapping(indent + 1)
							} else {
								v, err = p.parseValue()
							}
						case TokenIndent:
							p.advance()
							v, err = p.parseValue()
						case TokenLBrace:
							v, err = p.parseFlowMapping()
						case TokenLBracket:
							v, err = p.parseFlowSequence()
						case TokenDash:
							v, err = p.parseBlockSequence(indent + 1)
						case TokenString, TokenNumber, TokenBool, TokenNull:
							v, err = p.parseScalar()
						default:
							v = &Node{Type: NodeScalar, Value: ""}
						}
						if err != nil {
							return nil, err
						}
						if err := addMappingPair(value, seenItemKeys, k, v); err != nil {
							return nil, err
						}
					}
				} else {
					// Just a scalar
					value = &Node{Type: NodeScalar, Value: p.current.Value}
					p.advance()
				}
			} else {
				value = &Node{Type: NodeScalar, Value: ""}
			}
		case TokenString, TokenNumber, TokenBool, TokenNull:
			// Check if this is a mapping by looking ahead
			next := p.peek()
			if p.current.Type == TokenString && next.Type == TokenColon {
				// It's a mapping - consume the peeked token
				p.hasPeek = false
				savedKey := &Node{
					Type:  NodeScalar,
					Value: p.current.Value,
					Line:  p.current.Line,
					Col:   p.current.Col,
				}
				p.current = next // Now at COLON
				p.advance()      // Consume colon
				// Parse value after colon
				var valNode *Node
				switch p.current.Type {
				case TokenNewline:
					p.advance()
					for p.current.Type == TokenNewline {
						p.advance()
					}
					if p.current.Type == TokenIndent {
						p.advance()
					}
					if p.current.Type == TokenDash {
						valNode, err = p.parseBlockSequence(indent + 1)
					} else if p.current.Type == TokenString {
						next2 := p.peek()
						if next2.Type == TokenColon {
							p.hasPeek = false
							p.current = next2
							valNode, err = p.parseMapping(indent + 1)
						} else {
							valNode = &Node{Type: NodeScalar, Value: p.current.Value}
							p.advance()
						}
					} else {
						valNode, err = p.parseValue()
					}
				case TokenIndent:
					p.advance()
					valNode, err = p.parseValue()
				case TokenLBrace:
					valNode, err = p.parseFlowMapping()
				case TokenLBracket:
					valNode, err = p.parseFlowSequence()
				case TokenDash:
					valNode, err = p.parseBlockSequence(indent + 1)
				case TokenString, TokenNumber, TokenBool, TokenNull:
					valNode, err = p.parseScalar()
				default:
					valNode = &Node{Type: NodeScalar, Value: ""}
				}
				if err != nil {
					return nil, err
				}
				value = &Node{
					Type: NodeMapping,
					Line: savedKey.Line,
					Col:  savedKey.Col,
				}
				seenItemKeys := make(map[string]struct{})
				if err := addMappingPair(value, seenItemKeys, savedKey, valNode); err != nil {
					return nil, err
				}
				// Continue parsing rest of mapping if more keys
				// Parse additional key-value pairs that belong to THIS
				// sequence-item mapping. See sibling loop above for the
				// column-based dedent handling rationale.
				itemCol := savedKey.Col
				for {
					for p.current.Type == TokenNewline || p.current.Type == TokenIndent {
						p.advance()
					}
					if p.current.Type == TokenEOF {
						break
					}
					if p.current.Type == TokenDedent {
						next := p.peek()
						if next.Type == TokenString && next.Col >= itemCol {
							p.advance()
							continue
						}
						break
					}
					if p.current.Type != TokenString {
						break
					}
					k := &Node{
						Type:  NodeScalar,
						Value: p.current.Value,
						Line:  p.current.Line,
						Col:   p.current.Col,
					}
					p.advance()
					if p.current.Type != TokenColon {
						break
					}
					p.advance()
					var v *Node
					switch p.current.Type {
					case TokenNewline:
						p.advance()
						for p.current.Type == TokenNewline {
							p.advance()
						}
						if p.current.Type == TokenIndent {
							p.advance()
						}
						if p.current.Type == TokenDash {
							v, err = p.parseBlockSequence(indent + 1)
						} else if p.current.Type == TokenString && p.peek().Type == TokenColon {
							v, err = p.parseMapping(indent + 1)
						} else {
							v, err = p.parseValue()
						}
					case TokenIndent:
						p.advance()
						v, err = p.parseValue()
					case TokenLBrace:
						v, err = p.parseFlowMapping()
					case TokenLBracket:
						v, err = p.parseFlowSequence()
					case TokenDash:
						v, err = p.parseBlockSequence(indent + 1)
					case TokenString, TokenNumber, TokenBool, TokenNull:
						v, err = p.parseScalar()
					default:
						v = &Node{Type: NodeScalar, Value: ""}
					}
					if err != nil {
						return nil, err
					}
					if err := addMappingPair(value, seenItemKeys, k, v); err != nil {
						return nil, err
					}
				}
			} else {
				// Just a scalar
				value, err = p.parseScalar()
			}
		case TokenLBrace:
			value, err = p.parseFlowMapping()
		case TokenLBracket:
			value, err = p.parseFlowSequence()
		default:
			value = &Node{Type: NodeScalar, Value: ""}
		}

		if err != nil {
			return nil, err
		}

		node.Children = append(node.Children, value)

		// Skip newlines
		for p.current.Type == TokenNewline {
			p.advance()
		}

		// The inline-mapping continuation loops break on Dedent without
		// consuming it (so the enclosing parser sees the dedent when an
		// item ends). Between two items of THIS sequence the dedents
		// are internal closure of nested content — absorb them as long
		// as a Dash at THIS sequence's column waits behind them. A Dash
		// at a different column belongs to an enclosing sequence and we
		// leave the dedent(s) for the enclosing parser to see.
		for p.current.Type == TokenDedent {
			next := p.peek()
			if next.Type == TokenDash && next.Col == sequenceDashCol {
				// Consume this Dedent and check the next one.
				p.hasPeek = false
				p.current = next
				break
			}
			// Peek further: maybe another Dedent stacks before the dash.
			if next.Type == TokenDedent {
				p.hasPeek = false
				p.current = next
				continue
			}
			break
		}

		// Continue if we see another dash at same level
		if p.current.Type != TokenDash {
			break
		}
	}

	return node, nil
}

// parseFlowMapping parses a flow mapping {key: value, ...}.
func (p *Parser) parseFlowMapping() (*Node, error) {
	if p.depth > maxYAMLDepth {
		return nil, fmt.Errorf("yaml nesting depth exceeds maximum (%d levels) at line %d", maxYAMLDepth, p.current.Line)
	}
	p.depth++
	defer func() { p.depth-- }()
	node := &Node{
		Type: NodeMapping,
		Line: p.current.Line,
		Col:  p.current.Col,
	}
	seenKeys := make(map[string]struct{})

	p.advance() // consume '{'

	for p.current.Type != TokenRBrace {
		if p.current.Type == TokenEOF {
			return nil, fmt.Errorf("unterminated flow mapping")
		}

		// Parse key
		if p.current.Type != TokenString {
			return nil, fmt.Errorf("expected string key in flow mapping but got %s", p.current.Type)
		}
		key := &Node{
			Type:  NodeScalar,
			Value: p.current.Value,
			Line:  p.current.Line,
			Col:   p.current.Col,
		}
		p.advance()

		// Expect colon
		if p.current.Type != TokenColon {
			return nil, fmt.Errorf("expected ':' after key in flow mapping")
		}
		p.advance()

		// Parse value
		var value *Node
		var err error
		switch p.current.Type {
		case TokenString, TokenNumber, TokenBool, TokenNull:
			value, err = p.parseScalar()
		case TokenLBrace:
			value, err = p.parseFlowMapping()
		case TokenLBracket:
			value, err = p.parseFlowSequence()
		default:
			return nil, fmt.Errorf("unexpected token %s in flow mapping", p.current.Type)
		}
		if err != nil {
			return nil, err
		}

		if err := addMappingPair(node, seenKeys, key, value); err != nil {
			return nil, err
		}

		// Optional comma
		if p.current.Type == TokenComma {
			p.advance()
		}
	}

	p.advance() // consume '}'
	return node, nil
}

func addMappingPair(node *Node, seenKeys map[string]struct{}, key, value *Node) error {
	if _, exists := seenKeys[key.Value]; exists {
		return fmt.Errorf("duplicate mapping key %q at line %d", key.Value, key.Line)
	}
	seenKeys[key.Value] = struct{}{}
	node.Children = append(node.Children, key, value)
	return nil
}

// parseFlowSequence parses a flow sequence [item, ...].
func (p *Parser) parseFlowSequence() (*Node, error) {
	if p.depth > maxYAMLDepth {
		return nil, fmt.Errorf("yaml nesting depth exceeds maximum (%d levels) at line %d", maxYAMLDepth, p.current.Line)
	}
	p.depth++
	defer func() { p.depth-- }()
	node := &Node{
		Type: NodeSequence,
		Line: p.current.Line,
		Col:  p.current.Col,
	}

	p.advance() // consume '['

	for p.current.Type != TokenRBracket {
		if p.current.Type == TokenEOF {
			return nil, fmt.Errorf("unterminated flow sequence")
		}

		// Parse item
		var value *Node
		var err error
		switch p.current.Type {
		case TokenString, TokenNumber, TokenBool, TokenNull:
			value, err = p.parseScalar()
		case TokenLBrace:
			value, err = p.parseFlowMapping()
		case TokenLBracket:
			value, err = p.parseFlowSequence()
		default:
			return nil, fmt.Errorf("unexpected token %s in flow sequence", p.current.Type)
		}
		if err != nil {
			return nil, err
		}

		node.Children = append(node.Children, value)

		// Optional comma
		if p.current.Type == TokenComma {
			p.advance()
		}
	}

	p.advance() // consume ']'
	return node, nil
}

// Parse simple interface values (for unmarshaling)
func (n *Node) toInterface() interface{} {
	switch n.Type {
	case NodeScalar:
		return n.Value
	case NodeSequence:
		result := make([]interface{}, len(n.Children))
		for i, child := range n.Children {
			result[i] = child.toInterface()
		}
		return result
	case NodeMapping:
		result := make(map[string]interface{})
		for i := 0; i < len(n.Children); i += 2 {
			if i+1 < len(n.Children) {
				result[n.Children[i].Value] = n.Children[i+1].toInterface()
			}
		}
		return result
	default:
		return nil
	}
}

// getStringSlice returns a []string for a sequence node.
func (n *Node) getStringSlice() []string {
	if n.Type != NodeSequence {
		return nil
	}
	var result []string
	for _, child := range n.Children {
		if child.Type == NodeScalar {
			result = append(result, child.Value)
		}
	}
	return result
}
