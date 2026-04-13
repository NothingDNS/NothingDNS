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
	node := &Node{
		Type: NodeMapping,
		Line: p.current.Line,
		Col:  p.current.Col,
	}

	// Remember the indentation level when we entered this mapping
	entryIndentLevel := p.tokenizer.CurrentIndent()

	for {
		// Skip newlines at current level
		for p.current.Type == TokenNewline {
			p.advance()
		}

		// Check for end of mapping
		if p.current.Type == TokenEOF {
			break
		}

		// On DEDENT, check if we've dropped below our entry level
		if p.current.Type == TokenDedent {
			// Consume the DEDENT and check if we're below entry level
			p.advance()
			if p.tokenizer.CurrentIndent() < entryIndentLevel {
				// We've exited this mapping's level
				break
			}
			// We're still at or above entry level, continue parsing
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
			value = &Node{Type: NodeScalar, Value: ""}
		}

		if err != nil {
			return nil, err
		}

		node.Children = append(node.Children, key, value)

		// Check for end of mapping after a pair
		for p.current.Type == TokenNewline {
			p.advance()
		}

		// Handle DEDENT after a value
		if p.current.Type == TokenDedent {
			p.advance()
			if p.tokenizer.CurrentIndent() < entryIndentLevel {
				break
			}
		}
	}

	return node, nil
}

// parseBlockSequence parses a block sequence (list with - items).
func (p *Parser) parseBlockSequence(indent int) (*Node, error) {
	if p.depth > maxYAMLDepth {
		return nil, fmt.Errorf("yaml nesting depth exceeds maximum (%d levels) at line %d", maxYAMLDepth, p.current.Line)
	}
	p.depth++
	node := &Node{
		Type: NodeSequence,
		Line: p.current.Line,
		Col:  p.current.Col,
	}

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
					// Continue parsing rest of mapping if more keys
					value = &Node{
						Type:     NodeMapping,
						Line:     savedKey.Line,
						Col:      savedKey.Col,
						Children: []*Node{savedKey, valNode},
					}
					// Parse additional key-value pairs
					for {
						for p.current.Type == TokenNewline || p.current.Type == TokenIndent {
							p.advance()
						}
						if p.current.Type == TokenEOF {
							break
						}
						if p.current.Type == TokenDedent {
							p.advance()
							continue
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
						value.Children = append(value.Children, k, v)
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
				// Continue parsing rest of mapping if more keys
				value = &Node{
					Type:     NodeMapping,
					Line:     savedKey.Line,
					Col:      savedKey.Col,
					Children: []*Node{savedKey, valNode},
				}
				// Parse additional key-value pairs
				for {
					for p.current.Type == TokenNewline || p.current.Type == TokenIndent {
						p.advance()
					}
					if p.current.Type == TokenEOF {
						break
					}
					if p.current.Type == TokenDedent {
						p.advance()
						continue
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
					value.Children = append(value.Children, k, v)
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
	node := &Node{
		Type: NodeMapping,
		Line: p.current.Line,
		Col:  p.current.Col,
	}

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

		node.Children = append(node.Children, key, value)

		// Optional comma
		if p.current.Type == TokenComma {
			p.advance()
		}
	}

	p.advance() // consume '}'
	return node, nil
}

// parseFlowSequence parses a flow sequence [item, ...].
func (p *Parser) parseFlowSequence() (*Node, error) {
	if p.depth > maxYAMLDepth {
		return nil, fmt.Errorf("yaml nesting depth exceeds maximum (%d levels) at line %d", maxYAMLDepth, p.current.Line)
	}
	p.depth++
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
