package config

// NodeType represents the type of a YAML node.
type NodeType int

const (
	NodeDocument NodeType = iota
	NodeMapping
	NodeSequence
	NodeScalar
)

// String returns the human-readable name of a node type.
func (t NodeType) String() string {
	switch t {
	case NodeDocument:
		return "Document"
	case NodeMapping:
		return "Mapping"
	case NodeSequence:
		return "Sequence"
	case NodeScalar:
		return "Scalar"
	default:
		return "Unknown"
	}
}

// Node represents a node in the YAML tree.
type Node struct {
	Type     NodeType
	Value    string  // For scalars
	Children []*Node // For mappings (key-value pairs) and sequences
	Line     int     // Line number for error reporting
	Col      int     // Column number for error reporting
}

// IsMapping returns true if this is a mapping node.
func (n *Node) IsMapping() bool {
	return n.Type == NodeMapping
}

// IsSequence returns true if this is a sequence node.
func (n *Node) IsSequence() bool {
	return n.Type == NodeSequence
}

// IsScalar returns true if this is a scalar node.
func (n *Node) IsScalar() bool {
	return n.Type == NodeScalar
}

// Get returns the child with the given key (for mappings).
func (n *Node) Get(key string) *Node {
	if n.Type != NodeMapping {
		return nil
	}
	for i := 0; i < len(n.Children); i += 2 {
		if i+1 < len(n.Children) && n.Children[i].Value == key {
			return n.Children[i+1]
		}
	}
	return nil
}

// GetString returns a string value for the given key, or empty string if not found.
func (n *Node) GetString(key string) string {
	child := n.Get(key)
	if child == nil || child.Type != NodeScalar {
		return ""
	}
	return child.Value
}

// GetInt returns an int value for the given key, or 0 if not found.
func (n *Node) GetInt(key string) int {
	child := n.Get(key)
	if child == nil || child.Type != NodeScalar {
		return 0
	}
	var val int
	// Basic parsing with overflow protection
	for _, c := range child.Value {
		if c >= '0' && c <= '9' {
			digit := int(c - '0')
			// Check for overflow before multiplying and adding
			if val > (1<<31-1-digit)/10 {
				return 0 // Overflow, return zero
			}
			val = val*10 + digit
		}
	}
	return val
}

// GetBool returns a bool value for the given key, or false if not found.
func (n *Node) GetBool(key string) bool {
	child := n.Get(key)
	if child == nil || child.Type != NodeScalar {
		return false
	}
	return child.Value == "true" || child.Value == "yes" || child.Value == "on"
}

// GetSlice returns the children of a sequence node for the given key.
// If key is empty and this node is a sequence, returns this node's children.
func (n *Node) GetSlice(key string) []*Node {
	// If key is empty and this is a sequence, return own children
	if key == "" && n.Type == NodeSequence {
		return n.Children
	}
	child := n.Get(key)
	if child == nil || child.Type != NodeSequence {
		return nil
	}
	return child.Children
}

// Keys returns all keys in a mapping.
func (n *Node) Keys() []string {
	if n.Type != NodeMapping {
		return nil
	}
	var keys []string
	for i := 0; i < len(n.Children); i += 2 {
		if i < len(n.Children) {
			keys = append(keys, n.Children[i].Value)
		}
	}
	return keys
}
