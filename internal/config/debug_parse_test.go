package config

import (
	"fmt"
	"testing"
)

func TestDebugParseBasic(t *testing.T) {
	input := `
server:
  port: 5353
  bind:
    - 127.0.0.1
upstream:
  strategy: round_robin
  servers:
    - 1.1.1.1:53
    - 8.8.8.8:53
`

	parser := NewParser(input)
	node, err := parser.ParseMapping()
	if err != nil {
		t.Fatalf("ParseMapping error: %v", err)
	}

	fmt.Println("=== Parsed Node Structure ===")
	debugNode(node, 0)
	fmt.Println("=============================")

	// Check if upstream is present
	upstreamNode := node.Get("upstream")
	if upstreamNode == nil {
		t.Fatal("expected 'upstream' node")
	}
	fmt.Printf("Upstream node found: Type=%s\n", upstreamNode.Type)
	fmt.Printf("Upstream strategy: %q\n", upstreamNode.GetString("strategy"))
}

// debugNode prints a node tree for debugging
func debugNode(n *Node, indent int) {
	prefix := ""
	for i := 0; i < indent; i++ {
		prefix += "  "
	}
	if n == nil {
		fmt.Printf("%snil\n", prefix)
		return
	}
	fmt.Printf("%sNode{Type: %s, Value: %q, Children: %d}\n", prefix, n.Type, n.Value, len(n.Children))
	for i, child := range n.Children {
		fmt.Printf("%s  Child[%d]:\n", prefix, i)
		debugNode(child, indent+2)
	}
}
