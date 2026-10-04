package zone

import (
	"strings"
)

type radixNode struct {
	children map[string]*radixNode
	value    *Zone
}

type RadixTree struct {
	root *radixNode
}

func NewRadixTree() *RadixTree {
	return &RadixTree{
		root: &radixNode{children: make(map[string]*radixNode)},
	}
}

func (t *RadixTree) ensureRoot() *radixNode {
	if t == nil {
		return nil
	}
	if t.root == nil {
		t.root = &radixNode{children: make(map[string]*radixNode)}
	}
	return t.root
}

func (t *RadixTree) Insert(origin string, z *Zone) {
	labels := splitDomainReversed(origin)
	node := t.ensureRoot()
	if node == nil {
		return
	}
	for _, label := range labels {
		if label == "" {
			label = "."
		}
		if node.children == nil {
			node.children = make(map[string]*radixNode)
		}
		child, ok := node.children[label]
		if !ok {
			child = &radixNode{children: make(map[string]*radixNode)}
			node.children[label] = child
		}
		node = child
	}
	node.value = z
}

func (t *RadixTree) Find(name string) *Zone {
	if t == nil || t.root == nil {
		return nil
	}
	labels := splitDomainReversed(name)
	node := t.root
	var best *Zone
	if rootZone := node.children["."]; rootZone != nil {
		best = rootZone.value
	}
	for i := 0; i < len(labels); i++ {
		label := labels[i]
		if label == "" {
			label = "."
		}
		child, ok := node.children[label]
		if !ok {
			// Dead end — no child for this query label.
			// If we have a best zone from an earlier match, return it.
			// (The query name is a subdomain of the best zone.)
			// Only return nil if we never found any zone.
			return best
		}
		node = child
		if node.value != nil {
			best = node.value
		}
	}
	return best
}

func (t *RadixTree) List() map[string]*Zone {
	result := make(map[string]*Zone)
	if t == nil || t.root == nil {
		return result
	}
	t.root.collectZones(result)
	return result
}

func (n *radixNode) collectZones(result map[string]*Zone) {
	if n == nil {
		return
	}
	if n.value != nil {
		result[n.value.Origin] = n.value
	}
	for _, child := range n.children {
		child.collectZones(result)
	}
}

func splitDomainReversed(name string) []string {
	if name == "" {
		return []string{""}
	}
	// RFC 1035 §2.3.3: domain names are case-insensitive. Normalise both Insert
	// and Find inputs to lowercase here so a zone inserted as "EXAMPLE.COM."
	// matches a query for "example.com." and vice versa.
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return []string{"."}
	}
	parts := strings.Split(name, ".")
	// Reverse in-place using temp variable (parallel assignment buggy on this system)
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		tmp := parts[i]
		parts[i] = parts[j]
		parts[j] = tmp
	}
	return parts
}

func BuildRadixTree(zones map[string]*Zone) *RadixTree {
	t := NewRadixTree()
	for origin, z := range zones {
		t.Insert(origin, z)
	}
	return t
}
