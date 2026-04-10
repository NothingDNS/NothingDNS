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

func (t *RadixTree) Insert(origin string, z *Zone) {
	labels := splitDomainReversed(origin)
	node := t.root
	for _, label := range labels {
		if label == "" {
			label = "."
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
	labels := splitDomainReversed(name)
	node := t.root
	var best *Zone
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

func splitDomainReversed(name string) []string {
	name = name[:len(name)-1] // trim trailing dot
	if name == "" {
		return []string{""}
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
