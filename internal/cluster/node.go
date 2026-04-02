package cluster

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"
)

// NodeState represents the state of a cluster node.
type NodeState int

const (
	NodeStateUnknown NodeState = iota
	NodeStateAlive
	NodeStateSuspect
	NodeStateDead
)

func (s NodeState) String() string {
	switch s {
	case NodeStateAlive:
		return "alive"
	case NodeStateSuspect:
		return "suspect"
	case NodeStateDead:
		return "dead"
	default:
		return "unknown"
	}
}

// Node represents a member of the cluster.
type Node struct {
	ID       string
	Addr     string
	Port     int
	State    NodeState
	LastSeen time.Time
	Version  uint64 // Incremented on state changes
	Meta     NodeMeta
}

// NodeMeta contains node metadata.
type NodeMeta struct {
	Region   string
	Zone     string
	Weight   int // For load balancing
	HTTPAddr string
}

// IsAlive returns true if the node is alive.
func (n *Node) IsAlive() bool {
	return n.State == NodeStateAlive
}

// String returns a string representation of the node.
func (n *Node) String() string {
	return fmt.Sprintf("%s@%s:%d", n.ID, n.Addr, n.Port)
}

// NodeList manages a collection of cluster nodes.
type NodeList struct {
	mu    sync.RWMutex
	nodes map[string]*Node
	self  *Node
}

// NewNodeList creates a new node list.
func NewNodeList(self *Node) *NodeList {
	nl := &NodeList{
		nodes: make(map[string]*Node),
		self:  self,
	}
	nl.nodes[self.ID] = self
	return nl
}

// GetSelf returns the local node.
func (nl *NodeList) GetSelf() *Node {
	nl.mu.RLock()
	defer nl.mu.RUnlock()
	return nl.self
}

// Get returns a value copy of a node by ID.
// Returns a copy to prevent data races when callers read fields after the lock is released.
func (nl *NodeList) Get(id string) (*Node, bool) {
	nl.mu.RLock()
	defer nl.mu.RUnlock()
	n, ok := nl.nodes[id]
	if !ok {
		return nil, false
	}
	cp := *n
	return &cp, true
}

// Add adds a node to the list.
func (nl *NodeList) Add(node *Node) bool {
	nl.mu.Lock()
	defer nl.mu.Unlock()

	if existing, ok := nl.nodes[node.ID]; ok {
		// Update if version is newer
		if node.Version > existing.Version {
			nl.nodes[node.ID] = node
			return true
		}
		return false
	}

	nl.nodes[node.ID] = node
	return true
}

// UpdateState updates the state of a node.
func (nl *NodeList) UpdateState(id string, state NodeState) bool {
	nl.mu.Lock()
	defer nl.mu.Unlock()

	node, ok := nl.nodes[id]
	if !ok || id == nl.self.ID {
		return false
	}

	node.State = state
	node.LastSeen = time.Now()
	node.Version++
	return true
}

// MarkSeen updates the last seen time for a node.
func (nl *NodeList) MarkSeen(id string) {
	nl.mu.Lock()
	defer nl.mu.Unlock()

	if node, ok := nl.nodes[id]; ok {
		node.LastSeen = time.Now()
	}
}

// Remove removes a node from the list.
func (nl *NodeList) Remove(id string) {
	nl.mu.Lock()
	defer nl.mu.Unlock()
	delete(nl.nodes, id)
}

// GetAll returns copies of all nodes.
// Returns value copies to prevent data races when callers read fields
// after the lock is released.
func (nl *NodeList) GetAll() []Node {
	nl.mu.RLock()
	defer nl.mu.RUnlock()

	result := make([]Node, 0, len(nl.nodes))
	for _, n := range nl.nodes {
		result = append(result, *n)
	}
	return result
}

// GetAlive returns copies of all alive nodes (excluding self).
// Returns value copies to prevent data races when callers read fields
// after the lock is released.
func (nl *NodeList) GetAlive() []Node {
	nl.mu.RLock()
	defer nl.mu.RUnlock()

	result := make([]Node, 0)
	for _, n := range nl.nodes {
		if n.ID != nl.self.ID && n.IsAlive() {
			result = append(result, *n)
		}
	}
	return result
}

// GetRandom returns a copy of a random alive node (for gossip targets).
// Returns a value copy to prevent data races, consistent with GetAll/GetAlive.
func (nl *NodeList) GetRandom(exclude []string) *Node {
	nl.mu.RLock()
	defer nl.mu.RUnlock()

	excludeMap := make(map[string]bool)
	for _, id := range exclude {
		excludeMap[id] = true
	}

	var candidates []*Node
	for _, n := range nl.nodes {
		if n.ID != nl.self.ID && n.IsAlive() && !excludeMap[n.ID] {
			candidates = append(candidates, n)
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	// Random selection using crypto/rand
	var b [4]byte
	idx := uint32(0)
	if _, err := rand.Read(b[:]); err != nil {
		idx = uint32(time.Now().UnixNano() % int64(len(candidates)))
	} else {
		idx = binary.BigEndian.Uint32(b[:]) % uint32(len(candidates))
	}
	copy := *candidates[idx]
	return &copy
}

// Count returns the total number of nodes.
func (nl *NodeList) Count() int {
	nl.mu.RLock()
	defer nl.mu.RUnlock()
	return len(nl.nodes)
}

// AliveCount returns the number of alive nodes.
func (nl *NodeList) AliveCount() int {
	nl.mu.RLock()
	defer nl.mu.RUnlock()

	count := 0
	for _, n := range nl.nodes {
		if n.IsAlive() {
			count++
		}
	}
	return count
}

// GenerateNodeID creates a unique node ID.
func GenerateNodeID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID if crypto/rand fails
		now := time.Now().UnixNano()
		binary.BigEndian.PutUint64(b, uint64(now))
	}
	return hex.EncodeToString(b)
}

// GetLocalIP returns the first non-loopback IP address.
func GetLocalIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}

	return "127.0.0.1", nil
}
