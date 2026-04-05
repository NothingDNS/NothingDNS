package raft

import (
	"encoding/json"
	"fmt"
	"sync"
)

// ClusterIntegration integrates Raft consensus into the cluster.
type ClusterIntegration struct {
	node           *Node
	stateMachine   *ZoneStateMachine
	transport      *TCPTransport
	rpcServer      *RPCServer
	wal            *WAL
	snapshotter    *Snapshotter

	// Configuration
	config         Config
	nodeID         NodeID
	peers          []NodeID

	// Leadership tracking
	mu            sync.RWMutex
	isLeader      bool
	currentTerm   Term

	// Applied index tracking
	appliedIndex   Index
	lastAppliedTerm Term

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewClusterIntegration creates a new Raft cluster integration.
func NewClusterIntegration(nodeID NodeID, peers []NodeID, addr string, dataDir string) (*ClusterIntegration, error) {
	config := DefaultConfig()
	config.NodeID = nodeID

	// Create transport
	transport := NewTCPTransport()

	// Set peer addresses (simplified — would be looked up from config)
	for _, peerID := range peers {
		transport.SetPeerAddr(peerID, string(peerID)) // Placeholder
	}

	// Create Raft node
	node := NewNode(config, peers, transport)

	// Create RPC server
	rpcServer, err := NewRPCServer(addr, node)
	if err != nil {
		return nil, fmt.Errorf("rpc server: %w", err)
	}

	// Create WAL
	wal, err := NewWAL(dataDir + "/raft-wal")
	if err != nil {
		return nil, fmt.Errorf("wal: %w", err)
	}

	// Load WAL entries into node
	if entries, err := wal.ReadAll(); err == nil && len(entries) > 0 {
		// Replay entries into node's log
		for _, e := range entries {
			node.log = append(node.log, e)
		}
	}

	// Create snapshotter
	snapshotter, err := NewSnapshotter(dataDir + "/snapshots")
	if err != nil {
		return nil, fmt.Errorf("snapshotter: %w", err)
	}

	ci := &ClusterIntegration{
		node:         node,
		stateMachine: NewZoneStateMachine(),
		transport:    transport,
		rpcServer:    rpcServer,
		wal:          wal,
		snapshotter:  snapshotter,
		config:       config,
		nodeID:       nodeID,
		peers:        peers,
		stopCh:       make(chan struct{}),
	}

	return ci, nil
}

// Start starts the Raft integration.
func (ci *ClusterIntegration) Start() error {
	// Start RPC server
	ci.rpcServer.Start()

	// Wire up RPC handlers to use transport
	// In real implementation, node would use ci.transport for outbound RPC

	// Start Raft node
	ci.node.Start()

	// Start commit applier
	ci.wg.Add(1)
	go ci.applyLoop()

	// Start leadership tracker
	ci.wg.Add(1)
	go ci.leadershipLoop()

	return nil
}

// Stop stops the Raft integration.
func (ci *ClusterIntegration) Stop() error {
	close(ci.stopCh)
	ci.node.Stop()
	ci.rpcServer.Stop()
	ci.wal.Close()
	ci.wg.Wait()
	return nil
}

// applyLoop applies committed entries to the state machine.
func (ci *ClusterIntegration) applyLoop() {
	defer ci.wg.Done()

	for {
		select {
		case <-ci.stopCh:
			return
		case <-ci.node.CommitCh():
			ci.node.mu.Lock()
			commitIdx := ci.node.commitIndex
			ci.node.mu.Unlock()

			// Apply entries from lastApplied+1 to commitIndex
			ci.node.mu.Lock()
			for i := int(ci.appliedIndex) + 1; i <= int(commitIdx); i++ {
				if i > 0 && i <= len(ci.node.log) {
					e := ci.node.log[i-1]
					if e.Term == 0 {
						continue
					}
					ci.stateMachine.Apply(e)
					ci.appliedIndex = e.Index
					ci.lastAppliedTerm = e.Term
				}
			}
			ci.node.mu.Unlock()
		}
	}
}

// leadershipLoop tracks leadership changes.
func (ci *ClusterIntegration) leadershipLoop() {
	defer ci.wg.Done()

	for {
		select {
		case <-ci.stopCh:
			return
		case state := <-ci.node.LeadershipCh():
			ci.mu.Lock()
			ci.isLeader = (state.State == StateLeader)
			ci.currentTerm = state.Term
			ci.mu.Unlock()
		}
	}
}

// IsLeader returns true if this node is the current leader.
func (ci *ClusterIntegration) IsLeader() bool {
	ci.mu.RLock()
	defer ci.mu.RUnlock()
	return ci.isLeader
}

// ProposeZoneChange proposes a zone change for consensus.
func (ci *ClusterIntegration) ProposeZoneChange(cmd ZoneCommand) error {
	data, err := json.Marshal(cmd)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	if err := ci.node.Propose(data, EntryNormal); err != nil {
		return fmt.Errorf("propose: %w", err)
	}

	return nil
}

// GetLeaderID returns the current leader's node ID, or empty if unknown.
func (ci *ClusterIntegration) GetLeaderID() NodeID {
	ci.mu.RLock()
	defer ci.mu.RUnlock()

	if ci.isLeader {
		return ci.nodeID
	}
	// In real implementation, would track who we think the leader is
	return ""
}

// Stats returns cluster statistics.
func (ci *ClusterIntegration) Stats() ClusterStats {
	ci.mu.RLock()
	isLeader := ci.isLeader
	term := ci.currentTerm
	ci.mu.RUnlock()

	ci.node.mu.Lock()
	state := ci.node.state
	commitIdx := ci.node.commitIndex
	ci.node.mu.Unlock()

	return ClusterStats{
		NodeID:      ci.nodeID,
		State:       state.String(),
		Term:        int64(term),
		CommitIndex: int64(commitIdx),
		AppliedIndex: int64(ci.appliedIndex),
		IsLeader:    isLeader,
	}
}

// ClusterStats contains cluster statistics.
type ClusterStats struct {
	NodeID      NodeID
	State       string
	Term        int64
	CommitIndex int64
	AppliedIndex int64
	IsLeader    bool
}

// ProposeAddRecord proposes adding a record to a zone.
func (ci *ClusterIntegration) ProposeAddRecord(zone, name string, rrtype uint16, ttl uint32, rdata string) error {
	cmd := ZoneCommand{
		Type:   "add_record",
		Zone:   zone,
		Name:   name,
		RRType: rrtype,
		TTL:    ttl,
		RData:  []string{rdata},
	}
	return ci.ProposeZoneChange(cmd)
}

// ProposeDeleteRecord proposes deleting a record from a zone.
func (ci *ClusterIntegration) ProposeDeleteRecord(zone, name string, rrtype uint16) error {
	cmd := ZoneCommand{
		Type:   "del_record",
		Zone:   zone,
		Name:   name,
		RRType: rrtype,
	}
	return ci.ProposeZoneChange(cmd)
}

// GetZoneData returns zone data from the state machine.
func (ci *ClusterIntegration) GetZoneData(zone string) []RecordEntry {
	return ci.stateMachine.GetRecords(zone)
}
