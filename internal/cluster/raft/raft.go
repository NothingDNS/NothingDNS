package raft

import (
	"fmt"
	"sync"
	"time"
)

// State represents the Raft node state.
type State int

const (
	StateFollower State = iota
	StateCandidate
	StateLeader
)

func (s State) String() string {
	switch s {
	case StateFollower:
		return "Follower"
	case StateCandidate:
		return "Candidate"
	case StateLeader:
		return "Leader"
	default:
		return "Unknown"
	}
}

// NodeID is a unique node identifier.
type NodeID string

// Term is the Raft term number.
type Term uint64

// Index is the log index.
type Index uint64

// Config configures the Raft node.
type Config struct {
	NodeID      NodeID
	HeartbeatInterval time.Duration // Interval between heartbeats
	ElectionTimeout  time.Duration // Election timeout (should be >> heartbeat)
	MaxLogEntries    int           // Max entries per AppendEntries call
	SnapshotInterval  time.Duration // How often to snapshot
}

// DefaultConfig returns a default Raft configuration.
func DefaultConfig() Config {
	return Config{
		HeartbeatInterval: 150 * time.Millisecond,
		ElectionTimeout:   1000 * time.Millisecond,
		MaxLogEntries:     128,
		SnapshotInterval:  30 * time.Second,
	}
}

// entry is a single log entry.
type entry struct {
	Index      Index
	Term       Term
	Command    []byte // Application-specific command data
	Type       EntryType
	Commitment uint64 // Used for commit acknowledgment
}

// EntryType distinguishes different entry types.
type EntryType uint8

const (
	EntryNormal EntryType = iota // Regular application command
	EntryNoOp                    // No-op entry for commit acknowledgment
)

// Node is a single Raft node.
type Node struct {
	config Config

	// Persistent state (must survive crashes)
	mu sync.Mutex
	currentTerm Term
	votedFor    NodeID
	log         []entry

	// Volatile state
	state        State
	commitIndex  Index
	lastApplied  Index
	lastSnapshot Index // Highest index included in snapshot

	// Leader-specific volatile state
	nextIndex  map[NodeID]Index // For each peer, the next log index to send
	matchIndex map[NodeID]Index // For each peer, the highest replicated index

	// Membership
	peers map[NodeID]*Peer

	// Channels
	voteCh       chan VoteRequest   // Incoming vote requests from RPC
	appendCh     chan AppendRequest // Incoming append requests from RPC
	voteRespCh   chan VoteResponse  // Outgoing vote responses
	appendRespCh chan AppendResponse // Outgoing append responses
	commitCh     chan Commit
	applyCh      chan Apply
	snapshotCh   chan SnapshotRequest
	leadershipCh chan LeadershipState

	// Control
	stopCh chan struct{}
	wg     sync.WaitGroup

	// Tick function (injected for testing)
	tick func()

	// RNG for election timeout randomization
	rng *LockedRand
}

// Peer represents a Raft cluster peer.
type Peer struct {
	ID   NodeID
	Addr string // Network address for RPC
}

// VoteRequest is the RequestVote RPC arguments.
type VoteRequest struct {
	Term         Term
	CandidateID  NodeID
	LastLogIndex Index
	LastLogTerm  Term
}

// VoteResponse is the RequestVote RPC response.
type VoteResponse struct {
	Term    Term
	VoteGranted bool
	From     NodeID
}

// AppendRequest is the AppendEntries RPC arguments.
type AppendRequest struct {
	Term         Term
	LeaderID     NodeID
	PrevLogIndex Index
	PrevLogTerm  Term
	Entries      []entry
	LeaderCommit Index
}

// AppendResponse is the AppendEntries RPC response.
type AppendResponse struct {
	Term    Term
	Success bool
	From    NodeID
	// Optimization: hint for faster log reconciliation
	MatchIndex Index
	// For leader to track commitment
	Commitment uint64
}

// SnapshotRequest requests a snapshot install from the leader.
type SnapshotRequest struct {
	Term     Term
	LeaderID NodeID
	// Snapshot data
	Data []byte
	// Last included index/term in snapshot
	LastIndex Index
	LastTerm  Term
}

// Commit represents a committed entry ready to be applied.
type Commit struct {
	Entries []entry
}

// Apply represents an entry to be applied to the state machine.
type Apply struct {
	Entry entry
}

// LeadershipState indicates leadership changes.
type LeadershipState struct {
	State State
	Term  Term
}

// NewNode creates a new Raft node.
func NewNode(config Config, peers []NodeID) *Node {
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = 150 * time.Millisecond
	}
	if config.ElectionTimeout == 0 {
		config.ElectionTimeout = 1000 * time.Millisecond
	}
	if config.MaxLogEntries == 0 {
		config.MaxLogEntries = 128
	}

	n := &Node{
		config:       config,
		state:        StateFollower,
		currentTerm:  0,
		votedFor:     "",
		log:          make([]entry, 0),
		nextIndex:    make(map[NodeID]Index),
		matchIndex:   make(map[NodeID]Index),
		peers:        make(map[NodeID]*Peer),
		voteCh:       make(chan VoteRequest, 10),
		appendCh:     make(chan AppendRequest, 10),
		voteRespCh:   make(chan VoteResponse, 10),
		appendRespCh: make(chan AppendResponse, 10),
		commitCh:     make(chan Commit, 10),
		applyCh:      make(chan Apply, 256),
		snapshotCh:   make(chan SnapshotRequest, 10),
		leadershipCh: make(chan LeadershipState, 10),
		stopCh:       make(chan struct{}),
		rng:          NewLockedRand(),
	}

	// Initialize peer tracking
	for _, id := range peers {
		n.peers[id] = &Peer{ID: id}
		n.nextIndex[id] = 0
		n.matchIndex[id] = 0
	}

	return n
}

// Start starts the Raft node's main loop.
func (n *Node) Start() {
	n.wg.Add(1)
	go n.run()
}

// Stop stops the Raft node.
func (n *Node) Stop() {
	close(n.stopCh)
	n.wg.Wait()
}

// run is the main event loop.
func (n *Node) run() {
	defer n.wg.Done()

	electionTimer := n.newElectionTimer()

	for {
		n.mu.Lock()
		state := n.state
		n.mu.Unlock()

		switch state {
		case StateFollower:
			n.runFollower(electionTimer)
		case StateCandidate:
			n.runCandidate()
		case StateLeader:
			n.runLeader()
		}
	}
}

// runFollower runs the follower state.
func (n *Node) runFollower(electionTimer *time.Timer) {
	for {
		select {
		case <-n.stopCh:
			return
		case <-electionTimer.C:
			// Election timeout — become candidate
			n.mu.Lock()
			n.state = StateCandidate
			n.currentTerm++
			n.votedFor = "" // Reset vote
			n.mu.Unlock()
			return
		case req := <-n.voteCh:
			n.handleVoteRequest(req)
		case req := <-n.appendCh:
			n.handleAppendRequest(req)
		case req := <-n.snapshotCh:
			n.handleSnapshotRequest(req)
		}
	}
}

// runCandidate runs the candidate state.
func (n *Node) runCandidate() {
	// Vote for self
	n.mu.Lock()
	n.votedFor = n.config.NodeID
	term := n.currentTerm
	lastLogIndex, lastLogTerm := n.lastLogInfo()
	n.mu.Unlock()

	// Request votes from all peers
	n.broadcastVoteRequest(term, lastLogIndex, lastLogTerm)

	// Collect votes
	voteCount := 1 // Vote for self
	quorum := len(n.peers)/2 + 1
	electionTimer := n.newElectionTimer()

	for {
		select {
		case <-n.stopCh:
			return
		case <-electionTimer.C:
			// Election timeout — restart election
			n.mu.Lock()
			n.state = StateCandidate
			n.currentTerm++
			n.votedFor = ""
			n.mu.Unlock()
			return
		case resp := <-n.voteRespCh:
			if resp.Term > term {
				// Discovered higher term — become follower
				n.becomeFollower(resp.Term)
				return
			}
			if resp.VoteGranted {
				voteCount++
				if voteCount >= quorum {
					// Won election — become leader
					n.becomeLeader(term)
					return
				}
			}
		case req := <-n.appendCh:
			n.handleAppendRequest(req)
		case req := <-n.snapshotCh:
			n.handleSnapshotRequest(req)
		}
	}
}

// runLeader runs the leader state.
func (n *Node) runLeader() {
	n.mu.Lock()
	term := n.currentTerm
	n.mu.Unlock()

	// Broadcast initial heartbeats
	n.broadcastHeartbeat(term)

	heartbeatTicker := time.NewTicker(n.config.HeartbeatInterval)
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-n.stopCh:
			return
		case <-heartbeatTicker.C:
			n.mu.Lock()
			if n.state != StateLeader {
				n.mu.Unlock()
				return
			}
			currentTerm := n.currentTerm
			n.mu.Unlock()
			n.broadcastHeartbeat(currentTerm)
		case resp := <-n.appendRespCh:
			n.handleAppendResponse(resp)
		case <-n.commitCh:
			// Check for committed entries
			n.sendCommitted()
		case req := <-n.snapshotCh:
			n.handleSnapshotRequest(req)
		}
	}
}

// handleVoteRequest handles a vote request.
func (n *Node) handleVoteRequest(req VoteRequest) {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Reply false if term < currentTerm
	if req.Term < n.currentTerm {
		n.voteRespCh <- VoteResponse{
			Term:    n.currentTerm,
			VoteGranted: false,
			From:    n.config.NodeID,
		}
		return
	}

	// If votedFor is null or candidateId, and candidate's log is at least as
	// up-to-date as receiver's log, grant vote
	if (n.votedFor == "" || n.votedFor == req.CandidateID) && n.isLogUpToDate(req.LastLogIndex, req.LastLogTerm) {
		n.votedFor = req.CandidateID
		n.voteRespCh <- VoteResponse{
			Term:    n.currentTerm,
			VoteGranted: true,
			From:    n.config.NodeID,
		}
	} else {
		n.voteRespCh <- VoteResponse{
			Term:    n.currentTerm,
			VoteGranted: false,
			From:    n.config.NodeID,
		}
	}
}

// handleAppendRequest handles an AppendEntries request.
func (n *Node) handleAppendRequest(req AppendRequest) {
	n.mu.Lock()
	defer n.mu.Unlock()

	resp := AppendResponse{
		Term:    n.currentTerm,
		Success: false,
		From:    n.config.NodeID,
	}

	// Reply false if term < currentTerm
	if req.Term < n.currentTerm {
		n.appendRespCh <- resp
		return
	}

	// Update term and convert to follower if necessary
	if req.Term > n.currentTerm {
		n.currentTerm = req.Term
		n.state = StateFollower
		n.votedFor = ""
	}

	// Check if we have the previous log entry
	if req.PrevLogIndex > 0 {
		if int(req.PrevLogIndex) > len(n.log) {
			// Don't have this many log entries
			n.appendRespCh <- resp
			return
		}
		if n.log[req.PrevLogIndex-1].Term != req.PrevLogTerm {
			// Term mismatch — delete this and all following
			n.log = n.log[:req.PrevLogIndex-1]
			n.appendRespCh <- resp
			return
		}
	}

	// Append new entries
	if len(req.Entries) > 0 {
		// Remove conflicting entries
		offset := int(req.PrevLogIndex) + 1
		if offset <= len(n.log) {
			n.log = n.log[:offset-1]
		}
		n.log = append(n.log, req.Entries...)
	}

	// Update commit index
	if req.LeaderCommit > n.commitIndex {
		if req.LeaderCommit < Index(len(n.log)) {
			n.commitIndex = req.LeaderCommit
		} else {
			n.commitIndex = Index(len(n.log))
		}
	}

	resp.Success = true
	n.appendRespCh <- resp
}

// HandleVoteRequest is the exported RPC handler for vote requests.
func (n *Node) HandleVoteRequest(req VoteRequest) VoteResponse {
	n.mu.Lock()
	defer n.mu.Unlock()

	if req.Term < n.currentTerm {
		return VoteResponse{
			Term:    n.currentTerm,
			VoteGranted: false,
			From:    n.config.NodeID,
		}
	}

	if req.Term > n.currentTerm {
		n.currentTerm = req.Term
		n.state = StateFollower
		n.votedFor = ""
	}

	if (n.votedFor == "" || n.votedFor == req.CandidateID) && n.isLogUpToDate(req.LastLogIndex, req.LastLogTerm) {
		n.votedFor = req.CandidateID
		return VoteResponse{
			Term:    n.currentTerm,
			VoteGranted: true,
			From:    n.config.NodeID,
		}
	}
	return VoteResponse{
		Term:    n.currentTerm,
		VoteGranted: false,
		From:    n.config.NodeID,
	}
}

// HandleAppendRequest is the exported RPC handler for append requests.
func (n *Node) HandleAppendRequest(req AppendRequest) AppendResponse {
	n.mu.Lock()
	defer n.mu.Unlock()

	resp := AppendResponse{
		Term:    n.currentTerm,
		Success: false,
		From:    n.config.NodeID,
	}

	if req.Term < n.currentTerm {
		return resp
	}

	if req.Term > n.currentTerm {
		n.currentTerm = req.Term
		n.state = StateFollower
		n.votedFor = ""
	}

	if req.PrevLogIndex > 0 {
		if int(req.PrevLogIndex) > len(n.log) {
			return resp
		}
		if n.log[req.PrevLogIndex-1].Term != req.PrevLogTerm {
			n.log = n.log[:req.PrevLogIndex-1]
			return resp
		}
	}

	if len(req.Entries) > 0 {
		offset := int(req.PrevLogIndex) + 1
		if offset <= len(n.log) {
			n.log = n.log[:offset-1]
		}
		n.log = append(n.log, req.Entries...)
	}

	if req.LeaderCommit > n.commitIndex {
		if req.LeaderCommit < Index(len(n.log)) {
			n.commitIndex = req.LeaderCommit
		} else {
			n.commitIndex = Index(len(n.log))
		}
	}

	resp.Success = true
	return resp
}

// HandleSnapshotRequest is the exported RPC handler for snapshot requests.
func (n *Node) HandleSnapshotRequest(req SnapshotRequest) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if req.Term < n.currentTerm {
		return
	}

	if req.Term > n.currentTerm {
		n.currentTerm = req.Term
		n.state = StateFollower
		n.votedFor = ""
	}

	n.lastSnapshot = req.LastIndex
	n.lastApplied = req.LastIndex
	n.commitIndex = req.LastIndex
	n.log = make([]entry, 0)
}

// handleAppendResponse handles an AppendEntries response from a peer.
func (n *Node) handleAppendResponse(resp AppendResponse) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.state != StateLeader {
		return
	}

	if resp.Term > n.currentTerm {
		// Newer term discovered
		n.state = StateFollower
		n.currentTerm = resp.Term
		return
	}

	if resp.Success {
		// Update match index for this peer using hint from response
		if resp.MatchIndex > n.matchIndex[resp.From] {
			n.matchIndex[resp.From] = resp.MatchIndex
		}
		// Advance commit index
		n.maybeAdvanceCommitIndex()
	} else {
		// Retry with lower next index
		if int(n.nextIndex[resp.From]) > 1 {
			n.nextIndex[resp.From]--
		}
	}
}

// handleSnapshotRequest handles a snapshot install request.
func (n *Node) handleSnapshotRequest(req SnapshotRequest) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if req.Term < n.currentTerm {
		return
	}

	if req.Term > n.currentTerm {
		n.currentTerm = req.Term
		n.state = StateFollower
		n.votedFor = ""
	}

	// Install snapshot
	// (Simplified — real implementation would stream the snapshot)
	n.lastSnapshot = req.LastIndex
	n.lastApplied = req.LastIndex
	n.commitIndex = req.LastIndex
	n.log = make([]entry, 0)
}

// becomeFollower transitions to follower state.
func (n *Node) becomeFollower(term Term) {
	n.state = StateFollower
	n.currentTerm = term
	n.votedFor = ""
	n.leadershipCh <- LeadershipState{State: StateFollower, Term: term}
}

// becomeLeader transitions to leader state.
func (n *Node) becomeLeader(term Term) {
	n.state = StateLeader
	n.leadershipCh <- LeadershipState{State: StateLeader, Term: term}

	// Initialize nextIndex and matchIndex for all peers
	for id := range n.peers {
		n.nextIndex[id] = Index(len(n.log)) + 1
		n.matchIndex[id] = 0
	}

	// Commit a no-op entry to prove liveness
	n.Propose(nil, EntryNoOp)
}

// broadcastVoteRequest sends vote requests to all peers.
func (n *Node) broadcastVoteRequest(term Term, lastLogIndex Index, lastLogTerm Term) {
	for id := range n.peers {
		go func(peerID NodeID) {
			req := VoteRequest{
				Term:         term,
				CandidateID:  n.config.NodeID,
				LastLogIndex:  lastLogIndex,
				LastLogTerm:   lastLogTerm,
			}
			// RPC call — would be injected in real implementation
			n.sendVoteRequest(peerID, req)
		}(id)
	}
}

// broadcastHeartbeat sends AppendEntries with no entries to all peers.
func (n *Node) broadcastHeartbeat(term Term) {
	for id := range n.peers {
		go func(peerID NodeID) {
			n.sendHeartbeat(peerID, term)
		}(id)
	}
}

// sendHeartbeat sends a heartbeat (AppendEntries with no entries) to a peer.
func (n *Node) sendHeartbeat(peerID NodeID, term Term) {
	n.mu.Lock()
	prevLogIndex := Index(len(n.log))
	var prevLogTerm Term
	if prevLogIndex > 0 {
		prevLogTerm = n.log[prevLogIndex-1].Term
	}
	n.mu.Unlock()

	req := AppendRequest{
		Term:         term,
		LeaderID:     n.config.NodeID,
		PrevLogIndex: prevLogIndex,
		PrevLogTerm:  prevLogTerm,
		Entries:      nil,
		LeaderCommit: 0, // Heartbeat carries no commit index update
	}
	n.sendAppendRequest(peerID, req)
}

// sendCommitted sends committed entries to the apply channel.
func (n *Node) sendCommitted() {
	n.mu.Lock()
	defer n.mu.Unlock()

	start := int(n.lastApplied) + 1
	end := int(n.commitIndex) + 1

	if start > end || end > len(n.log)+int(n.lastSnapshot) {
		return
	}

	// Adjust for snapshot offset
	startIdx := start - int(n.lastSnapshot) - 1
	endIdx := end - int(n.lastSnapshot) - 1

	if startIdx < 0 {
		startIdx = 0
	}
	if endIdx > len(n.log) {
		endIdx = len(n.log)
	}

	if startIdx >= endIdx {
		return
	}

	entries := make([]entry, endIdx-startIdx)
	copy(entries, n.log[startIdx:endIdx])

	n.lastApplied = n.commitIndex

	select {
	case n.commitCh <- Commit{Entries: entries}:
	default:
		// Channel full — will retry
	}
}

// maybeAdvanceCommitIndex advances the commit index if a quorum agrees.
func (n *Node) maybeAdvanceCommitIndex() {
	if n.state != StateLeader {
		return
	}

	// Can't commit entries from previous terms
	for i := int(n.commitIndex) + 1; i <= len(n.log); i++ {
		entry := n.log[i-1]
		if entry.Term != Term(n.currentTerm) {
			continue
		}

		// Count replicas
		replicas := 1 // Leader
		for id := range n.peers {
			if n.matchIndex[id] >= Index(i) {
				replicas++
			}
		}

		if replicas > len(n.peers)/2 {
			n.commitIndex = Index(i)
			break
		}
	}
}

// isLogUpToDate checks if the candidate's log is at least as up-to-date as receiver's.
func (n *Node) isLogUpToDate(candidateLastIndex Index, candidateLastTerm Term) bool {
	lastIndex, lastTerm := n.lastLogInfo()

	if lastTerm != candidateLastTerm {
		return candidateLastTerm > lastTerm
	}
	return candidateLastIndex >= lastIndex
}

// lastLogInfo returns the last log index and term.
func (n *Node) lastLogInfo() (Index, Term) {
	if len(n.log) == 0 {
		return 0, 0
	}
	last := n.log[len(n.log)-1]
	return last.Index, last.Term
}

// newElectionTimer creates a randomized election timeout.
func (n *Node) newElectionTimer() *time.Timer {
	// Randomize within [electionTimeout, 2 * electionTimeout)
	extra := n.rng.Int63n(int64(n.config.ElectionTimeout))
	return time.NewTimer(time.Duration(extra) + n.config.ElectionTimeout)
}

// Propose proposes a command for replication. If node is not leader, returns error.
func (n *Node) Propose(command []byte, entryType EntryType) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.state != StateLeader {
		return fmt.Errorf("not leader (state=%s)", n.state)
	}

	entry := entry{
		Index: Index(len(n.log) + 1),
		Term:  n.currentTerm,
		Type:  entryType,
	}
	if command != nil {
		cmd := make([]byte, len(command))
		copy(cmd, command)
		entry.Command = cmd
	}

	n.log = append(n.log, entry)

	// Send to followers asynchronously
	go n.replicateToFollowers(entry)

	return nil
}

// replicateToFollowers sends new entries to all followers.
func (n *Node) replicateToFollowers(newEntry entry) {
	n.mu.Lock()
	term := n.currentTerm
	n.mu.Unlock()

	for id := range n.peers {
		go func(peerID NodeID) {
			n.mu.Lock()
			nextIdx := n.nextIndex[peerID]
			n.mu.Unlock()

			n.mu.Lock()
			var entries []entry
			if int(newEntry.Index) >= int(nextIdx) {
				// This entry and any following
				offset := int(nextIdx) - 1
				if offset < 0 {
					offset = 0
				}
				if offset < len(n.log) {
					entries = make([]entry, len(n.log)-offset)
					copy(entries, n.log[offset:])
				}
			}
			prevLogIndex := Index(len(n.log))
			var prevLogTerm Term
			if prevLogIndex > 0 && int(prevLogIndex)-1 < len(n.log) {
				prevLogTerm = n.log[prevLogIndex-1].Term
			}
			n.mu.Unlock()

			req := AppendRequest{
				Term:         term,
				LeaderID:     n.config.NodeID,
				PrevLogIndex: prevLogIndex,
				PrevLogTerm:  prevLogTerm,
				Entries:      entries,
				LeaderCommit: 0,
			}
			n.sendAppendRequest(peerID, req)
		}(id)
	}
}

// sendVoteRequest sends a vote request to a peer (placeholder for network layer).
func (n *Node) sendVoteRequest(peerID NodeID, req VoteRequest) {
	// This would be implemented via an injected transport interface
	// For now, the RPC layer is assumed external
}

// sendAppendRequest sends an AppendEntries request to a peer (placeholder).
func (n *Node) sendAppendRequest(peerID NodeID, req AppendRequest) {
	// This would be implemented via an injected transport interface
}

// AddPeer adds a new peer to the cluster.
func (n *Node) AddPeer(id NodeID, addr string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if _, ok := n.peers[id]; !ok {
		n.peers[id] = &Peer{ID: id, Addr: addr}
		n.nextIndex[id] = Index(len(n.log)) + 1
		n.matchIndex[id] = 0
	}
}

// RemovePeer removes a peer from the cluster.
func (n *Node) RemovePeer(id NodeID) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.peers, id)
	delete(n.nextIndex, id)
	delete(n.matchIndex, id)
}

// State returns the current state.
func (n *Node) State() State {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.state
}

// Term returns the current term.
func (n *Node) Term() Term {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.currentTerm
}

// CommitIndex returns the current commit index.
func (n *Node) CommitIndex() Index {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.commitIndex
}

// LeadershipCh returns the leadership change channel.
func (n *Node) LeadershipCh() <-chan LeadershipState {
	return n.leadershipCh
}

// CommitCh returns the commit channel.
func (n *Node) CommitCh() <-chan Commit {
	return n.commitCh
}

// ApplyCh returns the apply channel.
func (n *Node) ApplyCh() <-chan Apply {
	return n.applyCh
}
