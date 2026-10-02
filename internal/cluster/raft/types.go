package raft

import (
	"fmt"
	"sync"
	"time"
)

// raftRPCTimeout bounds each outgoing RPC. Without a timeout a transport
// call that hangs (peer down, network partition) ties up a goroutine
// indefinitely. A 5 s timeout is long enough for a live peer but clears
// a blocked goroutine quickly when a node is unreachable.
const raftRPCTimeout = 5 * time.Second

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
	NodeID            NodeID
	HeartbeatInterval time.Duration // Interval between heartbeats
	ElectionTimeout   time.Duration // Election timeout (should be >> heartbeat)
	MaxLogEntries     int           // Max entries per AppendEntries call
	SnapshotInterval  time.Duration // How often to snapshot

	// DataDir is the directory where Raft persists HardState (currentTerm
	// and votedFor) per RFC §5.1. Leaving this empty disables persistence —
	// which is unsafe for production: a restart loses all votes and the
	// node may vote twice in the same term, violating election safety.
	// Tests may use a temp dir; production deployments must set this
	// alongside the WAL directory.
	DataDir string
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
	EntryNormal        EntryType = iota // Regular application command
	EntryNoOp                           // No-op entry for commit acknowledgment
	EntryAddNode                        // Add node to cluster (joint consensus phase 1)
	EntryRemoveNode                     // Remove node from cluster (joint consensus phase 1)
	EntryJointComplete                  // Joint consensus complete, using new config
)

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
	Term        Term
	VoteGranted bool
	From        NodeID
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

// SnapshotResponse acknowledges a snapshot install. Success reports
// whether the follower actually restored and installed the snapshot —
// the leader must not advance matchIndex on anything less (an
// unacknowledged install would let the leader count an uninstalled
// snapshot toward quorum).
type SnapshotResponse struct {
	Term    Term
	Success bool
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

// logPersister durably records Raft log mutations. Implemented by *WAL.
// All methods are called with the Node lock held, so implementations must
// not call back into the Node.
type logPersister interface {
	// Write appends a single log entry.
	Write(e entry) error
	// TruncateAfter discards entries with Index > keepThrough.
	TruncateAfter(keepThrough Index) error
	// CompactBefore discards entries with Index <= through (subsumed by a
	// snapshot), keeping the post-snapshot tail.
	CompactBefore(through Index) error
	// Sync flushes buffered writes to stable storage.
	Sync() error
}

// StateMachine is the interface for the state machine that applies snapshots.
// Implemented by ZoneStateMachine.
type StateMachine interface {
	// Apply applies a Raft log entry to the state machine.
	Apply(entry) error
	// Snapshot returns a serialized snapshot of the current state.
	Snapshot() ([]byte, error)
	// Restore restores state from a serialized snapshot.
	Restore([]byte) error
}

// JointConfig represents a joint consensus configuration per RFC 7003.
// It contains both the old and new configurations during transitions.
type JointConfig struct {
	OldPeers map[NodeID]*Peer // Previous configuration
	NewPeers map[NodeID]*Peer // New configuration
}

// NewJointConfig creates a new joint config from old and new peer sets.
func NewJointConfig(oldPeers, newPeers map[NodeID]*Peer) *JointConfig {
	return &JointConfig{
		OldPeers: oldPeers,
		NewPeers: newPeers,
	}
}

// QuorumForConfig returns the quorum size for a given configuration.
func (jc *JointConfig) QuorumForConfig(peerSet map[NodeID]*Peer) int {
	return len(peerSet)/2 + 1
}

// HasQuorumOldAndNew checks if we have quorum in both old and new configurations.
// Per RFC 7003, for joint consensus, we need quorum from BOTH configurations.
func (jc *JointConfig) HasQuorumOldAndNew(matchIndex map[NodeID]Index, commitIdx Index) bool {
	// Count replicas in old config
	oldReplicas := 0
	for id := range jc.OldPeers {
		if matchIndex[id] >= commitIdx {
			oldReplicas++
		}
	}
	oldQuorum := jc.QuorumForConfig(jc.OldPeers)
	if oldReplicas < oldQuorum {
		return false
	}

	// Count replicas in new config
	newReplicas := 0
	for id := range jc.NewPeers {
		if matchIndex[id] >= commitIdx {
			newReplicas++
		}
	}
	newQuorum := jc.QuorumForConfig(jc.NewPeers)
	return newReplicas >= newQuorum
}

// JointConfigProposal describes a pending configuration change.
type JointConfigProposal struct {
	Type     EntryType // EntryAddNode or EntryRemoveNode
	PeerID   NodeID
	PeerAddr string
	Proposed time.Time // When this was proposed
}

// Node is a single Raft node.
type Node struct {
	config    Config
	transport Transport // Network transport for RPC

	// Persistent state (must survive crashes)
	mu          sync.Mutex
	currentTerm Term
	votedFor    NodeID
	log         []entry

	// Volatile state
	state            State
	commitIndex      Index
	lastApplied      Index
	lastSnapshot     Index // Highest index included in snapshot
	lastSnapshotTerm Term  // Term of the entry at lastSnapshot

	// leaderID is the most-recently-seen leader. Followers learn this
	// from AppendEntries (req.LeaderID). Candidates clear it on start
	// of an election; leaders set it to themselves on becomeLeader.
	// Used so cluster-membership clients calling Add/Remove on a
	// non-leader can be redirected to the right node.
	leaderID NodeID

	// Leader-specific volatile state
	nextIndex  map[NodeID]Index // For each peer, the next log index to send
	matchIndex map[NodeID]Index // For each peer, the highest replicated index

	// snapshotInFlight guards against a resend storm: sendInstallSnapshot
	// now waits for the follower's install ACK, which can take longer than
	// the 150ms heartbeat interval. Without this guard every heartbeat
	// tick would spawn another full snapshot send to the same lagging peer.
	// A peer is marked true while a send is outstanding and cleared when it
	// completes. Guarded by n.mu.
	snapshotInFlight map[NodeID]bool

	// Membership
	peers map[NodeID]*Peer

	// Joint consensus state (RFC 7003)
	jointConfig       *JointConfig         // Current joint configuration (nil = using simple config)
	jointConfigIdx    Index                // Index of joint config entry in log
	pendingConfChange *JointConfigProposal // Pending configuration change proposal

	// State machine for applying snapshots (optional, set by ClusterIntegration)
	// When set, snapshot install will restore state from snapshot data
	stateMachine StateMachine

	// persister durably records log mutations (optional). When set, log
	// entries are written and fsynced before a Propose returns or a follower
	// acknowledges an AppendEntries, so committed entries survive a crash.
	persister logPersister

	// snapshotBytes is the payload of the most recent snapshot this node took
	// (leader) or installed (follower). The leader streams it to followers
	// that have fallen behind lastSnapshot via InstallSnapshot.
	snapshotBytes []byte

	// onSnapshotInstalled, when set, is called after a snapshot is installed
	// (with its last-included index) so the integration layer can fast-forward
	// its applied index. Guarded by n.mu at call time.
	onSnapshotInstalled func(Index)

	// Channels
	voteCh       chan VoteRequest    // Incoming vote requests from RPC
	appendCh     chan AppendRequest  // Incoming append requests from RPC
	voteRespCh   chan VoteResponse   // Outgoing vote responses
	appendRespCh chan AppendResponse // Outgoing append responses
	commitCh     chan Commit
	applyCh      chan Apply
	snapshotCh   chan SnapshotRequest
	leadershipCh chan LeadershipState

	// electionResetCh carries "legitimate leader contact" events from the
	// RPC handlers (valid AppendEntries received, or a vote granted) to the
	// run loop. A follower resets its election timer on this; a candidate
	// steps down. Without it the run-loop timer fires on a fixed schedule
	// regardless of heartbeats, so every follower repeatedly times out and
	// challenges a healthy leader — the cluster livelocks and never settles.
	electionResetCh chan struct{}

	// Control
	stopCh   chan struct{}
	stopOnce sync.Once // guards Stop() against second-call panic
	wg       sync.WaitGroup

	// RNG for election timeout randomization
	rng *LockedRand
}

// NewNode creates a new Raft node. It returns an error when the data dir
// holds an unreadable HardState file (fail-closed boot; see the comment on
// the restore block below).
func NewNode(config Config, peers []NodeID, transport Transport) (*Node, error) {
	if config.HeartbeatInterval <= 0 {
		config.HeartbeatInterval = 150 * time.Millisecond
	}
	if config.ElectionTimeout <= 0 {
		config.ElectionTimeout = 1000 * time.Millisecond
	}
	if config.MaxLogEntries <= 0 {
		config.MaxLogEntries = 128
	}

	n := &Node{
		config:           config,
		transport:        transport,
		state:            StateFollower,
		currentTerm:      0,
		votedFor:         "",
		log:              make([]entry, 0),
		nextIndex:        make(map[NodeID]Index),
		matchIndex:       make(map[NodeID]Index),
		snapshotInFlight: make(map[NodeID]bool),
		peers:            make(map[NodeID]*Peer),
		voteCh:           make(chan VoteRequest, 10),
		appendCh:         make(chan AppendRequest, 10),
		voteRespCh:       make(chan VoteResponse, 10),
		appendRespCh:     make(chan AppendResponse, 10),
		commitCh:         make(chan Commit, 10),
		applyCh:          make(chan Apply, 256),
		snapshotCh:       make(chan SnapshotRequest, 10),
		leadershipCh:     make(chan LeadershipState, 10),
		electionResetCh:  make(chan struct{}, 1),
		stopCh:           make(chan struct{}),
		rng:              NewLockedRand(),
	}

	// Restore persistent HardState from disk so currentTerm and votedFor
	// survive a restart. Without this the node can grant the same term's
	// vote twice and violate election safety on the very first RPC after
	// reboot. If DataDir is empty (e.g. unit tests, in-memory clusters)
	// persistence is silently skipped — production callers must set it.
	//
	// A hardstate file that exists but cannot be READ (bad magic, truncation,
	// I/O error) is fail-closed, like ErrWALCorrupt for the WAL: booting
	// fresh on top of unreadable durable state would forget the previous
	// term's vote and allow a second vote in that term (split-brain).
	if config.DataDir != "" {
		hs, err := loadHardState(config.DataDir)
		if err != nil {
			return nil, fmt.Errorf("raft: refusing to boot: unreadable hardstate in %s: %w", config.DataDir, err)
		}
		n.currentTerm = hs.CurrentTerm
		n.votedFor = hs.VotedFor
	}

	// Initialize peer tracking
	for _, id := range peers {
		n.peers[id] = &Peer{ID: id}
		n.nextIndex[id] = 0
		n.matchIndex[id] = 0
	}

	return n, nil
}

// IsInJoint returns true if we're currently in joint consensus.
func (n *Node) IsInJoint() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.jointConfig != nil
}
