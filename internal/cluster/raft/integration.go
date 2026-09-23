package raft

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

const zoneChangeWaitPollInterval = 5 * time.Millisecond

// ClusterIntegration integrates Raft consensus into the cluster.
type ClusterIntegration struct {
	node         *Node
	stateMachine *ZoneStateMachine
	transport    *TCPTransport
	rpcServer    *RPCServer
	wal          *WAL
	snapshotter  *Snapshotter
	logger       *util.Logger // structured logger; no raw log.Printf

	// Configuration
	config Config
	nodeID NodeID
	peers  []NodeID

	// Leadership tracking
	mu          sync.RWMutex
	isLeader    bool
	currentTerm Term

	// Applied index tracking
	appliedIndex    Index
	lastAppliedTerm Term

	// applyHook, when set, is invoked with each committed ZoneCommand so the
	// real zone store can be updated. Guarded by mu.
	applyHook func(ZoneCommand)

	// snapshotFn produces the full state-machine snapshot payload (the real
	// zone store, serialized). Used by the leader to take/send snapshots.
	// restoreFn loads a snapshot payload into the real store; used at boot to
	// restore the latest persisted snapshot. Guarded by mu.
	snapshotFn func() ([]byte, error)
	restoreFn  func([]byte) error

	// applyMu serializes state-machine application with snapshot capture, so a
	// snapshot reads a consistent (appliedIndex, zone-store) pair.
	applyMu sync.Mutex

	stopCh   chan struct{}
	stopOnce sync.Once // guards Stop() against second-call panic
	wg       sync.WaitGroup
}

// NewClusterIntegration creates a new Raft cluster integration.
// encryptionKey is a hex-encoded 32-byte AES-256 key used for the
// network/transport AEAD. If empty, transport AEAD is disabled
// (dev-only; production must supply a key).
//
// snapshotEncryptionKey, when set, is an independent hex-encoded
// 32-byte AES-256 key used for on-disk snapshot encryption (L-6).
// Empty leaves snapshots in plaintext (existing behaviour).
// peerAddrs maps each peer NodeID to its reachable RPC address. When an entry
// is missing (or the whole map is nil), the NodeID itself is used as the
// address — preserving the old behavior for callers/tests that name peers by
// their address.
//
// rpcTLS, when non-nil, wraps the Raft RPC listener and peer dials in TLS
// (typically mTLS built from cluster.rpc.*). It is independent of the
// message-level AEAD derived from encryptionKey: AEAD authenticates every
// frame, while TLS adds transport-level mutual authentication. nil = plain TCP.
func NewClusterIntegration(nodeID NodeID, peers []NodeID, peerAddrs map[NodeID]string, addr string, dataDir string, encryptionKey, snapshotEncryptionKey string, rpcTLS *tls.Config, logger *util.Logger) (*ClusterIntegration, error) {
	config := DefaultConfig()
	config.NodeID = nodeID
	// Wire the on-disk data directory so HardState (currentTerm/votedFor) is
	// persisted and reloaded across restarts. Without this, persistHardStateLocked
	// silently no-ops and NewNode skips loadHardState, so a restarted node comes
	// back at term 0 with no vote record and can grant the same term's vote twice
	// → split-brain (election-safety violation). The WAL and snapshotter use
	// dataDir/raft-wal and dataDir/snapshots; HardState lives at
	// dataDir/raft-hardstate.bin, so there is no path collision.
	config.DataDir = dataDir

	// Derive AEAD from the cluster encryption key (same scheme as gossip).
	var aead cipher.AEAD
	if encryptionKey != "" {
		key, err := hex.DecodeString(encryptionKey)
		if err != nil {
			return nil, fmt.Errorf("invalid encryption key hex: %w", err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("encryption key must be 32 bytes (%d provided)", len(key))
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("aes cipher: %w", err)
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("gcm: %w", err)
		}
		// Warn if running without transport-level encryption.
		// Note: the gossip protocol uses AES-256-GCM with per-sender sequence tracking.
	}

	// Create transport with optional TLS + AEAD encryption (nil AEAD = plaintext
	// for dev). rpcTLS, when set, also wraps peer dials in (m)TLS.
	transport := NewTCPTransport(rpcTLS, aead)

	// Register each peer's reachable RPC address.
	for _, peerID := range peers {
		paddr := peerAddrs[peerID]
		if paddr == "" {
			paddr = string(peerID) // fall back to NodeID-as-address
		}
		transport.SetPeerAddr(peerID, paddr)
	}

	// Create Raft node.
	node := NewNode(config, peers, transport)

	// ONE shared state machine. The node uses it for snapshot install
	// (Restore), and the apply loop below uses the same instance to apply
	// committed entries and to serve reads. The previous code created two
	// independent ZoneStateMachines — snapshot restores landed in the
	// node's copy while every read went to ci's copy, so a follower that
	// installed a snapshot served permanently stale zone data.
	stateMachine := NewZoneStateMachine()
	node.SetStateMachine(stateMachine)

	// Create RPC server with optional TLS listener + AEAD encryption.
	rpcServer, err := NewRPCServer(addr, node, rpcTLS, aead)
	if err != nil {
		return nil, fmt.Errorf("rpc server: %w", err)
	}

	// Create WAL.
	wal, err := NewWAL(dataDir + "/raft-wal")
	if err != nil {
		return nil, fmt.Errorf("wal: %w", err)
	}

	// Install the WAL as the node's durable log persister. The WAL is NOT
	// replayed here — bootstrapState() (in Start, after the snapshot fns are
	// wired) loads the latest snapshot first and then replays only the
	// post-snapshot WAL tail.
	node.SetLogPersister(wal)

	// Create snapshotter — L-6: encrypted at rest if a snapshot key
	// is provided. The hex decode mirrors the transport-AEAD path
	// above; config.Validate already enforces 32-byte hex + key
	// separation from EncryptionKey.
	var snapAeadKey []byte
	if snapshotEncryptionKey != "" {
		key, err := hex.DecodeString(snapshotEncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("invalid snapshot encryption key hex: %w", err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("snapshot encryption key must be 32 bytes (%d provided)", len(key))
		}
		snapAeadKey = key
	}
	snapshotter, err := NewSnapshotterEncrypted(dataDir+"/snapshots", snapAeadKey)
	if err != nil {
		return nil, fmt.Errorf("snapshotter: %w", err)
	}

	ci := &ClusterIntegration{
		node:         node,
		stateMachine: stateMachine, // SAME instance the node restores into
		transport:    transport,
		rpcServer:    rpcServer,
		wal:          wal,
		snapshotter:  snapshotter,
		logger:       logger,
		config:       config,
		nodeID:       nodeID,
		peers:        peers,
		stopCh:       make(chan struct{}),
	}

	return ci, nil
}

// bootstrapState reconstructs durable state at startup: restore the latest
// persisted snapshot (if any) into the store and indices, then replay only the
// WAL entries that follow the snapshot. Called once, before the node starts.
func (ci *ClusterIntegration) bootstrapState() {
	var snapIndex Index

	ci.mu.RLock()
	restore := ci.restoreFn
	ci.mu.RUnlock()

	if ci.snapshotter != nil {
		if snap, err := ci.snapshotter.Load(); err == nil && snap != nil && snap.LastIndex > 0 {
			if restore != nil {
				if err := restore(snap.Data); err != nil {
					ci.logger.Errorf("raft: restoring boot snapshot failed: %v", err)
				}
			}
			ci.node.lastSnapshot = snap.LastIndex
			ci.node.lastSnapshotTerm = snap.LastTerm
			ci.node.snapshotBytes = snap.Data
			ci.node.lastApplied = snap.LastIndex
			ci.node.commitIndex = snap.LastIndex
			ci.appliedIndex = snap.LastIndex
			ci.lastAppliedTerm = snap.LastTerm
			snapIndex = snap.LastIndex
			ci.logger.Infof("raft: booted from snapshot at index %d (term %d)", snap.LastIndex, snap.LastTerm)
		}
	}

	// Replay only the post-snapshot WAL tail into the log.
	if entries, err := ci.wal.ReadAll(); err == nil {
		for _, e := range entries {
			if e.Index > snapIndex {
				ci.node.log = append(ci.node.log, e)
			}
		}
	} else {
		ci.logger.Warnf("raft: reading WAL at boot failed: %v", err)
	}
}

// Start starts the Raft integration.
func (ci *ClusterIntegration) Start() error {
	// Reconstruct durable state (snapshot + WAL tail) before the node runs.
	ci.bootstrapState()

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

	// Start periodic snapshotter (leader-only work happens inside the loop)
	ci.wg.Add(1)
	go ci.snapshotLoop()

	return nil
}

// snapshotLoop periodically takes a snapshot while this node is the leader, so
// the log is bounded and followers that fall behind (or join fresh) can be
// caught up via InstallSnapshot.
func (ci *ClusterIntegration) snapshotLoop() {
	defer ci.wg.Done()
	interval := ci.config.SnapshotInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ci.stopCh:
			return
		case <-t.C:
			if ci.IsLeader() {
				ci.takeSnapshot()
			}
		}
	}
}

// takeSnapshot captures a consistent (appliedIndex, zone-store) pair, persists
// it, and compacts the log up to that index. No-op if there's nothing newly
// applied since the last snapshot.
func (ci *ClusterIntegration) takeSnapshot() {
	ci.mu.RLock()
	fn := ci.snapshotFn
	ci.mu.RUnlock()
	if fn == nil {
		return
	}

	// applyMu blocks the apply loop so the store and appliedIndex we read are
	// a coherent pair.
	ci.applyMu.Lock()
	ci.node.mu.Lock()
	idx := ci.appliedIndex
	isLeader := ci.node.state == StateLeader
	term, termOK := ci.node.entryTerm(idx)
	already := idx <= ci.node.lastSnapshot
	ci.node.mu.Unlock()
	if !isLeader || already || idx == 0 || !termOK {
		ci.applyMu.Unlock()
		return
	}
	data, err := fn()
	ci.applyMu.Unlock()
	if err != nil {
		ci.logger.Warnf("raft: snapshot serialization failed: %v", err)
		return
	}

	if ci.snapshotter != nil {
		if err := ci.snapshotter.Save(&Snapshot{Index: idx, Term: term, LastIndex: idx, LastTerm: term, Data: data}); err != nil {
			ci.logger.Warnf("raft: persisting snapshot failed: %v", err)
		}
	}
	ci.node.installLeaderSnapshot(idx, term, data)
	ci.logger.Infof("raft: snapshot taken at index %d (term %d, %d bytes); log compacted", idx, term, len(data))
}

// fastForwardApplied is invoked (with ci.node.mu held) after a snapshot is
// installed, advancing the integration's applied index past the snapshot.
func (ci *ClusterIntegration) fastForwardApplied(idx Index) {
	if idx > ci.appliedIndex {
		ci.appliedIndex = idx
		ci.lastAppliedTerm = ci.node.lastSnapshotTerm
		// The in-memory ledger (ci.stateMachine) only tracks log applies;
		// an installed snapshot went straight to the real zone store via
		// the restore fn. The ledger's pre-snapshot contents are now stale
		// — reset it so GetZoneData returns empty rather than lying.
		// Authoritative reads go through the zone manager, not this ledger.
		ci.stateMachine.reset()
	}
}

// Stop stops the Raft integration. Idempotent — subsequent calls
// return nil without re-closing ci.stopCh (which would panic) or
// re-stopping the child components.
func (ci *ClusterIntegration) Stop() error {
	closed := false
	ci.stopOnce.Do(func() {
		close(ci.stopCh)
		closed = true
	})
	if !closed {
		return nil
	}
	ci.node.Stop()
	ci.rpcServer.Stop()
	walErr := ci.wal.Close()
	ci.wg.Wait()
	if walErr != nil {
		return fmt.Errorf("close raft WAL: %w", walErr)
	}
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
			// Collect the newly-committed entries under the node lock, then
			// apply them OUTSIDE it. stateMachine.Apply fires the zone-apply
			// hook (which writes through to the real zone store and may do
			// disk I/O); holding the Raft node lock across that would stall
			// heartbeats and replication. appliedIndex is advanced only AFTER
			// each entry's apply completes, so a caller waiting on
			// appliedIndex >= idx is guaranteed the store mutation is done.
			ci.node.mu.Lock()
			commitIdx := ci.node.commitIndex
			start := ci.appliedIndex + 1
			lastSnap := ci.node.lastSnapshot
			var pending []entry
			for i := start; i <= commitIdx; i++ {
				if i <= lastSnap {
					continue
				}
				pos := int(i - lastSnap - 1)
				if pos >= 0 && pos < len(ci.node.log) {
					pending = append(pending, ci.node.log[pos])
				}
			}
			ci.node.mu.Unlock()

			for _, e := range pending {
				// applyMu makes (apply-to-store + advance appliedIndex) atomic
				// with respect to snapshot capture, so a snapshot never sees a
				// store mutated past the appliedIndex it records.
				ci.applyMu.Lock()
				if e.Term != 0 {
					// F050 (revised): an apply failure means this node's
					// state machine is diverging from the committed log.
					// Advancing appliedIndex anyway would mark the entry
					// "applied" and hide the divergence forever. Instead,
					// retry with backoff (transient I/O errors heal) and,
					// if the node is shutting down, exit without advancing
					// so the entry is re-applied on restart.
					if err := ci.applyWithRetry(e); err != nil {
						ci.applyMu.Unlock()
						return
					}
					ci.runApplyHook(e)
				}
				ci.node.mu.Lock()
				ci.appliedIndex = e.Index
				ci.lastAppliedTerm = e.Term
				ci.node.mu.Unlock()
				ci.applyMu.Unlock()
			}
		}
	}
}

// applyWithRetry applies a committed entry to the state machine, retrying
// with capped exponential backoff on failure. A committed entry MUST
// eventually be applied — skipping it silently diverges this node from the
// cluster. Blocking here is deliberate: appliedIndex stops advancing, which
// is observable (Sev-1 logs, lag metrics) instead of a hidden divergence.
// Returns a non-nil error only when the integration is shutting down.
func (ci *ClusterIntegration) applyWithRetry(e entry) error {
	return applyEntryWithRetry(ci.stateMachine.Apply, e, ci.stopCh, ci.logger)
}

// applyEntryWithRetry is the testable core of applyWithRetry: retries
// apply with capped exponential backoff until it succeeds or stopCh
// closes. Backoff starts at 100ms and caps at 5s.
func applyEntryWithRetry(apply func(entry) error, e entry, stopCh <-chan struct{}, logger *util.Logger) error {
	backoff := 100 * time.Millisecond
	const maxBackoff = 5 * time.Second
	for attempt := 1; ; attempt++ {
		err := apply(e)
		if err == nil {
			if attempt > 1 {
				logger.Warnf("raft: stateMachine.Apply for index=%d succeeded after %d attempts", e.Index, attempt)
			}
			return nil
		}
		logger.Errorf("raft: stateMachine.Apply failed for index=%d term=%d (attempt %d, Sev-1): %v", e.Index, e.Term, attempt, err)
		select {
		case <-stopCh:
			return fmt.Errorf("raft: shutting down with entry index=%d unapplied: %w", e.Index, err)
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// runApplyHook decodes a committed normal entry's ZoneCommand and forwards
// it to the registered apply hook (if any). Runs outside the Raft node lock.
func (ci *ClusterIntegration) runApplyHook(e entry) {
	if e.Type != EntryNormal || len(e.Command) == 0 {
		return
	}
	ci.mu.RLock()
	hook := ci.applyHook
	ci.mu.RUnlock()
	if hook == nil {
		return
	}
	var cmd ZoneCommand
	if err := json.Unmarshal(e.Command, &cmd); err != nil {
		ci.logger.Errorf("raft: apply-hook decode failed for index=%d: %v", e.Index, err)
		return
	}
	hook(cmd)
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

// ProposeZoneChangeWait replicates cmd through Raft and blocks until it has
// been applied locally (so the zone store reflects it) or the timeout
// elapses. Must be called on the leader — otherwise the underlying propose
// returns a "not leader" error.
func (ci *ClusterIntegration) ProposeZoneChangeWait(cmd ZoneCommand, timeout time.Duration) error {
	data, err := json.Marshal(cmd)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	idx, err := ci.node.ProposeEntry(data, EntryNormal)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	for {
		if ci.AppliedIndex() >= idx {
			return nil
		}
		now := time.Now()
		if zoneChangeWaitTimedOut(now, deadline) {
			return fmt.Errorf("raft: zone change at index %d not applied within %s", idx, timeout)
		}
		select {
		case <-ci.stopCh:
			return fmt.Errorf("raft: shutting down before zone change applied")
		case <-time.After(zoneChangeWaitDelay(now, deadline)):
		}
	}
}

func zoneChangeWaitTimedOut(now, deadline time.Time) bool {
	return !now.Before(deadline)
}

func zoneChangeWaitDelay(now, deadline time.Time) time.Duration {
	if zoneChangeWaitTimedOut(now, deadline) {
		return 0
	}
	remaining := deadline.Sub(now)
	if remaining < zoneChangeWaitPollInterval {
		return remaining
	}
	return zoneChangeWaitPollInterval
}

// AppliedIndex returns the highest log index applied to the state machine.
func (ci *ClusterIntegration) AppliedIndex() Index {
	ci.node.mu.Lock()
	defer ci.node.mu.Unlock()
	return ci.appliedIndex
}

// snapshotAdapter is the StateMachine the node uses solely for Snapshot()/
// Restore() — delegating to the real zone store via cluster-provided funcs.
// Apply is a no-op: committed entries reach the zone store through the apply
// hook (and ci.stateMachine's ledger), not this.
type snapshotAdapter struct {
	snapshot func() ([]byte, error)
	restore  func([]byte) error
}

func (a snapshotAdapter) Apply(entry) error { return nil }

func (a snapshotAdapter) Snapshot() ([]byte, error) {
	if a.snapshot == nil {
		return nil, nil
	}
	return a.snapshot()
}

func (a snapshotAdapter) Restore(data []byte) error {
	if a.restore == nil {
		return nil
	}
	return a.restore(data)
}

// SetSnapshotFns wires the real zone-store snapshot/restore functions. The
// node uses restore on InstallSnapshot receive; the leader uses snapshot to
// produce the payload it sends and persists. Call before Start.
func (ci *ClusterIntegration) SetSnapshotFns(snapshot func() ([]byte, error), restore func([]byte) error) {
	ci.mu.Lock()
	ci.snapshotFn = snapshot
	ci.restoreFn = restore
	ci.mu.Unlock()
	ci.node.SetStateMachine(snapshotAdapter{snapshot: snapshot, restore: restore})
	// When a snapshot is installed, fast-forward our applied index. Set
	// directly (no lock): SetSnapshotFns runs at construction, before Start.
	ci.node.onSnapshotInstalled = ci.fastForwardApplied
}

// SetApplyHook installs fn, called with each committed ZoneCommand as it is
// applied on this node (leader and followers alike), so the real DNS zone
// store stays in sync. Fires for every command type, independent of how the
// in-memory ledger models it.
func (ci *ClusterIntegration) SetApplyHook(fn func(ZoneCommand)) {
	ci.mu.Lock()
	ci.applyHook = fn
	ci.mu.Unlock()
}

// GetLeaderID returns the current leader's node ID. If this node is the
// leader, returns its own ID; otherwise returns the leader ID learned
// via AppendEntries, or "" if no leader has been observed yet.
func (ci *ClusterIntegration) GetLeaderID() NodeID {
	ci.mu.RLock()
	isLdr := ci.isLeader
	ci.mu.RUnlock()

	if isLdr {
		return ci.nodeID
	}
	return ci.node.LeaderID()
}

// ErrNotLeader is returned by AddNode/RemoveNode when this node is not
// the Raft leader. Callers can read LeaderID to redirect the request
// to the right node. LeaderID is "" if no leader has been observed yet
// (the cluster may be in an election).
type ErrNotLeader struct {
	LeaderID NodeID
}

func (e *ErrNotLeader) Error() string {
	if e.LeaderID == "" {
		return "raft: not the leader; leader unknown (cluster may be in election)"
	}
	return fmt.Sprintf("raft: not the leader; retry against %s", e.LeaderID)
}

// ErrMembershipChangeUnsupported is returned by AddNode/RemoveNode. Runtime
// membership changes via joint consensus are NOT fully implemented: the joint
// configuration is never committed into the peer set (advanceJointConfig is
// never driven), the conf-change entry is appended without being persisted to
// the WAL, and its index ignores the snapshot base — so invoking these would
// wedge all future membership ops and diverge the leader/follower logs (a
// leader-completeness hazard). Rather than silently corrupt the log, these
// entry points fail closed. Change cluster membership by updating cluster.peers
// in the config and performing a rolling restart.
var ErrMembershipChangeUnsupported = errors.New(
	"raft: runtime membership changes are not supported; update cluster.peers in config and restart")

// AddNode is intentionally unsupported at runtime — see
// ErrMembershipChangeUnsupported. It fails closed to avoid log corruption.
func (ci *ClusterIntegration) AddNode(nodeID NodeID, addr string) error {
	return ErrMembershipChangeUnsupported
}

// RemoveNode is intentionally unsupported at runtime — see
// ErrMembershipChangeUnsupported. It fails closed to avoid log corruption.
func (ci *ClusterIntegration) RemoveNode(nodeID NodeID) error {
	return ErrMembershipChangeUnsupported
}

// Stats returns cluster statistics.
//
// ci.appliedIndex is written by applyLoop under ci.node.mu.Lock();
// reading it outside that lock was a data race against the
// concurrent commit applier. While uint64 stores are atomic at the
// hardware level on every platform we target, the Go memory model
// still requires synchronization for cross-goroutine visibility,
// and the race detector flagged this site. Snapshot appliedIndex
// inside the same ci.node.mu critical section that captures
// state and commitIndex — those three values are then a coherent
// view of the same instant.
func (ci *ClusterIntegration) Stats() ClusterStats {
	ci.mu.RLock()
	isLeader := ci.isLeader
	ci.mu.RUnlock()

	// Read the term from the node itself, not ci.currentTerm: the latter is
	// only updated on a leadership transition, so a follower that simply
	// follows a new leader (no transition of its own) would otherwise report
	// a stale term (e.g. 0) in the dashboard.
	ci.node.mu.Lock()
	state := ci.node.state
	term := ci.node.currentTerm
	commitIdx := ci.node.commitIndex
	applied := ci.appliedIndex
	ci.node.mu.Unlock()

	return ClusterStats{
		NodeID:       ci.nodeID,
		State:        state.String(),
		Term:         int64(term),
		CommitIndex:  int64(commitIdx),
		AppliedIndex: int64(applied),
		IsLeader:     isLeader,
	}
}

// ClusterStats contains cluster statistics.
type ClusterStats struct {
	NodeID       NodeID
	State        string
	Term         int64
	CommitIndex  int64
	AppliedIndex int64
	IsLeader     bool
}

// PeerReplication holds per-peer replication progress known to this node.
// MatchIndex is only meaningful when this node is the leader (0 otherwise).
type PeerReplication struct {
	ID         NodeID
	Addr       string
	MatchIndex Index
}

// Peers returns configured Raft peers with optional match-index progress.
func (ci *ClusterIntegration) Peers() []PeerReplication {
	addrs := ci.transport.PeerAddrs()

	ci.node.mu.Lock()
	match := make(map[NodeID]Index, len(ci.node.matchIndex))
	for id, idx := range ci.node.matchIndex {
		match[id] = idx
	}
	ci.node.mu.Unlock()

	out := make([]PeerReplication, 0, len(ci.peers))
	for _, id := range ci.peers {
		out = append(out, PeerReplication{
			ID:         id,
			Addr:       addrs[id],
			MatchIndex: match[id],
		})
	}
	return out
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

// GetZoneData returns zone data from the log-apply ledger. NOTE: this is
// a debugging/introspection view, NOT the authoritative store — it is
// reset after a snapshot install (the snapshot restores the real zone
// store directly). Read zones through the zone manager instead.
func (ci *ClusterIntegration) GetZoneData(zone string) []RecordEntry {
	return ci.stateMachine.GetRecords(zone)
}
