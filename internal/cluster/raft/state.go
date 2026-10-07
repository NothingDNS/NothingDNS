package raft

import (
	"fmt"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

// setVotedForLocked records a vote for v and persists it before any
// response that depends on it can be sent. MUST be called with n.mu held.
func (n *Node) setVotedForLocked(v NodeID) error {
	if v == n.votedFor {
		return nil
	}
	if err := n.persistHardStateLocked(HardState{CurrentTerm: n.currentTerm, VotedFor: v}); err != nil {
		return err
	}
	n.votedFor = v
	return nil
}

// advanceTermLocked advances currentTerm to t, resets votedFor (Raft §5.1
// "first vote of a new term is fresh"), transitions to follower state, and
// persists the change to disk before returning. MUST be called with n.mu
// held. No-op when t is not greater than n.currentTerm.
func (n *Node) advanceTermLocked(t Term) error {
	if t <= n.currentTerm {
		return nil
	}
	if err := n.persistHardStateLocked(HardState{CurrentTerm: t, VotedFor: ""}); err != nil {
		return err
	}
	n.currentTerm = t
	n.state = StateFollower
	n.votedFor = ""
	return nil
}

// persistHardStateLocked writes a candidate (currentTerm, votedFor) tuple to
// disk via the atomic+fsync helper. MUST be called with n.mu held. Callers
// apply the in-memory mutation only after this returns nil, so persistence
// failures reject the Raft transition instead of acknowledging unsafe state.
func (n *Node) persistHardStateLocked(hs HardState) error {
	if n.config.DataDir == "" {
		return nil
	}
	if err := saveHardState(n.config.DataDir, hs); err != nil {
		return fmt.Errorf("raft: persisting HardState failed: %w (term=%d votedFor=%q)", err, hs.CurrentTerm, hs.VotedFor)
	}
	return nil
}

// Start starts the Raft node's main loop.
func (n *Node) Start() {
	n.wg.Add(1)
	go n.run()
}

// Stop stops the Raft node. Idempotent — a second call is a no-op
// instead of the close-of-closed-channel panic the bare close would
// produce.
func (n *Node) Stop() {
	closed := false
	n.stopOnce.Do(func() {
		close(n.stopCh)
		closed = true
	})
	if !closed {
		return
	}
	n.wg.Wait()
}

// run is the main event loop.
func (n *Node) run() {
	defer n.wg.Done()

	electionTimer := n.newElectionTimer()
	defer electionTimer.Stop()

	for {
		// Exit promptly on Stop(): the inner state functions return when
		// stopCh closes, but without this guard run() would busy-loop
		// re-entering them forever and wg.Done (deferred above) would never
		// fire, hanging Stop().
		select {
		case <-n.stopCh:
			return
		default:
		}

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

// drainTimer empties a timer's channel after Stop so a stale fire can't be
// observed by the next Reset cycle.
func drainTimer(t *time.Timer) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}

// runFollower runs the follower state. The election timer is restarted on
// entry and every time the RPC layer reports legitimate leader contact, so
// a follower only becomes a candidate after a genuine silence.
func (n *Node) runFollower(electionTimer *time.Timer) {
	drainTimer(electionTimer)
	electionTimer.Reset(n.randomElectionTimeout())

	for {
		select {
		case <-n.stopCh:
			return
		case <-n.electionResetCh:
			// Heard from the leader (or granted a vote): restart the clock.
			drainTimer(electionTimer)
			electionTimer.Reset(n.randomElectionTimeout())
		case <-electionTimer.C:
			// Election timeout — become candidate. advanceTermLocked must
			// run FIRST: it bumps the term, clears votedFor AND forces state
			// back to Follower, so setting StateCandidate afterwards is what
			// actually leaves us a candidate. The reverse order (the original
			// bug) had advanceTermLocked silently stamp us back to Follower,
			// so the node only ever incremented its term and never campaigned.
			n.mu.Lock()
			if err := n.advanceTermLocked(n.currentTerm + 1); err != nil {
				util.Errorf("raft: election term advance failed: %v", err)
				n.mu.Unlock()
				return
			}
			n.state = StateCandidate
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
	// Vote for self (Raft §5.2). Persist before sending vote requests so a
	// restart can't lead us to vote again for someone else in the same term.
	n.mu.Lock()
	if err := n.setVotedForLocked(n.config.NodeID); err != nil {
		util.Errorf("raft: self-vote persistence failed: %v", err)
		n.state = StateFollower
		n.mu.Unlock()
		return
	}
	term := n.currentTerm
	lastLogIndex, lastLogTerm := n.lastLogInfo()
	n.mu.Unlock()

	// Request votes from all peers
	n.broadcastVoteRequest(term, lastLogIndex, lastLogTerm)

	// Collect votes
	voteCount := 1 // Vote for self
	quorum := n.quorumSize()

	// A self-vote may already be a majority (single-node cluster). Without
	// this early check the node would wait forever for vote responses that
	// no peer will ever send.
	if voteCount >= quorum {
		n.becomeLeader(term)
		return
	}

	electionTimer := n.newElectionTimer()

	for {
		select {
		case <-n.stopCh:
			return
		case <-electionTimer.C:
			// Election timeout — restart election. advanceTermLocked first
			// (it resets state to Follower); then mark candidate. See the
			// matching note in runFollower.
			n.mu.Lock()
			if err := n.advanceTermLocked(n.currentTerm + 1); err != nil {
				util.Errorf("raft: election term advance failed: %v", err)
				n.state = StateFollower
				n.mu.Unlock()
				return
			}
			n.state = StateCandidate
			n.mu.Unlock()
			return
		case <-n.electionResetCh:
			// An RPC handler accepted another leader (or we granted a vote
			// and stepped down to follower). Abandon this candidacy and let
			// run() re-dispatch on the updated state.
			n.mu.Lock()
			stillCandidate := n.state == StateCandidate
			n.mu.Unlock()
			if !stillCandidate {
				return
			}
		case resp := <-n.voteRespCh:
			if resp.Term > term {
				// Discovered higher term — become follower
				n.becomeFollower(resp.Term)
				return
			}
			if resp.Term < term {
				// Stale reply left over from a previous candidacy. Raft
				// §5.2 counts votes only for the term in which they were
				// granted, and voteRespCh is never drained between
				// elections (run() re-dispatches into runCandidate on
				// every iteration), so a late response from term-1 would
				// otherwise slip past the higher-term check and inflate
				// voteCount — letting this node win a term in which it
				// never won a majority, i.e. two leaders in one term.
				continue
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
		case req := <-n.snapshotCh:
			n.handleSnapshotRequest(req)
		}
	}
}

// notifyLeadership publishes a leadership transition. The send is
// non-blocking: leadershipCh is buffered and drained promptly by the
// integration layer, but the run-loop goroutine must never block here —
// a stalled consumer would otherwise freeze elections and replication.
func (n *Node) notifyLeadership(s LeadershipState) {
	select {
	case n.leadershipCh <- s:
	default:
	}
}

// becomeFollower transitions to follower state. Called from the candidate
// loop without n.mu held, so it takes the lock itself — the prior version
// mutated state and called advanceTermLocked (which requires the lock and
// fsyncs HardState) entirely unlocked, a data race against every other
// accessor.
func (n *Node) becomeFollower(term Term) {
	n.mu.Lock()
	// advanceTermLocked is a no-op when term <= currentTerm; ensure we at
	// least transition to follower state in that case (e.g. on a peer
	// step-down where the term doesn't move).
	if term > n.currentTerm {
		if err := n.advanceTermLocked(term); err != nil {
			util.Errorf("raft: follower transition term advance failed: %v", err)
			n.mu.Unlock()
			return
		}
	} else {
		n.state = StateFollower
	}
	n.mu.Unlock()
	n.notifyLeadership(LeadershipState{State: StateFollower, Term: term})
}

// becomeLeader transitions to leader state. Called from the candidate loop
// without n.mu held. State mutation happens under the lock; Propose is
// called afterwards because it acquires the lock itself.
func (n *Node) becomeLeader(term Term) {
	n.mu.Lock()
	n.state = StateLeader
	n.leaderID = n.config.NodeID
	// Initialize nextIndex and matchIndex for all peers (Raft §5.3:
	// nextIndex = leader's last log index + 1, matchIndex = 0).
	for id := range n.peers {
		n.nextIndex[id] = n.lastIndex() + 1
		n.matchIndex[id] = 0
	}
	n.mu.Unlock()

	n.notifyLeadership(LeadershipState{State: StateLeader, Term: term})

	// Commit a no-op entry to prove liveness. Failure here is logged but
	// does not abort the leader transition — the next AppendEntries cycle
	// will retry. The no-op also defends against the Raft §5.4.2 commit
	// bug (a leader cannot commit entries from a previous term without
	// also committing one of its own).
	if err := n.Propose(nil, EntryNoOp); err != nil {
		_ = err // logged by integration layer
	}
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

	// Only advance lastApplied AFTER the commit goes through. The
	// previous code bumped lastApplied before the channel send and
	// then fell into a default branch on a full commitCh — so on the
	// next sendCommitted call, the start/end window had already moved
	// past these entries and they were skipped forever. State machine
	// never saw them and the cluster silently lost commits. With this
	// ordering, a dropped send leaves lastApplied where it was; the
	// next maybeAdvanceCommitIndex / commit tick retries the same
	// window.
	select {
	case n.commitCh <- Commit{Entries: entries}:
		n.lastApplied = n.commitIndex
	default:
		// Channel full — will retry on the next commit tick.
	}
}

// quorumSize is the number of nodes (including self) that must agree for a
// decision — a strict majority of the full cluster. peers excludes self, so
// the cluster has len(peers)+1 nodes and the majority is
// ⌊(len(peers)+1)/2⌋ + 1. Correct for both odd and even cluster sizes.
func (n *Node) quorumSize() int {
	return (len(n.peers)+1)/2 + 1
}

// maybeAdvanceCommitIndex advances the commit index to the highest global
// index replicated on a quorum, subject to the Raft §5.4.2 rule that a
// leader may only commit an entry from its OWN term directly (older-term
// entries commit transitively once a current-term entry does). MUST hold
// n.mu.
func (n *Node) maybeAdvanceCommitIndex() {
	if n.state != StateLeader {
		return
	}

	newCommit := n.commitIndex
	for i := n.commitIndex + 1; i <= n.lastIndex(); i++ {
		if i <= n.lastSnapshot {
			continue
		}
		if t, ok := n.entryTerm(i); !ok || t != n.currentTerm {
			continue
		}

		replicas := 1 // the leader itself stores entry i
		for id := range n.peers {
			if n.matchIndex[id] >= i {
				replicas++
			}
		}
		// Commit once a strict majority of the FULL cluster (peers + self)
		// holds the entry. quorumSize() is correct for both odd and even
		// cluster sizes — the old `replicas > len(peers)/2` under-counted
		// for even sizes (e.g. it committed with just the leader in a
		// 2-node cluster, a split-brain hazard).
		if replicas >= n.quorumSize() {
			newCommit = i
		}
	}

	if newCommit > n.commitIndex {
		n.commitIndex = newCommit
		n.signalCommit()
	}
}

// signalCommit wakes the apply loop after commitIndex advances. The send
// is non-blocking: the applier always re-reads the current commitIndex
// when it wakes, so a dropped signal (buffer full ⇒ applier already
// behind) is harmless — any queued signal makes it apply up to the
// latest commit. Safe to call with n.mu held.
func (n *Node) signalCommit() {
	select {
	case n.commitCh <- Commit{}:
	default:
	}
}

// signalElectionReset notifies the run loop that we've had legitimate
// leader contact (valid AppendEntries) or just granted a vote, so the
// election timer should be restarted (follower) or the candidacy
// abandoned (candidate). Non-blocking: the buffer-of-1 collapses bursts
// and a dropped signal only costs one extra timer cycle. Safe under n.mu.
func (n *Node) signalElectionReset() {
	select {
	case n.electionResetCh <- struct{}{}:
	default:
	}
}

// --- Snapshot-aware log index helpers ---
//
// The Raft log uses GLOBAL indices: an entry's logical index counts from
// 1 and never resets, even after compaction. n.log only holds the entries
// AFTER the snapshot, so the entry with global index i lives at
// n.log[i-lastSnapshot-1]. Every place that maps between a global index
// and the n.log slice MUST go through these helpers — mixing the two
// conventions (as the pre-fix code did: maybeAdvanceCommitIndex used the
// array offset while sendCommitted applied the snapshot offset) silently
// commits the wrong entries once lastSnapshot > 0. All require n.mu held.

// lastIndex returns the highest global log index the node holds.
func (n *Node) lastIndex() Index {
	return n.lastSnapshot + Index(len(n.log))
}

// entryTerm returns the term of the entry at global index i.
// ok is false when i was compacted away (below the snapshot, term
// unknown) or is beyond the last index.
func (n *Node) entryTerm(i Index) (term Term, ok bool) {
	if i == 0 {
		return 0, true
	}
	if i == n.lastSnapshot {
		return n.lastSnapshotTerm, true
	}
	if i < n.lastSnapshot || i > n.lastIndex() {
		return 0, false
	}
	return n.log[i-n.lastSnapshot-1].Term, true
}

// entriesFrom returns a fresh copy of the log entries at global indices
// [from, lastIndex]. Entries already inside the snapshot are skipped.
func (n *Node) entriesFrom(from Index) []entry {
	if from <= n.lastSnapshot {
		from = n.lastSnapshot + 1
	}
	startArr := int(from - n.lastSnapshot - 1)
	if startArr < 0 || startArr >= len(n.log) {
		return nil
	}
	out := make([]entry, len(n.log)-startArr)
	copy(out, n.log[startArr:])
	return out
}

// truncateFrom drops every log entry with global index >= idx.
func (n *Node) truncateFrom(idx Index) {
	if idx <= n.lastSnapshot+1 {
		n.log = n.log[:0]
		return
	}
	keep := int(idx - n.lastSnapshot - 1)
	if keep < len(n.log) {
		n.log = n.log[:keep]
	}
}

// lastLogInfo returns the last global log index and its term.
func (n *Node) lastLogInfo() (Index, Term) {
	li := n.lastIndex()
	t, _ := n.entryTerm(li)
	return li, t
}

// randomElectionTimeout returns a randomized duration in
// [electionTimeout, 2*electionTimeout). Randomization across nodes is what
// breaks symmetric split votes (Raft §5.2).
func (n *Node) randomElectionTimeout() time.Duration {
	extra := n.rng.Int63n(int64(n.config.ElectionTimeout))
	return time.Duration(extra) + n.config.ElectionTimeout
}

// newElectionTimer creates a timer armed with a randomized election timeout.
func (n *Node) newElectionTimer() *time.Timer {
	return time.NewTimer(n.randomElectionTimeout())
}

// --- Accessors ---

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

// SetDNSAddr sets the DNS (TCP) host:port this node advertises to its
// followers in AppendEntries ("" advertises none). F562.
func (n *Node) SetDNSAddr(addr string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.dnsAddr = addr
}

// LeaderDNSAddr returns the known leader and the DNS address it advertised
// in its last accepted AppendEntries. addr is "" when no leader is known,
// the leader advertises none, or the address was learned from a different
// (earlier) leader. A leader reports its own address. F562.
func (n *Node) LeaderDNSAddr() (leader NodeID, addr string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.state == StateLeader {
		return n.config.NodeID, n.dnsAddr
	}
	if n.leaderID == "" || n.leaderDNSFrom != n.leaderID {
		return n.leaderID, ""
	}
	return n.leaderID, n.leaderDNSAddr
}

// LeaderID returns the most-recently-seen leader node ID, or "" if no
// leader has been observed since startup (e.g. fresh follower waiting
// for the first heartbeat). Followers learn the leader via
// AppendEntries; leaders return their own ID.
func (n *Node) LeaderID() NodeID {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.leaderID
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

// SetStateMachine sets the state machine for applying snapshots.
// This should be called before starting the node.
func (n *Node) SetStateMachine(sm StateMachine) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.stateMachine = sm
}

// SetLogPersister installs the durable log store. Call before Start.
func (n *Node) SetLogPersister(p logPersister) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.persister = p
}

// persistEntriesLocked durably appends entries and fsyncs, returning any
// failure so the caller can refuse to acknowledge non-durable entries. A
// follower that ACKs entries it did not actually fsync (e.g. disk full) lets
// the leader count it toward quorum and commit data this follower will lose on
// restart — a Raft durability/safety violation. Caller holds n.mu.
func (n *Node) persistEntriesLocked(entries []entry) error {
	if n.persister == nil || len(entries) == 0 {
		return nil
	}
	for _, e := range entries {
		if err := n.persister.Write(e); err != nil {
			util.Errorf("raft: WAL write failed (index=%d): %v", e.Index, err)
			return fmt.Errorf("wal write (index=%d): %w", e.Index, err)
		}
	}
	if err := n.persister.Sync(); err != nil {
		util.Errorf("raft: WAL sync failed: %v", err)
		return fmt.Errorf("wal sync: %w", err)
	}
	return nil
}

// persistTruncateLocked durably discards WAL entries past keepThrough,
// returning any failure so the caller can refuse to acknowledge a
// reconciliation that was not actually persisted. Caller holds n.mu.
func (n *Node) persistTruncateLocked(keepThrough Index) error {
	if n.persister == nil {
		return nil
	}
	if err := n.persister.TruncateAfter(keepThrough); err != nil {
		util.Errorf("raft: WAL truncate failed (keepThrough=%d): %v", keepThrough, err)
		return fmt.Errorf("wal truncate (keepThrough=%d): %w", keepThrough, err)
	}
	return nil
}
