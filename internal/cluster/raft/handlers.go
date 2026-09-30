package raft

import (
	"context"

	"github.com/nothingdns/nothingdns/internal/util"
)

// handleVoteRequest handles a vote request.
func (n *Node) handleVoteRequest(req VoteRequest) {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Reply false if term < currentTerm
	if req.Term < n.currentTerm {
		n.sendVoteResponseLocked(VoteResponse{
			Term:        n.currentTerm,
			VoteGranted: false,
			From:        n.config.NodeID,
		})
		return
	}

	// Raft §5.1: if RPC carries a higher term we MUST update our own
	// currentTerm, drop to follower, and reset votedFor BEFORE deciding
	// whether to grant this vote. The previous code skipped this step
	// and proceeded to the votedFor check below with the *old* term's
	// vote intact — so a node that had voted for itself in term N
	// would reject every candidate's request in term N+1 even though
	// no one in term N+1 had been voted for yet. The cluster could get
	// stuck unable to elect a leader (livelock) because every node
	// holds a stale per-term vote from an earlier term.
	//
	// Note: advanceTermLocked also persists the new (currentTerm,
	// votedFor="") tuple via fsync before we proceed, satisfying the
	// election-safety durability requirement.
	if req.Term > n.currentTerm {
		if err := n.advanceTermLocked(req.Term); err != nil {
			util.Errorf("raft: vote request term advance failed: %v", err)
			n.sendVoteResponseLocked(VoteResponse{
				Term:        n.currentTerm,
				VoteGranted: false,
				From:        n.config.NodeID,
			})
			return
		}
	}

	// If votedFor is null or candidateId, and candidate's log is at least as
	// up-to-date as receiver's log, grant vote
	if (n.votedFor == "" || n.votedFor == req.CandidateID) && n.isLogUpToDate(req.LastLogIndex, req.LastLogTerm) {
		if err := n.setVotedForLocked(req.CandidateID); err != nil {
			util.Errorf("raft: vote persistence failed: %v", err)
			n.sendVoteResponseLocked(VoteResponse{
				Term:        n.currentTerm,
				VoteGranted: false,
				From:        n.config.NodeID,
			})
			return
		}
		// Granting a vote counts as leader contact: don't immediately start
		// our own campaign against the candidate we just endorsed.
		n.signalElectionReset()
		n.sendVoteResponseLocked(VoteResponse{
			Term:        n.currentTerm,
			VoteGranted: true,
			From:        n.config.NodeID,
		})
	} else {
		n.sendVoteResponseLocked(VoteResponse{
			Term:        n.currentTerm,
			VoteGranted: false,
			From:        n.config.NodeID,
		})
	}
}

// sendVoteResponseLocked delivers a vote response without ever blocking the
// caller. voteRespCh is bounded (size 10) and its only consumer is
// runCandidate, so a node that is NOT a candidate never drains it. A blocking
// send there would wedge handleVoteRequest — which runs under n.mu — after
// the buffer filled, deadlocking every other n.mu holder. This mirrors the
// non-blocking send-and-drop used by the transport path in sendVoteRequest.
//
// Dropping is safe: a vote response nobody collects is a response to a
// campaign this node is not running, and the candidate's own election timeout
// expires it. MUST be called with n.mu held.
func (n *Node) sendVoteResponseLocked(resp VoteResponse) {
	select {
	case n.voteRespCh <- resp:
	default:
		// voteRespCh is bounded (size 10); if full drop the response
		// rather than block the handler while holding n.mu.
	}
}

// handleAppendRequest handles an AppendEntries request arriving on the
// in-process channel path and pushes the response to appendRespCh.
func (n *Node) handleAppendRequest(req AppendRequest) {
	n.mu.Lock()
	resp := n.appendEntriesLocked(req)
	n.mu.Unlock()
	n.appendRespCh <- resp
}

// appendEntriesLocked is the single, snapshot-aware implementation of the
// AppendEntries receiver rules (Raft §5.3). Both the channel-based and the
// exported RPC handler delegate here so the two can never drift apart.
// MUST be called with n.mu held.
//
// On success it sets resp.MatchIndex to the global index of the last entry
// the follower now stores that is consistent with the leader — WITHOUT
// this the leader's matchIndex never advances and nothing ever commits.
// On a consistency-check failure it returns a MatchIndex hint so the
// leader can back nextIndex up quickly instead of decrementing by one.
func (n *Node) appendEntriesLocked(req AppendRequest) AppendResponse {
	resp := AppendResponse{
		Term:    n.currentTerm,
		Success: false,
		From:    n.config.NodeID,
	}

	// Reply false if term < currentTerm (Raft §5.1).
	if req.Term < n.currentTerm {
		return resp
	}

	// A valid AppendEntries means the sender is the leader of a term at
	// least as new as ours: adopt the term, step down to follower, and
	// record the leader for client redirection.
	if req.Term > n.currentTerm {
		if err := n.advanceTermLocked(req.Term); err != nil {
			util.Errorf("raft: append request term advance failed: %v", err)
			return resp
		}
	}
	n.state = StateFollower
	if req.LeaderID != "" {
		n.leaderID = req.LeaderID
	}
	resp.Term = n.currentTerm

	// Legitimate leader contact for this term: restart the election clock
	// (and, if we were a candidate, step down) so a healthy leader isn't
	// repeatedly challenged.
	n.signalElectionReset()

	// Log-consistency check at PrevLogIndex (Raft §5.3).
	if req.PrevLogIndex > n.lastIndex() {
		// We're missing entries before PrevLogIndex. Hint our last index
		// so the leader resumes from there.
		resp.MatchIndex = n.lastIndex()
		return resp
	}
	if req.PrevLogIndex > n.lastSnapshot {
		if t, ok := n.entryTerm(req.PrevLogIndex); !ok || t != req.PrevLogTerm {
			// Term conflict at PrevLogIndex: drop it and everything after,
			// then ask the leader to retry one entry earlier.
			n.truncateFrom(req.PrevLogIndex)
			if err := n.persistTruncateLocked(req.PrevLogIndex - 1); err != nil {
				// Reconciliation not durable — leave Success false so the
				// leader retries rather than trusting an unpersisted truncation.
				return resp
			}
			resp.MatchIndex = req.PrevLogIndex - 1
			return resp
		}
	}

	// PrevLog matches. Reconcile the incoming entries with our log,
	// overwriting only on a genuine term conflict so we never discard
	// entries we already agree on (Raft §5.3 final paragraph).
	var toAppend []entry
	truncated := false
	var keepThrough Index
	for j, e := range req.Entries {
		idx := req.PrevLogIndex + 1 + Index(j)
		if idx <= n.lastSnapshot {
			continue // already captured by the snapshot
		}
		if idx <= n.lastIndex() {
			if t, _ := n.entryTerm(idx); t != e.Term {
				n.truncateFrom(idx)
				truncated = true
				keepThrough = idx - 1
				toAppend = req.Entries[j:]
				n.log = append(n.log, toAppend...)
				break
			}
			// identical entry already present — skip
			continue
		}
		// idx is past our log: append this and all remaining entries.
		toAppend = req.Entries[j:]
		n.log = append(n.log, toAppend...)
		break
	}
	// Durably record the reconciliation before acknowledging. If persistence
	// fails (e.g. disk full), do NOT ack as Success: a follower that reports
	// entries durable when they are not lets the leader commit data this
	// follower will lose on restart (Raft safety violation). resp.Success
	// stays false, so the leader simply retries.
	if truncated {
		if err := n.persistTruncateLocked(keepThrough); err != nil {
			return resp
		}
	}
	if err := n.persistEntriesLocked(toAppend); err != nil {
		return resp
	}

	// Advance commit index. Cap at the last entry this request let us
	// verify is consistent with the leader (PrevLogIndex + #entries) —
	// never blindly to the leader's commit, which may be ahead of what
	// this follower actually holds.
	lastConsistent := req.PrevLogIndex + Index(len(req.Entries))
	if req.LeaderCommit > n.commitIndex {
		newCommit := min(req.LeaderCommit, lastConsistent)
		if newCommit > n.commitIndex {
			n.commitIndex = newCommit
			n.signalCommit()
		}
	}

	resp.Success = true
	resp.MatchIndex = lastConsistent
	return resp
}

// HandleVoteRequest is the exported RPC handler for vote requests.
func (n *Node) HandleVoteRequest(req VoteRequest) VoteResponse {
	n.mu.Lock()
	defer n.mu.Unlock()

	if req.Term < n.currentTerm {
		return VoteResponse{
			Term:        n.currentTerm,
			VoteGranted: false,
			From:        n.config.NodeID,
		}
	}

	if req.Term > n.currentTerm {
		if err := n.advanceTermLocked(req.Term); err != nil {
			util.Errorf("raft: vote request term advance failed: %v", err)
			return VoteResponse{
				Term:        n.currentTerm,
				VoteGranted: false,
				From:        n.config.NodeID,
			}
		}
	}

	if (n.votedFor == "" || n.votedFor == req.CandidateID) && n.isLogUpToDate(req.LastLogIndex, req.LastLogTerm) {
		if err := n.setVotedForLocked(req.CandidateID); err != nil {
			util.Errorf("raft: vote persistence failed: %v", err)
			return VoteResponse{
				Term:        n.currentTerm,
				VoteGranted: false,
				From:        n.config.NodeID,
			}
		}
		// Granting a vote counts as leader contact: don't immediately start
		// our own campaign against the candidate we just endorsed.
		n.signalElectionReset()
		return VoteResponse{
			Term:        n.currentTerm,
			VoteGranted: true,
			From:        n.config.NodeID,
		}
	}
	return VoteResponse{
		Term:        n.currentTerm,
		VoteGranted: false,
		From:        n.config.NodeID,
	}
}

// HandleAppendRequest is the exported RPC handler for append requests.
// It delegates to the shared receiver implementation so the RPC and
// in-process channel paths apply identical rules.
func (n *Node) HandleAppendRequest(req AppendRequest) AppendResponse {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.appendEntriesLocked(req)
}

// HandleSnapshotRequest is the exported RPC handler for snapshot requests.
// Installs a snapshot from the leader, restoring state machine state.
// The returned response tells the leader whether the install actually
// happened — only a Success=true acknowledgement may advance matchIndex.
func (n *Node) HandleSnapshotRequest(req SnapshotRequest) SnapshotResponse {
	n.mu.Lock()
	defer n.mu.Unlock()

	if req.Term < n.currentTerm {
		return SnapshotResponse{Term: n.currentTerm, Success: false}
	}

	if req.Term > n.currentTerm {
		if err := n.advanceTermLocked(req.Term); err != nil {
			util.Errorf("raft: snapshot request term advance failed: %v", err)
			return SnapshotResponse{Term: n.currentTerm, Success: false}
		}
	}

	// Reject a stale or duplicate snapshot: installing one whose
	// LastIndex is not past what we already have would rewind
	// commitIndex/lastApplied and discard log entries this follower
	// already acknowledged. A delayed retry of an already-installed
	// snapshot must be idempotent, so ACK success without reinstalling.
	if req.LastIndex <= n.lastSnapshot || req.LastIndex <= n.commitIndex {
		return SnapshotResponse{Term: n.currentTerm, Success: true}
	}

	// If we have a state machine and snapshot data, restore it.
	// On Restore failure, we MUST NOT advance the snapshot indices
	// or clear the log: committing to a state we couldn't load means
	// the node now claims `lastApplied=N` while the state machine is
	// still at `M < N`. The follower silently diverges from the rest
	// of the cluster and there is no recovery path — the leader
	// won't re-send a snapshot it already thinks we acknowledged.
	// The right behavior is to refuse the install; the leader's
	// next AppendEntries / snapshot retry will try again.
	if len(req.Data) > 0 && n.stateMachine != nil {
		if err := n.stateMachine.Restore(req.Data); err != nil {
			util.Errorf("failed to restore state machine from snapshot: %v", err)
			return SnapshotResponse{Term: n.currentTerm, Success: false}
		}
	}

	// Install snapshot: update indices and clear log. lastSnapshotTerm
	// must move with lastSnapshot so entryTerm(lastSnapshot) keeps
	// answering correctly for the new compaction point.
	n.lastSnapshot = req.LastIndex
	n.lastSnapshotTerm = req.LastTerm
	n.lastApplied = req.LastIndex
	n.commitIndex = req.LastIndex
	n.log = make([]entry, 0) // Discard all log entries before snapshot
	n.snapshotBytes = req.Data
	if n.persister != nil {
		if err := n.persister.CompactBefore(req.LastIndex); err != nil {
			util.Errorf("raft: WAL compaction to %d failed: %v", req.LastIndex, err)
		}
	}
	// Fast-forward the integration's applied index so its apply loop doesn't
	// try to re-apply entries the snapshot already subsumes.
	if n.onSnapshotInstalled != nil {
		n.onSnapshotInstalled(req.LastIndex)
	}
	return SnapshotResponse{Term: n.currentTerm, Success: true}
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
		if err := n.advanceTermLocked(resp.Term); err != nil {
			util.Errorf("raft: append response term advance failed: %v", err)
			n.state = StateFollower
		}
		return
	}

	if resp.Term != n.currentTerm {
		// Stale response from a prior term (resp.Term < currentTerm; the
		// resp.Term > currentTerm case is handled above). The leader must act
		// only on responses to AppendEntries it sent in its CURRENT term. A node
		// that briefly stepped down and regained leadership in a higher term
		// within the RPC window could otherwise accept a delayed term-T success,
		// advance matchIndex from a since-overwritten follower log, and falsely
		// commit a current-term entry that is not actually on a quorum (Raft
		// §5.3/§5.5 safety violation).
		return
	}

	if resp.Success {
		// Advance match/next for this peer from the follower's hint, then
		// recompute the commit index.
		if resp.MatchIndex > n.matchIndex[resp.From] {
			n.matchIndex[resp.From] = resp.MatchIndex
		}
		n.nextIndex[resp.From] = n.matchIndex[resp.From] + 1
		n.maybeAdvanceCommitIndex()
	} else {
		// Consistency check failed. Back nextIndex up — toward the
		// follower's MatchIndex hint when it's useful, otherwise by one —
		// so the next AppendEntries probes an earlier point in the log.
		hintNext := resp.MatchIndex + 1
		if hintNext >= 1 && hintNext < n.nextIndex[resp.From] {
			n.nextIndex[resp.From] = hintNext
		} else if n.nextIndex[resp.From] > 1 {
			n.nextIndex[resp.From]--
		}
	}
}

// handleSnapshotRequest handles a snapshot install request.
// This is the internal version used for local snapshot installation.
func (n *Node) handleSnapshotRequest(req SnapshotRequest) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if req.Term < n.currentTerm {
		return
	}

	if req.Term > n.currentTerm {
		if err := n.advanceTermLocked(req.Term); err != nil {
			util.Errorf("raft: snapshot request term advance failed: %v", err)
			return
		}
	}

	// If we have a state machine and snapshot data, restore it.
	// On Restore failure, we MUST NOT update the snapshot indices or
	// clear the log: doing so would commit to a state we couldn't
	// actually load, leaving the node permanently divergent from the
	// rest of the cluster. The leader will retry the snapshot install
	// on its next AppendEntries; that's the standard recovery path.
	if len(req.Data) > 0 && n.stateMachine != nil {
		if err := n.stateMachine.Restore(req.Data); err != nil {
			util.Errorf("failed to restore state machine from snapshot: %v", err)
			return
		}
	}

	// Install snapshot: update indices and clear log
	n.lastSnapshot = req.LastIndex
	n.lastSnapshotTerm = req.LastTerm
	n.lastApplied = req.LastIndex
	n.commitIndex = req.LastIndex
	n.log = make([]entry, 0)
	n.snapshotBytes = req.Data
	if n.persister != nil {
		if err := n.persister.CompactBefore(req.LastIndex); err != nil {
			util.Errorf("raft: WAL compaction to %d failed: %v", req.LastIndex, err)
		}
	}
	if n.onSnapshotInstalled != nil {
		n.onSnapshotInstalled(req.LastIndex)
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

// sendVoteRequest sends a vote request to a peer via the transport.
func (n *Node) sendVoteRequest(peerID NodeID, req VoteRequest) {
	if n.transport == nil {
		return
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				util.Errorf("raft: panic in sendVoteRequest: %v", r)
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), raftRPCTimeout)
		defer cancel()
		resp, err := n.transport.SendRequestVote(ctx, peerID, req)
		if err != nil || resp == nil {
			// Transport error or a nil response (e.g. peer down): drop it
			// rather than dereference a nil pointer.
			return
		}
		select {
		case n.voteRespCh <- *resp:
		default:
			// voteRespCh is bounded (size 10); if full drop the response
			// rather than block the RPC handler.
		}
	}()
}

// sendAppendRequest sends an AppendEntries request to a peer via the transport.
func (n *Node) sendAppendRequest(peerID NodeID, req AppendRequest) {
	if n.transport == nil {
		return
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				util.Errorf("raft: panic in sendAppendRequest: %v", r)
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), raftRPCTimeout)
		defer cancel()
		resp, err := n.transport.SendAppendEntries(ctx, peerID, req)
		if err != nil || resp == nil {
			// Transport error or a nil response (e.g. peer down): drop it
			// rather than dereference a nil pointer.
			return
		}
		select {
		case n.appendRespCh <- *resp:
		default:
			// appendRespCh is bounded; if full drop rather than block.
		}
	}()
}

// SendVoteRequestChannel is used by tests to inject vote requests into the
// in-process channel path. Not for production use.
func (n *Node) SendVoteRequestChannel() chan<- VoteRequest {
	return n.voteCh
}

// SendAppendRequestChannel is used by tests to inject append requests into the
// in-process channel path. Not for production use.
func (n *Node) SendAppendRequestChannel() chan<- AppendRequest {
	return n.appendCh
}

// SendSnapshotRequestChannel is used by tests to inject snapshot requests into the
// in-process channel path. Not for production use.
func (n *Node) SendSnapshotRequestChannel() chan<- SnapshotRequest {
	return n.snapshotCh
}
