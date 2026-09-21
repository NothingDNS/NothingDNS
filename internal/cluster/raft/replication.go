package raft

import (
	"context"
	"fmt"

	"github.com/nothingdns/nothingdns/internal/util"
)

// Propose proposes a command for replication. If node is not leader, returns error.
func (n *Node) Propose(command []byte, entryType EntryType) error {
	_, err := n.ProposeEntry(command, entryType)
	return err
}

// ProposeEntry is Propose that also returns the global index assigned to the
// new entry, so callers can wait for it to be applied. Returns an error if
// this node is not the leader.
func (n *Node) ProposeEntry(command []byte, entryType EntryType) (Index, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.state != StateLeader {
		return 0, fmt.Errorf("not leader (state=%s)", n.state)
	}

	e := entry{
		Index: n.lastIndex() + 1,
		Term:  n.currentTerm,
		Type:  entryType,
	}
	if command != nil {
		cmd := make([]byte, len(command))
		copy(cmd, command)
		e.Command = cmd
	}

	n.log = append(n.log, e)
	// Durably record the entry before it can be replicated/committed. If the
	// WAL write/fsync fails, roll back the in-memory append so the log matches
	// durable state and refuse the proposal — never replicate or commit an
	// entry the leader itself could not persist.
	if err := n.persistEntriesLocked(n.log[len(n.log)-1:]); err != nil {
		n.log = n.log[:len(n.log)-1]
		return 0, fmt.Errorf("persist proposed entry: %w", err)
	}

	// Try to advance commit immediately: when the leader's own copy is
	// already a quorum (single-node cluster), the entry commits here with no
	// peer round-trip. For multi-node clusters this is a no-op until acks
	// arrive (peers' matchIndex is still behind).
	n.maybeAdvanceCommitIndex()

	// Send to followers asynchronously
	go n.replicateToFollowers(e)

	return e.Index, nil
}

// replicateToFollowers pushes newly-appended entries to every follower
// immediately after a Propose, instead of waiting for the next heartbeat
// tick. Each peer is served from its own nextIndex via replicateTo, so a
// lagging follower still receives exactly the entries it's missing.
// snapshotPeerIDs returns a copy of the current peer IDs under n.mu.
// Broadcast functions use this to iterate without racing membership
// changes (which replace n.peers under the same lock). Without the
// snapshot, iterating n.peers outside the lock races with
// membership.go's `n.peers = n.jointConfig.NewPeers`, triggering Go's
// "fatal error: concurrent map iteration and map write."
func (n *Node) snapshotPeerIDs() []NodeID {
	n.mu.Lock()
	defer n.mu.Unlock()
	ids := make([]NodeID, 0, len(n.peers))
	for id := range n.peers {
		ids = append(ids, id)
	}
	return ids
}

func (n *Node) replicateToFollowers(_ entry) {
	n.mu.Lock()
	term := n.currentTerm
	isLeader := n.state == StateLeader
	n.mu.Unlock()
	if !isLeader {
		return
	}

	for _, peerID := range n.snapshotPeerIDs() {
		go func(peerID NodeID) {
			defer func() {
				if r := recover(); r != nil {
					util.Errorf("raft: panic in replicateToFollowers for peer %s: %v", peerID, r)
				}
			}()
			n.replicateTo(peerID, term)
		}(peerID)
	}
}

// broadcastVoteRequest sends vote requests to all peers.
func (n *Node) broadcastVoteRequest(term Term, lastLogIndex Index, lastLogTerm Term) {
	for _, peerID := range n.snapshotPeerIDs() {
		go func(peerID NodeID) {
			defer func() {
				if r := recover(); r != nil {
					util.Errorf("raft: panic in broadcastVoteRequest for peer %s: %v", peerID, r)
				}
			}()
			req := VoteRequest{
				Term:         term,
				CandidateID:  n.config.NodeID,
				LastLogIndex: lastLogIndex,
				LastLogTerm:  lastLogTerm,
			}
			// RPC call — would be injected in real implementation
			n.sendVoteRequest(peerID, req)
		}(peerID)
	}
}

// broadcastHeartbeat sends AppendEntries to every peer. A "heartbeat" in
// this implementation is just a normal AppendEntries built from the peer's
// nextIndex: if the follower is behind it carries the missing entries, if
// it's caught up it carries none. This is the standard Raft model and is
// what lets the leader's periodic tick double as the catch-up driver.
func (n *Node) broadcastHeartbeat(term Term) {
	for _, peerID := range n.snapshotPeerIDs() {
		go func(peerID NodeID) {
			defer func() {
				if r := recover(); r != nil {
					util.Errorf("raft: panic in broadcastHeartbeat for peer %s: %v", peerID, r)
				}
			}()
			n.replicateTo(peerID, term)
		}(peerID)
	}
}

// buildAppendRequestLocked assembles the AppendEntries to send to peerID
// from its current nextIndex. ok is false only when the entries the peer
// needs have already been compacted into a snapshot (the caller should
// send an InstallSnapshot instead — not yet wired). MUST hold n.mu.
func (n *Node) buildAppendRequestLocked(peerID NodeID, term Term) (AppendRequest, bool) {
	nextIdx := n.nextIndex[peerID]
	if nextIdx < 1 {
		nextIdx = 1
	}
	prevLogIndex := nextIdx - 1
	if prevLogIndex < n.lastSnapshot {
		// The follower is so far behind that PrevLog is inside our
		// snapshot; a plain AppendEntries can't bridge that gap.
		return AppendRequest{}, false
	}
	prevLogTerm, ok := n.entryTerm(prevLogIndex)
	if !ok {
		return AppendRequest{}, false
	}
	return AppendRequest{
		Term:         term,
		LeaderID:     n.config.NodeID,
		PrevLogIndex: prevLogIndex,
		PrevLogTerm:  prevLogTerm,
		Entries:      n.entriesFrom(nextIdx),
		LeaderCommit: n.commitIndex,
	}, true
}

// replicateTo sends one AppendEntries to a single peer based on its nextIndex,
// or an InstallSnapshot when the peer has fallen behind our snapshot. Used by
// the heartbeat tick and immediately after a Propose.
func (n *Node) replicateTo(peerID NodeID, term Term) {
	n.mu.Lock()
	if n.state != StateLeader || n.currentTerm != term {
		n.mu.Unlock()
		return
	}
	req, ok := n.buildAppendRequestLocked(peerID, term)
	if !ok {
		// The follower needs entries we've already compacted into our
		// snapshot — bridge the gap with InstallSnapshot.
		snap := SnapshotRequest{
			Term:      term,
			LeaderID:  n.config.NodeID,
			Data:      n.snapshotBytes,
			LastIndex: n.lastSnapshot,
			LastTerm:  n.lastSnapshotTerm,
		}
		hasSnap := n.lastSnapshot > 0 && len(n.snapshotBytes) > 0
		n.mu.Unlock()
		if hasSnap {
			n.sendInstallSnapshot(peerID, snap)
		}
		return
	}
	n.mu.Unlock()
	n.sendAppendRequest(peerID, req)
}

// installLeaderSnapshot records a snapshot the LEADER just took: it caches the
// payload for InstallSnapshot sends, advances lastSnapshot/lastSnapshotTerm,
// and compacts the in-memory log up to index. The WAL is intentionally left
// intact — on restart the node replays the full WAL and reconstructs the log;
// snapshots are used for live follower catch-up, not boot recovery.
func (n *Node) installLeaderSnapshot(index Index, term Term, data []byte) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if index <= n.lastSnapshot || index > n.lastIndex() {
		return
	}
	remove := int(index - n.lastSnapshot) // entries lastSnapshot+1 .. index
	if remove >= len(n.log) {
		n.log = n.log[:0]
	} else {
		n.log = append([]entry(nil), n.log[remove:]...)
	}
	n.lastSnapshot = index
	n.lastSnapshotTerm = term
	n.snapshotBytes = data
	// Bound the WAL: entries up to the snapshot are now redundant.
	if n.persister != nil {
		if err := n.persister.CompactBefore(index); err != nil {
			util.Errorf("raft: WAL compaction to %d failed: %v", index, err)
		}
	}
}

// sendInstallSnapshot streams a snapshot to a peer and advances its
// progress only after the follower ACKNOWLEDGES the install. A transport
// success alone is not enough: the follower may refuse the install
// (stale term, Restore failure), and advancing matchIndex on an
// uninstalled snapshot would let the leader count it toward quorum.
func (n *Node) sendInstallSnapshot(peerID NodeID, req SnapshotRequest) {
	if n.transport == nil {
		return
	}
	// In-flight guard: at most one outstanding snapshot send per peer.
	// The ACK can take longer than a heartbeat interval, and every
	// heartbeat that finds the peer still behind lastSnapshot would
	// otherwise launch another full send — a resend storm that hammers
	// the follower with repeated Restore+CompactBefore under its lock.
	n.mu.Lock()
	if n.snapshotInFlight[peerID] {
		n.mu.Unlock()
		return
	}
	n.snapshotInFlight[peerID] = true
	n.mu.Unlock()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				util.Errorf("raft: panic in sendInstallSnapshot: %v", r)
			}
			n.mu.Lock()
			delete(n.snapshotInFlight, peerID)
			n.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), raftRPCTimeout)
		defer cancel()
		resp, err := n.transport.SendSnapshot(ctx, peerID, req)
		if err != nil || resp == nil {
			return
		}
		n.mu.Lock()
		defer n.mu.Unlock()
		if resp.Term > n.currentTerm {
			// Follower is in a newer term: step down.
			if err := n.advanceTermLocked(resp.Term); err != nil {
				util.Errorf("raft: snapshot response term advance failed: %v", err)
			}
			n.state = StateFollower
			return
		}
		if !resp.Success {
			return
		}
		if n.state == StateLeader && n.currentTerm == req.Term {
			if req.LastIndex > n.matchIndex[peerID] {
				n.matchIndex[peerID] = req.LastIndex
			}
			if n.nextIndex[peerID] < req.LastIndex+1 {
				n.nextIndex[peerID] = req.LastIndex + 1
			}
		}
	}()
}
