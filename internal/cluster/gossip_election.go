package cluster

import (
	"fmt"
	"net"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

// handleElection handles leader election messages.
//
// F053: the previous "bully algorithm" implementation crowned this node as
// leader on receipt of a single Election message whose ProposedLeader
// equalled our own NodeID — with NO quorum, vote-collection or proof-of-
// life from any other node. Any peer (or off-path attacker who could spoof
// an Election frame past the AEAD perimeter) could elect an arbitrary node
// by sending one message.
//
// The gossip layer is not the right place for consensus: real leader
// election uses the Raft RPC tier (internal/cluster/raft). This handler is
// kept alive only to bump the election term used by split-brain
// detection. It no longer mutates leadership state. Operators that need a
// gossip-layer election must build a quorum-vote state machine on top of
// this stub.
func (gp *GossipProtocol) handleElection(msg Message, from *net.UDPAddr) {
	var payload ElectionPayload
	if err := decodePayload(msg.Payload, &payload); err != nil {
		return
	}

	gp.leaderMu.Lock()
	defer gp.leaderMu.Unlock()

	// Track the highest term we have seen so split-brain telemetry remains
	// meaningful, but do NOT change isLeader / currentLeader here.
	if payload.Term > gp.electionTerm {
		gp.electionTerm = payload.Term
	}
}

// handleLeader handles leader announcement messages.
//
// Mirrors the same-term hardening already applied to
// handleHeartbeat: do NOT swap a known leader for a *different*
// leader claiming the same term. The previous code adopted any
// payload with Term >= leaderTerm, so a peer (or off-path
// attacker with the AEAD key) could send a Leader announcement
// at our current term naming a different LeaderID and flip the
// cluster's view of leadership without an election. Split-brain
// territory: leave the existing leader alone until a strictly
// higher term resolves the conflict. Adopt on (a) strictly
// higher term, or (b) we have no current leader yet (first
// announce after start or after a step-down).
func (gp *GossipProtocol) handleLeader(msg Message, from *net.UDPAddr) {
	var payload LeaderPayload
	if err := decodePayload(msg.Payload, &payload); err != nil {
		return
	}

	// Impostor protection: payload.LeaderID is the node claiming
	// leadership; msg.From is the AEAD-authenticated sender. Only the
	// leader itself may announce its own leadership — without this
	// check, a compromised gossip-keyring peer could forge a
	// higher-term Leader announcement naming itself, get adopted by
	// every follower, and then pass the msg.From == currentLeader gate
	// on forged ZoneUpdate/ConfigSync frames (full cluster takeover).
	// Mirrors the same check in handlePing/handleAck/handleZoneUpdate.
	if msg.From != payload.LeaderID {
		util.Warnf("gossip: dropped Leader announcement from impostor %s claiming to be %s", msg.From, payload.LeaderID)
		return
	}

	gp.leaderMu.Lock()
	defer gp.leaderMu.Unlock()

	// Stale terms ignored.
	if payload.Term < gp.leaderTerm {
		return
	}

	adopt := false
	if payload.Term > gp.leaderTerm {
		adopt = true
	} else if gp.currentLeader == "" {
		adopt = true
	} else if payload.LeaderID == gp.currentLeader {
		// Same term, same leader: refresh lastHeartbeat below.
		adopt = true
	}
	if !adopt {
		// Same term, different leader: don't switch (split-brain hazard).
		return
	}

	gp.currentLeader = payload.LeaderID
	gp.leaderTerm = payload.Term
	gp.isLeader = (payload.LeaderID == gp.nodeList.GetSelf().ID)
	gp.lastHeartbeat = time.Now()
}

// handleHeartbeat handles leader heartbeat messages.
func (gp *GossipProtocol) handleHeartbeat(msg Message, from *net.UDPAddr) {
	var payload LeaderHeartbeatPayload
	if err := decodePayload(msg.Payload, &payload); err != nil {
		return
	}

	// Impostor protection: payload.LeaderID is the node claiming to be
	// the leader; msg.From is the AEAD-authenticated sender. Only the
	// leader itself may send heartbeats. Without this check, a
	// compromised gossip-keyring peer could forge a higher-term
	// heartbeat naming itself, be adopted as leader by every follower
	// (adopt=true on payload.Term > leaderTerm), and then pass the
	// msg.From == currentLeader gate on forged ZoneUpdate/ConfigSync
	// frames — full cluster takeover. Mirrors the same check in
	// handleLeader/handlePing/handleZoneUpdate.
	if msg.From != payload.LeaderID {
		util.Warnf("gossip: dropped Heartbeat from impostor %s claiming to be %s", msg.From, payload.LeaderID)
		return
	}

	gp.leaderMu.Lock()
	defer gp.leaderMu.Unlock()

	// Stale terms are ignored.
	if payload.Term < gp.leaderTerm {
		return
	}

	// A heartbeat from a strictly higher term — or from any leader
	// when we don't yet know one — acts as an implicit leader
	// announcement. The previous code only refreshed lastHeartbeat
	// when the payload's LeaderID already matched our cached
	// currentLeader, so if the explicit Announce frame was lost on
	// the wire (UDP gossip is best-effort) the follower would wait
	// for the next periodic announcement before recognizing the new
	// leader — often dozens of seconds of "no leader known" during
	// which every heartbeat from that leader was silently dropped.
	//
	// Same-term heartbeats from a *different* LeaderID are NOT
	// adopted — that's split-brain territory and the safe move is
	// to keep believing in our currently-known leader until a
	// higher-term election resolves the conflict.
	adopt := false
	if payload.Term > gp.leaderTerm {
		adopt = true
	} else if gp.currentLeader == "" {
		adopt = true
	}
	if adopt {
		gp.currentLeader = payload.LeaderID
		gp.leaderTerm = payload.Term
		gp.isLeader = (payload.LeaderID == gp.nodeList.GetSelf().ID)
		gp.lastHeartbeat = time.Now()
		return
	}

	// Same-term, same-leader: ordinary refresh. Different leader at
	// same term: keep the old state — don't touch lastHeartbeat.
	if payload.LeaderID == gp.currentLeader {
		gp.lastHeartbeat = time.Now()
	}
}

// DetectSplitBrain checks for split-brain conditions.
// Returns true if this node should step down as leader due to split-brain.
// A split-brain occurs when multiple nodes believe they are the leader simultaneously.
func (gp *GossipProtocol) DetectSplitBrain() bool {
	gp.leaderMu.Lock()
	defer gp.leaderMu.Unlock()

	// If we're not the leader, we can't be in split-brain as leader
	if !gp.isLeader {
		return false
	}

	// Split-brain detection: if we receive election messages with higher term
	// while being the leader, it means another node started a new election.
	// The handleElection method updates electionTerm when receiving higher-term messages.
	// We check if electionTerm > leaderTerm which indicates a higher-term election
	// is in progress and we should step down.
	if gp.electionTerm > gp.leaderTerm {
		gp.isLeader = false
		gp.currentLeader = ""
		return true
	}

	return false
}

// StepDown forces this node to step down as leader.
// Used when split-brain is detected or when a higher-term leader is discovered.
func (gp *GossipProtocol) StepDown() {
	gp.leaderMu.Lock()
	defer gp.leaderMu.Unlock()

	if gp.isLeader {
		gp.isLeader = false
		gp.currentLeader = ""
		gp.leaderTerm++ // Increment to invalidate our old leadership
	}
}

// leaderHeartbeatLoop periodically sends leader heartbeats if this node is the leader.
func (gp *GossipProtocol) leaderHeartbeatLoop() {
	defer gp.wg.Done()

	interval := 5 * time.Second
	if gp.heartbeatInterval > 0 {
		interval = gp.heartbeatInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-gp.ctx.Done():
			return
		case <-ticker.C:
			gp.muLeaderSendHeartbeat()
		}
	}
}

// leaderFailureDetector monitors leader health and triggers new election if leader dies.
func (gp *GossipProtocol) leaderFailureDetector() {
	defer gp.wg.Done()

	// Check leader health every 10 seconds
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-gp.ctx.Done():
			return
		case <-ticker.C:
			gp.checkLeaderHealth()
		}
	}
}

func (gp *GossipProtocol) checkLeaderHealth() {
	gp.leaderMu.Lock()
	defer gp.leaderMu.Unlock()

	// Skip if we are the leader or no leader exists
	if gp.isLeader || gp.currentLeader == "" {
		return
	}

	// If last heartbeat is too old, leader is dead — start new election.
	// Use single-flight guard to prevent concurrent election goroutines.
	if heartbeatTimedOutAt(gp.lastHeartbeat, time.Now(), 15*time.Second) {
		if gp.electionRunning {
			return
		}
		gp.electionRunning = true
		gp.leaderTerm++ // Increment term — old leader's term is no longer valid
		go gp.startElection()
	}
}

func heartbeatTimedOutAt(lastHeartbeat, now time.Time, timeout time.Duration) bool {
	return !now.Before(lastHeartbeat.Add(timeout))
}

func (gp *GossipProtocol) muLeaderSendHeartbeat() {
	gp.leaderMu.Lock()
	defer gp.leaderMu.Unlock()

	if !gp.isLeader {
		return
	}

	self := gp.nodeList.GetSelf()
	payload := LeaderHeartbeatPayload{
		LeaderID: self.ID,
		Term:     gp.leaderTerm,
	}

	payloadBytes, err := encodePayload(payload)
	if err != nil {
		return
	}

	for _, node := range gp.nodeList.GetAll() {
		if node.ID == self.ID || node.State != NodeStateAlive {
			continue
		}
		addr := &net.UDPAddr{IP: net.ParseIP(node.Addr), Port: node.Port}
		if err := gp.sendMessage(MessageTypeHeartbeat, payloadBytes, addr); err != nil {
			util.Warnf("gossip: failed to send heartbeat to %s: %v", addr, err)
		}
	}
}

// startElection begins a new leader election.
func (gp *GossipProtocol) startElection() {
	defer func() {
		gp.leaderMu.Lock()
		gp.electionRunning = false
		gp.leaderMu.Unlock()
	}()

	gp.leaderMu.Lock()
	gp.electionTerm++
	selfID := gp.nodeList.GetSelf().ID

	payload := ElectionPayload{
		ProposedLeader: selfID,
		Priority:       1,
		Term:           gp.electionTerm,
	}
	gp.leaderMu.Unlock()

	payloadBytes, err := encodePayload(payload)
	if err != nil {
		return
	}

	// Route through sendMessage so each per-peer wire frame gets a
	// fresh sequence + AAD-bound ciphertext. The previous
	// encodeMessage+gp.encrypt path emitted Sequence=0 and used
	// plaintext-AAD encryption, both of which the receiver-side
	// replay/integrity guards reject — election broadcasts were
	// silently dropped by every peer that had ever seen us before.
	for _, node := range gp.nodeList.GetAll() {
		if node.ID == selfID || node.State != NodeStateAlive {
			continue
		}
		addr := &net.UDPAddr{IP: net.ParseIP(node.Addr), Port: node.Port}
		if err := gp.sendMessage(MessageTypeElection, payloadBytes, addr); err != nil {
			util.Warnf("gossip: failed to send election message to %s: %v", addr, err)
		}
	}
}

// AnnounceLeader sends a leader announcement to all nodes.
func (gp *GossipProtocol) AnnounceLeader() error {
	gp.leaderMu.RLock()
	defer gp.leaderMu.RUnlock()

	if !gp.isLeader {
		return fmt.Errorf("not the leader")
	}

	self := gp.nodeList.GetSelf()
	payload := LeaderPayload{
		LeaderID:   self.ID,
		LeaderAddr: fmt.Sprintf("%s:%d", self.Addr, self.Port),
		Term:       gp.leaderTerm,
	}

	payloadBytes, err := encodePayload(payload)
	if err != nil {
		return err
	}

	// Route through sendMessage so each per-peer wire frame carries a
	// fresh monotonic sequence number AND the AAD-bound encryption
	// expected by replay protection (VULN-045/046). The old code built
	// one msgBytes (Sequence=0) and resent the same buffer to every
	// peer, plus used `encrypt` (no AAD) instead of `encryptWithAAD`.
	// Every peer that had ever received a non-zero-sequence message
	// from us dropped the announcement as a replay, so a new leader
	// could not actually inform the cluster of its election.
	for _, node := range gp.nodeList.GetAll() {
		if node.ID == self.ID || node.State != NodeStateAlive {
			continue
		}
		addr := &net.UDPAddr{IP: net.ParseIP(node.Addr), Port: node.Port}
		if err := gp.sendMessage(MessageTypeLeader, payloadBytes, addr); err != nil {
			util.Warnf("gossip: failed to send leader announcement to %s: %v", addr, err)
		}
	}

	return nil
}

// GetLeader returns the current leader's node ID.
func (gp *GossipProtocol) GetLeader() string {
	gp.leaderMu.RLock()
	defer gp.leaderMu.RUnlock()
	return gp.currentLeader
}

// IsLeader returns true if this node is the leader.
func (gp *GossipProtocol) IsLeader() bool {
	gp.leaderMu.RLock()
	defer gp.leaderMu.RUnlock()
	return gp.isLeader
}

// GetSelfID returns this node's own ID.
func (gp *GossipProtocol) GetSelfID() string {
	return gp.nodeList.GetSelf().ID
}

// GetLeaderTerm returns the current leader term.
func (gp *GossipProtocol) GetLeaderTerm() uint64 {
	gp.leaderMu.RLock()
	defer gp.leaderMu.RUnlock()
	return gp.leaderTerm
}

// IsLeaderAlive checks if the current leader is alive via heartbeat.
func (gp *GossipProtocol) IsLeaderAlive(timeout time.Duration) bool {
	gp.leaderMu.RLock()
	defer gp.leaderMu.RUnlock()
	if gp.currentLeader == "" {
		return false
	}
	if heartbeatTimedOutAt(gp.lastHeartbeat, time.Now(), timeout) {
		return false
	}
	return true
}
