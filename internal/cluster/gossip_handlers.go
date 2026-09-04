package cluster

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

// ── Cache ──────────────────────────────────────────────────────────

// BroadcastCacheInvalidation broadcasts cache invalidation to all nodes.
func (gp *GossipProtocol) BroadcastCacheInvalidation(keys []string) error {
	cachePayload := CacheInvalidatePayload{
		Keys:      keys,
		Source:    gp.nodeList.GetSelf().ID,
		Timestamp: time.Now(),
	}

	payloadBytes, err := encodePayload(cachePayload)
	if err != nil {
		return err
	}

	// Route per-peer through sendMessage — see BroadcastZoneUpdate for
	// the sequence+AAD rationale. Cache invalidations are best-effort,
	// but they still need to actually arrive at the peer's handler;
	// the previous Sequence=0 broadcasts were dropped by replay
	// protection at every peer that had ever exchanged any other
	// gossip frame with us.
	for _, node := range gp.nodeList.GetAlive() {
		port := node.Port
		if port == 0 {
			port = gp.config.BindPort
		}
		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", node.Addr, port))
		if err != nil {
			util.Warnf("gossip: failed to resolve address for %s: %v", node.Addr, err)
			continue
		}
		if err := gp.sendMessage(MessageTypeCacheInvalidate, payloadBytes, addr); err != nil {
			util.Warnf("gossip: failed to send cache invalidation to %s: %v", addr, err)
		}
	}

	return nil
}

// handleCacheInvalidate handles cache invalidation messages.
//
// Impostor protection: payload.Source declares which node "owns"
// this invalidation; msg.From is the AEAD-authenticated sender.
// Without checking equality, a compromised gossip-keyring peer
// could spoof CacheInvalidatePayload{Source: "victim", Keys: ["
// bank.com:A", ...]} and force every observer to evict targeted
// entries from its DNS cache — a chosen-prefix cache-bust that
// pushes the next query for those names back through the upstream/
// resolver path, useful as a stepping stone for slow MITM attacks.
// Same defense as ZoneUpdate, ConfigSync, NodeStats, etc.
func (gp *GossipProtocol) handleCacheInvalidate(msg Message, from *net.UDPAddr) {
	var payload CacheInvalidatePayload
	if err := decodePayload(msg.Payload, &payload); err != nil {
		return
	}

	// Ignore messages from self
	if payload.Source == gp.nodeList.GetSelf().ID {
		return
	}

	if msg.From != payload.Source {
		util.Warnf("gossip: dropped CacheInvalidate from impostor %s claiming source %s", msg.From, payload.Source)
		return
	}

	gp.callbacksMu.RLock()
	onCacheInvalid := gp.onCacheInvalid
	gp.callbacksMu.RUnlock()

	if onCacheInvalid != nil {
		func() {
			defer gp.recoverCallback("cache invalidation")
			onCacheInvalid(payload.Keys)
		}()
	}
}

// ── Zone ───────────────────────────────────────────────────────────

// BroadcastZoneUpdate propagates a zone update to all follower nodes.
// Only the leader should call this method.
func (gp *GossipProtocol) BroadcastZoneUpdate(payload ZoneUpdatePayload) error {
	gp.leaderMu.RLock()
	isLeader := gp.isLeader
	gp.leaderMu.RUnlock()

	if !isLeader {
		return fmt.Errorf("only the leader can broadcast zone updates")
	}

	payloadBytes, err := encodePayload(payload)
	if err != nil {
		return err
	}

	// Route through sendMessage — see AnnounceLeader/startElection fix
	// for the rationale (Sequence=0 + plaintext-AAD encryption causes
	// every receiver to drop these frames as replays or fail the
	// integrity check). Each per-peer send gets a fresh sequence and
	// AAD-bound ciphertext.
	self := gp.nodeList.GetSelf()
	for _, node := range gp.nodeList.GetAll() {
		if node.ID == self.ID || node.State != NodeStateAlive {
			continue
		}
		addr := &net.UDPAddr{IP: net.ParseIP(node.Addr), Port: node.Port}
		if err := gp.sendMessage(MessageTypeZoneUpdate, payloadBytes, addr); err != nil {
			util.Warnf("gossip: failed to send zone update to %s: %v", addr, err)
		}
	}

	return nil
}

// handleZoneUpdate processes zone update messages from the leader.
// This enables master/slave zone replication via the gossip protocol.
func (gp *GossipProtocol) handleZoneUpdate(msg Message, from *net.UDPAddr) {
	// Only accept zone updates from the current leader
	gp.leaderMu.RLock()
	isLeader := gp.isLeader
	currentLeader := gp.currentLeader
	gp.leaderMu.RUnlock()

	// Followers accept zone updates; leader does not process its own updates
	if isLeader {
		return
	}

	if currentLeader == "" {
		return
	}

	// Verify the sender IS the current leader. The gossip AEAD prevents
	// off-path attackers from injecting frames, but a compromised peer
	// inside the keyring would otherwise be able to overwrite every
	// other node's zone data by broadcasting forged ZoneUpdate frames
	// with action=full and an attacker-controlled RawZone. Reject any
	// update whose msg.From doesn't match the known leader ID.
	if msg.From != currentLeader {
		util.Warnf("gossip: dropped zone update from %s; current leader is %s", msg.From, currentLeader)
		return
	}

	gp.callbacksMu.RLock()
	onZoneUpdate := gp.onZoneUpdate
	gp.callbacksMu.RUnlock()

	if onZoneUpdate != nil {
		var payload ZoneUpdatePayload
		if err := decodePayload(msg.Payload, &payload); err != nil {
			return
		}
		func() {
			defer gp.recoverCallback("zone update")
			onZoneUpdate(payload)
		}()
	}
}

// ── Config ─────────────────────────────────────────────────────────

// BroadcastConfigUpdate sends a configuration update to all follower nodes.
// Called by the leader when config changes.
func (gp *GossipProtocol) BroadcastConfigUpdate(payload ConfigSyncPayload) error {
	gp.leaderMu.RLock()
	isLeader := gp.isLeader
	gp.leaderMu.RUnlock()

	if !isLeader {
		return fmt.Errorf("only the leader can broadcast config updates")
	}

	payloadBytes, err := encodePayload(payload)
	if err != nil {
		return err
	}

	// Route through sendMessage. See BroadcastZoneUpdate for rationale.
	self := gp.nodeList.GetSelf()
	for _, node := range gp.nodeList.GetAll() {
		if node.ID == self.ID || node.State != NodeStateAlive {
			continue
		}
		addr := &net.UDPAddr{IP: net.ParseIP(node.Addr), Port: node.Port}
		if err := gp.sendMessage(MessageTypeConfigSync, payloadBytes, addr); err != nil {
			util.Warnf("gossip: failed to send config sync to %s: %v", addr, err)
		}
	}

	return nil
}

// handleConfigSync processes configuration sync messages from the leader.
// The leader broadcasts config changes to all follower nodes.
func (gp *GossipProtocol) handleConfigSync(msg Message, from *net.UDPAddr) {
	// Only accept config sync from the current leader
	gp.leaderMu.RLock()
	isLeader := gp.isLeader
	currentLeader := gp.currentLeader
	gp.leaderMu.RUnlock()

	// Followers accept config updates; leader does not process its own updates
	if isLeader {
		return
	}

	if currentLeader == "" {
		return
	}

	// Same sender-is-leader check as handleZoneUpdate. A compromised
	// peer with the gossip key could otherwise force every follower to
	// reload a forged configuration by sending a ConfigSync frame.
	if msg.From != currentLeader {
		util.Warnf("gossip: dropped config sync from %s; current leader is %s", msg.From, currentLeader)
		return
	}

	gp.callbacksMu.RLock()
	onConfigSync := gp.onConfigSync
	gp.callbacksMu.RUnlock()

	if onConfigSync != nil {
		var payload ConfigSyncPayload
		if err := decodePayload(msg.Payload, &payload); err != nil {
			return
		}
		func() {
			defer gp.recoverCallback("config sync")
			onConfigSync(payload)
		}()
	}
}

// ── Draining ───────────────────────────────────────────────────────

// handleDraining processes a draining state message from another node.
//
// Same impostor protection rationale as handleNodeStats: only the
// node itself is allowed to announce its draining state. A
// compromised gossip peer could otherwise broadcast
// payload.NodeID="victim" with Draining=true and remove the victim
// from every other node's query-routing pool — a DoS vector that
// requires no protocol-level forgery, just a self-declared NodeID
// inside an otherwise valid frame.
func (gp *GossipProtocol) handleDraining(msg Message, from *net.UDPAddr) {
	var payload DrainingPayload
	if err := decodePayload(msg.Payload, &payload); err != nil {
		return
	}

	// Ignore messages from self
	if payload.NodeID == gp.nodeList.GetSelf().ID {
		return
	}

	if msg.From != payload.NodeID {
		util.Warnf("gossip: dropped Draining state for %s from impostor %s", payload.NodeID, msg.From)
		return
	}

	gp.nodeList.MarkSeen(payload.NodeID)

	if payload.Draining {
		// Node entering draining state — mark as draining
		gp.nodeList.UpdateState(payload.NodeID, NodeStateDraining)
		util.Infof("cluster: node %s entering draining state", payload.NodeID)
	} else {
		// Node exiting draining state — back to alive
		gp.nodeList.UpdateState(payload.NodeID, NodeStateAlive)
		util.Infof("cluster: node %s exiting draining state", payload.NodeID)
	}
}

// BroadcastDraining broadcasts a draining state change to all cluster nodes.
// When Draining=true, other nodes will stop routing new queries to this node.
// When Draining=false, the node is back to normal operation.
func (gp *GossipProtocol) BroadcastDraining(draining bool, inFlightReq int) error {
	payload := DrainingPayload{
		NodeID:      gp.nodeList.GetSelf().ID,
		Draining:    draining,
		Timestamp:   time.Now(),
		InFlightReq: inFlightReq,
	}

	payloadBytes, err := encodePayload(payload)
	if err != nil {
		return err
	}

	self := gp.nodeList.GetSelf()
	for _, node := range gp.nodeList.GetAll() {
		if node.ID == self.ID {
			continue
		}
		addr := &net.UDPAddr{IP: net.ParseIP(node.Addr), Port: node.Port}
		if err := gp.sendMessage(MessageTypeDraining, payloadBytes, addr); err != nil {
			util.Warnf("gossip: failed to send draining message to %s: %v", addr, err)
		}
	}

	return nil
}

// ── Node Stats ─────────────────────────────────────────────────────

// handleNodeStats processes node health statistics received via gossip.
//
// SECURITY: only a node may report its own stats. msg.From is the
// authenticated AEAD sender; payload.NodeID is the node the stats
// claim to describe. If the two diverge, a compromised peer inside
// the gossip keyring could broadcast forged stats for any other
// node — e.g., mark a healthy node as overloaded so health-based
// routing steers traffic away from it. Reject mismatches.
func (gp *GossipProtocol) handleNodeStats(msg Message, from *net.UDPAddr) {
	var payload NodeStatsPayload
	if err := decodePayload(msg.Payload, &payload); err != nil {
		return
	}

	// Ignore messages from self
	if payload.NodeID == gp.nodeList.GetSelf().ID {
		return
	}

	// Reject if the payload tries to update a node other than the sender.
	if msg.From != payload.NodeID {
		util.Warnf("gossip: dropped NodeStats for %s from impostor %s", payload.NodeID, msg.From)
		return
	}

	// Update the health stats for this node in our local node list
	health := NodeHealthStats{
		QueriesPerSecond: payload.QueriesPerSecond,
		LatencyMs:        payload.LatencyMs,
		CPUPercent:       payload.CPUPercent,
		MemoryPercent:    payload.MemoryPercent,
		ActiveConns:      payload.ActiveConns,
		LastUpdated:      payload.Timestamp,
	}
	gp.nodeList.UpdateHealth(payload.NodeID, health)
}

// BroadcastNodeStats broadcasts the local node's health statistics to all cluster nodes.
// This enables health-based query routing across the cluster.
// Should be called periodically (e.g., every 10 seconds) by the cluster.
func (gp *GossipProtocol) BroadcastNodeStats(stats NodeHealthStats) error {
	payload := NodeStatsPayload{
		NodeID:           gp.nodeList.GetSelf().ID,
		QueriesPerSecond: stats.QueriesPerSecond,
		LatencyMs:        stats.LatencyMs,
		CPUPercent:       stats.CPUPercent,
		MemoryPercent:    stats.MemoryPercent,
		ActiveConns:      stats.ActiveConns,
		Timestamp:        time.Now(),
	}

	payloadBytes, err := encodePayload(payload)
	if err != nil {
		return err
	}

	self := gp.nodeList.GetSelf()
	for _, node := range gp.nodeList.GetAll() {
		if node.ID == self.ID {
			continue
		}
		addr := &net.UDPAddr{IP: net.ParseIP(node.Addr), Port: node.Port}
		if err := gp.sendMessage(MessageTypeNodeStats, payloadBytes, addr); err != nil {
			util.Warnf("gossip: failed to send node stats to %s: %v", addr, err)
		}
	}

	return nil
}

// ── Cluster Metrics ────────────────────────────────────────────────

// handleClusterMetrics processes cluster metrics received via gossip.
//
// Same impostor protection as handleNodeStats: only the named node
// is allowed to report its own metrics. Without this, a compromised
// gossip peer could rewrite any other node's cluster metrics in
// every observer's view.
func (gp *GossipProtocol) handleClusterMetrics(msg Message, from *net.UDPAddr) {
	var payload ClusterMetricsPayload
	if err := decodePayload(msg.Payload, &payload); err != nil {
		return
	}

	// Ignore messages from self
	if payload.NodeID == gp.nodeList.GetSelf().ID {
		return
	}

	if msg.From != payload.NodeID {
		util.Warnf("gossip: dropped ClusterMetrics for %s from impostor %s", payload.NodeID, msg.From)
		return
	}

	// Store the metrics for this node
	gp.nodeMetricsMu.Lock()
	gp.nodeMetrics[payload.NodeID] = payload
	gp.nodeMetricsMu.Unlock()
}

// BroadcastClusterMetrics broadcasts operational metrics to all cluster nodes.
// This enables cluster-wide metrics aggregation via the API.
func (gp *GossipProtocol) BroadcastClusterMetrics(metrics ClusterMetricsPayload) error {
	metrics.NodeID = gp.nodeList.GetSelf().ID
	metrics.Timestamp = time.Now()

	payloadBytes, err := encodePayload(metrics)
	if err != nil {
		return err
	}

	// Route through sendMessage. See BroadcastZoneUpdate for rationale.
	self := gp.nodeList.GetSelf()
	for _, node := range gp.nodeList.GetAll() {
		if node.ID == self.ID {
			continue
		}
		addr := &net.UDPAddr{IP: net.ParseIP(node.Addr), Port: node.Port}
		if err := gp.sendMessage(MessageTypeClusterMetrics, payloadBytes, addr); err != nil {
			util.Warnf("gossip: failed to send cluster metrics to %s: %v", addr, err)
		}
	}

	return nil
}

// GetClusterMetrics returns aggregated cluster-wide metrics from all known nodes.
func (gp *GossipProtocol) GetClusterMetrics() ClusterMetricsPayload {
	gp.nodeMetricsMu.RLock()
	defer gp.nodeMetricsMu.RUnlock()

	var total ClusterMetricsPayload
	count := 0

	for _, m := range gp.nodeMetrics {
		total.QueriesTotal += m.QueriesTotal
		total.CacheHits += m.CacheHits
		total.CacheMisses += m.CacheMisses
		total.UptimeSeconds += m.UptimeSeconds
		// Weighted average for per-second and latency metrics
		if m.QueriesPerSec > 0 {
			total.QueriesPerSec += m.QueriesPerSec
			count++
		}
		if m.LatencyMsAvg > 0 {
			total.LatencyMsAvg += m.LatencyMsAvg
		}
		if m.LatencyMsP99 > 0 {
			total.LatencyMsP99 += m.LatencyMsP99
		}
	}

	// Average the per-second and latency metrics
	if count > 0 {
		total.QueriesPerSec /= float64(count)
	}
	if count > 0 {
		total.LatencyMsAvg /= float64(count)
		total.LatencyMsP99 /= float64(count)
	}

	return total
}

// ── Wire codec helpers ─────────────────────────────────────────────

// encodeMessage encodes a message with its payload.
// For internal use; sequence numbers are managed by sendMessage.
func encodeMessage(msgType MessageType, from string, protocolVersion uint32, payload []byte) ([]byte, error) {
	msg := Message{
		Type:            msgType,
		From:            from,
		Timestamp:       time.Now(),
		Payload:         payload,
		ProtocolVersion: protocolVersion,
	}
	return json.Marshal(msg)
}

// encodePayload encodes a payload structure to bytes.
func encodePayload(payload any) ([]byte, error) {
	return json.Marshal(payload)
}

// decodeMessage decodes a message envelope, decrypting if needed.
// If encryption is enabled, decryption is mandatory - unencrypted messages are rejected.
// This prevents downgrade attacks where an attacker strips encryption.
// If the message protocol version is incompatible, it is logged and skipped.
func (gp *GossipProtocol) decodeMessage(data []byte, msg *Message) error {
	// Decryption is mandatory when encryption is enabled (downgrade guard).
	// The AES-256-GCM tag authenticates the whole JSON payload, which already
	// includes From/Type/Sequence — so those fields are integrity-protected by
	// the single Open below. (The previous code sealed with an AAD over the
	// same fields and then tried a SECOND, nil-AAD decrypt to "peek" at them
	// first; a ciphertext sealed with an AAD can never open with a nil AAD, so
	// every encrypted message was dropped. The AAD was redundant with the
	// in-payload authenticated fields anyway.)
	if gp.aead != nil {
		decrypted, err := gp.decrypt(data)
		if err != nil {
			return fmt.Errorf("gossip decrypt: message appears unencrypted but encryption is enabled: %w", err)
		}
		data = decrypted
	}

	if err := json.Unmarshal(data, msg); err != nil {
		return err
	}

	// Reject incompatible protocol versions BEFORE bumping the
	// per-sender sequence tracker. The previous order let any party
	// who could send a high-sequence message (legitimate node running
	// a newer protocol, or an attacker with valid AAD) poison our
	// sequences map: we'd advance the high-water mark past `lastSeq`
	// to msg.Sequence, then reject the message on version. Legitimate
	// future v-matching messages from that sender at the old sequence
	// then get refused as replays — a self-inflicted partition.
	if msg.ProtocolVersion != 0 && msg.ProtocolVersion != gp.config.ProtocolVersion {
		util.Warnf("gossip: dropped message from node %s: protocol version %d != our version %d",
			msg.From, msg.ProtocolVersion, gp.config.ProtocolVersion)
		return fmt.Errorf("incompatible protocol version")
	}

	// VULN-045: Replay protection via per-sender high-water mark.
	if msg.ProtocolVersion != 0 {
		gp.sequenceMu.Lock()
		lastSeq, seen := gp.sequences[msg.From]
		if seen && msg.Sequence <= lastSeq {
			gp.sequenceMu.Unlock()
			return fmt.Errorf("gossip: replay detected from node %s (seq %d <= last %d)", msg.From, msg.Sequence, lastSeq)
		}
		gp.sequences[msg.From] = msg.Sequence
		gp.sequenceMu.Unlock()
	}

	return nil
}

// sendMessage encodes, encrypts, and sends a message to a UDP address.
func (gp *GossipProtocol) sendMessage(msgType MessageType, payload []byte, addr *net.UDPAddr) error {
	seq := atomic.AddUint64(&gp.nextSequence, 1)
	msg := Message{
		Type:            msgType,
		From:            gp.nodeList.GetSelf().ID,
		Timestamp:       time.Now(),
		Payload:         payload,
		ProtocolVersion: gp.config.ProtocolVersion,
		Sequence:        seq,
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	// Encrypt if enabled. From/Type/Sequence live inside the JSON, so the GCM
	// tag authenticates them directly — no separate AAD needed (and a separate
	// AAD over those fields is unusable on receive, since the receiver can't
	// read them to rebuild the AAD before decrypting). Replay protection is the
	// per-sender sequence check in decodeMessage.
	if gp.aead != nil {
		data, err = gp.encrypt(data)
		if err != nil {
			return err
		}
	}

	if _, err := writeGossipUDPPacket(gp.conn, data, addr); err != nil {
		return err
	}
	atomic.AddUint64(&gp.messagesSent, 1)
	return nil
}

func writeGossipUDPPacket(conn gossipUDPConn, data []byte, addr *net.UDPAddr) (int, error) {
	n, err := conn.WriteToUDP(data, addr)
	if err != nil {
		return n, err
	}
	if n != len(data) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

// decodeMessageRaw decodes a message without decryption (for tests).
func decodeMessageRaw(data []byte, msg *Message) error {
	return json.Unmarshal(data, msg)
}

// decodePayload decodes a message payload.
func decodePayload(data []byte, payload any) error {
	return json.Unmarshal(data, payload)
}
