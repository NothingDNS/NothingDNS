package cluster

import (
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

// Join joins the cluster by contacting a seed node.
func (gp *GossipProtocol) Join(seedAddr string) error {
	addr, err := net.ResolveUDPAddr("udp", seedAddr)
	if err != nil {
		return fmt.Errorf("resolving seed address: %w", err)
	}

	// Send ping to seed
	ping := PingPayload{
		NodeID:  gp.nodeList.GetSelf().ID,
		Version: gp.nodeList.GetSelf().Version,
	}

	payloadBytes, err := encodePayload(ping)
	if err != nil {
		return err
	}

	if err := gp.sendMessage(MessageTypePing, payloadBytes, addr); err != nil {
		return fmt.Errorf("sending ping: %w", err)
	}

	atomic.AddUint64(&gp.pingSent, 1)
	return nil
}

// receiveLoop handles incoming messages.
func (gp *GossipProtocol) receiveLoop() {
	defer gp.wg.Done()

	buf := make([]byte, 65536)

	for {
		select {
		case <-gp.ctx.Done():
			return
		default:
		}

		if err := gp.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			return
		}
		n, from, err := gp.conn.ReadFromUDP(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			if gp.ctx.Err() != nil {
				return
			}
			continue
		}

		atomic.AddUint64(&gp.messagesReceived, 1)
		// Recover per packet (V14): a panic decoding one malformed/malicious
		// datagram must not kill the receive loop or the process. Reuses the
		// existing callback recovery helper.
		func() {
			defer gp.recoverCallback("handleMessage")
			gp.handleMessage(buf[:n], from)
		}()
	}
}

// handleMessage processes a received message.
func (gp *GossipProtocol) handleMessage(data []byte, from *net.UDPAddr) {
	var msg Message
	if err := gp.decodeMessage(data, &msg); err != nil {
		return
	}

	// Ignore messages from self
	if msg.From == gp.nodeList.GetSelf().ID {
		return
	}

	switch msg.Type {
	case MessageTypePing:
		gp.handlePing(msg, from)
	case MessageTypeAck:
		gp.handleAck(msg, from)
	case MessageTypeGossip:
		gp.handleGossip(msg, from)
	case MessageTypeCacheInvalidate:
		gp.handleCacheInvalidate(msg, from)
	case MessageTypeElection:
		gp.handleElection(msg, from)
	case MessageTypeLeader:
		gp.handleLeader(msg, from)
	case MessageTypeHeartbeat:
		gp.handleHeartbeat(msg, from)
	case MessageTypeZoneUpdate:
		gp.handleZoneUpdate(msg, from)
	case MessageTypeConfigSync:
		gp.handleConfigSync(msg, from)
	case MessageTypeDraining:
		gp.handleDraining(msg, from)
	case MessageTypeNodeStats:
		gp.handleNodeStats(msg, from)
	case MessageTypeClusterMetrics:
		gp.handleClusterMetrics(msg, from)
	}
}

// handlePing handles a ping message.
//
// Impostor protection: ping.NodeID is the ping sender's claimed
// identity and MUST match the AEAD-authenticated msg.From. Without
// this check, a compromised gossip-keyring peer could keep
// reporting "victim sent a ping" frames; we'd keep refreshing
// victim's LastSeen even after victim actually died, and SWIM's
// failure detector would never tip the cluster's view of victim
// to Suspect/Dead. The cluster would route queries into a black
// hole indefinitely.
func (gp *GossipProtocol) handlePing(msg Message, from *net.UDPAddr) {
	atomic.AddUint64(&gp.pingReceived, 1)

	var ping PingPayload
	if err := decodePayload(msg.Payload, &ping); err != nil {
		return
	}

	if msg.From != ping.NodeID {
		util.Warnf("gossip: dropped Ping from impostor %s claiming to be %s", msg.From, ping.NodeID)
		return
	}

	// Mark node as seen
	gp.nodeList.MarkSeen(ping.NodeID)

	// Send ack
	ack := AckPayload{
		NodeID:  gp.nodeList.GetSelf().ID,
		Version: gp.nodeList.GetSelf().Version,
	}

	ackBytes, err := encodePayload(ack)
	if err != nil {
		util.Warnf("gossip: failed to encode ack payload: %v", err)
		return
	}
	if err := gp.sendMessage(MessageTypeAck, ackBytes, from); err != nil {
		util.Warnf("gossip: failed to send ack to %s: %v", from, err)
	}
}

// handleAck handles an ack message.
//
// Same impostor protection as handlePing: ack.NodeID is the ack
// sender's claimed identity. If an impostor sent acks claiming to
// be the victim, we'd reanimate the victim from NodeStateDead /
// NodeStateSuspect back to NodeStateAlive every time. SWIM relies
// on "ack proves liveness" — that proof MUST come from the actual
// peer, not just anyone with the AEAD key.
func (gp *GossipProtocol) handleAck(msg Message, from *net.UDPAddr) {
	var ack AckPayload
	if err := decodePayload(msg.Payload, &ack); err != nil {
		return
	}

	if msg.From != ack.NodeID {
		util.Warnf("gossip: dropped Ack from impostor %s claiming to be %s", msg.From, ack.NodeID)
		return
	}

	gp.nodeList.MarkSeen(ack.NodeID)
	gp.nodeList.UpdateState(ack.NodeID, NodeStateAlive)
}

// handleGossip handles gossip state updates.
func (gp *GossipProtocol) handleGossip(msg Message, from *net.UDPAddr) {
	var payload GossipPayload
	if err := decodePayload(msg.Payload, &payload); err != nil {
		return
	}

	for _, info := range payload.Nodes {
		// Skip self
		if info.ID == gp.nodeList.GetSelf().ID {
			continue
		}

		existing, ok := gp.nodeList.Get(info.ID)
		if !ok {
			// New node
			newNode := &Node{
				ID:       info.ID,
				Addr:     info.Addr,
				Port:     info.Port,
				State:    info.State,
				LastSeen: info.LastSeen,
				Version:  info.Version,
				Meta:     info.Meta,
			}
			if gp.nodeList.Add(newNode) {
				gp.callbacksMu.RLock()
				if gp.onNodeJoin != nil {
					func() {
						defer gp.recoverCallback("node join")
						gp.onNodeJoin(newNode)
					}()
				}
				gp.callbacksMu.RUnlock()
			}
		} else if info.Version > existing.Version {
			// Update existing node
			gp.nodeList.UpdateState(info.ID, info.State)
			gp.callbacksMu.RLock()
			if gp.onNodeUpdate != nil {
				func() {
					defer gp.recoverCallback("node update")
					gp.onNodeUpdate(existing)
				}()
			}
			gp.callbacksMu.RUnlock()
		}
	}
}

// gossipLoop periodically gossips node state.
func (gp *GossipProtocol) gossipLoop() {
	defer gp.wg.Done()

	ticker := time.NewTicker(gp.config.GossipInterval)
	defer ticker.Stop()

	for {
		select {
		case <-gp.ctx.Done():
			return
		case <-ticker.C:
			gp.gossip()
		}
	}
}

// gossip sends state to random nodes.
func (gp *GossipProtocol) gossip() {
	// Build payload with all nodes
	payload := GossipPayload{
		Nodes: make([]NodeInfo, 0),
	}

	for _, node := range gp.nodeList.GetAll() {
		payload.Nodes = append(payload.Nodes, NodeInfo{
			ID:       node.ID,
			Addr:     node.Addr,
			Port:     node.Port,
			State:    node.State,
			Version:  node.Version,
			LastSeen: node.LastSeen,
			Meta:     node.Meta,
		})
	}

	payloadBytes, err := encodePayload(payload)
	if err != nil {
		return
	}

	// Send to random nodes via sendMessage for proper sequencing + AAD.
	for i := 0; i < gp.config.GossipNodes; i++ {
		target := gp.nodeList.GetRandom(nil)
		if target == nil {
			break
		}

		port := target.Port
		if port == 0 {
			port = gp.config.BindPort
		}
		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", target.Addr, port))
		if err != nil {
			util.Warnf("gossip: failed to resolve address for %s: %v", target.Addr, err)
			continue
		}
		if err := gp.sendMessage(MessageTypeGossip, payloadBytes, addr); err != nil {
			util.Warnf("gossip: failed to send gossip to %s: %v", addr, err)
		}
	}
}

// probeLoop periodically probes nodes for liveness.
func (gp *GossipProtocol) probeLoop() {
	defer gp.wg.Done()

	ticker := time.NewTicker(gp.config.ProbeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-gp.ctx.Done():
			return
		case <-ticker.C:
			gp.probeNodes()
		}
	}
}

// probeNodes checks liveness of suspect nodes.
func (gp *GossipProtocol) probeNodes() {
	nodes := gp.nodeList.GetAll()
	for i := range nodes {
		node := &nodes[i]
		if node.ID == gp.nodeList.GetSelf().ID {
			continue
		}

		since := time.Since(node.LastSeen)

		switch node.State {
		case NodeStateAlive:
			// Mark suspect if not seen recently
			if since > gp.config.ProbeInterval*time.Duration(gp.config.SuspicionMult) {
				gp.nodeList.UpdateState(node.ID, NodeStateSuspect)
			}

		case NodeStateSuspect:
			// Mark dead if suspect for too long
			if since > gp.config.ProbeInterval*time.Duration(gp.config.SuspicionMult*2) {
				gp.nodeList.UpdateState(node.ID, NodeStateDead)
				gp.callbacksMu.RLock()
				if gp.onNodeLeave != nil {
					func() {
						defer gp.recoverCallback("node leave")
						gp.onNodeLeave(node)
					}()
				}
				gp.callbacksMu.RUnlock()
			} else {
				// Send direct ping to verify
				gp.sendPing(node)
			}

		case NodeStateDead:
			// Remove dead nodes after extended period
			if since > gp.config.ProbeInterval*10 {
				gp.nodeList.Remove(node.ID)
			}
		}
	}
}

// sendPing sends a ping to a specific node.
func (gp *GossipProtocol) sendPing(node *Node) {
	ping := PingPayload{
		NodeID:  gp.nodeList.GetSelf().ID,
		Version: gp.nodeList.GetSelf().Version,
	}

	pingBytes, err := encodePayload(ping)
	if err != nil {
		util.Warnf("gossip: failed to encode ping payload: %v", err)
		return
	}
	port := node.Port
	if port == 0 {
		port = gp.config.BindPort
	}
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", node.Addr, port))
	if err != nil {
		util.Warnf("gossip: failed to resolve address for %s: %v", node.Addr, err)
		return
	}
	if err := gp.sendMessage(MessageTypePing, pingBytes, addr); err != nil {
		util.Warnf("gossip: failed to send ping to %s: %v", addr, err)
		return
	}
	atomic.AddUint64(&gp.pingSent, 1)
}

// Stats returns gossip statistics.
func (gp *GossipProtocol) Stats() GossipStats {
	return GossipStats{
		MessagesSent:     atomic.LoadUint64(&gp.messagesSent),
		MessagesReceived: atomic.LoadUint64(&gp.messagesReceived),
		PingSent:         atomic.LoadUint64(&gp.pingSent),
		PingReceived:     atomic.LoadUint64(&gp.pingReceived),
	}
}
