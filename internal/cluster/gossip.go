package cluster

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

func init() {
	// Register types for gob encoding
	gob.Register(PingPayload{})
	gob.Register(AckPayload{})
	gob.Register(GossipPayload{})
	gob.Register(NodeInfo{})
	gob.Register(CacheInvalidatePayload{})
	gob.Register(Message{})
	gob.Register(NodeState(0))
	gob.Register(NodeMeta{})
}

// MessageType represents the type of gossip message.
type MessageType uint8

const (
	MessageTypePing MessageType = iota
	MessageTypeAck
	MessageTypeGossip
	MessageTypeCacheInvalidate
	MessageTypeCacheUpdate
)

// Message is the envelope for all gossip messages.
type Message struct {
	Type      MessageType
	From      string
	Timestamp time.Time
	Payload   []byte
}

// PingPayload is sent to check node liveness.
type PingPayload struct {
	NodeID  string
	Version uint64
}

// AckPayload is the response to a ping.
type AckPayload struct {
	NodeID  string
	Version uint64
}

// GossipPayload contains node state updates.
type GossipPayload struct {
	Nodes []NodeInfo
}

// NodeInfo is a lightweight node representation for gossip.
type NodeInfo struct {
	ID       string
	Addr     string
	Port     int
	State    NodeState
	Version  uint64
	LastSeen time.Time
	Meta     NodeMeta
}

// CacheInvalidatePayload notifies nodes to invalidate cache entries.
type CacheInvalidatePayload struct {
	Keys      []string
	Source    string
	Timestamp time.Time
}

// GossipProtocol implements the gossip-based membership protocol.
type GossipProtocol struct {
	config   GossipConfig
	nodeList *NodeList
	conn     *net.UDPConn

	// Message sequencing
	seqNum uint64

	// Callbacks
	callbacksMu    sync.RWMutex
	onNodeJoin     func(*Node)
	onNodeLeave    func(*Node)
	onNodeUpdate   func(*Node)
	onCacheInvalid func([]string)

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Stats
	messagesSent     uint64
	messagesReceived uint64
	pingSent         uint64
	pingReceived     uint64
}

// GossipConfig configures the gossip protocol.
type GossipConfig struct {
	BindAddr         string
	BindPort         int
	GossipInterval   time.Duration
	ProbeInterval    time.Duration
	ProbeTimeout     time.Duration
	SuspicionMult    int
	RetransmitMult   int
	GossipNodes      int
	IndirectChecks   int
}

// DefaultGossipConfig returns default configuration.
func DefaultGossipConfig() GossipConfig {
	return GossipConfig{
		BindAddr:       "0.0.0.0",
		BindPort:       7946,
		GossipInterval: 200 * time.Millisecond,
		ProbeInterval:  1 * time.Second,
		ProbeTimeout:   500 * time.Millisecond,
		SuspicionMult:  4,
		RetransmitMult: 4,
		GossipNodes:    3,
		IndirectChecks: 3,
	}
}

// NewGossipProtocol creates a new gossip protocol instance.
func NewGossipProtocol(config GossipConfig, nodeList *NodeList) (*GossipProtocol, error) {
	ctx, cancel := context.WithCancel(context.Background())

	gp := &GossipProtocol{
		config:   config,
		nodeList: nodeList,
		ctx:      ctx,
		cancel:   cancel,
	}

	return gp, nil
}

// SetCallbacks sets the event callbacks.
func (gp *GossipProtocol) SetCallbacks(
	onJoin, onLeave, onUpdate func(*Node),
	onCacheInvalid func([]string),
) {
	gp.callbacksMu.Lock()
	defer gp.callbacksMu.Unlock()
	gp.onNodeJoin = onJoin
	gp.onNodeLeave = onLeave
	gp.onNodeUpdate = onUpdate
	gp.onCacheInvalid = onCacheInvalid
}

// Start starts the gossip protocol.
func (gp *GossipProtocol) Start() error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", gp.config.BindAddr, gp.config.BindPort))
	if err != nil {
		return fmt.Errorf("resolving address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listening: %w", err)
	}
	gp.conn = conn

	// Start goroutines
	gp.wg.Add(3)
	go gp.receiveLoop()
	go gp.gossipLoop()
	go gp.probeLoop()

	return nil
}

// Stop stops the gossip protocol.
func (gp *GossipProtocol) Stop() error {
	gp.cancel()

	if gp.conn != nil {
		gp.conn.Close()
	}

	gp.wg.Wait()
	return nil
}

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

	data, err := encodeMessage(MessageTypePing, payloadBytes)
	if err != nil {
		return err
	}

	_, err = gp.conn.WriteToUDP(data, addr)
	if err != nil {
		return fmt.Errorf("sending ping: %w", err)
	}

	atomic.AddUint64(&gp.pingSent, 1)
	return nil
}

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

	data, err := encodeMessage(MessageTypeCacheInvalidate, payloadBytes)
	if err != nil {
		return err
	}

	// Send to all alive nodes
	for _, node := range gp.nodeList.GetAlive() {
		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", node.Addr, gp.config.BindPort))
		if err != nil {
			log.Printf("gossip: failed to resolve address for %s: %v", node.Addr, err)
			continue
		}
		if _, err := gp.conn.WriteToUDP(data, addr); err != nil {
			log.Printf("gossip: failed to send cache invalidation to %s: %v", addr, err)
		}
		atomic.AddUint64(&gp.messagesSent, 1)
	}

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
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if gp.ctx.Err() != nil {
				return
			}
			continue
		}

		atomic.AddUint64(&gp.messagesReceived, 1)
		gp.handleMessage(buf[:n], from)
	}
}

// handleMessage processes a received message.
func (gp *GossipProtocol) handleMessage(data []byte, from *net.UDPAddr) {
	var msg Message
	if err := decodeMessage(data, &msg); err != nil {
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
	}
}

// handlePing handles a ping message.
func (gp *GossipProtocol) handlePing(msg Message, from *net.UDPAddr) {
	atomic.AddUint64(&gp.pingReceived, 1)

	var ping PingPayload
	if err := decodePayload(msg.Payload, &ping); err != nil {
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
		log.Printf("gossip: failed to encode ack payload: %v", err)
		return
	}
	data, err := encodeMessage(MessageTypeAck, ackBytes)
	if err != nil {
		log.Printf("gossip: failed to encode ack message: %v", err)
		return
	}
	if _, err := gp.conn.WriteToUDP(data, from); err != nil {
		log.Printf("gossip: failed to send ack to %s: %v", from, err)
	}
	atomic.AddUint64(&gp.messagesSent, 1)
}

// handleAck handles an ack message.
func (gp *GossipProtocol) handleAck(msg Message, from *net.UDPAddr) {
	var ack AckPayload
	if err := decodePayload(msg.Payload, &ack); err != nil {
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
					gp.onNodeJoin(newNode)
				}
				gp.callbacksMu.RUnlock()
			}
		} else if info.Version > existing.Version {
			// Update existing node
			gp.nodeList.UpdateState(info.ID, info.State)
			gp.callbacksMu.RLock()
			if gp.onNodeUpdate != nil {
				gp.onNodeUpdate(existing)
			}
			gp.callbacksMu.RUnlock()
		}
	}
}

// handleCacheInvalidate handles cache invalidation messages.
func (gp *GossipProtocol) handleCacheInvalidate(msg Message, from *net.UDPAddr) {
	var payload CacheInvalidatePayload
	if err := decodePayload(msg.Payload, &payload); err != nil {
		return
	}

	// Ignore messages from self
	if payload.Source == gp.nodeList.GetSelf().ID {
		return
	}

	gp.callbacksMu.RLock()
	if gp.onCacheInvalid != nil {
		gp.onCacheInvalid(payload.Keys)
	}
	gp.callbacksMu.RUnlock()
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

	data, err := encodeMessage(MessageTypeGossip, payloadBytes)
	if err != nil {
		return
	}

	// Send to random nodes
	for i := 0; i < gp.config.GossipNodes; i++ {
		target := gp.nodeList.GetRandom(nil)
		if target == nil {
			break
		}

		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", target.Addr, gp.config.BindPort))
		if err != nil {
			log.Printf("gossip: failed to resolve address for %s: %v", target.Addr, err)
			continue
		}
		if _, err := gp.conn.WriteToUDP(data, addr); err != nil {
			log.Printf("gossip: failed to send gossip to %s: %v", addr, err)
		}
		atomic.AddUint64(&gp.messagesSent, 1)
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
					gp.onNodeLeave(node)
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
		log.Printf("gossip: failed to encode ping payload: %v", err)
		return
	}
	data, err := encodeMessage(MessageTypePing, pingBytes)
	if err != nil {
		log.Printf("gossip: failed to encode ping message: %v", err)
		return
	}
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", node.Addr, gp.config.BindPort))
	if err != nil {
		log.Printf("gossip: failed to resolve address for %s: %v", node.Addr, err)
		return
	}
	if _, err := gp.conn.WriteToUDP(data, addr); err != nil {
		log.Printf("gossip: failed to send ping to %s: %v", addr, err)
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

// GossipStats contains gossip protocol statistics.
type GossipStats struct {
	MessagesSent     uint64
	MessagesReceived uint64
	PingSent         uint64
	PingReceived     uint64
}

// encodeMessage encodes a message with its payload.
func encodeMessage(msgType MessageType, payload []byte) ([]byte, error) {
	msg := Message{
		Type:      msgType,
		Timestamp: time.Now(),
		Payload:   payload,
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(msg); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// encodePayload encodes a payload structure to bytes.
func encodePayload(payload interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(payload); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decodeMessage decodes a message envelope.
func decodeMessage(data []byte, msg *Message) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return dec.Decode(msg)
}

// decodePayload decodes a message payload.
func decodePayload(data []byte, payload interface{}) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return dec.Decode(payload)
}
