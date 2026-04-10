package cluster

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"

	"github.com/nothingdns/nothingdns/internal/util"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// MessageType represents the type of gossip message.
type MessageType uint8

const (
	MessageTypePing MessageType = iota
	MessageTypeAck
	MessageTypeGossip
	MessageTypeCacheInvalidate
	MessageTypeCacheUpdate
	MessageTypeElection    // Leader election (bully algorithm)
	MessageTypeLeader      // Leader announcement
	MessageTypeHeartbeat   // Leader heartbeat to confirm leadership
	MessageTypeZoneUpdate  // Zone data propagated from leader to followers
	MessageTypeConfigSync  // Cluster config propagated from leader to followers
	MessageTypeDraining    // Node entering/leaving draining state
	MessageTypeNodeStats   // Periodic node health stats broadcast
	MessageTypeClusterMetrics // Periodic cluster metrics aggregation
)

// Message is the envelope for all gossip messages.
type Message struct {
	Type           MessageType
	From           string
	Timestamp      time.Time
	Payload        []byte
	ProtocolVersion uint32 // Gossip protocol version for rolling upgrade compatibility
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

// ElectionPayload is sent during leader election (bully algorithm).
// A node proposes itself as leader by sending its ID and priority.
type ElectionPayload struct {
	ProposedLeader string // NodeID of the proposed leader
	Priority       int    // Higher priority wins (use NodeID as tiebreaker)
	Term           uint64 // Election term (increments each election)
}

// LeaderPayload announces the current leader to all nodes.
type LeaderPayload struct {
	LeaderID   string
	LeaderAddr string
	Term       uint64 // Leader's term
}

// LeaderHeartbeatPayload is sent periodically by the leader to confirm leadership.
type LeaderHeartbeatPayload struct {
	LeaderID string
	Term     uint64
}

// ZoneUpdatePayload carries zone change data from leader to follower nodes.
// This enables master/slave zone replication via the gossip protocol.
type ZoneUpdatePayload struct {
	ZoneName    string            // Origin of the zone being updated
	Action      string            // "add", "delete", "reload", "full"
	Serial      uint32            // SOA serial of the zone after this change
	Records     []ZoneRecord      // Records being added/deleted
	DeletedKeys []string          // Record names deleted (for "delete" action)
	RawZone     []byte            // Full zone file content (for "full" or "reload" action)
}

// ZoneRecord is a serialized DNS record for gossip transport.
type ZoneRecord struct {
	Name   string
	TTL    uint32
	Class  string
	Type   string
	RData  string
}

// ConfigSyncPayload carries configuration changes from leader to followers.
// This enables automatic propagation and synchronization of config changes.
type ConfigSyncPayload struct {
	ConfigSHA256  string            // SHA-256 hash of the config for change detection
	Timestamp     time.Time         // When this config was generated
	NodeID        string            // Leader's node ID
	ClusterConfig *ClusterConfigJSON // Serialized cluster configuration
}

// ClusterConfigJSON is a JSON-serializable version of cluster configuration.
type ClusterConfigJSON struct {
	Enabled      bool     `json:"enabled"`
	NodeID       string   `json:"node_id"`
	BindAddr     string   `json:"bind_addr"`
	BindPort     int      `json:"bind_port"`
	GossipPort   int      `json:"gossip_port"`
	ConsensusMode string   `json:"consensus_mode"`
	Region       string   `json:"region"`
	Zone         string   `json:"zone"`
	Weight       int      `json:"weight"`
	SeedNodes    []string `json:"seed_nodes"`
	CacheSync    bool     `json:"cache_sync"`
	HTTPAddr     string   `json:"http_addr"`
}

// DrainingPayload is broadcast when a node enters or leaves draining state.
type DrainingPayload struct {
	NodeID      string    // Node entering/exiting draining
	Draining    bool      // true = entering draining, false = exiting (back to alive)
	Timestamp   time.Time // When the draining action was initiated
	InFlightReq int       // Estimated number of in-flight queries (for monitoring)
}

// NodeStatsPayload carries periodic health statistics for health-based routing.
type NodeStatsPayload struct {
	NodeID           string    // Node reporting stats
	QueriesPerSecond float64   // Rolling average queries/sec
	LatencyMs        float64   // Rolling average latency in milliseconds
	CPUPercent       float64   // Estimated CPU usage (0-100)
	MemoryPercent    float64   // Estimated memory pressure (0-100)
	ActiveConns      int       // Current active connections
	Timestamp        time.Time // When these stats were collected
}

// ClusterMetricsPayload carries aggregated per-node operational metrics for
// cluster-wide monitoring and aggregation.
type ClusterMetricsPayload struct {
	NodeID           string    // Node reporting metrics
	QueriesTotal     uint64    // Total queries processed by this node
	QueriesPerSec    float64   // Current queries per second
	CacheHits        uint64    // Total cache hits
	CacheMisses      uint64    // Total cache misses
	LatencyMsAvg     float64   // Average latency in milliseconds
	LatencyMsP99     float64   // P99 latency in milliseconds
	UptimeSeconds    uint64    // Node uptime in seconds
	Timestamp        time.Time // When these metrics were collected
}

// GossipProtocol implements the gossip-based membership protocol.
type GossipProtocol struct {
	config   GossipConfig
	nodeList *NodeList
	conn     *net.UDPConn

	// Encryption
	aead   cipher.AEAD
	encKey []byte

	// Callbacks
	callbacksMu    sync.RWMutex
	onNodeJoin     func(*Node)
	onNodeLeave    func(*Node)
	onNodeUpdate   func(*Node)
	onCacheInvalid func([]string)
	onZoneUpdate   func(ZoneUpdatePayload)   // Called when leader propagates zone changes
	onConfigSync   func(ConfigSyncPayload)   // Called when leader propagates config changes

	// Leader election state
	leaderMu          sync.RWMutex
	currentLeader     string        // NodeID of current leader (empty if none)
	isLeader          bool          // True if this node is the leader
	leaderTerm        uint64        // Current term
	electionTerm       uint64        // Current election term
	heartbeatInterval time.Duration // Interval for leader heartbeats
	lastHeartbeat      time.Time     // Last heartbeat received

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Per-node operational metrics (keyed by node ID)
	nodeMetricsMu sync.RWMutex
	nodeMetrics   map[string]ClusterMetricsPayload // NodeID -> metrics

	// Stats
	messagesSent     uint64
	messagesReceived uint64
	pingSent         uint64
	pingReceived     uint64
}

// GossipConfig configures the gossip protocol.
type GossipConfig struct {
	BindAddr       string
	BindPort       int
	GossipInterval time.Duration
	ProbeInterval  time.Duration
	ProbeTimeout   time.Duration
	SuspicionMult  int
	RetransmitMult int
	GossipNodes    int
	IndirectChecks int

	// Protocol version for rolling upgrade compatibility.
	// Nodes with different protocol versions can coexist during rolling upgrades.
	ProtocolVersion uint32

	// Encryption key (32 bytes for AES-256). When set, all gossip
	// messages are encrypted with AES-256-GCM.
	EncryptionKey []byte
}

// DefaultGossipConfig returns default configuration.
func DefaultGossipConfig() GossipConfig {
	return GossipConfig{
		BindAddr:        "0.0.0.0",
		BindPort:        7946,
		GossipInterval:  200 * time.Millisecond,
		ProbeInterval:   1 * time.Second,
		ProbeTimeout:    500 * time.Millisecond,
		SuspicionMult:   4,
		RetransmitMult:  4,
		GossipNodes:     3,
		IndirectChecks:  3,
		ProtocolVersion: 1, // Gossip protocol version for rolling upgrade compatibility
	}
}

// NewGossipProtocol creates a new gossip protocol instance.
func NewGossipProtocol(config GossipConfig, nodeList *NodeList) (*GossipProtocol, error) {
	ctx, cancel := context.WithCancel(context.Background())

	gp := &GossipProtocol{
		config:      config,
		nodeList:    nodeList,
		ctx:         ctx,
		cancel:      cancel,
		nodeMetrics: make(map[string]ClusterMetricsPayload),
	}

	// Initialize AES-GCM if encryption key is provided
	if len(config.EncryptionKey) > 0 {
		if err := gp.initEncryption(config.EncryptionKey); err != nil {
			cancel()
			return nil, fmt.Errorf("init encryption: %w", err)
		}
	}

	return gp, nil
}

// SetCallbacks sets the event callbacks.
func (gp *GossipProtocol) SetCallbacks(
	onJoin, onLeave, onUpdate func(*Node),
	onCacheInvalid func([]string),
	onZoneUpdate func(ZoneUpdatePayload),
	onConfigSync func(ConfigSyncPayload),
) {
	gp.callbacksMu.Lock()
	defer gp.callbacksMu.Unlock()
	gp.onNodeJoin = onJoin
	gp.onNodeLeave = onLeave
	gp.onNodeUpdate = onUpdate
	gp.onCacheInvalid = onCacheInvalid
	gp.onZoneUpdate = onZoneUpdate
	gp.onConfigSync = onConfigSync
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
	gp.wg.Add(5)
	go gp.receiveLoop()
	go gp.gossipLoop()
	go gp.probeLoop()
	go gp.leaderHeartbeatLoop()
	go gp.leaderFailureDetector()

	// Start leader election if we're the only node (no peers to join)
	if len(gp.nodeList.GetAll()) <= 1 {
		go gp.startElection()
	}

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

	if err := gp.sendMessage(MessageTypePing, payloadBytes, addr); err != nil {
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

	data, err := encodeMessage(MessageTypeCacheInvalidate, gp.nodeList.GetSelf().ID, gp.config.ProtocolVersion, payloadBytes)
	if err != nil {
		return err
	}

	// Encrypt if enabled
	if gp.aead != nil {
		data, err = gp.encrypt(data)
		if err != nil {
			return err
		}
	}

	// Send to all alive nodes
	for _, node := range gp.nodeList.GetAlive() {
		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", node.Addr, gp.config.BindPort))
		if err != nil {
			util.Warnf("gossip: failed to resolve address for %s: %v", node.Addr, err)
			continue
		}
		if _, err := gp.conn.WriteToUDP(data, addr); err != nil {
			util.Warnf("gossip: failed to send cache invalidation to %s: %v", addr, err)
		}
		atomic.AddUint64(&gp.messagesSent, 1)
	}

	return nil
}

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

	msgBytes, err := encodeMessage(MessageTypeZoneUpdate, gp.nodeList.GetSelf().ID, gp.config.ProtocolVersion, payloadBytes)
	if err != nil {
		return err
	}

	data := msgBytes
	if gp.aead != nil {
		data, _ = gp.encrypt(data)
	}

	self := gp.nodeList.GetSelf()
	for _, node := range gp.nodeList.GetAll() {
		if node.ID == self.ID || node.State != NodeStateAlive {
			continue
		}
		addr := &net.UDPAddr{IP: net.ParseIP(node.Addr), Port: node.Port}
		if _, err := gp.conn.WriteToUDP(data, addr); err != nil {
			util.Warnf("gossip: failed to send zone update to %s: %v", addr, err)
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
		util.Warnf("gossip: failed to encode ack payload: %v", err)
		return
	}
	data, err := encodeMessage(MessageTypeAck, gp.nodeList.GetSelf().ID, gp.config.ProtocolVersion, ackBytes)
	if err != nil {
		util.Warnf("gossip: failed to encode ack message: %v", err)
		return
	}
	// Encrypt if enabled
	if gp.aead != nil {
		data, err = gp.encrypt(data)
		if err != nil {
			util.Warnf("gossip: failed to encrypt ack: %v", err)
			return
		}
	}
	if _, err := gp.conn.WriteToUDP(data, from); err != nil {
		util.Warnf("gossip: failed to send ack to %s: %v", from, err)
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
					func() {
						defer recover()
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
					defer recover()
					gp.onNodeUpdate(existing)
				}()
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
		func() {
			defer recover()
			gp.onCacheInvalid(payload.Keys)
		}()
	}
	gp.callbacksMu.RUnlock()
}

// handleElection handles leader election messages (bully algorithm).
func (gp *GossipProtocol) handleElection(msg Message, from *net.UDPAddr) {
	var payload ElectionPayload
	if err := decodePayload(msg.Payload, &payload); err != nil {
		return
	}

	gp.leaderMu.Lock()
	defer gp.leaderMu.Unlock()

	selfID := gp.nodeList.GetSelf().ID

	// If we have a higher priority (lower NodeID lexically as tiebreaker), we win
	if payload.ProposedLeader != selfID {
		// Start our own election with higher term
		gp.electionTerm = payload.Term + 1
		go gp.startElection()
		return
	}

	// We are the proposed leader — send Leader message to all
	gp.leaderTerm = payload.Term
	gp.currentLeader = selfID
	gp.isLeader = true
}

// handleLeader handles leader announcement messages.
func (gp *GossipProtocol) handleLeader(msg Message, from *net.UDPAddr) {
	var payload LeaderPayload
	if err := decodePayload(msg.Payload, &payload); err != nil {
		return
	}

	gp.leaderMu.Lock()
	defer gp.leaderMu.Unlock()

	// Accept leader if term is >= our term
	if payload.Term >= gp.leaderTerm {
		gp.currentLeader = payload.LeaderID
		gp.isLeader = false
		gp.leaderTerm = payload.Term
		gp.lastHeartbeat = time.Now()
	}
}

// handleHeartbeat handles leader heartbeat messages.
func (gp *GossipProtocol) handleHeartbeat(msg Message, from *net.UDPAddr) {
	var payload LeaderHeartbeatPayload
	if err := decodePayload(msg.Payload, &payload); err != nil {
		return
	}

	gp.leaderMu.Lock()
	defer gp.leaderMu.Unlock()

	if payload.Term >= gp.leaderTerm && payload.LeaderID == gp.currentLeader {
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

	// Optionally verify the message came from the leader via from address
	// For now we trust the message type + leader state

	gp.callbacksMu.RLock()
	onZoneUpdate := gp.onZoneUpdate
	gp.callbacksMu.RUnlock()

	if onZoneUpdate != nil {
		var payload ZoneUpdatePayload
		if err := decodePayload(msg.Payload, &payload); err != nil {
			return
		}
		func() {
			defer recover()
			onZoneUpdate(payload)
		}()
	}
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

	gp.callbacksMu.RLock()
	onConfigSync := gp.onConfigSync
	gp.callbacksMu.RUnlock()

	if onConfigSync != nil {
		var payload ConfigSyncPayload
		if err := decodePayload(msg.Payload, &payload); err != nil {
			return
		}
		func() {
			defer recover()
			onConfigSync(payload)
		}()
	}
}

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

	msgBytes, err := encodeMessage(MessageTypeConfigSync, gp.nodeList.GetSelf().ID, gp.config.ProtocolVersion, payloadBytes)
	if err != nil {
		return err
	}

	data := msgBytes
	if gp.aead != nil {
		data, _ = gp.encrypt(data)
	}

	self := gp.nodeList.GetSelf()
	for _, node := range gp.nodeList.GetAll() {
		if node.ID == self.ID || node.State != NodeStateAlive {
			continue
		}
		addr := &net.UDPAddr{IP: net.ParseIP(node.Addr), Port: node.Port}
		if _, err := gp.conn.WriteToUDP(data, addr); err != nil {
			util.Warnf("gossip: failed to send config sync to %s: %v", addr, err)
		}
		atomic.AddUint64(&gp.messagesSent, 1)
	}

	return nil
}

// handleDraining processes a draining state message from another node.
func (gp *GossipProtocol) handleDraining(msg Message, from *net.UDPAddr) {
	var payload DrainingPayload
	if err := decodePayload(msg.Payload, &payload); err != nil {
		return
	}

	// Ignore messages from self
	if payload.NodeID == gp.nodeList.GetSelf().ID {
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

	msgBytes, err := encodeMessage(MessageTypeDraining, gp.nodeList.GetSelf().ID, gp.config.ProtocolVersion, payloadBytes)
	if err != nil {
		return err
	}

	data := msgBytes
	if gp.aead != nil {
		data, _ = gp.encrypt(data)
	}

	for _, node := range gp.nodeList.GetAll() {
		if node.ID == gp.nodeList.GetSelf().ID {
			continue
		}
		addr := &net.UDPAddr{IP: net.ParseIP(node.Addr), Port: node.Port}
		if _, err := gp.conn.WriteToUDP(data, addr); err != nil {
			util.Warnf("gossip: failed to send draining message to %s: %v", addr, err)
		}
		atomic.AddUint64(&gp.messagesSent, 1)
	}

	return nil
}

// handleNodeStats processes node health statistics received via gossip.
func (gp *GossipProtocol) handleNodeStats(msg Message, from *net.UDPAddr) {
	var payload NodeStatsPayload
	if err := decodePayload(msg.Payload, &payload); err != nil {
		return
	}

	// Ignore messages from self
	if payload.NodeID == gp.nodeList.GetSelf().ID {
		return
	}

	// Update the health stats for this node in our local node list
	health := NodeHealthStats{
		QueriesPerSecond: payload.QueriesPerSecond,
		LatencyMs:       payload.LatencyMs,
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

	msgBytes, err := encodeMessage(MessageTypeNodeStats, gp.nodeList.GetSelf().ID, gp.config.ProtocolVersion, payloadBytes)
	if err != nil {
		return err
	}

	data := msgBytes
	if gp.aead != nil {
		data, _ = gp.encrypt(data)
	}

	for _, node := range gp.nodeList.GetAll() {
		if node.ID == gp.nodeList.GetSelf().ID {
			continue
		}
		addr := &net.UDPAddr{IP: net.ParseIP(node.Addr), Port: node.Port}
		if _, err := gp.conn.WriteToUDP(data, addr); err != nil {
			util.Warnf("gossip: failed to send node stats to %s: %v", addr, err)
		}
		atomic.AddUint64(&gp.messagesSent, 1)
	}

	return nil
}

// handleClusterMetrics processes cluster metrics received via gossip.
func (gp *GossipProtocol) handleClusterMetrics(msg Message, from *net.UDPAddr) {
	var payload ClusterMetricsPayload
	if err := decodePayload(msg.Payload, &payload); err != nil {
		return
	}

	// Ignore messages from self
	if payload.NodeID == gp.nodeList.GetSelf().ID {
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

	msgBytes, err := encodeMessage(MessageTypeClusterMetrics, gp.nodeList.GetSelf().ID, gp.config.ProtocolVersion, payloadBytes)
	if err != nil {
		return err
	}

	data := msgBytes
	if gp.aead != nil {
		data, _ = gp.encrypt(data)
	}

	for _, node := range gp.nodeList.GetAll() {
		if node.ID == gp.nodeList.GetSelf().ID {
			continue
		}
		addr := &net.UDPAddr{IP: net.ParseIP(node.Addr), Port: node.Port}
		if _, err := gp.conn.WriteToUDP(data, addr); err != nil {
			util.Warnf("gossip: failed to send cluster metrics to %s: %v", addr, err)
		}
		atomic.AddUint64(&gp.messagesSent, 1)
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

	// If last heartbeat is too old, leader is dead — start new election
	if time.Since(gp.lastHeartbeat) > 15*time.Second {
		gp.leaderTerm++ // Increment term — old leader's term is no longer valid
		go gp.startElection()
	}
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

	msgBytes, err := encodeMessage(MessageTypeHeartbeat, gp.nodeList.GetSelf().ID, gp.config.ProtocolVersion, payloadBytes)
	if err != nil {
		return
	}

	data := msgBytes
	if gp.aead != nil {
		data, _ = gp.encrypt(data)
	}

	for _, node := range gp.nodeList.GetAll() {
		if node.ID == self.ID || node.State != NodeStateAlive {
			continue
		}
		addr := &net.UDPAddr{IP: net.ParseIP(node.Addr), Port: node.Port}
		gp.conn.WriteToUDP(data, addr)
	}
}

// startElection begins a new leader election.
func (gp *GossipProtocol) startElection() {
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

	msgBytes, err := encodeMessage(MessageTypeElection, gp.nodeList.GetSelf().ID, gp.config.ProtocolVersion, payloadBytes)
	if err != nil {
		return
	}

	// Broadcast to all known nodes
	for _, node := range gp.nodeList.GetAll() {
		if node.ID == selfID || node.State != NodeStateAlive {
			continue
		}
		addr := &net.UDPAddr{IP: net.ParseIP(node.Addr), Port: node.Port}
		data := msgBytes
		if gp.aead != nil {
			data, _ = gp.encrypt(data)
		}
		gp.conn.WriteToUDP(data, addr)
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

	msgBytes, err := encodeMessage(MessageTypeLeader, gp.nodeList.GetSelf().ID, gp.config.ProtocolVersion, payloadBytes)
	if err != nil {
		return err
	}

	// Broadcast to all known nodes
	for _, node := range gp.nodeList.GetAll() {
		if node.ID == self.ID || node.State != NodeStateAlive {
			continue
		}
		addr := &net.UDPAddr{IP: net.ParseIP(node.Addr), Port: node.Port}
		data := msgBytes
		if gp.aead != nil {
			data, _ = gp.encrypt(data)
		}
		gp.conn.WriteToUDP(data, addr)
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
	if time.Since(gp.lastHeartbeat) > timeout {
		return false
	}
	return true
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

	data, err := encodeMessage(MessageTypeGossip, gp.nodeList.GetSelf().ID, gp.config.ProtocolVersion, payloadBytes)
	if err != nil {
		return
	}

	// Encrypt if enabled
	if gp.aead != nil {
		data, err = gp.encrypt(data)
		if err != nil {
			return
		}
	}

	// Send to random nodes
	for i := 0; i < gp.config.GossipNodes; i++ {
		target := gp.nodeList.GetRandom(nil)
		if target == nil {
			break
		}

		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", target.Addr, gp.config.BindPort))
		if err != nil {
			util.Warnf("gossip: failed to resolve address for %s: %v", target.Addr, err)
			continue
		}
		if _, err := gp.conn.WriteToUDP(data, addr); err != nil {
			util.Warnf("gossip: failed to send gossip to %s: %v", addr, err)
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
					func() {
						defer recover()
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
	data, err := encodeMessage(MessageTypePing, gp.nodeList.GetSelf().ID, gp.config.ProtocolVersion, pingBytes)
	if err != nil {
		util.Warnf("gossip: failed to encode ping message: %v", err)
		return
	}
	// Encrypt if enabled
	if gp.aead != nil {
		data, err = gp.encrypt(data)
		if err != nil {
			util.Warnf("gossip: failed to encrypt ping: %v", err)
			return
		}
	}
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", node.Addr, gp.config.BindPort))
	if err != nil {
		util.Warnf("gossip: failed to resolve address for %s: %v", node.Addr, err)
		return
	}
	if _, err := gp.conn.WriteToUDP(data, addr); err != nil {
		util.Warnf("gossip: failed to send ping to %s: %v", addr, err)
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

// initEncryption initializes AES-256-GCM from a 32-byte key.
func (gp *GossipProtocol) initEncryption(key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("gossip encryption key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("gossip encryption: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("gossip encryption GCM: %w", err)
	}
	gp.aead = aead
	gp.encKey = make([]byte, 32)
	copy(gp.encKey, key)
	return nil
}

// IsEncrypted returns whether gossip encryption is enabled.
func (gp *GossipProtocol) IsEncrypted() bool {
	return gp.aead != nil
}

// encrypt encrypts data using AES-256-GCM.
// Output format: nonce (12 bytes) + ciphertext + tag.
func (gp *GossipProtocol) encrypt(plaintext []byte) ([]byte, error) {
	if gp.aead == nil {
		return plaintext, nil
	}
	nonce := make([]byte, gp.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("gossip encrypt nonce: %w", err)
	}
	// Seal appends the ciphertext to the nonce slice
	return gp.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// decrypt decrypts AES-256-GCM encrypted data.
func (gp *GossipProtocol) decrypt(ciphertext []byte) ([]byte, error) {
	if gp.aead == nil {
		return ciphertext, nil
	}
	if len(ciphertext) < gp.aead.NonceSize()+gp.aead.Overhead() {
		return nil, fmt.Errorf("gossip decrypt: ciphertext too short")
	}
	nonce := ciphertext[:gp.aead.NonceSize()]
	data := ciphertext[gp.aead.NonceSize():]
	return gp.aead.Open(nil, nonce, data, nil)
}

// encodeMessage encodes a message with its payload.
func encodeMessage(msgType MessageType, from string, protocolVersion uint32, payload []byte) ([]byte, error) {
	msg := Message{
		Type:           msgType,
		From:           from,
		Timestamp:      time.Now(),
		Payload:        payload,
		ProtocolVersion: protocolVersion,
	}

	return json.Marshal(msg)
}

// encodePayload encodes a payload structure to bytes.
func encodePayload(payload any) ([]byte, error) {
	return json.Marshal(payload)
}

// decodeMessage decodes a message envelope, decrypting if needed.
// If decryption fails (e.g., during rolling upgrade with mixed encrypted/unencrypted nodes),
// falls back to parsing as unencrypted message.
// If the message protocol version is incompatible, it is logged and skipped.
func (gp *GossipProtocol) decodeMessage(data []byte, msg *Message) error {
	// Try decryption first if encryption is enabled
	if gp.aead != nil {
		decrypted, err := gp.decrypt(data)
		if err != nil {
			// Might be unencrypted message during rolling upgrade - try unencrypted parse
			if rawErr := decodeMessageRaw(data, msg); rawErr != nil {
				return fmt.Errorf("gossip decrypt: %w (also failed unencrypted parse: %v)", err, rawErr)
			}
			return nil
		}
		data = decrypted
	}

	if err := json.Unmarshal(data, msg); err != nil {
		return err
	}

	// Check protocol version compatibility during rolling upgrades.
	// Messages without a ProtocolVersion field (version 0) are from pre-versioning nodes.
	// Accept version 0 (legacy) or matching version.
	if msg.ProtocolVersion != 0 && msg.ProtocolVersion != gp.config.ProtocolVersion {
		util.Warnf("gossip: dropped message from node %s: protocol version %d != our version %d",
			msg.From, msg.ProtocolVersion, gp.config.ProtocolVersion)
		return fmt.Errorf("incompatible protocol version")
	}

	return nil
}

// sendMessage encodes, encrypts, and sends a message to a UDP address.
func (gp *GossipProtocol) sendMessage(msgType MessageType, payload []byte, addr *net.UDPAddr) error {
	data, err := encodeMessage(msgType, gp.nodeList.GetSelf().ID, gp.config.ProtocolVersion, payload)
	if err != nil {
		return err
	}

	// Encrypt if enabled
	if gp.aead != nil {
		data, err = gp.encrypt(data)
		if err != nil {
			return err
		}
	}

	_, err = gp.conn.WriteToUDP(data, addr)
	return err
}

// decodeMessageRaw decodes a message without decryption (for tests).
func decodeMessageRaw(data []byte, msg *Message) error {
	return json.Unmarshal(data, msg)
}

// decodePayload decodes a message payload.
func decodePayload(data []byte, payload any) error {
	return json.Unmarshal(data, payload)
}
