package cluster

import (
	"context"
	"crypto/cipher"
	"net"
	"sync"
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
	MessageTypeElection       // Leader election (bully algorithm)
	MessageTypeLeader         // Leader announcement
	MessageTypeHeartbeat      // Leader heartbeat to confirm leadership
	MessageTypeZoneUpdate     // Zone data propagated from leader to followers
	MessageTypeConfigSync     // Cluster config propagated from leader to followers
	MessageTypeDraining       // Node entering/leaving draining state
	MessageTypeNodeStats      // Periodic node health stats broadcast
	MessageTypeClusterMetrics // Periodic cluster metrics aggregation
)

// Message is the envelope for all gossip messages.
// Sequence is transmitted on the wire for replay protection.
// Receivers use it to detect and reject replayed messages.
// Backwards compatible with pre-sequence nodes (ProtocolVersion 0 sends Sequence=0).
type Message struct {
	Type            MessageType
	From            string
	Timestamp       time.Time
	Payload         []byte
	ProtocolVersion uint32
	Sequence        uint64 // monotonic sequence for replay protection
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
	ZoneName    string       // Origin of the zone being updated
	Action      string       // "add", "delete", "reload", "full"
	Serial      uint32       // SOA serial of the zone after this change
	Records     []ZoneRecord // Records being added/deleted
	DeletedKeys []string     // Record names deleted (for "delete" action)
	RawZone     []byte       // Full zone file content (for "full" or "reload" action)
}

// ZoneRecord is a serialized DNS record for gossip transport.
type ZoneRecord struct {
	Name  string
	TTL   uint32
	Class string
	Type  string
	RData string
}

// ConfigSyncPayload carries configuration changes from leader to followers.
// This enables automatic propagation and synchronization of config changes.
type ConfigSyncPayload struct {
	ConfigSHA256  string             // SHA-256 hash of the config for change detection
	Timestamp     time.Time          // When this config was generated
	NodeID        string             // Leader's node ID
	ClusterConfig *ClusterConfigJSON // Serialized cluster configuration
}

// ClusterConfigJSON is a JSON-serializable version of cluster configuration.
type ClusterConfigJSON struct {
	Enabled       bool     `json:"enabled"`
	NodeID        string   `json:"node_id"`
	BindAddr      string   `json:"bind_addr"`
	BindPort      int      `json:"bind_port"`
	GossipPort    int      `json:"gossip_port"`
	ConsensusMode string   `json:"consensus_mode"`
	Region        string   `json:"region"`
	Zone          string   `json:"zone"`
	Weight        int      `json:"weight"`
	SeedNodes     []string `json:"seed_nodes"`
	CacheSync     bool     `json:"cache_sync"`
	HTTPAddr      string   `json:"http_addr"`
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
	NodeID        string    // Node reporting metrics
	QueriesTotal  uint64    // Total queries processed by this node
	QueriesPerSec float64   // Current queries per second
	CacheHits     uint64    // Total cache hits
	CacheMisses   uint64    // Total cache misses
	LatencyMsAvg  float64   // Average latency in milliseconds
	LatencyMsP99  float64   // P99 latency in milliseconds
	UptimeSeconds uint64    // Node uptime in seconds
	Timestamp     time.Time // When these metrics were collected
}

// GossipProtocol implements the gossip-based membership protocol.
type GossipProtocol struct {
	config   GossipConfig
	nodeList *NodeList
	conn     gossipUDPConn

	// Encryption
	aead   cipher.AEAD
	encKey []byte

	// Callbacks
	callbacksMu    sync.RWMutex
	onNodeJoin     func(*Node)
	onNodeLeave    func(*Node)
	onNodeUpdate   func(*Node)
	onCacheInvalid func([]string)
	onZoneUpdate   func(ZoneUpdatePayload) // Called when leader propagates zone changes
	onConfigSync   func(ConfigSyncPayload) // Called when leader propagates config changes

	// Leader election state
	leaderMu          sync.RWMutex
	currentLeader     string        // NodeID of current leader (empty if none)
	isLeader          bool          // True if this node is the leader
	leaderTerm        uint64        // Current term
	electionTerm      uint64        // Current election term
	electionRunning   bool          // Single-flight guard for startElection
	heartbeatInterval time.Duration // Interval for leader heartbeats
	lastHeartbeat     time.Time     // Last heartbeat received

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Per-node operational metrics (keyed by node ID)
	nodeMetricsMu sync.RWMutex
	nodeMetrics   map[string]ClusterMetricsPayload // NodeID -> metrics

	// Sequence tracking for replay protection (per-sender high-water mark)
	sequenceMu   sync.RWMutex
	sequences    map[string]uint64 // NodeID -> last seen sequence number
	seqWindows   map[string]uint64 // NodeID -> bit i set = (high-water - i) already seen (F142)
	nextSequence uint64            // Monotonic counter for outgoing messages

	// Stats
	messagesSent     uint64
	messagesReceived uint64
	pingSent         uint64
	pingReceived     uint64
}

type gossipUDPConn interface {
	ReadFromUDP([]byte) (int, *net.UDPAddr, error)
	WriteToUDP([]byte, *net.UDPAddr) (int, error)
	SetReadDeadline(time.Time) error
	Close() error
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

// GossipStats contains gossip protocol statistics.
type GossipStats struct {
	MessagesSent     uint64
	MessagesReceived uint64
	PingSent         uint64
	PingReceived     uint64
}
