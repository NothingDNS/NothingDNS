package cluster

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/cluster/raft"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// ConsensusMode defines the consensus protocol for the cluster.
type ConsensusMode string

const (
	ConsensusSWIM ConsensusMode = "swim" // Gossip-based SWIM
	ConsensusRaft ConsensusMode = "raft" // Raft consensus (default, per SPEC §10)
)

// Cluster manages the DNS server cluster.
type Cluster struct {
	config   Config
	nodeList *NodeList
	gossip   *GossipProtocol
	logger   *util.Logger

	// Zone manager for replication
	zoneManager *zone.Manager

	// Config hot-reload callback from leader
	configReloadCallback func(*ClusterConfigJSON) error

	// Raft consensus (when mode = raft)
	raft      *raft.ClusterIntegration
	consensus ConsensusMode

	// Cache integration
	cache         *cache.Cache
	cacheSyncChan chan CacheSyncEvent

	// Event handlers
	handlersMu sync.RWMutex
	handlers   []EventHandler

	// Status
	started     bool
	cacheClosed bool
	mu          sync.RWMutex
	wg          sync.WaitGroup

	// Local health stats for health-based routing
	localHealth NodeHealthStats
}

// Config configures the cluster.
type Config struct {
	Enabled              bool
	NodeID               string
	BindAddr             string
	BindPort             int
	GossipPort           int
	ConsensusMode        ConsensusMode // "raft" (default) or "swim"
	Region               string
	Zone                 string
	Weight               int
	SeedNodes            []string
	CacheSync            bool
	HTTPAddr             string
	EncryptionKey        string                         // hex-encoded 32-byte AES-256 key
	// AllowInsecureCluster, when true, permits cluster startup without an
	// EncryptionKey. The default is false: gossip messages carry zone updates
	// and config sync, so plaintext on the cluster plane means a network
	// attacker can forge either. Only set this for single-node/dev setups.
	AllowInsecureCluster bool
	DataDir              string                         // Directory for Raft WAL and snapshots
	Peers                []PeerConfig                   // Raft peer nodes
	ZoneManager          *zone.Manager                  // zone manager for replication
	ConfigReloadCallback func(*ClusterConfigJSON) error // called when leader sends config
}

// PeerConfig describes a Raft cluster peer.
type PeerConfig struct {
	NodeID string
	Addr   string
}

// CacheSyncEvent represents a cache synchronization event.
type CacheSyncEvent struct {
	Type      string // "invalidate", "update"
	Keys      []string
	Source    string
	Timestamp time.Time
}

// EventHandler handles cluster events.
type EventHandler interface {
	OnNodeJoin(node *Node)
	OnNodeLeave(node *Node)
	OnNodeUpdate(node *Node)
	OnCacheInvalid(keys []string)
}

// EventHandlerFunc is a function that implements EventHandler.
type EventHandlerFunc struct {
	OnJoinFunc         func(*Node)
	OnLeaveFunc        func(*Node)
	OnUpdateFunc       func(*Node)
	OnCacheInvalidFunc func([]string)
}

func (f EventHandlerFunc) OnNodeJoin(node *Node) {
	if f.OnJoinFunc != nil {
		f.OnJoinFunc(node)
	}
}

func (f EventHandlerFunc) OnNodeLeave(node *Node) {
	if f.OnLeaveFunc != nil {
		f.OnLeaveFunc(node)
	}
}

func (f EventHandlerFunc) OnNodeUpdate(node *Node) {
	if f.OnUpdateFunc != nil {
		f.OnUpdateFunc(node)
	}
}

func (f EventHandlerFunc) OnCacheInvalid(keys []string) {
	if f.OnCacheInvalidFunc != nil {
		f.OnCacheInvalidFunc(keys)
	}
}

// New creates a new cluster manager.
func New(config Config, logger *util.Logger, dnsCache *cache.Cache) (*Cluster, error) {
	// Generate node ID if not provided
	if config.NodeID == "" {
		config.NodeID = GenerateNodeID()
	}

	// Default to SWIM consensus if not specified
	if config.ConsensusMode == "" {
		config.ConsensusMode = ConsensusSWIM
	}

	// Get local IP if not specified
	if config.BindAddr == "" {
		ip, err := GetLocalIP()
		if err != nil {
			return nil, fmt.Errorf("getting local IP: %w", err)
		}
		config.BindAddr = ip
	}

	c := &Cluster{
		config:               config,
		logger:               logger,
		cache:                dnsCache,
		cacheSyncChan:        make(chan CacheSyncEvent, 100),
		consensus:            config.ConsensusMode,
		zoneManager:          config.ZoneManager,
		configReloadCallback: config.ConfigReloadCallback,
	}

	// Initialize based on consensus mode
	if config.ConsensusMode == ConsensusRaft {
		if err := c.initRaft(); err != nil {
			return nil, fmt.Errorf("initializing Raft: %w", err)
		}
	} else {
		if err := c.initGossip(); err != nil {
			return nil, fmt.Errorf("initializing gossip: %w", err)
		}
	}

	return c, nil
}

// initGossip initializes the SWIM gossip protocol.
func (c *Cluster) initGossip() error {
	self := &Node{
		ID:      c.config.NodeID,
		Addr:    c.config.BindAddr,
		Port:    c.config.GossipPort,
		State:   NodeStateAlive,
		Version: 1,
		Meta: NodeMeta{
			Region:   c.config.Region,
			Zone:     c.config.Zone,
			Weight:   c.config.Weight,
			HTTPAddr: c.config.HTTPAddr,
		},
	}

	c.nodeList = NewNodeList(self)

	gossipConfig := DefaultGossipConfig()
	gossipConfig.BindAddr = c.config.BindAddr
	gossipConfig.BindPort = c.config.GossipPort

	if c.config.EncryptionKey != "" {
		key, err := hex.DecodeString(c.config.EncryptionKey)
		if err != nil {
			return fmt.Errorf("decoding cluster encryption key: %w", err)
		}
		if len(key) != 32 {
			return fmt.Errorf("cluster encryption key must be 32 bytes (hex-encoded); got %d bytes", len(key))
		}
		gossipConfig.EncryptionKey = key
	} else if len(c.config.SeedNodes) > 0 && !c.config.AllowInsecureCluster {
		// VULN-005: refuse to start a multi-node cluster in plaintext. Gossip
		// carries zone updates and config sync; a network attacker can forge
		// either. Single-node clusters (no seeds) skip this check since no
		// peer traffic is generated. Dev/test multi-node setups must opt in
		// via cluster.allow_insecure=true.
		return fmt.Errorf("cluster encryption key is required when seed_nodes are configured (set cluster.encryption_key, or cluster.allow_insecure=true for dev)")
	}

	gossip, err := NewGossipProtocol(gossipConfig, c.nodeList, c.config.AllowInsecureCluster)
	if err != nil {
		return fmt.Errorf("creating gossip protocol: %w", err)
	}
	c.gossip = gossip

	gossip.SetCallbacks(
		c.handleNodeJoin,
		c.handleNodeLeave,
		c.handleNodeUpdate,
		c.handleCacheInvalid,
		c.handleZoneUpdate,
		c.handleConfigSync,
	)

	return nil
}

// initRaft initializes the Raft consensus protocol.
func (c *Cluster) initRaft() error {
	if len(c.config.Peers) == 0 {
		return fmt.Errorf("raft consensus requires at least one peer in config")
	}

	// Build peer list
	var peerIDs []raft.NodeID
	for _, p := range c.config.Peers {
		peerIDs = append(peerIDs, raft.NodeID(p.NodeID))
	}

	// Create self node entry for nodeList (used for gossip compatibility)
	self := &Node{
		ID:      c.config.NodeID,
		Addr:    c.config.BindAddr,
		Port:    c.config.GossipPort,
		State:   NodeStateAlive,
		Version: 1,
		Meta: NodeMeta{
			Region:   c.config.Region,
			Zone:     c.config.Zone,
			Weight:   c.config.Weight,
			HTTPAddr: c.config.HTTPAddr,
		},
	}
	c.nodeList = NewNodeList(self)

	// Create data directory if not specified
	dataDir := c.config.DataDir
	if dataDir == "" {
		dataDir = "/var/lib/nothingdns/cluster"
	}

	// Determine Raft bind address
	raftAddr := fmt.Sprintf("%s:%d", c.config.BindAddr, c.config.GossipPort)

	// Create Raft cluster integration
	raftNode, err := raft.NewClusterIntegration(
		raft.NodeID(c.config.NodeID),
		peerIDs,
		raftAddr,
		dataDir,
		c.config.EncryptionKey,
	)
	if err != nil {
		return fmt.Errorf("creating Raft node: %w", err)
	}
	c.raft = raftNode

	return nil
}

// Start starts the cluster.
func (c *Cluster) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.started {
		return fmt.Errorf("cluster already started")
	}

	if c.consensus == ConsensusRaft {
		// Start Raft consensus
		if err := c.raft.Start(); err != nil {
			return fmt.Errorf("starting Raft: %w", err)
		}
		c.logger.Infof("Raft cluster started with node ID %s", c.config.NodeID)
		c.logger.Infof("Raft consensus: %s, leader: %v", c.raft.Stats().State, c.raft.IsLeader())
	} else {
		// Start gossip protocol
		if err := c.gossip.Start(); err != nil {
			return fmt.Errorf("starting gossip: %w", err)
		}

		// Join seed nodes
		for _, seed := range c.config.SeedNodes {
			if err := c.gossip.Join(seed); err != nil {
				c.logger.Warnf("Failed to join seed node %s: %v", seed, err)
			} else {
				c.logger.Infof("Joined seed node %s", seed)
			}
		}
		c.logger.Infof("Cluster listening on %s:%d (SWIM)", c.config.BindAddr, c.config.GossipPort)
	}

	// Start cache sync processor (works with both modes)
	if c.config.CacheSync {
		c.wg.Add(1)
		go c.cacheSyncLoop()
	}

	c.started = true
	c.logger.Infof("Cluster started with node ID %s", c.config.NodeID)

	return nil
}

// Stop stops the cluster.
func (c *Cluster) Stop() error {
	c.mu.Lock()
	if !c.started {
		c.mu.Unlock()
		return nil
	}

	// Atomically close cache sync channel if not already closed.
	// Must set cacheClosed BEFORE close() to prevent double-close race.
	if !c.cacheClosed {
		c.cacheClosed = true
		close(c.cacheSyncChan)
	}
	c.started = false

	if c.consensus == ConsensusRaft {
		if err := c.raft.Stop(); err != nil {
			c.logger.Warnf("Error stopping Raft: %v", err)
		}
	} else {
		if err := c.gossip.Stop(); err != nil {
			c.logger.Warnf("Error stopping gossip: %v", err)
		}
	}
	c.logger.Info("Cluster stopped")
	c.mu.Unlock()

	// Wait for cacheSyncLoop to finish
	c.wg.Wait()

	return nil
}

// IsStarted returns true if the cluster is started.
func (c *Cluster) IsStarted() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.started
}

// GetNodeID returns the local node ID.
func (c *Cluster) GetNodeID() string {
	return c.config.NodeID
}

// GetNodes returns copies of all cluster nodes.
func (c *Cluster) GetNodes() []Node {
	return c.nodeList.GetAll()
}

// GetAliveNodes returns copies of all alive nodes.
func (c *Cluster) GetAliveNodes() []Node {
	return c.nodeList.GetAlive()
}

// GetNodeCount returns the total number of nodes.
func (c *Cluster) GetNodeCount() int {
	return c.nodeList.Count()
}

// GetAliveCount returns the number of alive nodes.
func (c *Cluster) GetAliveCount() int {
	return c.nodeList.AliveCount()
}

// GetNodeForQuery returns the best node to handle a query using health-based routing.
// Excludes draining nodes (via IsAlive()) and selects the healthiest node
// using weighted random selection. Returns nil if no alive nodes are available.
func (c *Cluster) GetNodeForQuery(excludeSelf bool) *Node {
	exclude := []string{}
	if excludeSelf {
		exclude = append(exclude, c.config.NodeID)
	}
	return c.nodeList.GetBest(exclude)
}

// UpdateNodeHealth updates the health stats for the local node.
// Other nodes will learn about this node's health via periodic gossip.
// Call this periodically (e.g., every 10s) to keep health stats current.
func (c *Cluster) UpdateNodeHealth(health NodeHealthStats) {
	c.localHealth = health
	c.nodeList.UpdateHealth(c.config.NodeID, health)

	// Broadcast to all cluster peers
	if c.gossip != nil && c.started {
		if err := c.gossip.BroadcastNodeStats(health); err != nil {
			c.logger.Warnf("Failed to broadcast node health stats: %v", err)
		}
	}
}

// GetNodesWithHealth returns all nodes including their health stats.
// This is used by the API to expose health metrics.
func (c *Cluster) GetNodesWithHealth() []Node {
	return c.nodeList.GetAllWithHealth()
}

// BroadcastClusterMetrics broadcasts operational metrics to all cluster peers.
// Call this periodically (e.g., every 30s) with the server's current metrics.
func (c *Cluster) BroadcastClusterMetrics(queriesTotal, cacheHits, cacheMisses uint64, qps, latencyAvg, latencyP99 float64, uptime uint64) {
	if c.gossip == nil || !c.started {
		return
	}

	metrics := ClusterMetricsPayload{
		QueriesTotal:  queriesTotal,
		QueriesPerSec: qps,
		CacheHits:     cacheHits,
		CacheMisses:   cacheMisses,
		LatencyMsAvg:  latencyAvg,
		LatencyMsP99:  latencyP99,
		UptimeSeconds: uptime,
	}

	if err := c.gossip.BroadcastClusterMetrics(metrics); err != nil {
		c.logger.Warnf("Failed to broadcast cluster metrics: %v", err)
	}
}

// GetClusterMetrics returns aggregated cluster-wide metrics from all known nodes.
func (c *Cluster) GetClusterMetrics() ClusterMetricsPayload {
	if c.gossip == nil {
		return ClusterMetricsPayload{}
	}
	return c.gossip.GetClusterMetrics()
}

// AddEventHandler adds an event handler.
func (c *Cluster) AddEventHandler(handler EventHandler) {
	c.handlersMu.Lock()
	defer c.handlersMu.Unlock()
	c.handlers = append(c.handlers, handler)
}

// RemoveEventHandler removes an event handler.
func (c *Cluster) RemoveEventHandler(handler EventHandler) {
	c.handlersMu.Lock()
	defer c.handlersMu.Unlock()

	for i, h := range c.handlers {
		// Use reflection to compare the underlying values since function fields
		// are not comparable with ==
		if reflect.ValueOf(h).Pointer() == reflect.ValueOf(handler).Pointer() {
			c.handlers = append(c.handlers[:i], c.handlers[i+1:]...)
			return
		}
	}
}

// InvalidateCache broadcasts cache invalidation to all nodes.
func (c *Cluster) InvalidateCache(keys []string) error {
	if !c.config.CacheSync {
		return nil
	}

	// In Raft mode, cache sync is handled via the gossip fallback for cache invalidation
	// (zone changes go through Raft consensus, cache invalidation is best-effort)
	if c.consensus == ConsensusRaft {
		// Raft handles zone consistency; cache invalidation uses gossip fallback
		if c.gossip != nil {
			return c.gossip.BroadcastCacheInvalidation(keys)
		}
		return nil
	}

	// Gossip mode
	if c.gossip != nil {
		return c.gossip.BroadcastCacheInvalidation(keys)
	}
	return nil
}

// BroadcastZoneUpdate propagates a zone update to all follower nodes.
// Only the leader calls this to push changes to followers.
func (c *Cluster) BroadcastZoneUpdate(zoneName, action string, serial uint32, records []ZoneRecord, deletedKeys []string) error {
	if c.gossip == nil {
		return fmt.Errorf("gossip protocol not initialized")
	}

	payload := ZoneUpdatePayload{
		ZoneName:    zoneName,
		Action:      action,
		Serial:      serial,
		Records:     records,
		DeletedKeys: deletedKeys,
	}

	return c.gossip.BroadcastZoneUpdate(payload)
}

// GetLeader returns the current cluster leader's node ID and whether a leader exists.
func (c *Cluster) GetLeader() (leaderID string, ok bool) {
	if c.gossip != nil {
		id := c.gossip.GetLeader()
		return id, id != ""
	}
	return "", false
}

// IsLeader returns true if this node is the cluster leader.
func (c *Cluster) IsLeader() bool {
	if c.gossip != nil {
		return c.gossip.IsLeader()
	}
	return false
}

// DetectSplitBrain checks for split-brain conditions in the cluster.
// Returns true if this node should step down due to split-brain detected.
func (c *Cluster) DetectSplitBrain() bool {
	if c.gossip != nil {
		return c.gossip.DetectSplitBrain()
	}
	return false
}

// StartDraining initiates graceful node draining.
// The node stops accepting new queries and broadcasts its draining state to all peers.
// Other nodes will exclude this node from query routing (via IsAlive() = false).
// Call CompleteDraining() once all in-flight queries have finished.
func (c *Cluster) StartDraining() error {
	c.mu.Lock()
	if !c.started {
		c.mu.Unlock()
		return fmt.Errorf("cluster not started")
	}
	c.mu.Unlock()

	// Update local node state to draining
	self := c.nodeList.GetSelf()
	c.nodeList.UpdateState(self.ID, NodeStateDraining)

	// Broadcast draining state to all peers
	if c.gossip != nil {
		if err := c.gossip.BroadcastDraining(true, 0); err != nil {
			c.logger.Warnf("Failed to broadcast draining state: %v", err)
		}
	}

	c.logger.Infof("Node draining initiated, cluster peers notified")
	return nil
}

// CompleteDraining completes the draining process and optionally leaves the cluster.
// If leaveCluster=true, the node removes itself from the cluster and can shut down.
// If leaveCluster=false, the node exits draining state and resumes normal operation.
func (c *Cluster) CompleteDraining(leaveCluster bool) error {
	if leaveCluster {
		// Broadcast that we're leaving the cluster
		if c.gossip != nil {
			if err := c.gossip.BroadcastDraining(false, 0); err != nil {
				c.logger.Warnf("Failed to broadcast node leave: %v", err)
			}
		}
		// Remove self from node list
		self := c.nodeList.GetSelf()
		c.nodeList.Remove(self.ID)
		c.logger.Infof("Node left the cluster after draining")
	} else {
		// Exit draining state — back to alive
		self := c.nodeList.GetSelf()
		c.nodeList.UpdateState(self.ID, NodeStateAlive)
		if c.gossip != nil {
			if err := c.gossip.BroadcastDraining(false, 0); err != nil {
				c.logger.Warnf("Failed to broadcast draining exit: %v", err)
			}
		}
		c.logger.Infof("Node draining cancelled, back to normal operation")
	}
	return nil
}

// BroadcastConfigUpdate propagates a config update to all follower nodes.
// Only the leader calls this to push config changes to followers.
func (c *Cluster) BroadcastConfigUpdate(configSHA256 string, clusterConfig *ClusterConfigJSON) error {
	if c.gossip == nil {
		return fmt.Errorf("gossip protocol not initialized")
	}

	selfID := c.gossip.GetSelfID()
	payload := ConfigSyncPayload{
		ConfigSHA256:  configSHA256,
		Timestamp:     time.Now(),
		NodeID:        selfID,
		ClusterConfig: clusterConfig,
	}

	return c.gossip.BroadcastConfigUpdate(payload)
}

// InvalidateCacheLocal invalidates cache entries locally.
func (c *Cluster) InvalidateCacheLocal(keys []string) {
	if c.cache == nil {
		return
	}

	for _, key := range keys {
		// Use DeleteLocal to avoid triggering another broadcast
		c.cache.DeleteLocal(key)
	}

	c.logger.Debugf("Invalidated %d cache entries from cluster", len(keys))
}

// IsHealthy returns true if the cluster is healthy (has quorum).
func (c *Cluster) IsHealthy() bool {
	c.mu.RLock()
	started := c.started
	c.mu.RUnlock()

	if !started {
		return true // Single node mode is always healthy
	}

	alive := c.nodeList.AliveCount()
	total := c.nodeList.Count()

	// Need majority of nodes to be alive
	return alive >= (total/2)+1
}

// Stats returns cluster statistics.
func (c *Cluster) Stats() Stats {
	stats := Stats{
		NodeID:        c.config.NodeID,
		ConsensusMode: c.consensus,
		NodeCount:     c.nodeList.Count(),
		AliveCount:    c.nodeList.AliveCount(),
		IsHealthy:     c.IsHealthy(),
	}

	if c.consensus == ConsensusRaft {
		stats.IsLeader = c.raft.IsLeader()
		stats.RaftStats = c.raft.Stats()
	} else {
		stats.GossipStats = c.gossip.Stats()
	}

	return stats
}

// handleNodeJoin handles a node join event.
func (c *Cluster) handleNodeJoin(node *Node) {
	c.logger.Infof("Node joined: %s (%s)", node.ID, node.Addr)

	c.handlersMu.RLock()
	defer c.handlersMu.RUnlock()

	for _, handler := range c.handlers {
		handler.OnNodeJoin(node)
	}
}

// handleNodeLeave handles a node leave event.
func (c *Cluster) handleNodeLeave(node *Node) {
	c.logger.Infof("Node left: %s (%s)", node.ID, node.Addr)

	c.handlersMu.RLock()
	defer c.handlersMu.RUnlock()

	for _, handler := range c.handlers {
		handler.OnNodeLeave(node)
	}
}

// handleNodeUpdate handles a node update event.
func (c *Cluster) handleNodeUpdate(node *Node) {
	c.logger.Debugf("Node updated: %s (state: %s)", node.ID, node.State)

	c.handlersMu.RLock()
	defer c.handlersMu.RUnlock()

	for _, handler := range c.handlers {
		handler.OnNodeUpdate(node)
	}
}

// handleCacheInvalid handles cache invalidation from other nodes.
func (c *Cluster) handleCacheInvalid(keys []string) {
	c.logger.Debugf("Received cache invalidation for %d keys", len(keys))
	c.InvalidateCacheLocal(keys)

	c.handlersMu.RLock()
	defer c.handlersMu.RUnlock()

	for _, handler := range c.handlers {
		handler.OnCacheInvalid(keys)
	}
}

// handleZoneUpdate processes zone update messages received via gossip.
// Leader propagates zone changes; followers apply them locally.
func (c *Cluster) handleZoneUpdate(payload ZoneUpdatePayload) {
	c.logger.Debugf("Received zone update for %s (action=%s, serial=%d)", payload.ZoneName, payload.Action, payload.Serial)

	if c.zoneManager == nil {
		c.logger.Warnf("zoneManager not configured, ignoring zone update for %s", payload.ZoneName)
		return
	}

	switch payload.Action {
	case "full", "reload":
		// Full zone transfer — parse and reload zone data
		if payload.RawZone != nil {
			z, err := zone.ParseFile(payload.ZoneName, bytes.NewReader(payload.RawZone))
			if err != nil {
				c.logger.Warnf("Failed to parse zone %s from gossip: %v", payload.ZoneName, err)
				return
			}
			c.zoneManager.LoadZone(z, "")
			c.logger.Infof("Zone %s reloaded via gossip (serial=%d)", payload.ZoneName, payload.Serial)
		}
	case "add":
		// Incremental add — apply record changes
		for _, rec := range payload.Records {
			record := zone.Record{
				Name:  rec.Name,
				TTL:   rec.TTL,
				Class: rec.Class,
				Type:  rec.Type,
				RData: rec.RData,
			}
			if err := c.zoneManager.AddRecord(payload.ZoneName, record); err != nil {
				c.logger.Warnf("Failed to add record %s %s via gossip: %v", rec.Name, rec.Type, err)
			}
		}
	case "delete":
		// Incremental delete — remove records
		for _, key := range payload.DeletedKeys {
			// Extract record name and type from key (format: "name/type")
			parts := splitKey(key)
			if len(parts) == 2 {
				if err := c.zoneManager.DeleteRecord(payload.ZoneName, parts[0], parts[1]); err != nil {
					c.logger.Warnf("Failed to delete record %s via gossip: %v", key, err)
				}
			}
		}
	}
}

// splitKey splits a "name/type" key into name and type components.
func splitKey(key string) []string {
	for i := 0; i < len(key); i++ {
		if key[i] == '/' {
			return []string{key[:i], key[i+1:]}
		}
	}
	return []string{key}
}

// handleConfigSync processes configuration sync messages received via gossip.
// The leader broadcasts config changes; followers apply them locally.
func (c *Cluster) handleConfigSync(payload ConfigSyncPayload) {
	c.logger.Debugf("Received config sync from leader %s (SHA=%s)", payload.NodeID, payload.ConfigSHA256)

	if c.configReloadCallback == nil {
		c.logger.Debugf("configReloadCallback not set, ignoring config sync")
		return
	}

	if err := c.configReloadCallback(payload.ClusterConfig); err != nil {
		c.logger.Warnf("Failed to apply config sync from leader %s: %v", payload.NodeID, err)
		return
	}
	c.logger.Infof("Config sync applied from leader %s (SHA=%s)", payload.NodeID, payload.ConfigSHA256)
}

// cacheSyncLoop processes cache synchronization events.
func (c *Cluster) cacheSyncLoop() {
	defer c.wg.Done()
	for event := range c.cacheSyncChan {
		switch event.Type {
		case "invalidate":
			// In Raft mode, also use gossip for cache invalidation broadcast
			if c.consensus == ConsensusRaft && c.gossip != nil {
				if err := c.gossip.BroadcastCacheInvalidation(event.Keys); err != nil {
					c.logger.Warnf("Failed to broadcast cache invalidation: %v", err)
				}
			} else if c.gossip != nil {
				if err := c.gossip.BroadcastCacheInvalidation(event.Keys); err != nil {
					c.logger.Warnf("Failed to broadcast cache invalidation: %v", err)
				}
			}
		}
	}
}

// Stats contains cluster statistics.
type Stats struct {
	NodeID        string
	ConsensusMode ConsensusMode
	NodeCount     int
	AliveCount    int
	IsHealthy     bool
	IsLeader      bool
	GossipStats   GossipStats       // Valid if consensus = SWIM
	RaftStats     raft.ClusterStats // Valid if consensus = Raft
}
