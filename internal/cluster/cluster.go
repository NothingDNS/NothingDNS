package cluster

import (
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/util"
)

// Cluster manages the DNS server cluster.
type Cluster struct {
	config   Config
	nodeList *NodeList
	gossip   *GossipProtocol
	logger   *util.Logger

	// Cache integration
	cache         *cache.Cache
	cacheSyncChan chan CacheSyncEvent

	// Event handlers
	handlersMu sync.RWMutex
	handlers   []EventHandler

	// Status
	started     bool
	cacheClosed bool
	mu         sync.RWMutex
	wg         sync.WaitGroup
}

// Config configures the cluster.
type Config struct {
	Enabled      bool
	NodeID       string
	BindAddr     string
	BindPort     int
	GossipPort   int
	Region       string
	Zone         string
	Weight       int
	SeedNodes    []string
	CacheSync    bool
	HTTPAddr     string
}

// CacheSyncEvent represents a cache synchronization event.
type CacheSyncEvent struct {
	Type      string   // "invalidate", "update"
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
	OnJoinFunc        func(*Node)
	OnLeaveFunc       func(*Node)
	OnUpdateFunc      func(*Node)
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

	// Get local IP if not specified
	if config.BindAddr == "" {
		ip, err := GetLocalIP()
		if err != nil {
			return nil, fmt.Errorf("getting local IP: %w", err)
		}
		config.BindAddr = ip
	}

	// Create self node
	self := &Node{
		ID:      config.NodeID,
		Addr:    config.BindAddr,
		Port:    config.GossipPort,
		State:   NodeStateAlive,
		Version: 1,
		Meta: NodeMeta{
			Region:   config.Region,
			Zone:     config.Zone,
			Weight:   config.Weight,
			HTTPAddr: config.HTTPAddr,
		},
	}

	nodeList := NewNodeList(self)

	gossipConfig := DefaultGossipConfig()
	gossipConfig.BindAddr = config.BindAddr
	gossipConfig.BindPort = config.GossipPort

	gossip, err := NewGossipProtocol(gossipConfig, nodeList)
	if err != nil {
		return nil, fmt.Errorf("creating gossip protocol: %w", err)
	}

	c := &Cluster{
		config:        config,
		nodeList:      nodeList,
		gossip:        gossip,
		logger:        logger,
		cache:         dnsCache,
		cacheSyncChan: make(chan CacheSyncEvent, 100),
	}

	// Set up gossip callbacks
	gossip.SetCallbacks(
		c.handleNodeJoin,
		c.handleNodeLeave,
		c.handleNodeUpdate,
		c.handleCacheInvalid,
	)

	return c, nil
}

// Start starts the cluster.
func (c *Cluster) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.started {
		return fmt.Errorf("cluster already started")
	}

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

	// Start cache sync processor
	if c.config.CacheSync {
		c.wg.Add(1)
		go c.cacheSyncLoop()
	}

	c.started = true
	c.logger.Infof("Cluster started with node ID %s", c.config.NodeID)
	c.logger.Infof("Cluster listening on %s:%d", c.config.BindAddr, c.config.GossipPort)

	return nil
}

// Stop stops the cluster.
func (c *Cluster) Stop() error {
	c.mu.Lock()
	if !c.started {
		c.mu.Unlock()
		return nil
	}

	if !c.cacheClosed {
		close(c.cacheSyncChan)
		c.cacheClosed = true
	}
	c.mu.Unlock()

	// Wait for cacheSyncLoop to finish before stopping gossip
	c.wg.Wait()

	c.mu.Lock()
	if err := c.gossip.Stop(); err != nil {
		c.logger.Warnf("Error stopping gossip: %v", err)
	}

	c.started = false
	c.cacheClosed = true
	c.logger.Info("Cluster stopped")
	c.mu.Unlock()

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

	// Send through gossip
	return c.gossip.BroadcastCacheInvalidation(keys)
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
	return Stats{
		NodeID:        c.config.NodeID,
		NodeCount:     c.nodeList.Count(),
		AliveCount:    c.nodeList.AliveCount(),
		IsHealthy:     c.IsHealthy(),
		GossipStats:   c.gossip.Stats(),
	}
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

// cacheSyncLoop processes cache synchronization events.
func (c *Cluster) cacheSyncLoop() {
	defer c.wg.Done()
	for event := range c.cacheSyncChan {
		switch event.Type {
		case "invalidate":
			if err := c.gossip.BroadcastCacheInvalidation(event.Keys); err != nil {
				c.logger.Warnf("Failed to broadcast cache invalidation: %v", err)
			}
		}
	}
}

// Stats contains cluster statistics.
type Stats struct {
	NodeID      string
	NodeCount   int
	AliveCount  int
	IsHealthy   bool
	GossipStats GossipStats
}
