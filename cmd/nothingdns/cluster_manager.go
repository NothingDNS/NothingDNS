// NothingDNS - Cluster Manager
// Manages gossip-based clustering

package main

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/cluster"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/metrics"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// ClusterManager manages gossip-based clustering with cache sync.
type ClusterManager struct {
	Cluster  *cluster.Cluster
	logger   *util.Logger
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewClusterManager creates a new cluster manager with the given configuration.
func NewClusterManager(cfg *config.Config, logger *util.Logger, dnsCache *cache.Cache, metricsCollector *metrics.MetricsCollector, zoneMgr *zone.Manager) (*ClusterManager, error) {
	mgr := &ClusterManager{
		logger: logger,
		stopCh: make(chan struct{}),
	}

	if !cfg.Cluster.Enabled {
		return mgr, nil
	}

	// Build optional Raft RPC transport (m)TLS from cluster.rpc.*. Returns nil
	// when rpc.enabled is false. This is layered on top of the mandatory
	// message-level AEAD (cluster.encryption_key), not a replacement for it.
	rpcTLS, err := cfg.Cluster.RPC.NewTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("build cluster RPC TLS config: %w", err)
	}

	clusterConfig := cluster.Config{
		Enabled:               cfg.Cluster.Enabled,
		NodeID:                cfg.Cluster.NodeID,
		BindAddr:              cfg.Cluster.BindAddr,
		GossipPort:            cfg.Cluster.GossipPort,
		Region:                cfg.Cluster.Region,
		Zone:                  cfg.Cluster.Zone,
		Weight:                cfg.Cluster.Weight,
		SeedNodes:             cfg.Cluster.SeedNodes,
		CacheSync:             cfg.Cluster.CacheSync,
		HTTPAddr:              cfg.Server.HTTP.Bind,
		DNSAddr:               clusterDNSAdvertiseAddr(cfg),
		EncryptionKey:         cfg.Cluster.EncryptionKey,
		SnapshotEncryptionKey: cfg.Cluster.SnapshotEncryptionKey,
		AllowInsecureCluster:  cfg.Cluster.AllowInsecureCluster,
		ZoneManager:           zoneMgr,
		ConsensusMode:         cluster.ConsensusMode(cfg.Cluster.ConsensusMode),
		DataDir:               cfg.Cluster.DataDir,
		Peers:                 mapClusterPeers(cfg.Cluster.Peers),
		RPCTLS:                rpcTLS,
	}

	if clusterConfig.DNSAddr == "" && clusterConfig.ConsensusMode == cluster.ConsensusRaft {
		logger.Warnf("cluster: no DNS address to advertise (wildcard DNS bind and no cluster.dns_advertise_addr); while this node leads, followers answer forwarded RFC 2136 UPDATEs with SERVFAIL")
	} else if clusterConfig.DNSAddr != "" {
		logger.Infof("cluster: advertising DNS address %s", clusterConfig.DNSAddr)
	}

	mgr.Cluster, err = cluster.New(clusterConfig, logger, dnsCache)
	if err != nil {
		return nil, fmt.Errorf("initialize cluster: %w", err)
	}

	if err := mgr.Cluster.Start(); err != nil {
		mgr.Cluster = nil
		return nil, fmt.Errorf("start cluster: %w", err)
	}

	logger.Infof("Cluster initialized with node ID %s", mgr.Cluster.GetNodeID())
	logger.Infof("Cluster has %d nodes", mgr.Cluster.GetNodeCount())

	// Cache sync callbacks are registered in main.go after the cache
	// manager is fully wired; registering them here would be overwritten.

	// Start cluster metrics updater
	go mgr.metricsUpdater(metricsCollector, 30*time.Second)

	return mgr, nil
}

// clusterDNSAdvertiseAddr is the DNS TCP host:port this node advertises to
// the cluster (F562): cluster.dns_advertise_addr when set, else the first
// concrete (non-wildcard) DNS TCP listen address, else "" (none).
func clusterDNSAdvertiseAddr(cfg *config.Config) string {
	if cfg.Cluster.DNSAdvertiseAddr != "" {
		return cfg.Cluster.DNSAdvertiseAddr
	}
	for _, a := range dnsListenAddrs(cfg.Server.TCPBind, cfg.Server.Bind, cfg.Server.Port) {
		host, port, err := net.SplitHostPort(a)
		if err != nil || isWildcardHost(host) || port == "0" {
			continue
		}
		return a
	}
	return ""
}

// mapClusterPeers converts config peer entries to cluster.PeerConfig.
func mapClusterPeers(peers []config.ClusterPeerConfig) []cluster.PeerConfig {
	if len(peers) == 0 {
		return nil
	}
	out := make([]cluster.PeerConfig, 0, len(peers))
	for _, p := range peers {
		out = append(out, cluster.PeerConfig{NodeID: p.NodeID, Addr: p.Addr})
	}
	return out
}

// metricsUpdater periodically updates cluster metrics.
func (m *ClusterManager) metricsUpdater(metricsCollector *metrics.MetricsCollector, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if m.Cluster != nil && metricsCollector != nil {
				stats := m.Cluster.Stats()
				metricsCollector.SetClusterMetrics(
					stats.NodeCount,
					stats.AliveCount,
					stats.IsHealthy,
					stats.GossipStats.MessagesSent,
					stats.GossipStats.MessagesReceived,
				)
			}
		case <-m.stopCh:
			return
		}
	}
}

// Stop stops the cluster manager.
func (m *ClusterManager) Stop() {
	if m == nil {
		return
	}
	m.stopOnce.Do(func() {
		close(m.stopCh)
		if m.Cluster != nil {
			logManagerStopError(m.logger, "cluster", m.Cluster.Stop())
		}
	})
}
