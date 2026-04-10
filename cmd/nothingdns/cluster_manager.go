// NothingDNS - Cluster Manager
// Manages gossip-based clustering

package main

import (
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
	Cluster *cluster.Cluster
	logger  *util.Logger
	stopCh  chan struct{}
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

	clusterConfig := cluster.Config{
		Enabled:       cfg.Cluster.Enabled,
		NodeID:        cfg.Cluster.NodeID,
		BindAddr:      cfg.Cluster.BindAddr,
		GossipPort:    cfg.Cluster.GossipPort,
		Region:        cfg.Cluster.Region,
		Zone:          cfg.Cluster.Zone,
		Weight:        cfg.Cluster.Weight,
		SeedNodes:     cfg.Cluster.SeedNodes,
		CacheSync:     cfg.Cluster.CacheSync,
		HTTPAddr:      cfg.Server.HTTP.Bind,
		EncryptionKey: cfg.Cluster.EncryptionKey,
		ZoneManager:   zoneMgr,
	}

	var err error
	mgr.Cluster, err = cluster.New(clusterConfig, logger, dnsCache)
	if err != nil {
		logger.Warnf("Failed to initialize cluster: %v", err)
		return mgr, nil
	}

	if err := mgr.Cluster.Start(); err != nil {
		logger.Warnf("Failed to start cluster: %v", err)
		mgr.Cluster = nil
		return mgr, nil
	}

	logger.Infof("Cluster initialized with node ID %s", mgr.Cluster.GetNodeID())
	logger.Infof("Cluster has %d nodes", mgr.Cluster.GetNodeCount())

	// Set up cache invalidation callback for cluster sync
	if cfg.Cluster.CacheSync {
		dnsCache.SetInvalidateFunc(func(key string) {
			if err := mgr.Cluster.InvalidateCache([]string{key}); err != nil {
				logger.Debugf("Failed to broadcast cache invalidation: %v", err)
			}
		})
		logger.Info("Cache synchronization enabled across cluster")
	}

	// Start cluster metrics updater
	go mgr.metricsUpdater(metricsCollector)

	return mgr, nil
}

// metricsUpdater periodically updates cluster metrics.
func (m *ClusterManager) metricsUpdater(metricsCollector *metrics.MetricsCollector) {
	ticker := time.NewTicker(30 * time.Second)
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
	close(m.stopCh)
	if m.Cluster != nil {
		m.Cluster.Stop()
	}
}
