// NothingDNS - Cache Manager
// Manages DNS cache and memory monitoring

package main

import (
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/memory"
	"github.com/nothingdns/nothingdns/internal/util"
)

// CacheManager manages the DNS cache and optional memory monitoring.
type CacheManager struct {
	Cache       *cache.Cache
	MemMonitor  *memory.Monitor
	logger     *util.Logger
}

// NewCacheManager creates a new cache manager with the given configuration.
func NewCacheManager(cfg *config.Config, logger *util.Logger) (*CacheManager, error) {
	cacheConfig := cache.Config{
		Capacity:          cfg.Cache.Size,
		MinTTL:            time.Duration(cfg.Cache.MinTTL) * time.Second,
		MaxTTL:            time.Duration(cfg.Cache.MaxTTL) * time.Second,
		DefaultTTL:        time.Duration(cfg.Cache.DefaultTTL) * time.Second,
		NegativeTTL:       time.Duration(cfg.Cache.NegativeTTL) * time.Second,
		PrefetchEnabled:   cfg.Cache.Prefetch,
		PrefetchThreshold: time.Duration(cfg.Cache.PrefetchThreshold) * time.Second,
		ServeStale:        cfg.Cache.ServeStale,
		StaleGrace:        time.Duration(cfg.Cache.StaleGraceSecs) * time.Second,
	}

	dnsCache := cache.New(cacheConfig)
	logger.Infof("Cache initialized with capacity %d", cfg.Cache.Size)

	var memMonitor *memory.Monitor
	if cfg.MemoryLimitMB > 0 {
		memCfg := memory.DefaultConfig()
		memCfg.LimitBytes = uint64(cfg.MemoryLimitMB) * 1024 * 1024
		memMonitor = memory.NewMonitor(memCfg, memory.NewCacheEvictor(dnsCache))
		memMonitor.Start()
		logger.Infof("Memory monitor started: limit=%dMB", cfg.MemoryLimitMB)
	}

	return &CacheManager{
		Cache:      dnsCache,
		MemMonitor: memMonitor,
		logger:     logger,
	}, nil
}

// Stop stops the cache manager and its components.
func (m *CacheManager) Stop() {
	if m.MemMonitor != nil {
		m.MemMonitor.Stop()
	}
}

// SetInvalidateFunc sets the cache invalidation callback for cluster sync.
func (m *CacheManager) SetInvalidateFunc(fn func(string)) {
	if m.Cache != nil {
		m.Cache.SetInvalidateFunc(fn)
	}
}
