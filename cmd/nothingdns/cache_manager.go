// NothingDNS - Cache Manager
// Manages DNS cache and memory monitoring

package main

import (
	"encoding/gob"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/memory"
	"github.com/nothingdns/nothingdns/internal/storage"
	"github.com/nothingdns/nothingdns/internal/util"
)

const cachePersistFile = "cache.json"

// CacheManager manages the DNS cache and optional memory monitoring.
type CacheManager struct {
	Cache       *cache.Cache
	MemMonitor  *memory.Monitor
	logger      *util.Logger
	persistPath string
	stopCh     chan struct{}
	wg         sync.WaitGroup
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

	m := &CacheManager{
		Cache:      dnsCache,
		MemMonitor: memMonitor,
		logger:     logger,
		stopCh:     make(chan struct{}),
	}

	// Determine persistence path
	persistDir := cfg.ZoneDir
	if persistDir == "" {
		persistDir = "."
	}
	m.persistPath = filepath.Join(persistDir, cachePersistFile)

	return m, nil
}

// Stop stops the cache manager and its components.
func (m *CacheManager) Stop() {
	if m.MemMonitor != nil {
		m.MemMonitor.Stop()
	}
	close(m.stopCh)
	m.wg.Wait()
	// Final save on shutdown
	if m.persistPath != "" {
		m.saveToFile()
	}
}

// SetInvalidateFunc sets the cache invalidation callback for cluster sync.
func (m *CacheManager) SetInvalidateFunc(fn func(string)) {
	if m.Cache != nil {
		m.Cache.SetInvalidateFunc(fn)
	}
}

// LoadCache loads the cache from persistent storage.
// Called during startup to warm the cache.
func (m *CacheManager) LoadCache() {
	if m.persistPath == "" {
		return
	}

	data, err := os.ReadFile(m.persistPath)
	if err != nil {
		// File doesn't exist yet — no cached data
		return
	}

	var entries []cache.CacheEntryJSON
	if err := json.Unmarshal(data, &entries); err != nil {
		m.logger.Warnf("Failed to parse cache persistence file: %v", err)
		return
	}

	restored := m.Cache.Load(entries)
	if restored > 0 {
		m.logger.Infof("Cache restored %d entries from persistent storage", restored)
	}
}

// StartPersistence starts a goroutine that periodically saves the cache.
// interval specifies how often to save (default 5 minutes).
func (m *CacheManager) StartPersistence(interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-m.stopCh:
				return
			case <-ticker.C:
				m.saveToFile()
			}
		}
	}()
}

// saveToFile saves the cache to a JSON file.
func (m *CacheManager) saveToFile() {
	if m.persistPath == "" || m.Cache == nil {
		return
	}

	entries := m.Cache.Save()
	if len(entries) == 0 {
		return
	}

	data, err := json.Marshal(entries)
	if err != nil {
		m.logger.Warnf("Failed to serialize cache for persistence: %v", err)
		return
	}

	tmpPath := m.persistPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		m.logger.Warnf("Failed to write cache persistence file: %v", err)
		return
	}

	// Atomic rename
	if err := os.Rename(tmpPath, m.persistPath); err != nil {
		m.logger.Warnf("Failed to atomically rename cache persistence file: %v", err)
		return
	}
}

// SaveCacheToKV saves the cache to a KVStore bucket (alternative method).
func (m *CacheManager) SaveCacheToKV(kv *storage.KVStore) error {
	if kv == nil || m.Cache == nil {
		return nil
	}

	entries := m.Cache.Save()
	if len(entries) == 0 {
		return nil
	}

	return kv.Update(func(tx *storage.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("cache"))
		if err != nil {
			return err
		}

		data, err := json.Marshal(entries)
		if err != nil {
			return err
		}

		return bucket.Put([]byte("cache_data"), data)
	})
}

// LoadCacheFromKV loads the cache from a KVStore bucket (alternative method).
func (m *CacheManager) LoadCacheFromKV(kv *storage.KVStore) {
	if kv == nil || m.Cache == nil {
		return
	}

	kv.View(func(tx *storage.Tx) error {
		bucket := tx.Bucket([]byte("cache"))
		if bucket == nil {
			return nil
		}

		data := bucket.Get([]byte("cache_data"))
		if data == nil {
			return nil
		}

		var entries []cache.CacheEntryJSON
		if err := json.Unmarshal(data, &entries); err != nil {
			m.logger.Warnf("Failed to parse cache from KV store: %v", err)
			return nil
		}

		restored := m.Cache.Load(entries)
		if restored > 0 {
			m.logger.Infof("Cache restored %d entries from KV store", restored)
		}
		return nil
	})
}

func init() {
	// Register types for gob serialization
	gob.Register(cache.CacheEntryJSON{})
}
