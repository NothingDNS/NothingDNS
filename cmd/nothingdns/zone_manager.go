// NothingDNS - Zone Manager
// Manages DNS zones, zone files, and DNSSEC signing

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/storage"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// ZoneManagerResult holds the results of zone initialization.
type ZoneManagerResult struct {
	Manager       *zone.Manager
	Zones         map[string]*zone.Zone
	ZoneFiles     map[string]string // origin -> file path
	Signers       map[string]*dnssec.Signer
	KVPersistence *zone.KVPersistence
	KVStore       *storage.KVStore
}

// ZoneManager manages DNS zones, zone files, and DNSSEC signing.
type ZoneManager struct {
	result ZoneManagerResult
	logger *util.Logger
}

// NewZoneManager creates a new zone manager with the given configuration.
func NewZoneManager(cfg *config.Config, logger *util.Logger) (*ZoneManager, error) {
	mgr := &ZoneManager{
		result: ZoneManagerResult{
			Zones:     make(map[string]*zone.Zone),
			ZoneFiles: make(map[string]string),
			Signers:   make(map[string]*dnssec.Signer),
		},
		logger: logger,
	}

	zoneManager := zone.NewManager()
	// Wire the logger so best-effort persistence failures (zone files on
	// disk, KV store via the mutation hook) are observable in production.
	zoneManager.SetLogger(logger)
	if cfg.ZoneDir != "" {
		zoneManager.SetZoneDir(cfg.ZoneDir)
		logger.Infof("Zone file persistence enabled: %s", cfg.ZoneDir)
	}

	// Enable ZONEMD computation if configured
	if cfg.ZONEMD {
		zoneManager.SetZONEMDEnabled(true)
		logger.Info("ZONEMD zone message digests enabled (RFC 8976)")
	}

	// Load zone files in parallel for faster startup
	type zoneResult struct {
		zone     *zone.Zone
		zoneFile string
		err      error
	}

	zoneFiles, err := discoverStartupZoneFiles(cfg)
	if err != nil {
		return nil, err
	}
	zoneChans := make([]chan zoneResult, len(zoneFiles))
	for i, zoneFile := range zoneFiles {
		zoneChans[i] = make(chan zoneResult, 1)
		go func(zf string, ch chan zoneResult) {
			z, err := loadZoneFile(zf)
			ch <- zoneResult{z, zf, err}
		}(zoneFile, zoneChans[i])
	}

	// Drain all goroutines and collect results first. This ensures we detect every
	// parse error before committing any zone to the manager — all-or-nothing semantics.
	var results []zoneResult
	for _, ch := range zoneChans {
		results = append(results, <-ch)
	}

	// Check all results for errors before committing anything.
	for _, result := range results {
		if result.err != nil {
			return nil, fmt.Errorf("loading zone file %s: %w", result.zoneFile, result.err)
		}
	}

	// All files loaded successfully — now commit all zones atomically.
	for _, result := range results {
		if result.zone == nil {
			continue
		}
		// Results are drained in discovery order (configured zones first, then zone_dir
		// scan). A second file with the same $ORIGIN — e.g. a stray backup copy in
		// zone_dir — must not silently replace the zone that was loaded first.
		if existingFile, ok := mgr.result.ZoneFiles[result.zone.Origin]; ok {
			logger.Warnf("Skipping zone file %s: zone %s already loaded from %s",
				result.zoneFile, result.zone.Origin, existingFile)
			continue
		}
		mgr.result.Zones[result.zone.Origin] = result.zone
		mgr.result.ZoneFiles[result.zone.Origin] = result.zoneFile
		zoneManager.LoadZone(result.zone, result.zoneFile)
		logger.Infof("Loaded zone %s with %d records", result.zone.Origin, len(result.zone.Records))
	}

	// Initialize zone signers if DNSSEC signing is enabled
	if cfg.DNSSEC.Enabled && cfg.DNSSEC.Signing.Enabled {
		for origin, z := range mgr.result.Zones {
			signer, err := loadZoneSigner(z, cfg.DNSSEC.Signing)
			if err != nil {
				return nil, fmt.Errorf("loading zone signer for %s: %w", origin, err)
			}
			if signer != nil {
				mgr.result.Signers[origin] = signer
				logger.Infof("Zone signer loaded for %s (%d keys)", origin, len(signer.GetKeys()))
			}
		}
	}

	mgr.result.Manager = zoneManager

	// Initialize the embedded persistent zone database.
	dbDataDir := persistentZoneDBDir(cfg)
	// L-6: pass the optional at-rest AEAD key. config.Validate has
	// already enforced 32-byte hex + key-separation, so a decode
	// failure here is either a bug or a Validate-bypass; either way,
	// L-N11 says fail-fast — silently dropping to plaintext while
	// the operator thinks encryption is on is the worst outcome
	// (matches L-4's fail-fast pattern for token persistence).
	var aeadKey []byte
	if hexKey := cfg.Storage.EncryptionKey; hexKey != "" {
		decoded, decErr := decodeHex32(hexKey)
		if decErr != nil {
			return nil, fmt.Errorf("storage.encryption_key invalid (%w); refusing to start in plaintext mode (L-N11)", decErr)
		}
		aeadKey = decoded
	}
	kvStore, err := storage.OpenKVStoreEncrypted(dbDataDir, nil, aeadKey)
	if err != nil {
		if cfg.Storage.DataDir != "" || cfg.Storage.EncryptionKey != "" {
			return nil, fmt.Errorf("initializing persistent zone database at %s: %w "+
				"(if the file is AES-GCM encrypted, restore storage.encryption_key — often also in /etc/nothingdns/credentials as storage_encryption_key — "+
				"or move data.db aside to start fresh; zone files still load)",
				filepath.Join(dbDataDir, storage.DataFile), err)
		}
		logger.Warnf("Failed to initialize persistent zone database: %v", err)
	} else {
		mgr.result.KVStore = kvStore
		mgr.result.KVPersistence = zone.NewKVPersistence(zoneManager, kvStore)
		mgr.result.KVPersistence.Enable()
		synchronizeKVZones(mgr, zoneManager, mgr.result.KVPersistence, logger)
		if aeadKey != nil {
			logger.Infof("Persistent zone database initialized at %s (AES-256-GCM at rest)", filepath.Join(dbDataDir, storage.DataFile))
		} else {
			logger.Infof("Persistent zone database initialized at %s", filepath.Join(dbDataDir, storage.DataFile))
		}
	}

	return mgr, nil
}

func persistentZoneDBDir(cfg *config.Config) string {
	if cfg.Storage.DataDir != "" {
		return cfg.Storage.DataDir
	}
	if cfg.ZoneDir != "" {
		return cfg.ZoneDir
	}
	return "."
}

func synchronizeKVZones(mgr *ZoneManager, zoneManager *zone.Manager, kvPersistence *zone.KVPersistence, logger *util.Logger) {
	kvZones, err := kvPersistence.ListKVZones()
	if err != nil {
		logger.Warnf("Failed to list persistent database zones: %v", err)
	} else {
		for _, origin := range kvZones {
			if _, ok := zoneManager.Get(origin); ok {
				continue
			}
			z, found, err := kvPersistence.LoadFromKV(origin)
			if err != nil {
				logger.Warnf("Failed to load persistent database zone %s: %v", origin, err)
				continue
			}
			if !found || z == nil {
				continue
			}
			mgr.result.Zones[z.Origin] = z
			mgr.result.ZoneFiles[z.Origin] = ""
			zoneManager.LoadZone(z, "")

			// Compute ZONEMD for KV-loaded zones, mirroring Manager.Load.
			// ZoneMeta does not persist ZONEMD (it is recomputed), so a cold
			// restart of an API-created zone would lose its ZONEMD without this.
			if zoneManager.IsZONEMDEnabled() {
				if zonemd, err := zone.ComputeZoneMD(z, zone.ZONEMDSHA256); err != nil {
					logger.Warnf("zone: failed to compute ZONEMD for %s: %v", z.Origin, err)
				} else {
					z.ZONEMD = zonemd
				}
			}

			logger.Infof("Loaded zone %s from persistent database with %d records", z.Origin, len(z.Records))
		}
	}

	// Deliberately NO PersistAll() here: file-backed (config) zones must not
	// be mirrored into the KV database. Their durable source of truth is the
	// zone file; copying them into the KV store would resurrect them at the
	// next boot even after the operator removed them from the config — the
	// KV store is the durability layer for API-created zones only, and those
	// are persisted explicitly at mutation time by the API handlers.
}

func discoverStartupZoneFiles(cfg *config.Config) ([]string, error) {
	zoneFiles := make([]string, 0, len(cfg.Zones))
	seen := make(map[string]struct{}, len(cfg.Zones))
	for _, zoneFile := range cfg.Zones {
		addStartupZoneFile(&zoneFiles, seen, zoneFile)
	}

	if cfg.ZoneDir == "" {
		return zoneFiles, nil
	}

	entries, err := os.ReadDir(cfg.ZoneDir)
	if err != nil {
		return nil, fmt.Errorf("scanning zone_dir %s: %w", cfg.ZoneDir, err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".zone" {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		addStartupZoneFile(&zoneFiles, seen, filepath.Join(cfg.ZoneDir, name))
	}

	return zoneFiles, nil
}

func addStartupZoneFile(zoneFiles *[]string, seen map[string]struct{}, zoneFile string) {
	key := filepath.Clean(zoneFile)
	if abs, err := filepath.Abs(key); err == nil {
		key = abs
	}
	if _, ok := seen[key]; ok {
		return
	}
	seen[key] = struct{}{}
	*zoneFiles = append(*zoneFiles, zoneFile)
}

// Zones returns the loaded zones.
func (m *ZoneManager) Zones() map[string]*zone.Zone {
	return m.result.Zones
}

// ZoneFiles returns the zone file paths.
func (m *ZoneManager) ZoneFiles() map[string]string {
	return m.result.ZoneFiles
}

// Signers returns the DNSSEC signers.
func (m *ZoneManager) Signers() map[string]*dnssec.Signer {
	return m.result.Signers
}

// Manager returns the zone manager.
func (m *ZoneManager) Manager() *zone.Manager {
	return m.result.Manager
}

// KVPersistence returns the KV persistence layer.
func (m *ZoneManager) KVPersistence() *zone.KVPersistence {
	return m.result.KVPersistence
}
