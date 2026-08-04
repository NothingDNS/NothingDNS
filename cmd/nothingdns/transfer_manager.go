// NothingDNS - Transfer Manager
// Manages zone transfers: AXFR, IXFR, NOTIFY, DDNS, and slave zones

package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// TransferManagerResult holds the transfer servers and handlers.
type TransferManagerResult struct {
	AXFRServer    *transfer.AXFRServer
	IXFRServer    *transfer.IXFRServer
	NotifyHandler *transfer.NOTIFYSlaveHandler
	DDNSHandler   *transfer.DynamicDNSHandler
	SlaveManager  *transfer.SlaveManager
	JournalStore  *transfer.KVJournalStore
}

// TransferManager manages zone transfers and slave zone handling.
type TransferManager struct {
	result  TransferManagerResult
	logger  *util.Logger
	zonesMu *sync.RWMutex
}

// NewTransferManager creates a new transfer manager with the given configuration.
func NewTransferManager(cfg *config.Config, zones map[string]*zone.Zone, zonesMu *sync.RWMutex, logger *util.Logger) (*TransferManager, error) {
	mgr := &TransferManager{
		logger:  logger,
		zonesMu: zonesMu,
	}

	axfrOptions := []transfer.AXFRServerOption{transfer.WithAllowList(cfg.Transfer.AllowList)}
	if cfg.Transfer.RequireTSIG {
		axfrOptions = append(axfrOptions, transfer.WithRequireTSIG())
	}

	// Initialize AXFR server for zone transfers
	mgr.result.AXFRServer = transfer.NewAXFRServer(zones, axfrOptions...)
	logger.Infof("AXFR server initialized with %d zones", len(zones))

	// Initialize IXFR server for incremental zone transfers
	mgr.result.IXFRServer = transfer.NewIXFRServer(mgr.result.AXFRServer)
	logger.Infof("IXFR server initialized for incremental transfers")

	// Wire KV journal store for persistent IXFR journals. Prefer the same
	// explicit data directory used by the embedded zone DB so production does
	// not depend on the daemon's working directory when zone_dir is unset.
	// If transfer.journal_dir is configured, use it directly.
	journalDataDir := cfg.Transfer.JournalDir
	if journalDataDir == "" {
		journalDataDir = cfg.Storage.DataDir
	}
	if journalDataDir == "" {
		journalDataDir = cfg.ZoneDir
	}
	if journalDataDir == "" {
		journalDataDir = "."
	}
	journalStore, err := transfer.OpenKVJournalStore(journalDataDir)
	if err != nil {
		return nil, fmt.Errorf("initializing IXFR journal store: %w", err)
	}
	mgr.result.JournalStore = journalStore
	mgr.result.IXFRServer.SetJournalStore(mgr.result.JournalStore)
	logger.Infof("IXFR journal store initialized at %s", journalDataDir)

	// Initialize NOTIFY handler for slave servers
	mgr.result.NotifyHandler = transfer.NewNOTIFYSlaveHandler(zones)
	logger.Infof("NOTIFY handler initialized for %d zones", len(zones))

	// Initialize Dynamic DNS handler
	mgr.result.DDNSHandler = transfer.NewDynamicDNSHandler(zones)
	logger.Infof("Dynamic DNS handler initialized for %d zones", len(zones))

	// Initialize Slave Manager for automatic zone transfers
	keyStore := transfer.NewKeyStore()
	mgr.result.SlaveManager = transfer.NewSlaveManager(keyStore)
	logger.Info("Slave manager initialized for automatic zone transfers")

	// Configure slave zones from config if available
	for _, slaveConfig := range cfg.SlaveZones {
		transferConfig := transfer.SlaveZoneConfig{
			ZoneName:      slaveConfig.ZoneName,
			Masters:       slaveConfig.Masters,
			TransferType:  slaveConfig.TransferType,
			TSIGKeyName:   slaveConfig.TSIGKeyName,
			TSIGSecret:    slaveConfig.TSIGSecret,
			Timeout:       parseDurationOrDefault(slaveConfig.Timeout, 30*time.Second),
			RetryInterval: parseDurationOrDefault(slaveConfig.RetryInterval, 5*time.Minute),
			MaxRetries:    slaveConfig.MaxRetries,
		}

		if err := mgr.result.SlaveManager.AddSlaveZone(transferConfig); err != nil {
			logger.Warnf("Failed to add slave zone %s: %v", slaveConfig.ZoneName, err)
		} else {
			logger.Infof("Added slave zone %s (masters: %v)", slaveConfig.ZoneName, slaveConfig.Masters)
		}
	}

	// Start the slave manager
	mgr.result.SlaveManager.Start()
	logger.Info("Slave manager started")

	return mgr, nil
}

// SetZonesMu shares the zones mutex between handlers.
func (m *TransferManager) SetZonesMu(zonesMu *sync.RWMutex) {
	if m.result.AXFRServer != nil {
		m.result.AXFRServer.SetZonesMu(zonesMu)
	}
	if m.result.NotifyHandler != nil {
		m.result.NotifyHandler.SetZonesMu(zonesMu)
	}
	if m.result.DDNSHandler != nil {
		m.result.DDNSHandler.SetZonesMu(zonesMu)
	}
	m.zonesMu = zonesMu
}

// Stop stops the transfer manager and its components.
func (m *TransferManager) Stop() {
	if m.result.SlaveManager != nil {
		m.result.SlaveManager.Stop()
	}
	if m.result.NotifyHandler != nil {
		m.result.NotifyHandler.Close()
	}
	if m.result.DDNSHandler != nil {
		m.result.DDNSHandler.Close()
	}
}

// Result returns the transfer manager results.
func (m *TransferManager) Result() *TransferManagerResult {
	return &m.result
}
