// NothingDNS - Transfer Manager
// Manages zone transfers: AXFR, IXFR, NOTIFY, DDNS, and slave zones

package main

import (
	"bytes"
	"fmt"
	"strings"
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
	// AXFRKeys is the AXFR/IXFR server's TSIG key store and SlaveKeys the
	// slave manager's; SIGHUP re-syncs both in place (F583/F584).
	AXFRKeys  *managedKeyStore
	SlaveKeys *managedKeyStore
	// Notifier sends NOTIFY to transfer.also_notify on serial changes;
	// nil when no targets are configured (F547).
	Notifier *zoneNotifier
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
	// Keys secondaries sign AXFR/IXFR requests with. Without them a
	// require_tsig server (mandatory in production with an allow_list)
	// refused every transfer: the AXFR server's key store was always empty.
	// The store always exists (an empty store is what the server uses
	// without one) so a SIGHUP can add, rotate or remove keys (F583).
	xferKeys, err := transferKeysFromConfig(cfg.Transfer)
	if err != nil {
		return nil, err
	}
	mgr.result.AXFRKeys = newManagedKeyStore()
	mgr.result.AXFRKeys.sync(xferKeys)
	axfrOptions = append(axfrOptions, transfer.WithKeyStore(mgr.result.AXFRKeys.store))

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
	// NOTIFY is the trigger for slave zone transfers (RFC 1996), so the
	// same transfer allow list must authorize it. Previously the NOTIFY
	// allow list was never populated in production — only in tests —
	// and since isNOTIFYAllowed fails closed on an empty list, every
	// incoming NOTIFY was REFUSED and slave replication via NOTIFY was
	// silently broken.
	for _, cidr := range cfg.Transfer.AllowList {
		if err := mgr.result.NotifyHandler.AddNotifyAllowed(cidr); err != nil {
			logger.Warnf("NOTIFY: invalid allowlist CIDR %q: %v", cidr, err)
		}
	}
	logger.Infof("NOTIFY handler initialized for %d zones", len(zones))

	// Initialize Dynamic DNS handler. UPDATE authorization (F452): an
	// UPDATE must be TSIG-signed with a transfer.tsig_keys key (from an
	// address in its allowed_cidrs, if set) whose allow_update names the
	// zone. Every key is known (so a valid signature from a key without a
	// grant is answered REFUSED, signed), but only allow_update grants
	// update rights; with no keys every UPDATE is refused.
	var grants int
	mgr.result.DDNSHandler, grants = newDDNSHandlerFromConfig(zones, cfg.Transfer, xferKeys)
	logger.Infof("Dynamic DNS handler initialized for %d zones (%d key/zone update grants)", len(zones), grants)

	// Outgoing NOTIFY (RFC 1996) to transfer.also_notify, optionally signed
	// with the tsig_keys entry named by transfer.notify_key (F547). The
	// notifier always exists so a SIGHUP can add, change or remove targets
	// (F567); with no targets it sends nothing.
	notifySend, err := notifySendFromConfig(cfg.Transfer)
	if err != nil {
		return nil, err
	}
	mgr.result.Notifier = newZoneNotifier(cfg.Transfer.AlsoNotify, notifySend, logger)
	if len(cfg.Transfer.AlsoNotify) > 0 {
		logger.Infof("NOTIFY enabled for %d also_notify target(s)", len(cfg.Transfer.AlsoNotify))
	}

	// Initialize Slave Manager for automatic zone transfers. Each slave
	// zone's TSIG key is loaded into the slave key store first: AddSlaveZone
	// and the transfer paths look the key up by tsig_key_name; previously the
	// store stayed empty, so every keyed slave transfer failed with "TSIG key
	// not found" before contacting the master. A SIGHUP re-syncs the store
	// from the new slave_zones secrets (F584).
	mgr.result.SlaveKeys = newManagedKeyStore()
	mgr.result.SlaveKeys.sync(slaveKeysFromConfig(cfg.SlaveZones, logger))
	mgr.result.SlaveManager = transfer.NewSlaveManager(mgr.result.SlaveKeys.store)
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
	m.result.Notifier.Stop()
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

// notifySendFromConfig builds the NOTIFY send function for a transfer
// section: signed with the tsig_keys entry named by notify_key, if any
// (F547; also used by SIGHUP reload, F567).
func notifySendFromConfig(tc config.TransferConfig) (notifySendFunc, error) {
	if tc.NotifyKey == "" {
		return newTransferNOTIFYSend(nil), nil
	}
	want := transfer.CanonicalTSIGKeyName(tc.NotifyKey)
	for _, kc := range tc.TSIGKeys {
		if transfer.CanonicalTSIGKeyName(kc.Name) != want {
			continue
		}
		key, err := transfer.ParseTSIGKey(kc.Name, strings.ToLower(strings.TrimSuffix(kc.Algorithm, ".")), kc.Secret)
		if err != nil {
			return nil, fmt.Errorf("transfer.tsig_keys %q: %w", kc.Name, err)
		}
		return newTransferNOTIFYSend(key), nil
	}
	return nil, fmt.Errorf("transfer.notify_key %q does not name a transfer.tsig_keys entry", tc.NotifyKey)
}

// transferKeysFromConfig parses transfer.tsig_keys (with their
// allowed_cidrs). Used at startup and by SIGHUP reload (F583).
func transferKeysFromConfig(tc config.TransferConfig) ([]*transfer.TSIGKey, error) {
	keys := make([]*transfer.TSIGKey, 0, len(tc.TSIGKeys))
	for _, kc := range tc.TSIGKeys {
		key, err := transfer.ParseTSIGKey(kc.Name, strings.ToLower(strings.TrimSuffix(kc.Algorithm, ".")), kc.Secret)
		if err != nil {
			return nil, fmt.Errorf("transfer.tsig_keys %q: %w", kc.Name, err)
		}
		key.AllowedCIDRs = kc.AllowedCIDRs
		keys = append(keys, key)
	}
	return keys, nil
}

// newDDNSHandlerFromConfig builds the Dynamic DNS handler for zones. UPDATE
// authorization (F452): an UPDATE must be TSIG-signed with a
// transfer.tsig_keys key (from an address in its allowed_cidrs, if set)
// whose allow_update names the zone. Every key is known (so a valid
// signature from a key without a grant is answered REFUSED, signed), but
// only allow_update grants update rights; with no keys every UPDATE is
// refused. The handler cannot revoke a grant, so SIGHUP builds a new one
// (F583). It returns the number of key/zone grants.
func newDDNSHandlerFromConfig(zones map[string]*zone.Zone, tc config.TransferConfig, keys []*transfer.TSIGKey) (*transfer.DynamicDNSHandler, int) {
	h := transfer.NewDynamicDNSHandler(zones)
	store := transfer.NewKeyStore()
	for _, k := range keys {
		store.AddKey(k)
	}
	grants := 0
	for _, kc := range tc.TSIGKeys {
		for _, zoneName := range kc.AllowUpdate {
			h.AllowKeyUpdate(kc.Name, zoneName)
			grants++
		}
	}
	h.SetKeyStore(store)
	return h, grants
}

// slaveKeysFromConfig decodes each keyed slave zone's tsig_key_name /
// tsig_secret (hmac-sha256). An invalid secret is skipped with a warning; a
// name configured with different secrets keeps the first.
func slaveKeysFromConfig(slaves []config.SlaveZoneConfig, logger *util.Logger) []*transfer.TSIGKey {
	var keys []*transfer.TSIGKey
	seen := make(map[string]*transfer.TSIGKey)
	for _, sc := range slaves {
		if sc.TSIGKeyName == "" {
			continue
		}
		key, err := transfer.ParseTSIGKey(sc.TSIGKeyName, transfer.HmacSHA256, sc.TSIGSecret)
		if err != nil {
			if logger != nil {
				logger.Warnf("slave zone %s: invalid tsig_secret: %v", sc.ZoneName, err)
			}
			continue
		}
		if prev, ok := seen[key.Name]; ok {
			if !bytes.Equal(prev.Secret, key.Secret) && logger != nil {
				logger.Warnf("slave zone %s: TSIG key %s is configured with different secrets; using the first", sc.ZoneName, key.Name)
			}
			continue
		}
		seen[key.Name] = key
		keys = append(keys, key)
	}
	return keys
}

// managedKeyStore is a transfer.KeyStore whose contents this package owns:
// it remembers the names it loaded so a reload can remove the ones the new
// config dropped (KeyStore cannot list its keys). Not safe for concurrent
// sync calls; reloads are serialized by reloadableState.reloadMu.
type managedKeyStore struct {
	store *transfer.KeyStore
	names map[string]bool
}

func newManagedKeyStore() *managedKeyStore {
	return &managedKeyStore{store: transfer.NewKeyStore(), names: make(map[string]bool)}
}

// sync makes the store hold exactly keys: every key is added (replacing a
// same-named one) and every previously loaded name not in keys is removed.
// Each change is atomic per key; request handlers that must see the whole
// set change at once hold integratedHandler.xferKeysMu, which the reload
// holds exclusively around sync (F583).
func (m *managedKeyStore) sync(keys []*transfer.TSIGKey) {
	if m == nil {
		return
	}
	want := make(map[string]bool, len(keys))
	for _, k := range keys {
		want[transfer.CanonicalTSIGKeyName(k.Name)] = true
	}
	for name := range m.names {
		if !want[name] {
			m.store.RemoveKey(name)
		}
	}
	for _, k := range keys {
		m.store.AddKey(k)
	}
	m.names = want
}
