package transfer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// SlaveZoneConfig represents configuration for a slave zone.
// Slave zones are replicated from master servers via zone transfers.
type SlaveZoneConfig struct {
	// Zone name (e.g., "example.com.")
	ZoneName string

	// Master servers to transfer from (host:port format)
	// Multiple masters can be specified for redundancy
	Masters []string

	// Transfer type: "ixfr" (incremental) or "axfr" (full)
	// Default is "ixfr" with fallback to "axfr"
	TransferType string

	// TSIG key name for authenticated transfers (optional)
	TSIGKeyName string

	// TSIG secret for authenticated transfers (optional)
	TSIGSecret string

	// Transfer timeout
	Timeout time.Duration

	// Retry interval on transfer failure while the zone has no transferred
	// SOA yet; once a SOA is held its RETRY field governs (F412).
	RetryInterval time.Duration

	// Maximum consecutive retry attempts (0 = unlimited). For a zone that
	// has never loaded, retries stop after this many failures; for a loaded
	// zone the next attempt is deferred to the SOA REFRESH interval instead.
	MaxRetries int
}

// Validate checks the slave zone configuration.
func (c *SlaveZoneConfig) Validate() error {
	if c.ZoneName == "" {
		return fmt.Errorf("zone name cannot be empty")
	}

	// Ensure zone name ends with dot
	if !strings.HasSuffix(c.ZoneName, ".") {
		c.ZoneName += "."
	}

	if len(c.Masters) == 0 {
		return fmt.Errorf("at least one master server must be specified")
	}

	for _, master := range c.Masters {
		if _, err := net.ResolveTCPAddr("tcp", master); err != nil {
			return fmt.Errorf("invalid master address %s: %w", master, err)
		}
	}

	if c.TransferType == "" {
		c.TransferType = "ixfr"
	}

	if c.TransferType != "ixfr" && c.TransferType != "axfr" {
		return fmt.Errorf("invalid transfer type: %s (must be 'ixfr' or 'axfr')", c.TransferType)
	}

	if c.Timeout <= 0 {
		c.Timeout = 30 * time.Second
	}

	if c.RetryInterval <= 0 {
		c.RetryInterval = 5 * time.Minute
	}

	return nil
}

// SlaveZone represents a slave zone being replicated.
type SlaveZone struct {
	Config       SlaveZoneConfig
	Zone         *zone.Zone
	LastSerial   uint32
	LastTransfer time.Time
	// retries counts consecutive failures since the last successful
	// transfer; reset to zero on success. Used by scheduleRetry to
	// honor SlaveZoneConfig.MaxRetries — when MaxRetries > 0 and we
	// hit it, retries stop. Previously MaxRetries was declared on
	// SlaveZoneConfig but read nowhere, so a permanently-unreachable
	// master would receive a steady hammer of zone-transfer attempts
	// for the lifetime of the process.
	retries int
	// transferring is true while one goroutine owns this zone's transfer;
	// refreshPending records a NOTIFY/retry that arrived meanwhile, so it
	// is served by one follow-up run instead of a concurrent transfer.
	// retryScheduled is true while a scheduleRetry wait is pending, so
	// failures never fork a second retry chain (F204).
	transferring   bool
	refreshPending bool
	retryScheduled bool
	// SOA timer state (RFC 1035 §4.3.5, F412). stopTimer cancels the zone's
	// single pending refresh-or-retry timer (retryScheduled says which);
	// timerGen invalidates a timer callback that fired after it was replaced
	// or cancelled. expireAt ends the EXPIRE window that began at the last
	// successful refresh (zero: no window known, never expires); now is the
	// manager's clock.
	stopTimer func() bool
	timerGen  uint64
	expireAt  time.Time
	now       func() time.Time
	mu        sync.RWMutex
}

// claimTransfer makes the caller the zone's single transfer owner. If a
// transfer is already running it records a pending refresh and returns false.
func (sz *SlaveZone) claimTransfer() bool {
	sz.mu.Lock()
	defer sz.mu.Unlock()
	if sz.transferring {
		sz.refreshPending = true
		return false
	}
	sz.transferring = true
	return true
}

// releaseTransfer drops ownership and any pending refresh (manager stopping).
func (sz *SlaveZone) releaseTransfer() {
	sz.mu.Lock()
	defer sz.mu.Unlock()
	sz.transferring = false
	sz.refreshPending = false
}

// NewSlaveZone creates a new slave zone.
func NewSlaveZone(config SlaveZoneConfig) (*SlaveZone, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	z := zone.NewZone(config.ZoneName)

	return &SlaveZone{
		Config:     config,
		Zone:       z,
		LastSerial: 0,
	}, nil
}

// GetZone returns the current zone data (thread-safe).
func (sz *SlaveZone) GetZone() *zone.Zone {
	sz.mu.RLock()
	defer sz.mu.RUnlock()
	return sz.Zone
}

// UpdateZone updates the zone data (thread-safe). A successful zone
// transfer clears the consecutive-failure counter so a transient
// master outage doesn't permanently disable retries once the master
// recovers.
func (sz *SlaveZone) UpdateZone(newZone *zone.Zone, serial uint32) {
	sz.mu.Lock()
	defer sz.mu.Unlock()
	sz.Zone = newZone
	sz.LastSerial = serial
	sz.LastTransfer = time.Now()
	sz.retries = 0
}

// GetLastSerial returns the last known SOA serial (thread-safe).
func (sz *SlaveZone) GetLastSerial() uint32 {
	sz.mu.RLock()
	defer sz.mu.RUnlock()
	return sz.LastSerial
}

// GetLastTransfer returns when the last successful transfer completed, or
// the zero time if none has (thread-safe; UpdateZone writes it, F537).
func (sz *SlaveZone) GetLastTransfer() time.Time {
	sz.mu.RLock()
	defer sz.mu.RUnlock()
	return sz.LastTransfer
}

// SlaveManager manages slave zones and handles automatic zone transfers.
// It listens for NOTIFY messages and initiates zone transfers when needed.
type SlaveManager struct {
	slaveZones map[string]*SlaveZone  // zone name -> slave zone
	clients    map[string]*IXFRClient // zone name -> IXFR client
	notifyChan chan *NOTIFYRequest
	stopChan   chan struct{}
	stopOnce   sync.Once // guards Stop() against second-call panic
	keyStore   *KeyStore
	mu         sync.RWMutex
	wg         sync.WaitGroup
	// stopped is set (under mu) by Stop; no timer is armed and no transfer
	// is started afterwards. now/afterFunc are the SOA timer clock (F412).
	stopped   bool
	now       func() time.Time
	afterFunc func(d time.Duration, f func()) (stop func() bool)
}

// NewSlaveManager creates a new slave zone manager.
func NewSlaveManager(keyStore *KeyStore) *SlaveManager {
	return &SlaveManager{
		slaveZones: make(map[string]*SlaveZone),
		clients:    make(map[string]*IXFRClient),
		notifyChan: make(chan *NOTIFYRequest, 100),
		stopChan:   make(chan struct{}),
		keyStore:   keyStore,
		now:        time.Now,
		afterFunc:  realAfterFunc,
	}
}

// AddSlaveZone adds a slave zone to be managed.
func (sm *SlaveManager) AddSlaveZone(config SlaveZoneConfig) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Normalize zone name
	zoneName := strings.ToLower(config.ZoneName)
	if !strings.HasSuffix(zoneName, ".") {
		zoneName += "."
	}

	if sm.stopped {
		return fmt.Errorf("slave manager stopped")
	}
	if _, exists := sm.slaveZones[zoneName]; exists {
		return fmt.Errorf("slave zone %s already exists", zoneName)
	}

	slaveZone, err := NewSlaveZone(config)
	if err != nil {
		return err
	}

	// A configured tsig_secret must be usable for the transfers that name its
	// key (F202): register it unless the key store already holds that key.
	// The secret is base64 (as in BIND key statements); HMAC-SHA256.
	if config.TSIGKeyName != "" && config.TSIGSecret != "" {
		if sm.keyStore == nil {
			return fmt.Errorf("slave zone %s: tsig_secret configured but no TSIG key store", zoneName)
		}
		if _, ok := sm.keyStore.GetKey(config.TSIGKeyName); !ok {
			key, err := ParseTSIGKey(config.TSIGKeyName, HmacSHA256, config.TSIGSecret)
			if err != nil {
				return fmt.Errorf("slave zone %s: invalid tsig_secret (base64 expected): %w", zoneName, err)
			}
			if len(key.Secret) == 0 {
				return fmt.Errorf("slave zone %s: tsig_secret decodes to an empty key", zoneName)
			}
			sm.keyStore.AddKey(key)
		}
	}

	slaveZone.now = sm.now
	sm.slaveZones[zoneName] = slaveZone

	// Create IXFR client for this zone
	clientOpts := []IXFROption{
		WithIXFRTimeout(config.Timeout),
	}

	if config.TSIGKeyName != "" && sm.keyStore != nil {
		if _, ok := sm.keyStore.GetKey(config.TSIGKeyName); ok {
			clientOpts = append(clientOpts, WithIXFRKeyStore(sm.keyStore))
		}
	}

	// Use first master as primary
	client := NewIXFRClient(config.Masters[0], clientOpts...)
	sm.clients[zoneName] = client

	// Perform initial zone transfer
	sm.startZoneTransfer(zoneName, slaveZone)

	return nil
}

// RemoveSlaveZone removes a slave zone from management.
func (sm *SlaveManager) RemoveSlaveZone(zoneName string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	zoneName = strings.ToLower(zoneName)
	if !strings.HasSuffix(zoneName, ".") {
		zoneName += "."
	}

	if sz, ok := sm.slaveZones[zoneName]; ok {
		sz.mu.Lock()
		sz.cancelTimerLocked()
		sz.mu.Unlock()
	}
	delete(sm.slaveZones, zoneName)
	delete(sm.clients, zoneName)
}

// GetSlaveZone returns a slave zone by name.
func (sm *SlaveManager) GetSlaveZone(zoneName string) *SlaveZone {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	zoneName = strings.ToLower(zoneName)
	if !strings.HasSuffix(zoneName, ".") {
		zoneName += "."
	}

	return sm.slaveZones[zoneName]
}

// GetAllSlaveZones returns all managed slave zones.
func (sm *SlaveManager) GetAllSlaveZones() map[string]*SlaveZone {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	result := make(map[string]*SlaveZone)
	for k, v := range sm.slaveZones {
		result[k] = v
	}
	return result
}

// Start starts the slave manager and begins listening for NOTIFY events.
func (sm *SlaveManager) Start() {
	sm.wg.Add(1)
	go sm.notifyListener()
}

// Stop stops the slave manager: it cancels every zone's SOA refresh/retry
// timer, keeps new ones from being armed, and waits for in-flight transfers.
// Idempotent.
func (sm *SlaveManager) Stop() {
	closed := false
	sm.stopOnce.Do(func() {
		sm.mu.Lock()
		sm.stopped = true
		close(sm.stopChan)
		for _, sz := range sm.slaveZones {
			sz.mu.Lock()
			sz.cancelTimerLocked()
			sz.mu.Unlock()
		}
		sm.mu.Unlock()
		closed = true
	})
	if !closed {
		return
	}
	sm.wg.Wait()
}

// GetNotifyChannel returns the channel for receiving NOTIFY requests.
func (sm *SlaveManager) GetNotifyChannel() chan<- *NOTIFYRequest {
	return sm.notifyChan
}

// notifyListener listens for NOTIFY events and triggers zone transfers.
func (sm *SlaveManager) notifyListener() {
	defer sm.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			util.Errorf("panic in notifyListener: %v", r)
		}
	}()

	for {
		select {
		case <-sm.stopChan:
			return
		case notifyReq := <-sm.notifyChan:
			if notifyReq == nil {
				continue
			}
			sm.handleNotify(notifyReq)
		}
	}
}

// handleNotify processes a NOTIFY request and initiates zone transfer if needed.
func (sm *SlaveManager) handleNotify(req *NOTIFYRequest) {
	zoneName := strings.ToLower(req.ZoneName)

	sm.mu.RLock()
	slaveZone, exists := sm.slaveZones[zoneName]
	sm.mu.RUnlock()

	if !exists {
		// Not a slave zone we manage
		return
	}

	// Check if serial is newer using RFC 1982 serial number arithmetic. A
	// NOTIFY without a serial hint always triggers a check (F208).
	lastSerial := slaveZone.GetLastSerial()
	if !req.SerialUnknown && !serialIsNewer(req.Serial, lastSerial) {
		// Zone is up to date
		return
	}

	// Perform zone transfer (coalesced with one already in flight, F204)
	sm.startZoneTransfer(zoneName, slaveZone)
}

// startZoneTransfer claims the zone's transfer synchronously and runs it in a
// wg-tracked goroutine. If a transfer is already in flight the request is
// folded into one follow-up run of that transfer instead (F204).
func (sm *SlaveManager) startZoneTransfer(zoneName string, slaveZone *SlaveZone) {
	if !slaveZone.claimTransfer() {
		return
	}
	sm.wg.Add(1)
	go func() {
		defer sm.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				slaveZone.releaseTransfer()
				util.Errorf("panic in zone transfer for %s: %v", zoneName, r)
			}
		}()
		sm.runZoneTransfer(zoneName, slaveZone)
	}()
}

// performZoneTransfer performs a zone transfer for the specified slave zone,
// unless one is already in flight (then it only requests a follow-up run).
// Callers should wrap this in a goroutine with wg tracking.
func (sm *SlaveManager) performZoneTransfer(zoneName string) {
	sm.mu.RLock()
	slaveZone, exists := sm.slaveZones[zoneName]
	sm.mu.RUnlock()

	if !exists || !slaveZone.claimTransfer() {
		return
	}
	sm.runZoneTransfer(zoneName, slaveZone)
}

// runZoneTransfer runs the transfer for a zone whose ownership the caller
// claimed, re-running once for refreshes requested meanwhile, then arms the
// zone's next SOA timer: REFRESH after success, one RETRY wait after failure
// (completeTransfer).
func (sm *SlaveManager) runZoneTransfer(zoneName string, slaveZone *SlaveZone) {
	for {
		err := sm.transferOnce(zoneName, slaveZone)
		if errors.Is(err, errSlaveZoneRemoved) {
			slaveZone.releaseTransfer()
			return
		}
		if !sm.completeTransfer(zoneName, slaveZone, err) {
			return
		}
		select {
		case <-sm.stopChan:
			slaveZone.releaseTransfer()
			return
		default:
		}
	}
}

var errSlaveZoneRemoved = errors.New("slave zone removed")

// transferOnce fetches and applies the zone, trying each configured master in
// order until one succeeds (F203). It returns the last master's error.
func (sm *SlaveManager) transferOnce(zoneName string, slaveZone *SlaveZone) error {
	sm.mu.RLock()
	current, exists := sm.slaveZones[zoneName]
	client, clientExists := sm.clients[zoneName]
	sm.mu.RUnlock()

	if !exists || !clientExists || current != slaveZone {
		return errSlaveZoneRemoved
	}

	var lastErr error
	for i, master := range slaveZone.Config.Masters {
		// The stored client is bound to Masters[0]; other masters get their own.
		var masterClient *IXFRClient
		if i == 0 {
			masterClient = client
		}
		if lastErr = sm.transferFromMaster(slaveZone, masterClient, master); lastErr == nil {
			return nil
		}
	}
	return lastErr
}

// transferFromMaster fetches the zone from one master (IXFR with AXFR
// fallback, or AXFR) and applies it.
func (sm *SlaveManager) transferFromMaster(slaveZone *SlaveZone, client *IXFRClient, master string) error {
	ctx, cancel := context.WithTimeout(context.Background(), slaveZone.Config.Timeout)
	defer cancel()

	// Try IXFR first (if we have a previous serial)
	var records []*protocol.ResourceRecord
	var err error

	if slaveZone.Config.TransferType == "ixfr" && slaveZone.GetLastSerial() > 0 {
		records, err = sm.performIXFRFrom(ctx, client, slaveZone, master)
		if err != nil {
			// Fall back to AXFR
			records, err = sm.performAXFRFrom(ctx, slaveZone, master)
		}
	} else {
		// Perform full AXFR
		records, err = sm.performAXFRFrom(ctx, slaveZone, master)
	}
	if err != nil {
		return err
	}

	// Apply the transferred zone
	return sm.applyTransferredZone(slaveZone, records)
}

// performIXFR performs an incremental zone transfer from the first master.
func (sm *SlaveManager) performIXFR(ctx context.Context, client *IXFRClient, slaveZone *SlaveZone) ([]*protocol.ResourceRecord, error) {
	return sm.performIXFRFrom(ctx, client, slaveZone, slaveZone.Config.Masters[0])
}

// performIXFRFrom performs an incremental zone transfer from master.
func (sm *SlaveManager) performIXFRFrom(ctx context.Context, client *IXFRClient, slaveZone *SlaveZone, master string) ([]*protocol.ResourceRecord, error) {
	// Create IXFR client if not provided
	if client == nil {
		client = NewIXFRClient(master, WithIXFRTimeout(slaveZone.Config.Timeout))
		if sm.keyStore != nil {
			client = NewIXFRClient(master, WithIXFRTimeout(slaveZone.Config.Timeout), WithIXFRKeyStore(sm.keyStore))
		}
	}

	// Get TSIG key if configured
	var tsigKey *TSIGKey
	if slaveZone.Config.TSIGKeyName != "" && sm.keyStore != nil {
		var ok bool
		tsigKey, ok = sm.keyStore.GetKey(slaveZone.Config.TSIGKeyName)
		if !ok {
			return nil, fmt.Errorf("TSIG key %q not found", slaveZone.Config.TSIGKeyName)
		}
	}

	// Get current serial
	lastSerial := slaveZone.GetLastSerial()

	// Perform IXFR transfer
	records, err := client.Transfer(slaveZone.Config.ZoneName, lastSerial, tsigKey)
	if err != nil {
		return nil, fmt.Errorf("IXFR transfer failed: %w", err)
	}

	return records, nil
}

// performAXFR performs a full zone transfer from the first master.
func (sm *SlaveManager) performAXFR(ctx context.Context, slaveZone *SlaveZone) ([]*protocol.ResourceRecord, error) {
	return sm.performAXFRFrom(ctx, slaveZone, slaveZone.Config.Masters[0])
}

// performAXFRFrom performs a full zone transfer from master.
func (sm *SlaveManager) performAXFRFrom(ctx context.Context, slaveZone *SlaveZone, master string) ([]*protocol.ResourceRecord, error) {
	// Create AXFR client
	axfrClient := NewAXFRClient(master, WithAXFRTimeout(slaveZone.Config.Timeout))
	if slaveZone.Config.TSIGKeyName != "" && sm.keyStore != nil {
		axfrClient = NewAXFRClient(master, WithAXFRTimeout(slaveZone.Config.Timeout), WithAXFRKeyStore(sm.keyStore))
	}

	// Get TSIG key if configured
	var tsigKey *TSIGKey
	if slaveZone.Config.TSIGKeyName != "" && sm.keyStore != nil {
		var ok bool
		tsigKey, ok = sm.keyStore.GetKey(slaveZone.Config.TSIGKeyName)
		if !ok {
			return nil, fmt.Errorf("TSIG key %q not found", slaveZone.Config.TSIGKeyName)
		}
	}

	// Perform transfer
	records, err := axfrClient.Transfer(slaveZone.Config.ZoneName, tsigKey)
	if err != nil {
		return nil, fmt.Errorf("AXFR failed: %w", err)
	}

	return records, nil
}

// applyTransferredZone applies transferred records to the slave zone. It
// dispatches on the wire shape of the response: a full AXFR-style transfer
// (SOA … SOA) rebuilds the zone from scratch, while an incremental IXFR
// (SOA(new) [SOA(old) deletions SOA(new) additions]… SOA(new), i.e. an SOA
// immediately following the leading SOA — RFC 1995 §4) is applied as a diff
// against the existing zone.
func (sm *SlaveManager) applyTransferredZone(slaveZone *SlaveZone, records []*protocol.ResourceRecord) error {
	if len(records) == 0 {
		return fmt.Errorf("no records received in zone transfer")
	}
	if records[0].Type != protocol.TypeSOA {
		return fmt.Errorf("zone transfer does not begin with an SOA record")
	}

	// RFC 1982: never commit a transfer whose serial is older than the one
	// we already hold — a stale or replayed response must not roll the zone
	// back. A fresh slave (LastSerial == 0, never transferred) accepts any
	// serial; an equal serial is still honored (lone-SOA refresh,
	// idempotent re-transfer).
	if leadingSOA, ok := records[0].Data.(*protocol.RDataSOA); ok {
		if cur := slaveZone.GetLastSerial(); cur != 0 && serialIsNewer(cur, leadingSOA.Serial) {
			return fmt.Errorf("ignoring stale zone transfer: received serial %d is older than current %d", leadingSOA.Serial, cur)
		}
	}

	// A lone SOA means the slave is already current (no changes). Refresh the
	// timers/serial but keep the existing zone data.
	if len(records) == 1 {
		if soa, ok := records[0].Data.(*protocol.RDataSOA); ok {
			slaveZone.UpdateZone(slaveZone.GetZone(), soa.Serial)
			return nil
		}
		return fmt.Errorf("single-record transfer is not an SOA")
	}

	// Incremental IXFR responses place an SOA (the first diff block's "old"
	// serial) immediately after the leading SOA. A full transfer places zone
	// data there instead.
	if records[1].Type == protocol.TypeSOA {
		base := slaveZone.GetZone()
		if base == nil {
			return fmt.Errorf("received an incremental IXFR without a base zone to apply it against")
		}
		return sm.applyIncrementalIXFR(slaveZone, base, records)
	}

	return sm.applyFullZone(slaveZone, records)
}

// applyFullZone rebuilds the slave zone from a full AXFR-style record stream.
func (sm *SlaveManager) applyFullZone(slaveZone *SlaveZone, records []*protocol.ResourceRecord) error {
	newZone := zone.NewZone(slaveZone.Config.ZoneName)

	var soaSerial uint32
	var haveSOA bool
	for _, rr := range records {
		if rr.Type == protocol.TypeSOA {
			if soaData, ok := rr.Data.(*protocol.RDataSOA); ok && !haveSOA {
				soaSerial = soaData.Serial
				setSlaveZoneSOA(newZone, rr, soaData)
				haveSOA = true
			}
			continue
		}
		rec := recordFromRR(rr)
		newZone.Records[rec.Name] = append(newZone.Records[rec.Name], rec)
	}

	if !haveSOA {
		return fmt.Errorf("no SOA record found in zone transfer")
	}

	slaveZone.UpdateZone(newZone, soaSerial)
	return nil
}

// applyIncrementalIXFR applies an RFC 1995 incremental diff to a clone of the
// existing zone. The body between the leading and trailing SOA is a sequence of
// (SOA-old, deletions, SOA-new, additions) blocks; each interior SOA toggles
// between the deletion and addition section.
func (sm *SlaveManager) applyIncrementalIXFR(slaveZone *SlaveZone, base *zone.Zone, records []*protocol.ResourceRecord) error {
	targetSOA, ok := records[0].Data.(*protocol.RDataSOA)
	if !ok {
		return fmt.Errorf("incremental IXFR does not begin with an SOA")
	}

	// RFC 1995 §4: "The first and the last RR of the response is the SOA
	// record of the zone." A stream that does not end in that terminating SOA
	// was cut short (the master died mid-diff — receiveIXFRResponse returns a
	// partial record list once it has seen two SOAs and the read fails). The
	// deletions and additions actually delivered therefore do not add up to
	// the target serial, so this is not a completed transfer. Applying it
	// would commit targetSOA.Serial over a half-built zone, and because the
	// slave's serial would then match it would never re-fetch. Reject it and
	// let the retry re-request the whole diff.
	if len(records) < 2 {
		return fmt.Errorf("incremental IXFR has no terminating SOA")
	}
	trailing := records[len(records)-1]
	trailingSOA, ok := trailing.Data.(*protocol.RDataSOA)
	if trailing.Type != protocol.TypeSOA || !ok {
		return fmt.Errorf("incremental IXFR does not end with an SOA record: truncated transfer")
	}
	if trailingSOA.Serial != targetSOA.Serial {
		return fmt.Errorf("IXFR terminating SOA serial %d does not match target serial %d",
			trailingSOA.Serial, targetSOA.Serial)
	}

	// RFC 1995 §4: the first interior SOA carries the diff's base serial; it
	// must match the serial this slave already holds, or the deletions and
	// additions were computed for a different generation of the zone. The
	// server side enforces the same continuity (buildIncrementalIXFR).
	if cur := slaveZone.GetLastSerial(); cur != 0 {
		if len(records) < 3 {
			return fmt.Errorf("incremental IXFR too short to contain a diff")
		}
		if baseSOA, ok := records[1].Data.(*protocol.RDataSOA); ok && baseSOA.Serial != cur {
			return fmt.Errorf("IXFR base serial %d does not match slave serial %d", baseSOA.Serial, cur)
		}
	}

	// Clone the base zone so a mid-apply error cannot corrupt the live zone.
	newZone := zone.NewZone(slaveZone.Config.ZoneName)
	base.RLock()
	if base.SOA != nil {
		soaCopy := *base.SOA
		newZone.SOA = &soaCopy
	}
	for name, recs := range base.Records {
		cp := make([]zone.Record, len(recs))
		copy(cp, recs)
		newZone.Records[name] = cp
	}
	base.RUnlock()

	// Walk the diff body (everything between the leading and trailing SOA).
	deleting := false
	started := false
	for _, rr := range records[1 : len(records)-1] {
		if rr.Type == protocol.TypeSOA {
			if !started {
				deleting = true // first interior SOA opens a deletion section
				started = true
			} else {
				deleting = !deleting // alternate delete/add on each SOA boundary
			}
			continue
		}
		rec := recordFromRR(rr)
		if deleting {
			removeZoneRecord(newZone, rec)
		} else {
			newZone.Records[rec.Name] = append(newZone.Records[rec.Name], rec)
		}
	}

	// The leading SOA is the zone's new SOA (RFC 1995 §4) — every field, not
	// only the serial: a master that changed REFRESH/MINIMUM/MNAME or the SOA
	// TTL in the same edit must not leave the slave on the old values (F588).
	setSlaveZoneSOA(newZone, records[0], targetSOA)

	slaveZone.UpdateZone(newZone, targetSOA.Serial)
	return nil
}

// setSlaveZoneSOA installs soa (carried by rr) as z's SOA, keeping the two
// places the zone model holds it in step, as the zone-file parser does: z.SOA
// (serial, timers, negative TTL) and the apex SOA RR in z.Records, which the
// authoritative lookup answers from. Before F587 a transferred zone had only
// z.SOA, so `<zone> SOA` was answered as NODATA (SOA in the authority section
// instead of the answer). Any SOA RR already at the apex (an IXFR base) is
// replaced; z.SOA.Serial and the apex RR always carry the same serial.
func setSlaveZoneSOA(z *zone.Zone, rr *protocol.ResourceRecord, soa *protocol.RDataSOA) {
	z.SOA = soaFromRData(soa, rr.TTL)
	z.SOA.Name = z.Origin
	rec := recordFromRR(rr)
	rec.Name = z.Origin
	apex := make([]zone.Record, 0, len(z.Records[z.Origin])+1)
	apex = append(apex, rec)
	for _, r := range z.Records[z.Origin] {
		if !strings.EqualFold(r.Type, "SOA") {
			apex = append(apex, r)
		}
	}
	z.Records[z.Origin] = apex
}

// recordFromRR converts a wire RR into a zone.Record, normalizing the owner
// name to lowercase so it matches zone.Lookup (which lowercases queries) and
// the parser's stored form.
func recordFromRR(rr *protocol.ResourceRecord) zone.Record {
	return zone.Record{
		Name:  strings.ToLower(rr.Name.String()),
		Type:  protocol.TypeString(rr.Type),
		TTL:   rr.TTL,
		RData: rr.Data.String(),
	}
}

// soaFromRData builds a zone.SOARecord from wire SOA rdata and the SOA
// record's TTL.
func soaFromRData(soa *protocol.RDataSOA, ttl uint32) *zone.SOARecord {
	return &zone.SOARecord{
		TTL:     ttl,
		MName:   soa.MName.String(),
		RName:   soa.RName.String(),
		Serial:  soa.Serial,
		Refresh: soa.Refresh,
		Retry:   soa.Retry,
		Expire:  soa.Expire,
		Minimum: soa.Minimum,
	}
}

// removeZoneRecord deletes the first record matching rec by owner name
// (case-insensitive), type, and exact RDATA. TTL is not part of the match, per
// RFC 1995 deletion semantics.
func removeZoneRecord(z *zone.Zone, rec zone.Record) {
	recs, ok := z.Records[rec.Name]
	if !ok {
		return
	}
	for i, r := range recs {
		if strings.EqualFold(r.Type, rec.Type) && r.RData == rec.RData {
			z.Records[rec.Name] = append(recs[:i], recs[i+1:]...)
			if len(z.Records[rec.Name]) == 0 {
				delete(z.Records, rec.Name)
			}
			return
		}
	}
}
