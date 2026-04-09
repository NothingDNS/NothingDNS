package transfer

import (
	"context"
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

	// Retry interval on transfer failure
	RetryInterval time.Duration

	// Maximum retry attempts (0 = unlimited)
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

	if c.Timeout == 0 {
		c.Timeout = 30 * time.Second
	}

	if c.RetryInterval == 0 {
		c.RetryInterval = 5 * time.Minute
	}

	return nil
}

// SlaveZone represents a slave zone being replicated.
type SlaveZone struct {
	Config     SlaveZoneConfig
	Zone       *zone.Zone
	LastSerial uint32
	LastTransfer time.Time
	mu         sync.RWMutex
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

// UpdateZone updates the zone data (thread-safe).
func (sz *SlaveZone) UpdateZone(newZone *zone.Zone, serial uint32) {
	sz.mu.Lock()
	defer sz.mu.Unlock()
	sz.Zone = newZone
	sz.LastSerial = serial
	sz.LastTransfer = time.Now()
}

// GetLastSerial returns the last known SOA serial (thread-safe).
func (sz *SlaveZone) GetLastSerial() uint32 {
	sz.mu.RLock()
	defer sz.mu.RUnlock()
	return sz.LastSerial
}

// SlaveManager manages slave zones and handles automatic zone transfers.
// It listens for NOTIFY messages and initiates zone transfers when needed.
type SlaveManager struct {
	slaveZones   map[string]*SlaveZone  // zone name -> slave zone
	clients      map[string]*IXFRClient // zone name -> IXFR client
	notifyChan   chan *NOTIFYRequest
	stopChan     chan struct{}
	keyStore     *KeyStore
	mu           sync.RWMutex
	wg           sync.WaitGroup
}

// NewSlaveManager creates a new slave zone manager.
func NewSlaveManager(keyStore *KeyStore) *SlaveManager {
	return &SlaveManager{
		slaveZones: make(map[string]*SlaveZone),
		clients:    make(map[string]*IXFRClient),
		notifyChan: make(chan *NOTIFYRequest, 100),
		stopChan:   make(chan struct{}),
		keyStore:   keyStore,
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

	if _, exists := sm.slaveZones[zoneName]; exists {
		return fmt.Errorf("slave zone %s already exists", zoneName)
	}

	slaveZone, err := NewSlaveZone(config)
	if err != nil {
		return err
	}

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
	sm.wg.Add(1)
	go func() {
		defer sm.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				util.Errorf("panic in performZoneTransfer for %s: %v", zoneName, r)
			}
		}()
		sm.performZoneTransfer(zoneName)
	}()

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

// Stop stops the slave manager.
func (sm *SlaveManager) Stop() {
	close(sm.stopChan)
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

	// Check if serial is newer using RFC 1982 serial number arithmetic
	lastSerial := slaveZone.GetLastSerial()
	if !serialIsNewer(req.Serial, lastSerial) {
		// Zone is up to date
		return
	}

	// Perform zone transfer
	sm.wg.Add(1)
	go func() {
		defer sm.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				util.Errorf("panic in zone transfer for %s: %v", zoneName, r)
			}
		}()
		sm.performZoneTransfer(zoneName)
	}()
}

// performZoneTransfer performs a zone transfer for the specified slave zone.
// Callers should wrap this in a goroutine with wg tracking.
func (sm *SlaveManager) performZoneTransfer(zoneName string) {
	sm.mu.RLock()
	slaveZone, exists := sm.slaveZones[zoneName]
	client, clientExists := sm.clients[zoneName]
	sm.mu.RUnlock()

	if !exists || !clientExists {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), slaveZone.Config.Timeout)
	defer cancel()

	// Try IXFR first (if we have a previous serial)
	var records []*protocol.ResourceRecord
	var err error

	if slaveZone.Config.TransferType == "ixfr" && slaveZone.GetLastSerial() > 0 {
		records, err = sm.performIXFR(ctx, client, slaveZone)
		if err != nil {
			// Fall back to AXFR
			records, err = sm.performAXFR(ctx, slaveZone)
		}
	} else {
		// Perform full AXFR
		records, err = sm.performAXFR(ctx, slaveZone)
	}

	if err != nil {
		// Schedule retry
		sm.wg.Add(1)
		go func() {
			defer sm.wg.Done()
			defer func() {
				if r := recover(); r != nil {
					util.Errorf("panic in scheduleRetry for %s: %v", zoneName, r)
				}
			}()
			sm.scheduleRetry(zoneName)
		}()
		return
	}

	// Apply the transferred zone
	if err := sm.applyTransferredZone(slaveZone, records); err != nil {
		sm.wg.Add(1)
		go func() {
			defer sm.wg.Done()
			defer func() {
				if r := recover(); r != nil {
					util.Errorf("panic in applyTransferredZone retry for %s: %v", zoneName, r)
				}
			}()
			sm.scheduleRetry(zoneName)
		}()
		return
	}
}

// performIXFR performs an incremental zone transfer.
func (sm *SlaveManager) performIXFR(ctx context.Context, client *IXFRClient, slaveZone *SlaveZone) ([]*protocol.ResourceRecord, error) {
	master := slaveZone.Config.Masters[0]

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

// performAXFR performs a full zone transfer.
func (sm *SlaveManager) performAXFR(ctx context.Context, slaveZone *SlaveZone) ([]*protocol.ResourceRecord, error) {
	// Create AXFR client
	master := slaveZone.Config.Masters[0]

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

// applyTransferredZone applies transferred records to the slave zone.
func (sm *SlaveManager) applyTransferredZone(slaveZone *SlaveZone, records []*protocol.ResourceRecord) error {
	if len(records) == 0 {
		return fmt.Errorf("no records received in zone transfer")
	}

	// Create new zone
	newZone := zone.NewZone(slaveZone.Config.ZoneName)

	// Extract SOA to get serial
	var soaSerial uint32
	for _, rr := range records {
		if rr.Type == protocol.TypeSOA {
			if soaData, ok := rr.Data.(*protocol.RDataSOA); ok {
				soaSerial = soaData.Serial

				// Set SOA in zone
				newZone.SOA = &zone.SOARecord{
					MName:   soaData.MName.String(),
					RName:   soaData.RName.String(),
					Serial:  soaData.Serial,
					Refresh: soaData.Refresh,
					Retry:   soaData.Retry,
					Expire:  soaData.Expire,
					Minimum: soaData.Minimum,
				}
				break
			}
		}
	}

	if soaSerial == 0 {
		return fmt.Errorf("no SOA record found in zone transfer")
	}

	// Add all records to zone
	for _, rr := range records {
		// Skip SOA records (we already handled the first one)
		if rr.Type == protocol.TypeSOA {
			continue
		}

		record := zone.Record{
			Name:  rr.Name.String(),
			Type:  protocol.TypeString(rr.Type),
			TTL:   rr.TTL,
			RData: rr.Data.String(),
		}
		newZone.Records[record.Name] = append(newZone.Records[record.Name], record)
	}

	// Update the slave zone
	slaveZone.UpdateZone(newZone, soaSerial)

	return nil
}

// scheduleRetry schedules a retry of the zone transfer.
func (sm *SlaveManager) scheduleRetry(zoneName string) {
	sm.mu.RLock()
	slaveZone, exists := sm.slaveZones[zoneName]
	sm.mu.RUnlock()

	if !exists {
		return
	}

	timer := time.NewTimer(slaveZone.Config.RetryInterval)
	defer timer.Stop()

	select {
	case <-timer.C:
		// Already running inside a wg-tracked goroutine, so call directly
		sm.performZoneTransfer(zoneName)
	case <-sm.stopChan:
		// Manager is stopping, abort retry
	}
}
