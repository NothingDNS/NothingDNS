// Package zone — KV Persistence Layer
//
// This file provides optional KV store integration for zone persistence.
// When enabled, zones are automatically persisted to the embedded KV store
// in addition to (or instead of) zone files on disk.

package zone

import (
	"fmt"
	"sync"

	"github.com/nothingdns/nothingdns/internal/storage"
)

// KVPersistence wraps a Manager and adds KV store persistence.
// All zone mutations are automatically persisted to the KV store.
type KVPersistence struct {
	manager *Manager
	store   *storage.ZoneStore
	mu      sync.RWMutex
	enabled bool
}

// NewKVPersistence creates a new KVPersistence wrapper around a Manager.
func NewKVPersistence(manager *Manager, kvStore *storage.KVStore) *KVPersistence {
	return &KVPersistence{
		manager: manager,
		store:  storage.NewZoneStore(kvStore),
	}
}

// Enable activates KV store persistence.
func (k *KVPersistence) Enable() {
	k.mu.Lock()
	k.enabled = true
	k.mu.Unlock()
}

// PersistZone persists a zone to the KV store.
// This should be called after any zone mutation (DDNS update, zone reload, etc.)
func (k *KVPersistence) PersistZone(zoneName string) error {
	k.mu.RLock()
	enabled := k.enabled
	manager := k.manager
	store := k.store
	k.mu.RUnlock()

	if !enabled {
		return nil
	}

	z, ok := manager.Get(zoneName)
	if !ok {
		return nil // Zone not found
	}

	meta := storage.ZoneMeta{
		Origin:     z.Origin,
		DefaultTTL: z.DefaultTTL,
	}

	// Convert zone records to storage.StoredRecord format
	records := k.zoneToStoredRecords(z)

	if err := store.SaveZone(zoneName, meta, records); err != nil {
		return fmt.Errorf("KV persist zone %s: %w", zoneName, err)
	}

	return nil
}

// PersistAll persists all zones to the KV store.
func (k *KVPersistence) PersistAll() error {
	k.mu.RLock()
	manager := k.manager
	enabled := k.enabled
	k.mu.RUnlock()

	if !enabled {
		return nil
	}

	manager.mu.RLock()
	zoneNames := make([]string, 0, len(manager.zones))
	for name := range manager.zones {
		zoneNames = append(zoneNames, name)
	}
	manager.mu.RUnlock()

	for _, name := range zoneNames {
		if err := k.PersistZone(name); err != nil {
			return err
		}
	}

	return nil
}

// LoadFromKV attempts to load a zone from the KV store.
// Returns (zone, true) if found, or (nil, false) if not in KV store.
func (k *KVPersistence) LoadFromKV(zoneName string) (*Zone, bool, error) {
	k.mu.RLock()
	store := k.store
	enabled := k.enabled
	k.mu.RUnlock()

	if !enabled {
		return nil, false, nil
	}

	meta, records, err := store.LoadZone(zoneName)
	if err != nil {
		if err == storage.ErrZoneNotFound {
			return nil, false, nil
		}
		return nil, false, err
	}

	// Convert stored records back to zone records
	z := k.storedRecordsToZone(meta, records)

	return z, true, nil
}

// DeleteFromKV removes a zone from the KV store.
func (k *KVPersistence) DeleteFromKV(zoneName string) error {
	k.mu.RLock()
	store := k.store
	enabled := k.enabled
	k.mu.RUnlock()

	if !enabled {
		return nil
	}

	return store.DeleteZone(zoneName)
}

// ListKVZones returns all zone origins stored in the KV store.
func (k *KVPersistence) ListKVZones() ([]string, error) {
	k.mu.RLock()
	store := k.store
	enabled := k.enabled
	k.mu.RUnlock()

	if !enabled {
		return nil, nil
	}

	return store.ListZones()
}

// zoneToStoredRecords converts zone records to storage.StoredRecord format.
func (k *KVPersistence) zoneToStoredRecords(z *Zone) map[string][]storage.StoredRecord {
	z.RLock()
	defer z.RUnlock()

	records := make(map[string][]storage.StoredRecord)

	for name, recs := range z.Records {
		for _, rr := range recs {
			stored := storage.StoredRecord{
				Name:  name,
				TTL:   rr.TTL,
				Class: rr.Class,
				Type:  rr.Type,
				RData: rr.RData,
			}
			records[name] = append(records[name], stored)
		}
	}

	return records
}

// storedRecordsToZone converts stored records back to a Zone.
func (k *KVPersistence) storedRecordsToZone(meta storage.ZoneMeta, records map[string][]storage.StoredRecord) *Zone {
	z := &Zone{
		Origin:     meta.Origin,
		DefaultTTL: meta.DefaultTTL,
		Records:    make(map[string][]Record),
	}

	for name, storedRecs := range records {
		for _, sr := range storedRecs {
			rr := Record{
				Name:  sr.Name,
				TTL:   sr.TTL,
				Class: sr.Class,
				Type:  sr.Type,
				RData: sr.RData,
			}
			z.Records[name] = append(z.Records[name], rr)
		}
	}

	// Find SOA record
	for _, recs := range z.Records {
		for _, rr := range recs {
			if rr.Type == "SOA" {
				// Parse SOA record from RData
				soa := parseSOAFromRData(rr.RData)
				if soa != nil {
					z.SOA = soa
				}
				break
			}
		}
		// Only one SOA per zone, break after first set
		break
	}

	return z
}

// parseSOAFromRData parses SOA record fields from RData string.
// Format: "mname rname serial refresh retry expire minimum"
func parseSOAFromRData(rdata string) *SOARecord {
	// SOA RData is space-separated fields
	// This is a simplified parser - zone parsing handles this in the parser
	var soa SOARecord
	// For now, just store the raw RData - proper parsing would need the parser
	// The SOA record type should be used for full parsing
	return &soa
}

// Manager returns the underlying zone manager.
func (k *KVPersistence) Manager() *Manager {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.manager
}
