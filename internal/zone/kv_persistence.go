// Package zone — KV Persistence Layer
//
// This file provides optional KV store integration for zone persistence.
// When enabled, zones are automatically persisted to the embedded KV store
// in addition to (or instead of) zone files on disk.

package zone

import (
	"errors"
	"fmt"
	"strings"
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
		store:   storage.NewZoneStore(kvStore),
	}
}

// Enable activates KV store persistence and installs a mutation hook on the
// underlying Manager, so EVERY zone mutation that goes through the manager —
// REST API handlers, Raft apply on each cluster node, gossip
// replication, or any future caller — is persisted to (or deleted from) the
// KV store automatically. Callers no longer persist explicitly; paths that
// mutate a *Zone directly (DDNS via transfer.ApplyUpdate) must call
// Manager.NotifyMutated instead.
//
// Persistence is deliberately best-effort: failures are logged via the
// manager's logger and do NOT fail the mutation, matching how the manager
// already treats zone-file disk writes ("zone is loaded in memory; log the
// error but don't fail"). NOTE: this is a behavior change for the REST API,
// which previously returned 500 when the explicit post-mutation KV persist
// failed even though the mutation itself had succeeded in memory.
func (k *KVPersistence) Enable() {
	k.mu.Lock()
	k.enabled = true
	manager := k.manager
	k.mu.Unlock()

	manager.SetMutationHook(func(zoneName string, deleted bool) {
		var err error
		if deleted {
			err = k.DeleteFromKV(zoneName)
		} else {
			err = k.PersistZone(zoneName)
		}
		if err != nil {
			manager.warnf("zone: KV persistence for %s failed: %v", zoneName, err)
		}
	})
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
		if errors.Is(err, storage.ErrZoneNotFound) {
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

	// Find SOA record — scan every name until it is found: the Records map
	// iterates in randomized order, so the apex (which holds the SOA) is not
	// guaranteed to be visited first.
	for _, recs := range z.Records {
		for _, rr := range recs {
			if rr.Type != "SOA" {
				continue
			}
			if soa := parseSOAFromRData(rr.RData); soa != nil {
				z.SOA = soa
			}
			break
		}
		if z.SOA != nil {
			break
		}
	}

	return z
}

// ParseSOAFromRData parses SOA record fields from an RData string.
// Format: "mname rname serial refresh retry expire minimum"
// Returns nil on parse failure. Exported for DDNS (RFC 2136 §3.4.2.2
// SOA-replacement rule needs the incoming serial).
func ParseSOAFromRData(rdata string) *SOARecord {
	return parseSOAFromRData(rdata)
}

// parseSOAFromRData parses SOA record fields from RData string.
// Format: "mname rname serial refresh retry expire minimum"
// Example: "ns1.example.com. hostmaster.example.com. 2024010101 3600 900 604800 86400"
func parseSOAFromRData(rdata string) *SOARecord {
	fields := parseRDataFields(rdata)
	if len(fields) < 7 {
		return nil // Return nil on parse failure
	}

	serial, _ := parseUint32(fields[2])
	refresh, _ := parseTTLValue(fields[3])
	retry, _ := parseTTLValue(fields[4])
	expire, _ := parseTTLValue(fields[5])
	minimum, _ := parseTTLValue(fields[6])

	return &SOARecord{
		MName:   fields[0],
		RName:   fields[1],
		Serial:  serial,
		Refresh: refresh,
		Retry:   retry,
		Expire:  expire,
		Minimum: minimum,
	}
}

// parseRDataFields splits SOA RData string into fields.
// Handles space-separated fields (SOA RData format).
func parseRDataFields(rdata string) []string {
	var fields []string
	var current strings.Builder
	inQuotes := false

	for _, r := range rdata {
		switch r {
		case '"':
			inQuotes = !inQuotes
		case ' ', '\t':
			if !inQuotes {
				if current.Len() > 0 {
					fields = append(fields, current.String())
					current.Reset()
				}
				continue
			}
		}
		current.WriteRune(r)
	}
	if current.Len() > 0 {
		fields = append(fields, current.String())
	}
	return fields
}

// parseUint32 parses a string to uint32.
func parseUint32(s string) (uint32, error) {
	var v uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid number")
		}
		v = v*10 + uint64(c-'0')
		if v > 1<<32-1 {
			return 0, fmt.Errorf("overflow")
		}
	}
	return uint32(v), nil
}

// parseTTLValue parses a TTL value (number or duration string like "1h", "30m", "1d").
func parseTTLValue(s string) (uint32, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return 0, fmt.Errorf("empty TTL value")
	}

	// Handle duration suffixes (S/M/H/D/W), matching zone.parseTTL
	multiplier := uint32(1)
	if len(s) > 0 {
		switch s[len(s)-1] {
		case 'S':
			s = s[:len(s)-1]
		case 'M':
			multiplier = 60
			s = s[:len(s)-1]
		case 'H':
			multiplier = 3600
			s = s[:len(s)-1]
		case 'D':
			multiplier = 86400
			s = s[:len(s)-1]
		case 'W':
			multiplier = 604800
			s = s[:len(s)-1]
		}
	}

	val, err := parseUint32(s)
	if err != nil {
		return 0, fmt.Errorf("invalid TTL value: %s", s)
	}

	// Check overflow: val * multiplier could exceed uint32 max
	maxVal := uint64(1<<32 - 1)
	if val > 0 && multiplier > 0 && uint64(val) > maxVal/uint64(multiplier) {
		return 0, fmt.Errorf("TTL overflow: %d * %d exceeds uint32 max", val, multiplier)
	}

	return val * multiplier, nil
}

// Manager returns the underlying zone manager.
func (k *KVPersistence) Manager() *Manager {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.manager
}
