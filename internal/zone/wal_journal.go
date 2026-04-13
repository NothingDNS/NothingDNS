// Package zone — WAL Journal for Zone Changes
//
// This file provides Write-Ahead Log (WAL) journaling for zone changes.
// Zone mutations (DDNS UPDATE, AXFR, IXFR) are logged to WAL before being
// applied, enabling crash recovery and replay.

package zone

import (
	"encoding/json"
	"fmt"

	"github.com/nothingdns/nothingdns/internal/storage"
)

// ZoneWALEntryType is the entry type used for zone entries in the WAL.
const ZoneWALEntryType byte = 'Z'

// MaxWALReplayEntries limits the number of WAL entries loaded during replay
// to prevent memory exhaustion from unbounded journal growth.
const MaxWALReplayEntries = 100000

// ZoneWALEntry represents a zone change entry in the WAL.
type ZoneWALEntry struct {
	Type      string // "add_record", "del_record", "update_record", "delete_zone"
	Zone      string
	Name      string
	RRType    string
	TTL       uint32
	RData     string
	Operation string // "apply" or "revert"
}

// ZoneJournal wraps a storage WAL for zone change journaling.
type ZoneJournal struct {
	wal  *storage.WAL
	zone string // The zone this journal tracks
}

// NewZoneJournal creates a new ZoneJournal for a specific zone.
func NewZoneJournal(wal *storage.WAL, zone string) *ZoneJournal {
	return &ZoneJournal{
		wal:  wal,
		zone: zone,
	}
}

// LogAddRecord logs a record addition to the WAL.
func (zj *ZoneJournal) LogAddRecord(name, rrtype string, ttl uint32, rdata string) error {
	entry := ZoneWALEntry{
		Type:   "add_record",
		Zone:   zj.zone,
		Name:   name,
		RRType: rrtype,
		TTL:    ttl,
		RData:  rdata,
	}
	return zj.logEntry(entry)
}

// LogDelRecord logs a record deletion to the WAL.
func (zj *ZoneJournal) LogDelRecord(name, rrtype string) error {
	entry := ZoneWALEntry{
		Type:   "del_record",
		Zone:   zj.zone,
		Name:   name,
		RRType: rrtype,
	}
	return zj.logEntry(entry)
}

// LogZoneDelete logs a zone deletion to the WAL.
func (zj *ZoneJournal) LogZoneDelete() error {
	entry := ZoneWALEntry{
		Type: "delete_zone",
		Zone: zj.zone,
	}
	return zj.logEntry(entry)
}

// Replay replays WAL entries to reconstruct zone state after a crash.
func (zj *ZoneJournal) Replay() ([]ZoneWALEntry, error) {
	entries, err := zj.wal.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read WAL: %w", err)
	}

	var zoneEntries []ZoneWALEntry
	count := 0
	for _, e := range entries {
		if e.Type != ZoneWALEntryType {
			continue
		}
		// SECURITY: Limit replayed entries to prevent memory exhaustion
		count++
		if count > MaxWALReplayEntries {
			return nil, fmt.Errorf("WAL replay exceeded %d entries — journal may be corrupted or oversized", MaxWALReplayEntries)
		}
		var entry ZoneWALEntry
		if err := json.Unmarshal(e.Data, &entry); err != nil {
			continue // Skip corrupt entries
		}
		if entry.Zone != zj.zone {
			continue
		}
		zoneEntries = append(zoneEntries, entry)
	}

	return zoneEntries, nil
}

// logEntry writes an entry to the WAL.
func (zj *ZoneJournal) logEntry(entry ZoneWALEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	_, err = zj.wal.Append(ZoneWALEntryType, data)
	return err
}
