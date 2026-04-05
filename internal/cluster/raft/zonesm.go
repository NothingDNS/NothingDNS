package raft

import (
	"encoding/json"
	"fmt"
	"sync"
)

// ZoneCommand represents a zone mutation command.
type ZoneCommand struct {
	Type      string          `json:"type"` // "add_record", "del_record", "update_record", "delete_zone"
	Zone      string          `json:"zone"`
	Name      string          `json:"name,omitempty"`
	RRType    uint16          `json:"rrtype,omitempty"`
	TTL       uint32          `json:"ttl,omitempty"`
	RData     []string        `json:"rdata,omitempty"`
	Priority  int             `json:"priority,omitempty"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
}

// ZoneStateMachine is the state machine that applies Raft log entries to zone data.
type ZoneStateMachine struct {
	mu     sync.RWMutex
	zones  map[string]*ZoneData
	onUpdate func(zone string, cmd ZoneCommand)
}

// ZoneData holds the zone's record data.
type ZoneData struct {
	Zone     string
	Records  map[string][]RecordEntry
	Modified bool
}

// RecordEntry is a single DNS record.
type RecordEntry struct {
	Name   string
	RRType uint16
	TTL    uint32
	RData  []byte
}

// NewZoneStateMachine creates a new zone state machine.
func NewZoneStateMachine() *ZoneStateMachine {
	return &ZoneStateMachine{
		zones: make(map[string]*ZoneData),
	}
}

// Apply applies a committed entry to the state machine.
func (z *ZoneStateMachine) Apply(e entry) error {
	if e.Type == EntryNoOp {
		return nil
	}

	if len(e.Command) == 0 {
		return nil
	}

	var cmd ZoneCommand
	if err := json.Unmarshal(e.Command, &cmd); err != nil {
		return fmt.Errorf("unmarshal command: %w", err)
	}

	return z.applyCommand(cmd)
}

// applyCommand applies a zone command.
func (z *ZoneStateMachine) applyCommand(cmd ZoneCommand) error {
	z.mu.Lock()
	defer z.mu.Unlock()

	switch cmd.Type {
	case "add_record":
		return z.addRecord(cmd)
	case "del_record":
		return z.delRecord(cmd)
	case "update_record":
		return z.updateRecord(cmd)
	case "delete_zone":
		return z.deleteZone(cmd)
	default:
		return fmt.Errorf("unknown command type: %s", cmd.Type)
	}
}

func (z *ZoneStateMachine) addRecord(cmd ZoneCommand) error {
	zone, ok := z.zones[cmd.Zone]
	if !ok {
		zone = &ZoneData{
			Zone:    cmd.Zone,
			Records: make(map[string][]RecordEntry),
		}
		z.zones[cmd.Zone] = zone
	}

	key := recordKey(cmd.Name, cmd.RRType)
	zone.Records[key] = append(zone.Records[key], RecordEntry{
		Name:   cmd.Name,
		RRType: cmd.RRType,
		TTL:    cmd.TTL,
		RData:  []byte(cmd.RData[0]), // Simplified
	})
	zone.Modified = true

	if z.onUpdate != nil {
		z.onUpdate(cmd.Zone, cmd)
	}

	return nil
}

func (z *ZoneStateMachine) delRecord(cmd ZoneCommand) error {
	zone, ok := z.zones[cmd.Zone]
	if !ok {
		return nil // Zone doesn't exist
	}

	key := recordKey(cmd.Name, cmd.RRType)
	delete(zone.Records, key)
	zone.Modified = true

	if z.onUpdate != nil {
		z.onUpdate(cmd.Zone, cmd)
	}

	return nil
}

func (z *ZoneStateMachine) updateRecord(cmd ZoneCommand) error {
	// Delete then add
	if err := z.delRecord(cmd); err != nil {
		return err
	}
	return z.addRecord(cmd)
}

func (z *ZoneStateMachine) deleteZone(cmd ZoneCommand) error {
	if _, ok := z.zones[cmd.Zone]; ok {
		delete(z.zones, cmd.Zone)
	}
	return nil
}

// recordKey creates a lookup key for a record.
func recordKey(name string, rrtype uint16) string {
	return fmt.Sprintf("%s:%d", name, rrtype)
}

// GetZones returns all zones.
func (z *ZoneStateMachine) GetZones() []string {
	z.mu.RLock()
	defer z.mu.RUnlock()

	zones := make([]string, 0, len(z.zones))
	for name := range z.zones {
		zones = append(zones, name)
	}
	return zones
}

// GetRecords returns all records for a zone.
func (z *ZoneStateMachine) GetRecords(zoneName string) []RecordEntry {
	z.mu.RLock()
	defer z.mu.RUnlock()

	zone, ok := z.zones[zoneName]
	if !ok {
		return nil
	}

	var records []RecordEntry
	for _, rrs := range zone.Records {
		records = append(records, rrs...)
	}
	return records
}

// Snapshot returns a snapshot of the current state.
func (z *ZoneStateMachine) Snapshot() ([]byte, error) {
	z.mu.RLock()
	defer z.mu.RUnlock()

	return json.Marshal(z.zones)
}

// Restore restores state from a snapshot.
func (z *ZoneStateMachine) Restore(data []byte) error {
	z.mu.Lock()
	defer z.mu.Unlock()

	return json.Unmarshal(data, &z.zones)
}

// OnUpdate sets a callback for zone updates.
func (z *ZoneStateMachine) OnUpdate(fn func(zone string, cmd ZoneCommand)) {
	z.onUpdate = fn
}
