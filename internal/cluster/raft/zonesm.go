package raft

import (
	"encoding/json"
	"fmt"
	"sync"
)

// ZoneCommand represents a zone mutation command replicated through Raft.
type ZoneCommand struct {
	Type   string `json:"type"` // "add_record", "del_record", "update_record", "create_zone", "delete_zone"
	Zone   string `json:"zone"`
	Name   string `json:"name,omitempty"`
	RRType uint16 `json:"rrtype,omitempty"`
	// RRTypeStr carries the textual record type ("A", "AAAA", …) so the
	// zone-store apply path is lossless (the store keys records by string
	// type, not the numeric RRType used by the in-memory ledger).
	RRTypeStr string   `json:"rrtype_str,omitempty"`
	Class     string   `json:"class,omitempty"`
	TTL       uint32   `json:"ttl,omitempty"`
	RData     []string `json:"rdata,omitempty"`
	// OldData identifies the record being replaced by update_record.
	OldData string `json:"old_data,omitempty"`
	// AdminEmail / Nameservers carry the parameters needed to rebuild a zone
	// for create_zone.
	AdminEmail  string          `json:"admin_email,omitempty"`
	Nameservers []string        `json:"nameservers,omitempty"`
	Priority    int             `json:"priority,omitempty"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
}

// ZoneStateMachine is the state machine that applies Raft log entries to zone data.
type ZoneStateMachine struct {
	mu       sync.RWMutex
	zones    map[string]*ZoneData
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
	case "create_zone":
		// The in-memory ledger doesn't model empty zones (records are added
		// lazily); the real zone store handles creation via the apply hook.
		return nil
	case "delete_zone":
		return z.deleteZone(cmd)
	default:
		return fmt.Errorf("unknown command type: %s", cmd.Type)
	}
}

func (z *ZoneStateMachine) addRecord(cmd ZoneCommand) error {
	if len(cmd.RData) == 0 {
		return fmt.Errorf("add_record requires RData")
	}

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
		RData:  []byte(cmd.RData[0]),
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
	delete(z.zones, cmd.Zone)
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

// reset drops all ledger state. Called after a snapshot install: the
// snapshot bypassed this ledger (it restores the real zone store), so
// whatever the ledger held predates the snapshot and must not be served.
func (sm *ZoneStateMachine) reset() {
	if sm == nil {
		return
	}
	sm.mu.Lock()
	sm.zones = make(map[string]*ZoneData)
	sm.mu.Unlock()
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
		for _, record := range rrs {
			// RecordEntry contains a byte slice. Copy it as well as the struct so
			// callers cannot mutate replicated ledger state after the read lock
			// is released (or race a concurrent Snapshot/Apply).
			record.RData = append([]byte(nil), record.RData...)
			records = append(records, record)
		}
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
//
// Unmarshals into a fresh map and only swaps it into place on
// success. The previous implementation passed &z.zones directly
// to Unmarshal, which leaves the map partially populated if
// Unmarshal errors out mid-way (e.g. a truncated payload that
// successfully decoded the first three zones before hitting bad
// data on the fourth). The Raft snapshot-install handler in
// raft.go now refuses to advance lastApplied when Restore fails,
// but only if Restore actually returns an error — and if we'd
// already mutated z.zones before erroring, the state machine
// holds half the new snapshot plus all of the old one.
func (z *ZoneStateMachine) Restore(data []byte) error {
	var newZones map[string]*ZoneData
	if err := json.Unmarshal(data, &newZones); err != nil {
		return err
	}
	if newZones == nil {
		return fmt.Errorf("snapshot contains a null zone map")
	}
	for name, zone := range newZones {
		if zone == nil {
			return fmt.Errorf("snapshot contains a null zone for %q", name)
		}
		if zone.Records == nil {
			return fmt.Errorf("snapshot contains a null records map for %q", name)
		}
	}

	z.mu.Lock()
	z.zones = newZones
	z.mu.Unlock()
	return nil
}

// OnUpdate sets a callback for zone updates.
// Mutates z.onUpdate under the state-machine lock so it can be called
// safely while applyCommand goroutines are reading the field. Without
// this guard a SetOnUpdate racing with an in-flight Apply would
// be a Go data race (the function-value word is non-atomic).
func (z *ZoneStateMachine) OnUpdate(fn func(zone string, cmd ZoneCommand)) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.onUpdate = fn
}
