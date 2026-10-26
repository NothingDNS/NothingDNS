package cluster

import (
	"encoding/json"
	"fmt"

	"github.com/nothingdns/nothingdns/internal/cluster/raft"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// SOA edits through Raft (#19).
//
// Wire format / rolling upgrade: like a zone batch (zone_batch.go), an SOA
// edit travels as a "create_zone" ZoneCommand without nameservers, with the
// edit in Metadata ({"zone_soa":{...}}), because a new command type would
// wedge the apply loop of an older node. A node that predates SOA edits logs
// "create_zone for <zone> missing nameservers" and keeps its old SOA until
// it next installs a snapshot, so every node must run a build with SOA edits
// before one is made.
//
// The same payload on a create_zone WITH nameservers carries the SOA timers
// of the new zone. An older node creates the zone with the default timers.

// zoneSOAVersion is the payload version this build produces and applies.
const zoneSOAVersion = 1

type zoneSOAPayload struct {
	V      int            `json:"v"`
	ID     string         `json:"id,omitempty"`
	Update zone.SOAUpdate `json:"update"`
}

type zoneSOAEnvelope struct {
	SOA *zoneSOAPayload `json:"zone_soa"`
}

// ProposeUpdateSOA replicates an SOA edit of zoneName as one Raft entry and
// waits for it to be applied locally. It returns nil only if the edit was
// applied; a validation error from the apply (the zone changed since the
// caller checked it) means nothing changed on any replica. *raft.ErrNotLeader
// is returned on a follower.
func (c *Cluster) ProposeUpdateSOA(zoneName string, u zone.SOAUpdate) error {
	if !c.IsRaftMode() {
		return fmt.Errorf("cluster is not in Raft mode")
	}
	if normalizeClusterZoneName(zoneName) == "" {
		return fmt.Errorf("zone name is required")
	}
	if u.IsEmpty() {
		return fmt.Errorf("no SOA field to update")
	}
	id, err := newZoneBatchID()
	if err != nil {
		return err
	}
	meta, err := json.Marshal(zoneSOAEnvelope{SOA: &zoneSOAPayload{V: zoneSOAVersion, ID: id, Update: u}})
	if err != nil {
		return fmt.Errorf("marshal SOA update: %w", err)
	}

	// SOA edits share the batch waiters: the ids are random and unique.
	ch := c.zoneBatches.register(id)
	defer c.zoneBatches.unregister(id)
	if err := c.proposeZoneChange(raft.ZoneCommand{Type: "create_zone", Zone: zoneName, Metadata: meta}); err != nil {
		return err
	}
	select {
	case res := <-ch:
		return res
	default:
		return fmt.Errorf("SOA update %s: committed but its apply result was not observed", id)
	}
}

// ProposeCreateZoneSOA replicates a zone creation whose SOA takes the fields
// soa sets (refresh, retry, expire, minimum) instead of the defaults.
func (c *Cluster) ProposeCreateZoneSOA(name string, ttl uint32, adminEmail string, nameservers []string, soa zone.SOAUpdate) error {
	cmd := raft.ZoneCommand{
		Type: "create_zone", Zone: name, TTL: ttl,
		AdminEmail: adminEmail, Nameservers: nameservers,
	}
	if !soa.IsEmpty() {
		meta, err := json.Marshal(zoneSOAEnvelope{SOA: &zoneSOAPayload{V: zoneSOAVersion, Update: soa}})
		if err != nil {
			return fmt.Errorf("marshal SOA fields: %w", err)
		}
		cmd.Metadata = meta
	}
	return c.proposeZoneChange(cmd)
}

// decodeZoneSOA reports whether cmd carries an SOA payload and, if so,
// returns it (nil with ok=true when the payload is malformed).
func decodeZoneSOA(cmd raft.ZoneCommand) (p *zoneSOAPayload, ok bool, err error) {
	if cmd.Type != "create_zone" || len(cmd.Metadata) == 0 {
		return nil, false, nil
	}
	var env zoneSOAEnvelope
	if err := json.Unmarshal(cmd.Metadata, &env); err != nil {
		return nil, true, fmt.Errorf("decode SOA update: %w", err)
	}
	if env.SOA == nil {
		return nil, false, nil
	}
	if env.SOA.V != zoneSOAVersion {
		return env.SOA, true, fmt.Errorf("SOA update version %d not supported by this node", env.SOA.V)
	}
	return env.SOA, true, nil
}

// applyZoneSOACommand is the apply-hook branch for an SOA edit (a create_zone
// envelope without nameservers).
func (c *Cluster) applyZoneSOACommand(cmd raft.ZoneCommand, p *zoneSOAPayload, decodeErr error) {
	err := decodeErr
	if err == nil {
		_, err = c.zoneManager.UpdateSOA(cmd.Zone, p.Update)
	}
	if err != nil {
		c.logger.Warnf("raft apply: SOA update on zone %s rejected, nothing applied: %v", cmd.Zone, err)
	}
	if p != nil && p.ID != "" {
		c.zoneBatches.deliver(p.ID, err)
	}
}
