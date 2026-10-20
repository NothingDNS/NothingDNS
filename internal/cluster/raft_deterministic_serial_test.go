package cluster

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/cluster/raft"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// Every replica applies the same Raft log, so the SOA serial a committed zone
// command produces must depend only on the zone and the log. The date-style
// bump of zone.IncrementSerial reads the local wall clock, so replicas applying
// the same entry on different days (or a replay after a restart) disagreed on
// the serial. A Raft-mode cluster makes its zone manager bump by plain RFC 1982
// increment instead.
func TestRaftModeClusterBumpsSerialsDeterministically(t *testing.T) {
	m := zone.NewManager()
	m.LoadZone(zoneHooksTestZone(t, "a.example.", "192.0.2.1"), "")
	c, err := New(Config{
		Enabled:              true,
		AllowInsecureCluster: true,
		NodeID:               "n1",
		BindAddr:             "127.0.0.1",
		GossipPort:           0,
		ConsensusMode:        ConsensusRaft,
		DataDir:              t.TempDir(),
		Peers:                []PeerConfig{{NodeID: "n1", Addr: "127.0.0.1:0"}},
		ZoneManager:          m,
	}, util.NewLogger(util.ERROR, util.TextFormat, nil), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	serial := func() uint32 {
		z, _ := m.Get("a.example.")
		z.RLock()
		defer z.RUnlock()
		return z.SOA.Serial
	}
	add := func(name, ip string) {
		c.applyRaftZoneCommand(raft.ZoneCommand{Type: "add_record", Zone: "a.example.", Name: name, RRTypeStr: "A", Class: "IN", TTL: 60, RData: []string{ip}})
	}

	start := serial()
	add("w1", "192.0.2.10")
	add("w2", "192.0.2.11")
	c.applyRaftZoneCommand(raft.ZoneCommand{Type: "del_record", Zone: "a.example.", Name: "w1", RRTypeStr: "A", RData: []string{"192.0.2.10"}})
	c.applyRaftZoneCommand(raft.ZoneCommand{Type: "update_record", Zone: "a.example.", Name: "w2", RRTypeStr: "A", OldData: "192.0.2.11", Class: "IN", TTL: 60, RData: []string{"192.0.2.12"}})
	if got, want := serial(), start+4; got != want {
		t.Fatalf("FAIL: serial after 4 applied commands = %d, want %d (start %d + 4, independent of the clock)", got, want, start)
	}

	// The SOA record in the zone data carries the same serial as the SOA state.
	recs, _ := m.GetRecords("a.example.", "a.example.")
	for _, r := range recs {
		if r.Type == "SOA" {
			if want := "ns1.a.example. hostmaster.a.example. 5 "; len(r.RData) < len(want) || r.RData[:len(want)] != want {
				t.Fatalf("SOA RDATA = %q, want it to carry serial 5", r.RData)
			}
		}
	}
}
