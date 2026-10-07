package cluster

import (
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cluster/raft"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func f418Manager(t *testing.T) *zone.Manager {
	t.Helper()
	m := zone.NewManager()
	m.LoadZone(zoneHooksTestZone(t, "a.example.", "192.0.2.1"), "")
	for _, ip := range []string{"192.0.2.10", "192.0.2.11"} {
		if err := m.AddRecord("a.example.", zone.Record{Name: "www", Type: "A", TTL: 60, RData: ip}); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func f418WWW(m *zone.Manager) []string {
	recs, _ := m.GetRecords("a.example.", "www")
	var out []string
	for _, r := range recs {
		if r.Type == "A" {
			out = append(out, r.RData)
		}
	}
	return out
}

// F418: a committed del_record carrying RData removes only that RR on every
// replica; an old-format del_record (no RData, as written by earlier
// releases and still present in existing Raft logs) removes the whole RRset.
func TestApplyRaftZoneCommand_F418_PerRecordDelete(t *testing.T) {
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)

	t.Run("old format deletes the RRset", func(t *testing.T) {
		m := f418Manager(t)
		c := &Cluster{zoneManager: m, logger: logger}
		c.applyRaftZoneCommand(raft.ZoneCommand{Type: "del_record", Zone: "a.example.", Name: "www", RRTypeStr: "A"})
		if got := f418WWW(m); len(got) != 0 {
			t.Fatalf("remaining = %v, want none", got)
		}
	})

	t.Run("RData deletes one RR, identically on every replica", func(t *testing.T) {
		cmd := raft.ZoneCommand{Type: "del_record", Zone: "A.EXAMPLE", Name: "WWW.a.example.", RRTypeStr: "a", RData: []string{"192.0.2.10"}}
		for i := 0; i < 3; i++ { // three replicas applying the same entry
			m := f418Manager(t)
			c := &Cluster{zoneManager: m, logger: logger}
			c.applyRaftZoneCommand(cmd)
			if got := f418WWW(m); len(got) != 1 || got[0] != "192.0.2.11" {
				t.Fatalf("replica %d remaining = %v, want [192.0.2.11]", i, got)
			}
			// Re-applying the same entry (e.g. replay) is a logged no-op.
			c.applyRaftZoneCommand(cmd)
			if got := f418WWW(m); len(got) != 1 {
				t.Fatalf("replica %d replay changed state: %v", i, got)
			}
		}
	})

	t.Run("blank RData keeps the old meaning", func(t *testing.T) {
		m := f418Manager(t)
		c := &Cluster{zoneManager: m, logger: logger}
		c.applyRaftZoneCommand(raft.ZoneCommand{Type: "del_record", Zone: "a.example.", Name: "www", RRTypeStr: "A", RData: []string{""}})
		if got := f418WWW(m); len(got) != 0 {
			t.Fatalf("remaining = %v, want none", got)
		}
	})
}

// F418: ProposeDeleteRecordData through a started single-node Raft cluster
// commits, applies via the apply hook, and leaves the sibling RR in place.
func TestProposeDeleteRecordData_F418_SingleNodeRaft(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a single-node Raft cluster")
	}
	m := f418Manager(t)
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
	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer c.Stop()

	deadline := time.Now().Add(10 * time.Second)
	for !c.raft.IsLeader() {
		if time.Now().After(deadline) {
			t.Fatal("single-node Raft never became leader")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := c.ProposeDeleteRecordData("a.example.", "www", "A", ""); err == nil {
		t.Fatal("blank data accepted by ProposeDeleteRecordData")
	}
	if err := c.ProposeDeleteRecordData("a.example.", "www", "A", "192.0.2.10"); err != nil {
		t.Fatalf("ProposeDeleteRecordData: %v", err)
	}
	if got := f418WWW(m); len(got) != 1 || got[0] != "192.0.2.11" {
		t.Fatalf("after per-record delete remaining = %v, want [192.0.2.11]", got)
	}
	// Whole-RRset delete still works through the same command type.
	if err := c.ProposeDeleteRecord("a.example.", "www", "A"); err != nil {
		t.Fatalf("ProposeDeleteRecord: %v", err)
	}
	if got := f418WWW(m); len(got) != 0 {
		t.Fatalf("after RRset delete remaining = %v, want none", got)
	}
}
