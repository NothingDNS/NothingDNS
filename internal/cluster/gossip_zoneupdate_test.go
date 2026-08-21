package cluster

import (
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// ============================================================================
// Cluster.handleZoneUpdate (cluster.go:1045) — gossip-side zone replication
//
// This is the receiving-node half of zone replication: peers' gossip
// messages land here and mutate the local zone store. Branches: nil
// zoneManager, "full"/"reload" with valid/invalid/absent RawZone, "add"
// with per-record success and failure, "delete" with well-formed and
// malformed keys, and unknown actions. (The raft-side handlers have their
// own TestHandleZoneUpdate_* suite in coverage_test.go:4894+.)
// ============================================================================

const gossipZoneFixture = `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. hostmaster.example.com. 2024010101 3600 900 604800 86400
@ IN NS ns1.example.com.
ns1 IN A 192.0.2.1
www IN A 192.0.2.2
`

// newGossipZoneCluster builds the minimal Cluster handleZoneUpdate needs:
// a real zone.Manager and a logger (the method Debugf/Warnf on every path).
func newGossipZoneCluster() *Cluster {
	return &Cluster{
		zoneManager: zone.NewManager(),
		logger:      util.DefaultLogger(),
	}
}

// newSeededGossipZoneCluster returns a cluster whose manager already has
// example.com. loaded, for incremental add/delete tests.
func newSeededGossipZoneCluster(t *testing.T) *Cluster {
	t.Helper()
	c := newGossipZoneCluster()
	z, err := zone.ParseFile("example.com.", strings.NewReader(gossipZoneFixture))
	if err != nil {
		t.Fatalf("ParseFile fixture: %v", err)
	}
	c.zoneManager.LoadZone(z, "")
	return c
}

func TestClusterHandleZoneUpdate_NoZoneManager(t *testing.T) {
	c := &Cluster{logger: util.DefaultLogger()} // zoneManager nil
	// Must return without panic on every action shape.
	c.handleZoneUpdate(ZoneUpdatePayload{ZoneName: "example.com.", Action: "full", RawZone: []byte("x")})
	c.handleZoneUpdate(ZoneUpdatePayload{ZoneName: "example.com.", Action: "add"})
}

func TestClusterHandleZoneUpdate_FullReload(t *testing.T) {
	c := newGossipZoneCluster()
	c.handleZoneUpdate(ZoneUpdatePayload{
		ZoneName: "example.com.",
		Action:   "full",
		Serial:   2024010101,
		RawZone:  []byte(gossipZoneFixture),
	})

	z, ok := c.zoneManager.Get("example.com.")
	if !ok {
		t.Fatal("zone not loaded after full update")
	}
	if got := z.Lookup("www.example.com.", "A"); len(got) != 1 {
		t.Errorf("www A records = %d, want 1", len(got))
	}
	// "reload" is the same path — verify it also lands.
	c.handleZoneUpdate(ZoneUpdatePayload{ZoneName: "example.com.", Action: "reload", RawZone: []byte(gossipZoneFixture)})
	if _, ok := c.zoneManager.Get("example.com."); !ok {
		t.Error("zone missing after reload action")
	}
}

func TestClusterHandleZoneUpdate_FullParseError(t *testing.T) {
	c := newGossipZoneCluster()
	c.handleZoneUpdate(ZoneUpdatePayload{
		ZoneName: "example.com.",
		Action:   "full",
		RawZone:  []byte("this is not a zone file"),
	})
	if _, ok := c.zoneManager.Get("example.com."); ok {
		t.Error("zone loaded despite unparseable RawZone")
	}
}

func TestClusterHandleZoneUpdate_FullWithoutRawZone(t *testing.T) {
	c := newSeededGossipZoneCluster(t)
	// nil RawZone: the branch must not touch the store.
	c.handleZoneUpdate(ZoneUpdatePayload{ZoneName: "example.com.", Action: "full"})
	if _, ok := c.zoneManager.Get("example.com."); !ok {
		t.Error("existing zone disturbed by full update without RawZone")
	}
}

func TestClusterHandleZoneUpdate_AddRecords(t *testing.T) {
	c := newSeededGossipZoneCluster(t)
	c.handleZoneUpdate(ZoneUpdatePayload{
		ZoneName: "example.com.",
		Action:   "add",
		Serial:   2024010102,
		Records: []ZoneRecord{
			{Name: "new.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.10"},
			{Name: "alt.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.11"},
		},
	})
	z, _ := c.zoneManager.Get("example.com.")
	if got := z.Lookup("new.example.com.", "A"); len(got) != 1 {
		t.Errorf("added record missing: new.example.com. A = %d, want 1", len(got))
	}
	if got := z.Lookup("alt.example.com.", "A"); len(got) != 1 {
		t.Errorf("added record missing: alt.example.com. A = %d, want 1", len(got))
	}
}

func TestClusterHandleZoneUpdate_AddUnknownZone(t *testing.T) {
	c := newGossipZoneCluster() // no zones loaded
	// AddRecord fails per-record; the loop warns and continues without panic.
	c.handleZoneUpdate(ZoneUpdatePayload{
		ZoneName: "missing.example.",
		Action:   "add",
		Records:  []ZoneRecord{{Name: "a.missing.example.", TTL: 60, Type: "A", RData: "192.0.2.1"}},
	})
	if _, ok := c.zoneManager.Get("missing.example."); ok {
		t.Error("zone materialized from failed add")
	}
}

func TestClusterHandleZoneUpdate_DeleteRecords(t *testing.T) {
	c := newSeededGossipZoneCluster(t)
	c.handleZoneUpdate(ZoneUpdatePayload{
		ZoneName:    "example.com.",
		Action:      "delete",
		Serial:      2024010103,
		DeletedKeys: []string{"www.example.com./A"},
	})
	z, _ := c.zoneManager.Get("example.com.")
	if got := z.Lookup("www.example.com.", "A"); len(got) != 0 {
		t.Errorf("www A records after delete = %d, want 0", len(got))
	}
	// Untouched records survive.
	if got := z.Lookup("ns1.example.com.", "A"); len(got) != 1 {
		t.Errorf("ns1 A records = %d, want 1 (delete must be scoped)", len(got))
	}
}

func TestClusterHandleZoneUpdate_DeleteMalformedKeySkipped(t *testing.T) {
	c := newSeededGossipZoneCluster(t)
	// No '/' in the key: splitKey returns 1 part and the entry is skipped.
	c.handleZoneUpdate(ZoneUpdatePayload{
		ZoneName:    "example.com.",
		Action:      "delete",
		DeletedKeys: []string{"www.example.com."},
	})
	z, _ := c.zoneManager.Get("example.com.")
	if got := z.Lookup("www.example.com.", "A"); len(got) != 1 {
		t.Errorf("record removed by malformed key: www A = %d, want 1", len(got))
	}
}

func TestClusterHandleZoneUpdate_UnknownActionIgnored(t *testing.T) {
	c := newSeededGossipZoneCluster(t)
	c.handleZoneUpdate(ZoneUpdatePayload{ZoneName: "example.com.", Action: "nonsense"})
	z, ok := c.zoneManager.Get("example.com.")
	if !ok {
		t.Fatal("zone missing after unknown action")
	}
	if got := z.Lookup("www.example.com.", "A"); len(got) != 1 {
		t.Errorf("store mutated by unknown action: www A = %d, want 1", len(got))
	}
}
