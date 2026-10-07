package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cluster"
	"github.com/nothingdns/nothingdns/internal/util"
)

// f419Exercise runs the per-record delete contract against a fixture (direct
// or Raft-routed).
func f419Exercise(t *testing.T, f *zoneRecordAPIFixture) {
	t.Helper()
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		f.expect("POST A "+ip, f.do(http.MethodPost, map[string]any{"name": "www", "type": "A", "data": ip}), http.StatusCreated)
	}
	f.expect("POST MX", f.do(http.MethodPost, map[string]any{"name": "mail", "type": "MX", "data": "10 mx1.example.com."}), http.StatusCreated)
	f.expect("POST MX2", f.do(http.MethodPost, map[string]any{"name": "mail", "type": "MX", "data": "20 mx2.example.com."}), http.StatusCreated)

	// Exactly one RR goes; owner name and type matched case-insensitively.
	f.expect("DELETE one A", f.do(http.MethodDelete, map[string]any{"name": "WWW.Example.COM.", "type": "a", "data": "192.0.2.2"}), http.StatusOK)
	var left []string
	for _, r := range f.records("www") {
		left = append(left, r.RData)
	}
	if len(left) != 2 || left[0] != "192.0.2.1" || left[1] != "192.0.2.3" {
		t.Fatalf("A RRset after single delete = %v, want [192.0.2.1 192.0.2.3]", left)
	}
	// Canonical RDATA comparison: target names are case-insensitive.
	f.expect("DELETE MX by canonical data", f.do(http.MethodDelete, map[string]any{"name": "mail", "type": "MX", "data": "10 MX1.Example.Com."}), http.StatusOK)
	if recs := f.records("mail"); len(recs) != 1 || recs[0].RData != "20 mx2.example.com." {
		t.Fatalf("MX RRset = %v, want only 20 mx2", recs)
	}
	// Already-deleted / unknown data: 404, nothing changes.
	f.expect("DELETE gone", f.do(http.MethodDelete, map[string]any{"name": "www", "type": "A", "data": "192.0.2.2"}), http.StatusNotFound)
	if n := len(f.records("www")); n != 2 {
		t.Fatalf("404 delete changed www: %d records", n)
	}
	// R44 F268 protections are unchanged, with or without data.
	f.expect("DELETE apex NS with data", f.do(http.MethodDelete, map[string]any{"name": "@", "type": "NS", "data": "ns1.example.com."}), http.StatusBadRequest)
	f.expect("DELETE SOA with data", f.do(http.MethodDelete, map[string]any{"name": "@", "type": "SOA", "data": "x"}), http.StatusBadRequest)
	// No data: the whole RRset still goes.
	f.expect("DELETE RRset", f.do(http.MethodDelete, map[string]any{"name": "www", "type": "A"}), http.StatusOK)
	if n := len(f.records("www")); n != 0 {
		t.Fatalf("RRset delete left %d records", n)
	}
	f.zoneFileParses()
}

// F419: DELETE /records with data removes exactly one RR (direct mode).
func TestZoneRecordAPI_F419_PerRecordDeleteDirect(t *testing.T) {
	f419Exercise(t, newZoneRecordAPIFixture(t))
}

// F419: the same contract when the write is replicated through a started
// single-node Raft cluster (ProposeDeleteRecordData → apply hook → zone store).
func TestZoneRecordAPI_F419_PerRecordDeleteRaft(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a single-node Raft cluster")
	}
	f := newZoneRecordAPIFixture(t)
	c, err := cluster.New(cluster.Config{
		Enabled:              true,
		AllowInsecureCluster: true,
		NodeID:               "f419-node",
		BindAddr:             "127.0.0.1",
		GossipPort:           0,
		ConsensusMode:        cluster.ConsensusRaft,
		DataDir:              t.TempDir(),
		Peers:                []cluster.PeerConfig{{NodeID: "f419-node", Addr: "127.0.0.1:0"}},
		ZoneManager:          f.s.zoneManager,
	}, util.NewLogger(util.ERROR, util.TextFormat, nil), nil)
	if err != nil {
		t.Fatalf("cluster.New: %v", err)
	}
	if err := c.Start(); err != nil {
		t.Fatalf("cluster.Start: %v", err)
	}
	defer c.Stop()
	deadline := time.Now().Add(10 * time.Second)
	for c.RaftLeaderID() != "f419-node" {
		if time.Now().After(deadline) {
			t.Fatal("single-node Raft never elected itself")
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.s.cluster = c
	f419Exercise(t, f)
}
