package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// Round-2 proof: internal/api/api_zones.go handleBulkPTR mutates the zone
// store directly (zoneManager.AddRecord / DeleteRecord) instead of routing
// the write through proposeZoneWrite -> cluster.Propose*, which every other
// zone-mutating API handler does. In Raft mode the bulk write therefore lands
// only on the receiving node's local zone store and is never replicated to the
// rest of the cluster — a silent, non-leader-accepting divergence that the
// sibling endpoints explicitly prevent (they return 421 and mutate nothing).
//
// CLAIM: with a Raft-mode cluster attached, a bulk-PTR apply must not change
// the local zone store.
// CONTROL 1 (sibling contract): a single-record POST on the same Raft-mode
// server is proposed (no local mutation, 421 from proposeZoneWrite).
// CONTROL 2 (standalone path): with no cluster, a bulk-PTR still applies.

func ptrBulkServer(t *testing.T, withCluster bool) *Server {
	t.Helper()

	zm := zone.NewManager()
	origin := "2.0.192.in-addr.arpa."
	if err := zm.CreateZone(origin, 3600, &zone.SOARecord{
		Name:    origin,
		TTL:     3600,
		MName:   "ns1.example.com.",
		RName:   "hostmaster.example.com.",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minimum: 86400,
	}, []zone.NSRecord{{Name: origin, TTL: 3600, NSDName: "ns1.example.com."}}); err != nil {
		t.Fatalf("CreateZone(%s): %v", origin, err)
	}

	c := cache.New(cache.Config{Capacity: 200, MinTTL: 60, MaxTTL: 3600, DefaultTTL: 300})
	srv := NewServer(config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}, zm, c, nil, nil, nil, nil)

	if withCluster {
		srv.cluster = newRaftModeCluster(t) // Raft mode, never started => not leader
	}
	attachTestAuth(srv)
	return srv
}

func doBulkPTR(t *testing.T, srv *Server, zoneName string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"cidr":"192.0.2.0/30","pattern":"host-[A]-[B]-[C]-[D]"}`
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/zones/"+zoneName+"/ptr-bulk", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = withTestAdminAuth(req, "")
	rec := httptest.NewRecorder()
	srv.handleZoneActions(rec, req)
	return rec
}

func countPTRs(t *testing.T, srv *Server, zoneName string) int {
	t.Helper()
	z, ok := srv.zoneManager.Get(zoneName)
	if !ok {
		t.Fatalf("zone %s not found in local store", zoneName)
	}
	return len(z.RecordsByType("PTR"))
}

// CLAIM: on a Raft-mode node, handleBulkPTR must not mutate the local zone
// store directly. The mutation is unreplicated cluster divergence; it belongs
// behind proposeZoneWrite like every sibling zone write.
func TestBulkPTR_RaftMode_DoesNotMutateLocalStore(t *testing.T) {
	zoneName := "2.0.192.in-addr.arpa."
	srv := ptrBulkServer(t, true)

	before := countPTRs(t, srv, zoneName)
	rec := doBulkPTR(t, srv, zoneName)
	after := countPTRs(t, srv, zoneName)

	if after != before {
		t.Errorf("FAIL: Raft-mode bulk PTR applied %d record(s) directly to the local zone store "+
			"(before=%d after=%d, status=%d). Such a write is never replicated to the cluster; "+
			"every other zone mutation routes through proposeZoneWrite.",
			after-before, before, after, rec.Code)
	}
}

// CONTROL 1: the sibling single-record endpoint on the same Raft-mode server
// already proposes instead of mutating locally. Unchanged behavior that proves
// the harness models a real Raft follower and that the contract is "propose, do
// not mutate locally".
func TestBulkPTR_Control_SiblingAddRecordProposes(t *testing.T) {
	zoneName := "2.0.192.in-addr.arpa."
	srv := ptrBulkServer(t, true)

	before := countPTRs(t, srv, zoneName)
	body := `{"name":"5","type":"PTR","data":"host-5.example.com."}`
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/zones/"+zoneName+"/records", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = withTestAdminAuth(req, "")
	rec := httptest.NewRecorder()
	srv.handleZoneActions(rec, req)

	after := countPTRs(t, srv, zoneName)
	if after != before {
		t.Errorf("CONTROL FAILED: sibling single-record add mutated local store in Raft mode "+
			"(before=%d after=%d); expected it to route through consensus", before, after)
	}
	if rec.Code == http.StatusOK {
		t.Errorf("CONTROL FAILED: expected non-200 (421/503) from a non-leader Raft propose, got %d", rec.Code)
	}
}

// CONTROL 2: with no cluster attached, the standalone bulk-PTR path must still
// apply records locally (the fix must not break single-node operation).
func TestBulkPTR_Control_StandaloneStillApplies(t *testing.T) {
	zoneName := "2.0.192.in-addr.arpa."
	srv := ptrBulkServer(t, false)

	before := countPTRs(t, srv, zoneName)
	rec := doBulkPTR(t, srv, zoneName)
	after := countPTRs(t, srv, zoneName)

	if rec.Code != http.StatusOK {
		t.Fatalf("standalone bulk PTR failed: status=%d body=%q", rec.Code, rec.Body.String())
	}
	if after <= before {
		t.Errorf("CONTROL FAILED: standalone bulk PTR applied no records (before=%d after=%d); "+
			"the cluster-less path must still mutate locally", before, after)
	}
	var res BulkPTRResultResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode bulk PTR result: %v (body=%q)", err, rec.Body.String())
	}
	if res.Added == 0 {
		t.Errorf("CONTROL FAILED: expected Added>0 in result, got %+v", res)
	}
}

// Guard: the /30 CIDR in this fixture must yield 4 PTR names, so a passing
// CLAIM test above cannot be vacuous (i.e. it is not passing simply because
// the request was rejected before producing any change).
func TestBulkPTR_FixtureProducesRecords(t *testing.T) {
	zoneName := "2.0.192.in-addr.arpa."
	srv := ptrBulkServer(t, false)
	rec := doBulkPTR(t, srv, zoneName)
	if rec.Code != http.StatusOK {
		t.Fatalf("fixture bulk PTR failed: %d %q", rec.Code, rec.Body.String())
	}
	var res BulkPTRResultResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Added != 4 {
		t.Errorf("fixture: expected 4 PTR records from a /30, got Added=%d", res.Added)
	}
	// Confirm the pattern actually expanded to distinct per-IP names in the
	// zone store, so the /30 fixture is genuinely producing four different
	// owners (guards against a vacuous CLAIM that passes only because the
	// request was rejected before any change).
	z, ok := srv.zoneManager.Get(zoneName)
	if !ok {
		t.Fatalf("fixture: zone %s missing", zoneName)
	}
	owners := map[string]bool{}
	for _, rec := range z.RecordsByType("PTR") {
		owners[rec.RData] = true
	}
	if len(owners) != 4 {
		t.Errorf("fixture: expected 4 distinct PTR targets from pattern expansion, got %d: %v", len(owners), owners)
	}
	_ = auth.RoleOperator // keep auth import referenced for role type clarity
}
