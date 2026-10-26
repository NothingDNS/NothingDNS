package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/cluster"
	"github.com/nothingdns/nothingdns/internal/util"
)

// soaRequest sends method to /api/v1/zones/{zone}/soa as the fixture's user.
func soaRequest(t *testing.T, s *Server, user *auth.User, method, zoneName string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "/api/v1/zones/"+zoneName+"/soa", rd)
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()
	s.handleZoneActions(rec, req)
	return rec
}

func decodeSOA(t *testing.T, rec *httptest.ResponseRecorder) SOADetail {
	t.Helper()
	var d SOADetail
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatalf("decode SOA response %q: %v", rec.Body.String(), err)
	}
	return d
}

// soaExercise runs the #19 SOA edit contract against a fixture (direct or
// Raft-routed).
func soaExercise(t *testing.T, f *zoneRecordAPIFixture, user *auth.User) {
	t.Helper()
	rec := soaRequest(t, f.s, user, http.MethodGet, "example.com.", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET soa: %d %s", rec.Code, rec.Body.String())
	}
	before := decodeSOA(t, rec)
	if before.TTL != 3600 || before.Minimum != 86400 || before.RName != "admin.example.com." {
		t.Fatalf("GET soa = %+v", before)
	}

	rec = soaRequest(t, f.s, user, http.MethodPut, "example.com.", map[string]any{
		"rname": "dns@example.org", "minimum": 300, "refresh": 7200, "retry": 900, "ttl": 600,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT soa: %d %s", rec.Code, rec.Body.String())
	}
	after := decodeSOA(t, rec)
	if after.RName != "dns.example.org." || after.Minimum != 300 || after.Refresh != 7200 ||
		after.Retry != 900 || after.TTL != 600 || after.Expire != before.Expire || after.MName != before.MName {
		t.Fatalf("PUT soa = %+v", after)
	}
	if after.Serial == before.Serial {
		t.Fatalf("serial not bumped: %d", after.Serial)
	}
	f.zoneFileParses()

	// Invalid edits are 400 and change nothing.
	for name, body := range map[string]map[string]any{
		"empty":               {},
		"serial":              {"serial": 5},
		"retry >= refresh":    {"retry": 7200},
		"expire <= refresh":   {"expire": 60},
		"negative":            {"minimum": -1},
		"bad email":           {"rname": "john.doe@example.com"},
		"unknown field":       {"minimum_ttl": 300},
		"ttl beyond 2^31 - 1": {"ttl": 1 << 31},
	} {
		if rec := soaRequest(t, f.s, user, http.MethodPut, "example.com.", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (%s)", name, rec.Code, rec.Body.String())
		}
	}
	if got := decodeSOA(t, soaRequest(t, f.s, user, http.MethodGet, "example.com.", nil)); got != after {
		t.Fatalf("rejected edits changed the SOA: %+v -> %+v", after, got)
	}

	if rec := soaRequest(t, f.s, user, http.MethodPut, "missing.example.", map[string]any{"minimum": 300}); rec.Code != http.StatusNotFound {
		t.Fatalf("missing zone: status %d, want 404", rec.Code)
	}
	if rec := soaRequest(t, f.s, user, http.MethodDelete, "example.com.", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE soa: status %d, want 405", rec.Code)
	}
}

func TestZoneSOAAPI_EditDirect(t *testing.T) {
	f := newZoneRecordAPIFixture(t)
	_, user := newServerWithAuthAndZones(t)
	soaExercise(t, f, user)
}

func TestZoneSOAAPI_EditRaft(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a single-node Raft cluster")
	}
	f := newZoneRecordAPIFixture(t)
	_, user := newServerWithAuthAndZones(t)
	c, err := cluster.New(cluster.Config{
		Enabled:              true,
		AllowInsecureCluster: true,
		NodeID:               "soa-node",
		BindAddr:             "127.0.0.1",
		GossipPort:           0,
		ConsensusMode:        cluster.ConsensusRaft,
		DataDir:              t.TempDir(),
		Peers:                []cluster.PeerConfig{{NodeID: "soa-node", Addr: "127.0.0.1:0"}},
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
	for c.RaftLeaderID() != "soa-node" {
		if time.Now().After(deadline) {
			t.Fatal("single-node Raft never elected itself")
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.s.cluster = c
	soaExercise(t, f, user)
}

// POST /api/v1/zones takes optional SOA timers (#19).
func TestCreateZone_SOATimers(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	create := func(body map[string]any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/zones", bytes.NewReader(b))
		req = req.WithContext(WithUser(req.Context(), user))
		rec := httptest.NewRecorder()
		s.handleZones(rec, req)
		return rec
	}
	rec := create(map[string]any{"name": "t.example.", "nameservers": []string{"ns1.t.example."},
		"refresh": 7200, "retry": 900, "expire": 1209600, "minimum": 300})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	soa, err := s.zoneManager.SOA("t.example.")
	if err != nil {
		t.Fatal(err)
	}
	if soa.Refresh != 7200 || soa.Retry != 900 || soa.Expire != 1209600 || soa.Minimum != 300 || soa.RName != "hostmaster.t.example." {
		t.Fatalf("SOA = %+v", soa)
	}

	// Omitted timers keep the defaults; inconsistent ones are refused.
	if rec := create(map[string]any{"name": "u.example.", "nameservers": []string{"ns1.u.example."}, "minimum": 60}); rec.Code != http.StatusCreated {
		t.Fatalf("create with minimum only: %d %s", rec.Code, rec.Body.String())
	}
	if soa, _ := s.zoneManager.SOA("u.example."); soa.Refresh != 3600 || soa.Retry != 600 || soa.Minimum != 60 {
		t.Fatalf("SOA = %+v", soa)
	}
	if rec := create(map[string]any{"name": "v.example.", "nameservers": []string{"ns1.v.example."}, "retry": 3600}); rec.Code != http.StatusBadRequest {
		t.Fatalf("retry == refresh: %d, want 400", rec.Code)
	}
	if _, ok := s.zoneManager.Get("v.example."); ok {
		t.Fatal("refused zone was created")
	}
}
