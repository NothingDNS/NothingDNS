package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/zone"
)

// zoneRecordAPIFixture serves /api/v1/zones/example.com./records for an admin
// against a zone persisted to a temporary zone_dir.
type zoneRecordAPIFixture struct {
	t   *testing.T
	s   *Server
	do  func(method string, body map[string]any) int
	dir string
}

func newZoneRecordAPIFixture(t *testing.T) *zoneRecordAPIFixture {
	t.Helper()
	s, user := newServerWithAuthAndZones(t)
	dir := t.TempDir()
	s.zoneManager.SetZoneDir(dir)
	createTestZone(t, s.zoneManager, "example.com.")
	f := &zoneRecordAPIFixture{t: t, s: s, dir: dir}
	f.do = func(method string, body map[string]any) int {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(method, "/api/v1/zones/example.com./records", bytes.NewReader(b))
		req = req.WithContext(WithUser(req.Context(), user))
		rec := httptest.NewRecorder()
		s.handleZoneActions(rec, req)
		return rec.Code
	}
	return f
}

func (f *zoneRecordAPIFixture) records(name string) []zone.Record {
	recs, _ := f.s.zoneManager.GetRecords("example.com.", name)
	return recs
}

func (f *zoneRecordAPIFixture) expect(what string, got, want int) {
	f.t.Helper()
	if got != want {
		f.t.Fatalf("%s: status %d, want %d", what, got, want)
	}
}

// The zone file written for API mutations must stay loadable: startup aborts
// on any zone-file parse error (F267).
func (f *zoneRecordAPIFixture) zoneFileParses() {
	f.t.Helper()
	path := filepath.Join(f.dir, "example.com.zone")
	fh, err := os.Open(path)
	if err != nil {
		f.t.Fatalf("open zone file: %v", err)
	}
	defer fh.Close()
	if _, err := zone.ParseFile(path, fh); err != nil {
		f.t.Fatalf("zone file no longer parses: %v", err)
	}
}

func TestZoneRecordAPI_F267_RejectsRecordsTheZoneFileCannotReload(t *testing.T) {
	f := newZoneRecordAPIFixture(t)
	f.expect("POST unknown type", f.do(http.MethodPost, map[string]any{"name": "h", "type": "FOO", "data": "x"}), http.StatusBadRequest)
	f.expect("POST TYPEnnn", f.do(http.MethodPost, map[string]any{"name": "h", "type": "TYPE65", "data": "x"}), http.StatusBadRequest)
	if len(f.records("h")) != 0 {
		t.Fatalf("rejected record was stored: %v", f.records("h"))
	}
	for _, rr := range [][2]string{
		{"A", "192.0.2.1"}, {"MX", "10 mail"}, {"TXT", `"v=spf1 -all"`},
		{"CAA", `0 issue "letsencrypt.org"`}, {"SRV", "1 2 443 h.example.com."}, {"HTTPS", "1 . alpn=h2"},
	} {
		f.expect("POST "+rr[0], f.do(http.MethodPost, map[string]any{"name": "ok-" + strings.ToLower(rr[0]), "type": rr[0], "data": rr[1]}), http.StatusCreated)
	}
	f.expect("POST lowercase type", f.do(http.MethodPost, map[string]any{"name": "lc", "type": "aaaa", "data": "2001:db8::1"}), http.StatusCreated)
	if recs := f.records("lc"); len(recs) != 1 || recs[0].Type != "AAAA" {
		t.Fatalf("lowercase type not normalized: %v", recs)
	}
	f.expect("PUT to unknown type", f.do(http.MethodPut, map[string]any{"name": "ok-a", "type": "FOO", "old_data": "192.0.2.1", "data": "x"}), http.StatusBadRequest)
	f.zoneFileParses()
}

func TestZoneRecordAPI_F268_SOAAndApexNSAreNotMutableAsRecords(t *testing.T) {
	f := newZoneRecordAPIFixture(t)
	z, _ := f.s.zoneManager.Get("example.com.")
	var soa string
	for _, r := range f.records("@") {
		if r.Type == "SOA" {
			soa = r.RData
		}
	}
	newSOA := strings.Replace(soa, " 3600 600 ", " 7200 600 ", 1)
	f.expect("PUT SOA", f.do(http.MethodPut, map[string]any{"name": "@", "type": "SOA", "old_data": soa, "data": newSOA}), http.StatusBadRequest)
	f.expect("POST SOA", f.do(http.MethodPost, map[string]any{"name": "@", "type": "SOA", "data": newSOA}), http.StatusBadRequest)
	f.expect("DELETE SOA", f.do(http.MethodDelete, map[string]any{"name": "@", "type": "soa"}), http.StatusBadRequest)
	f.expect("DELETE apex NS", f.do(http.MethodDelete, map[string]any{"name": "example.com.", "type": "NS"}), http.StatusBadRequest)
	hasType := func(rtype string) bool {
		for _, r := range f.records("@") {
			if strings.EqualFold(r.Type, rtype) {
				return true
			}
		}
		return false
	}
	if !hasType("SOA") || !hasType("NS") || z.SOA == nil {
		t.Fatalf("apex SOA/NS removed: %v", f.records("@"))
	}
	// Ordinary NS management keeps working.
	f.expect("POST apex NS", f.do(http.MethodPost, map[string]any{"name": "@", "type": "NS", "data": "ns2.example.com."}), http.StatusCreated)
	f.expect("PUT apex NS", f.do(http.MethodPut, map[string]any{"name": "@", "type": "NS", "old_data": "ns2.example.com.", "data": "ns3.example.com."}), http.StatusOK)
	f.expect("POST delegation NS", f.do(http.MethodPost, map[string]any{"name": "sub", "type": "NS", "data": "ns.sub.example.com."}), http.StatusCreated)
	f.expect("DELETE delegation NS", f.do(http.MethodDelete, map[string]any{"name": "sub", "type": "NS"}), http.StatusOK)
	f.zoneFileParses()
}

func TestZoneRecordAPI_F269_DataScopedDeleteNeverWidensToTheRRset(t *testing.T) {
	f := newZoneRecordAPIFixture(t)
	f.do(http.MethodPost, map[string]any{"name": "www", "type": "A", "data": "192.0.2.1"})
	f.do(http.MethodPost, map[string]any{"name": "www", "type": "A", "data": "192.0.2.2"})
	f.expect("DELETE non-matching data", f.do(http.MethodDelete, map[string]any{"name": "www", "type": "A", "data": "192.0.2.99"}), http.StatusNotFound)
	if n := len(f.records("www")); n != 2 {
		t.Fatalf("records at www = %d, want 2 untouched", n)
	}
	// F419: a data-scoped delete removes exactly that RR (was 409 under F269).
	f.expect("DELETE one of two", f.do(http.MethodDelete, map[string]any{"name": "www", "type": "A", "data": "192.0.2.1"}), http.StatusOK)
	if recs := f.records("www"); len(recs) != 1 || recs[0].RData != "192.0.2.2" {
		t.Fatalf("records at www = %v, want only 192.0.2.2", recs)
	}
	f.do(http.MethodPost, map[string]any{"name": "www", "type": "A", "data": "192.0.2.1"})
	// Whole-RRset delete (no data) keeps its meaning.
	f.expect("DELETE RRset", f.do(http.MethodDelete, map[string]any{"name": "www", "type": "A"}), http.StatusOK)
	if n := len(f.records("www")); n != 0 {
		t.Fatalf("RRset delete left %d records", n)
	}
	// A data-scoped delete of a single-record RRset removes it.
	f.do(http.MethodPost, map[string]any{"name": "mail", "type": "MX", "data": "10 mx.example.com."})
	f.do(http.MethodPost, map[string]any{"name": "mail", "type": "A", "data": "192.0.2.5"})
	f.expect("DELETE lone MX", f.do(http.MethodDelete, map[string]any{"name": "mail", "type": "MX", "data": "10 MX.example.com."}), http.StatusOK)
	if recs := f.records("mail"); len(recs) != 1 || recs[0].Type != "A" {
		t.Fatalf("records at mail = %v, want only the A record", recs)
	}
}

func TestZoneRecordAPI_F270_CNAMEExclusivityAndNoDuplicateRRs(t *testing.T) {
	f := newZoneRecordAPIFixture(t)
	f.expect("A", f.do(http.MethodPost, map[string]any{"name": "www", "type": "A", "data": "192.0.2.1"}), http.StatusCreated)
	f.expect("second A", f.do(http.MethodPost, map[string]any{"name": "www", "type": "A", "data": "192.0.2.2"}), http.StatusCreated)
	f.expect("CNAME", f.do(http.MethodPost, map[string]any{"name": "alias", "type": "CNAME", "data": "t.example.net."}), http.StatusCreated)
	f.expect("CNAME beside A", f.do(http.MethodPost, map[string]any{"name": "www", "type": "CNAME", "data": "o.example.net."}), http.StatusConflict)
	f.expect("TXT beside CNAME", f.do(http.MethodPost, map[string]any{"name": "alias", "type": "TXT", "data": `"x"`}), http.StatusConflict)
	f.expect("second CNAME", f.do(http.MethodPost, map[string]any{"name": "alias", "type": "CNAME", "data": "u.example.net."}), http.StatusConflict)
	f.expect("CNAME at apex", f.do(http.MethodPost, map[string]any{"name": "@", "type": "CNAME", "data": "o.example.net."}), http.StatusConflict)
	f.expect("duplicate A", f.do(http.MethodPost, map[string]any{"name": "WWW.example.com.", "type": "a", "data": "192.0.2.1"}), http.StatusConflict)
	f.expect("PUT onto sibling data", f.do(http.MethodPut, map[string]any{"name": "www", "type": "A", "old_data": "192.0.2.2", "data": "192.0.2.1"}), http.StatusConflict)
	ttl := uint32(60)
	f.expect("PUT TTL-only", f.do(http.MethodPut, map[string]any{"name": "www", "type": "A", "old_data": "192.0.2.2", "data": "192.0.2.2", "ttl": ttl}), http.StatusOK)
	if n := len(f.records("www")); n != 2 {
		t.Fatalf("records at www = %d, want 2", n)
	}
	if n := len(f.records("alias")); n != 1 {
		t.Fatalf("records at alias = %d, want 1", n)
	}
	f.zoneFileParses()
}
