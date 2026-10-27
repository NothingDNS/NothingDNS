package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// A name in RDATA sent without its trailing dot was stored as sent: served as
// absolute (ParseRDataText has no origin) but written to the zone file, where
// $ORIGIN made "target.example.org" read back as
// "target.example.org.example.com." after a restart. The API now stores it
// qualified (dotted = absolute, single label = relative to the zone), so the
// served data and the zone file agree.
func TestRecordsAPI_RDataNamesQualified(t *testing.T) {
	f := newZoneRecordAPIFixture(t)
	want := []struct{ name, rtype, data, stored string }{
		{"www", "CNAME", "target.example.org", "target.example.org."},
		{"mail", "MX", "10 mx", "10 mx.example.com."},
		{"_sip._tcp", "SRV", "10 5 5060 sip.example.net", "10 5 5060 sip.example.net."},
		{"n", "NAPTR", `100 10 "U" "E2U+sip" "!^ .*$!sip:a b@example.com!" sip.example.net`,
			`100 10 "U" "E2U+sip" "!^ .*$!sip:a b@example.com!" sip.example.net.`},
		{"t", "TXT", "a.example b", "a.example b"},
		{"abs", "CNAME", "already.example.org.", "already.example.org."},
	}
	served := func(m *zone.Manager) map[string]string {
		out := map[string]string{}
		for _, w := range want {
			recs, _ := m.GetRecords("example.com.", w.name)
			for _, r := range recs {
				if r.Type != w.rtype {
					continue
				}
				rd := protocol.ParseRDataText(r.Type, r.RData)
				if rd == nil {
					t.Fatalf("%s %s: stored %q is not servable", w.name, w.rtype, r.RData)
				}
				out[w.name+" "+w.rtype] = rd.String()
			}
		}
		return out
	}

	for _, w := range want {
		f.expect("add "+w.name, f.do(http.MethodPost, map[string]any{"name": w.name, "type": w.rtype, "data": w.data, "ttl": 300}), http.StatusCreated)
		var got []string
		for _, r := range f.records(w.name) {
			if r.Type == w.rtype {
				got = append(got, r.RData)
			}
		}
		if len(got) != 1 || got[0] != w.stored {
			t.Errorf("%s %s stored %q, want %q", w.name, w.rtype, got, w.stored)
		}
	}

	before := served(f.s.zoneManager)
	path := filepath.Join(f.dir, "example.com.zone")
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	z, err := zone.ParseFile(path, strings.NewReader(string(text)))
	if err != nil {
		t.Fatalf("zone file does not parse: %v", err)
	}
	reloaded := zone.NewManager()
	reloaded.LoadZone(z, "")
	after := served(reloaded)
	if len(after) != len(want) {
		t.Fatalf("reloaded zone serves %d of %d records:\n%s", len(after), len(want), text)
	}
	for k, v := range before {
		if after[k] != v {
			t.Errorf("%s: served %q before the restart, %q after", k, v, after[k])
		}
	}

	// A record is still addressed by the text it was added with.
	f.expect("update by the original text", f.do(http.MethodPut, map[string]any{
		"name": "www", "type": "CNAME", "old_data": "target.example.org", "data": "other.example.org"}), http.StatusOK)
	for _, r := range f.records("www") {
		if r.Type == "CNAME" && r.RData != "other.example.org." {
			t.Fatalf("www CNAME = %q", r.RData)
		}
	}
	f.expect("delete by the original text", f.do(http.MethodDelete, map[string]any{
		"name": "mail", "type": "MX", "data": "10 mx"}), http.StatusOK)
	for _, r := range f.records("mail") {
		if r.Type == "MX" {
			t.Fatalf("mail MX not deleted: %+v", r)
		}
	}
}

// F730: a record the API stored before its names were qualified ("10
// mail.example.org") differs from the qualified new data in text only. The
// duplicate check took it for another RR of the set, so a TTL-only edit, or
// re-saving it with the trailing dot, was refused with 409.
func TestRecordsAPI_UpdateUnqualifiedRecord(t *testing.T) {
	for _, data := range []string{"10 mail.example.org", "10 mail.example.org."} {
		f := newZoneRecordAPIFixture(t)
		if err := f.s.zoneManager.AddRecord("example.com.", zone.Record{Name: "legacy", Type: "MX", TTL: 300, Class: "IN", RData: "10 mail.example.org"}); err != nil {
			t.Fatal(err)
		}
		f.expect("update to "+data, f.do(http.MethodPut, map[string]any{
			"name": "legacy", "type": "MX", "old_data": "10 mail.example.org", "data": data, "ttl": 60}), http.StatusOK)
		recs := f.records("legacy")
		if len(recs) != 1 || recs[0].RData != "10 mail.example.org." || recs[0].TTL != 60 {
			t.Fatalf("update to %q: records %+v", data, recs)
		}
	}

	// The record being replaced is excluded, other RRs of the set are not.
	f := newZoneRecordAPIFixture(t)
	f.expect("add", f.do(http.MethodPost, map[string]any{"name": "m", "type": "MX", "data": "10 a.example.org", "ttl": 300}), http.StatusCreated)
	f.expect("add", f.do(http.MethodPost, map[string]any{"name": "m", "type": "MX", "data": "20 b.example.org", "ttl": 300}), http.StatusCreated)
	f.expect("update to a sibling", f.do(http.MethodPut, map[string]any{
		"name": "m", "type": "MX", "old_data": "10 a.example.org", "data": "20 b.example.org"}), http.StatusConflict)
}
