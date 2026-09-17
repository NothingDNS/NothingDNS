package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/dashboard"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func doJSON(t *testing.T, handler func(http.ResponseWriter, *http.Request), user *auth.User, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

// Invalid input is a client error (400); only a taken username conflicts (409).
func TestHandleUsers_CreateStatusCodes(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	admin, _ := store.GetUser("admin")

	rec := doJSON(t, s.handleUsers, admin, http.MethodPost, "/api/v1/auth/users",
		CreateUserRequest{Username: "weak", Password: "short", Role: "viewer"})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("weak password: status %d, want 400: %s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, s.handleUsers, admin, http.MethodPost, "/api/v1/auth/users",
		CreateUserRequest{Username: "admin", Password: "another-pass-123", Role: "viewer"})
	if rec.Code != http.StatusConflict {
		t.Errorf("existing username: status %d, want 409: %s", rec.Code, rec.Body.String())
	}
}

// An update without ttl keeps the record's TTL; an explicit 0 is honoured.
func TestHandleUpdateRecord_TTL(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "ttl.test.")
	if err := s.zoneManager.AddRecord("ttl.test.", zone.Record{Name: "www.ttl.test.", Type: "A", TTL: 7200, RData: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}

	ttlOf := func() uint32 {
		recs, err := s.zoneManager.GetRecords("ttl.test.", "www.ttl.test.")
		if err != nil || len(recs) != 1 {
			t.Fatalf("records = %+v, %v", recs, err)
		}
		return recs[0].TTL
	}

	rec := doJSON(t, func(w http.ResponseWriter, r *http.Request) { s.handleUpdateRecord(w, r, "ttl.test.") }, user,
		http.MethodPut, "/api/v1/zones/ttl.test./records",
		map[string]any{"name": "www.ttl.test.", "type": "A", "old_data": "192.0.2.1", "data": "192.0.2.2"})
	if rec.Code != http.StatusOK {
		t.Fatalf("update without ttl: %d %s", rec.Code, rec.Body.String())
	}
	if got := ttlOf(); got != 7200 {
		t.Errorf("TTL after update without ttl = %d, want 7200 (unchanged)", got)
	}

	rec = doJSON(t, func(w http.ResponseWriter, r *http.Request) { s.handleUpdateRecord(w, r, "ttl.test.") }, user,
		http.MethodPut, "/api/v1/zones/ttl.test./records",
		map[string]any{"name": "www.ttl.test.", "type": "A", "old_data": "192.0.2.2", "data": "192.0.2.3", "ttl": 0})
	if rec.Code != http.StatusOK {
		t.Fatalf("update with ttl 0: %d %s", rec.Code, rec.Body.String())
	}
	if got := ttlOf(); got != 0 {
		t.Errorf("TTL after explicit ttl 0 = %d, want 0", got)
	}

	rec = doJSON(t, func(w http.ResponseWriter, r *http.Request) { s.handleUpdateRecord(w, r, "ttl.test.") }, user,
		http.MethodPut, "/api/v1/zones/ttl.test./records",
		map[string]any{"name": "www.ttl.test.", "type": "A", "old_data": "198.51.100.9", "data": "192.0.2.4"})
	if rec.Code != http.StatusNotFound {
		t.Errorf("update of a missing record: %d, want 404", rec.Code)
	}
}

func TestHandleCreateZone_AdminEmail(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)

	rec := doJSON(t, s.handleZones, user, http.MethodPost, "/api/v1/zones",
		map[string]any{"name": "mail.test", "nameservers": []string{"ns1.mail.test"}, "admin_email": "first.last@mail.test"})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("dotted local part: %d, want 400: %s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, s.handleZones, user, http.MethodPost, "/api/v1/zones",
		map[string]any{"name": "mail.test", "nameservers": []string{"ns1.mail.test"}})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create without admin_email: %d %s", rec.Code, rec.Body.String())
	}
	z, ok := s.zoneManager.Get("mail.test.")
	if !ok || z.SOA == nil || z.SOA.RName != "hostmaster.mail.test." || z.SOA.MName != "ns1.mail.test." {
		t.Errorf("SOA = %+v", z.SOA)
	}
}

func TestHandleDashboardQueries_RedactsForNonAdmins(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	if _, err := store.CreateUser("ops", "operator-pass-1", auth.RoleOperator); err != nil {
		t.Fatal(err)
	}
	s := newServerWithAuth(store)
	ds := dashboard.NewServer()
	defer ds.Stop()
	ds.RecordQuery(&dashboard.QueryEvent{ClientIP: "192.0.2.55", Domain: "example.com"})
	s.dashboardServer = ds

	clientIP := func(user *auth.User) string {
		rec := doJSON(t, s.handleDashboardQueries, user, http.MethodGet, "/api/dashboard/queries", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		var events []dashboard.QueryEvent
		if err := json.NewDecoder(rec.Body).Decode(&events); err != nil || len(events) != 1 {
			t.Fatalf("events = %+v, %v", events, err)
		}
		return events[0].ClientIP
	}
	admin, _ := store.GetUser("admin")
	ops, _ := store.GetUser("ops")
	if got := clientIP(admin); got != "192.0.2.55" {
		t.Errorf("admin sees %q, want the full address", got)
	}
	if got := clientIP(ops); got != "192.0.2.xxx" {
		t.Errorf("operator sees %q, want 192.0.2.xxx", got)
	}
}
