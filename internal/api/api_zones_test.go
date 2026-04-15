package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// Helper to create a server with auth + zone manager
func newServerWithAuthAndZones(t *testing.T) (*Server, *auth.User) {
	t.Helper()
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	s.zoneManager = zone.NewManager()
	adminUser, _ := store.GetUser("admin")
	return s, adminUser
}

// Helper to create a test zone with SOA and NS records
func createTestZone(t *testing.T, mgr *zone.Manager, name string) {
	t.Helper()
	soa := &zone.SOARecord{
		TTL:     3600,
		MName:   "ns1." + name,
		RName:   "admin." + name,
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minimum: 86400,
	}
	nsRecords := []zone.NSRecord{
		{TTL: 3600, NSDName: "ns1." + name},
	}
	if err := mgr.CreateZone(name, 3600, soa, nsRecords); err != nil {
		t.Fatalf("CreateZone(%s): %v", name, err)
	}
}

// --- handleZones tests ---

func TestHandleZones_GetEmpty(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZones(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp ZoneListResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if len(resp.Zones) != 0 {
		t.Errorf("expected 0 zones, got %d", len(resp.Zones))
	}
}

func TestHandleZones_GetWithZones(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "example.com.")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZones(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp ZoneListResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if len(resp.Zones) != 1 {
		t.Fatalf("expected 1 zone, got %d", len(resp.Zones))
	}
	if resp.Zones[0].Name != "example.com." {
		t.Errorf("expected 'example.com.', got %q", resp.Zones[0].Name)
	}
}

func TestHandleZones_CreateZone(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)

	body, _ := json.Marshal(map[string]any{
		"name":        "test.example.com.",
		"ttl":         3600,
		"admin_email": "admin.test.example.com.",
		"nameservers": []string{"ns1.test.example.com."},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZones(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleZones_CreateZoneNoName(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)

	body, _ := json.Marshal(map[string]any{
		"name":        "",
		"nameservers": []string{"ns1.example.com."},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZones(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleZones_CreateZoneNoNS(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)

	body, _ := json.Marshal(map[string]any{
		"name":        "test.example.com.",
		"nameservers": []string{},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZones(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleZones_WrongMethod(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/zones", nil)
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZones(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHandleZones_NoAuth(t *testing.T) {
	s := NewServer(config.HTTPConfig{Enabled: true}, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
	rec := httptest.NewRecorder()

	s.handleZones(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

// --- handleZoneActions tests ---

func TestHandleZoneActions_GetZone(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "example.com.")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com.", nil)
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZoneActions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp ZoneDetailResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Name != "example.com." {
		t.Errorf("expected 'example.com.', got %q", resp.Name)
	}
}

func TestHandleZoneActions_GetZoneNotFound(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones/nonexistent.com.", nil)
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZoneActions(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestHandleZoneActions_DeleteZone(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "todelete.com.")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/zones/todelete.com.", nil)
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZoneActions(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Zone should be gone
	if s.zoneManager.Count() != 0 {
		t.Errorf("zone should be deleted")
	}
}

func TestHandleZoneActions_DeleteZoneNotFound(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/zones/nonexistent.com.", nil)
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZoneActions(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestHandleZoneActions_NoZoneManager(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	// zoneManager is nil
	adminUser, _ := store.GetUser("admin")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com.", nil)
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZoneActions(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestHandleZoneActions_WrongMethod(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/zones/example.com.", nil)
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZoneActions(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

// --- Records CRUD tests ---

func TestHandleZoneActions_AddRecord(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "example.com.")

	body, _ := json.Marshal(map[string]any{
		"name": "www.example.com.",
		"type": "A",
		"ttl":  300,
		"data": "1.2.3.4",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/example.com./records", bytes.NewReader(body))
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZoneActions(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleZoneActions_AddRecordMissingFields(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "example.com.")

	body, _ := json.Marshal(map[string]any{
		"name": "www.example.com.",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/example.com./records", bytes.NewReader(body))
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZoneActions(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleZoneActions_GetRecords(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "example.com.")

	// First add a record
	s.zoneManager.AddRecord("example.com.", zone.Record{
		Name: "www.example.com.", Type: "A", TTL: 300, Class: "IN", RData: "1.2.3.4",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com./records", nil)
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZoneActions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp RecordListResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if len(resp.Records) == 0 {
		t.Error("expected at least one record")
	}
}

func TestHandleZoneActions_GetRecordsFiltered(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "example.com.")

	s.zoneManager.AddRecord("example.com.", zone.Record{
		Name: "www.example.com.", Type: "A", TTL: 300, Class: "IN", RData: "1.2.3.4",
	})
	s.zoneManager.AddRecord("example.com.", zone.Record{
		Name: "mail.example.com.", Type: "A", TTL: 300, Class: "IN", RData: "5.6.7.8",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com./records?name=www.example.com.", nil)
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZoneActions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp RecordListResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if len(resp.Records) != 1 {
		t.Errorf("expected 1 record, got %d", len(resp.Records))
	}
	if resp.Records[0].Name != "www.example.com." {
		t.Errorf("expected www.example.com., got %q", resp.Records[0].Name)
	}
}

func TestHandleZoneActions_UpdateRecord(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "example.com.")

	s.zoneManager.AddRecord("example.com.", zone.Record{
		Name: "www.example.com.", Type: "A", TTL: 300, Class: "IN", RData: "1.2.3.4",
	})

	body, _ := json.Marshal(map[string]any{
		"name":     "www.example.com.",
		"type":     "A",
		"old_data": "1.2.3.4",
		"ttl":      600,
		"data":     "5.6.7.8",
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/zones/example.com./records", bytes.NewReader(body))
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZoneActions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleZoneActions_UpdateRecordMissingFields(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "example.com.")

	body, _ := json.Marshal(map[string]any{
		"name": "www.example.com.",
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/zones/example.com./records", bytes.NewReader(body))
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZoneActions(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleZoneActions_DeleteRecord(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "example.com.")

	s.zoneManager.AddRecord("example.com.", zone.Record{
		Name: "www.example.com.", Type: "A", TTL: 300, Class: "IN", RData: "1.2.3.4",
	})

	body, _ := json.Marshal(map[string]any{
		"name": "www.example.com.",
		"type": "A",
	})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/zones/example.com./records", bytes.NewReader(body))
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZoneActions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleZoneActions_DeleteRecordMissingFields(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "example.com.")

	body, _ := json.Marshal(map[string]any{
		"name": "www.example.com.",
	})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/zones/example.com./records", bytes.NewReader(body))
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZoneActions(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleZoneActions_RecordsWrongMethod(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "example.com.")

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/zones/example.com./records", nil)
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZoneActions(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

// --- Export zone tests ---

func TestHandleZoneActions_ExportZone(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "example.com.")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com./export", nil)
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZoneActions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "text/plain; charset=utf-8" {
		t.Errorf("expected text/plain content type, got %q", ct)
	}

	body := rec.Body.String()
	if len(body) == 0 {
		t.Error("expected non-empty export")
	}
}

func TestHandleZoneActions_ExportZoneWrongMethod(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "example.com.")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/example.com./export", nil)
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZoneActions(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHandleZoneActions_UnknownSubPath(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "example.com.")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com./unknown", nil)
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZoneActions(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

// --- handleZoneReload tests ---

func TestHandleZoneReload_RequestBody(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)

	// Can't reload a zone that wasn't loaded from file, but we test the handler path
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/reload?zone=example.com.", nil)
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZoneReload(rec, req)

	// Will fail because the zone has no file backing, but tests the handler logic
	// The actual error code depends on zoneManager.Reload implementation
	if rec.Code == http.StatusMethodNotAllowed {
		t.Error("should not get 405 for POST")
	}
}

func TestHandleZoneReload_WrongMethod(t *testing.T) {
	s, _ := newServerWithAuthAndZones(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones/reload?zone=example.com.", nil)
	rec := httptest.NewRecorder()

	s.handleZoneReload(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHandleZoneReload_MissingZone(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/reload", nil)
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZoneReload(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleZoneReload_NoZoneManager(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	adminUser, _ := store.GetUser("admin")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/reload?zone=example.com.", nil)
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZoneReload(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

// --- handleStatus tests ---

func TestHandleStatus_NoCache(t *testing.T) {
	s := NewServer(config.HTTPConfig{Enabled: true}, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rec := httptest.NewRecorder()

	s.handleStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var resp StatusResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Status != "running" {
		t.Errorf("expected 'running', got %q", resp.Status)
	}
	if resp.Cache != nil {
		t.Error("cache should be nil")
	}
}

// --- handleDNSSECStatus tests ---

func TestHandleDNSSECStatus_NoValidator(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	// validator is nil
	adminUser, _ := store.GetUser("admin")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dnssec/status", nil)
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleDNSSECStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestHandleDNSSECStatus_WrongMethod(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/dnssec/status", nil)
	rec := httptest.NewRecorder()

	s.handleDNSSECStatus(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

// --- handleDNSSECKeys tests ---

func TestHandleDNSSECKeys_NoKeys(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	adminUser, _ := store.GetUser("admin")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dnssec/keys", nil)
	ctx := WithUser(req.Context(), adminUser)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleDNSSECKeys(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestHandleDNSSECKeys_WrongMethod(t *testing.T) {
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/dnssec/keys", nil)
	rec := httptest.NewRecorder()

	s.handleDNSSECKeys(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

// --- Bulk PTR tests ---

func TestHandleZoneActions_BulkPTRWrongMethod(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "example.com.")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com./ptr-bulk", nil)
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZoneActions(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHandleZoneActions_Ptr6LookupWrongMethod(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "example.com.")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/example.com./ptr6-lookup", nil)
	ctx := WithUser(req.Context(), user)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleZoneActions(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}
