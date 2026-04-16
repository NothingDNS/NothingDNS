package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// helper to create an admin user for request context
func adminUser() *auth.User {
	return &auth.User{Username: "testadmin", Role: auth.RoleAdmin}
}

// helper to add user to request context
func withAdminCtx(r *http.Request) *http.Request {
	return r.WithContext(WithUser(r.Context(), adminUser()))
}

// helper to create API server with auth
func newTestAPIServerV2(t *testing.T) *Server {
	t.Helper()
	store := newAuthStoreWithUser(t, "testadmin", "testpass123", auth.RoleAdmin)
	return newServerWithAuth(store)
}

// ---------------------------------------------------------------------------
// handleSlaveZones — synced zone with records
// ---------------------------------------------------------------------------

func TestHandleSlaveZones_WithSyncedZone(t *testing.T) {
	sm := transfer.NewSlaveManager(nil)

	err := sm.AddSlaveZone(transfer.SlaveZoneConfig{
		ZoneName: "synced.example.com.",
		Masters:  []string{"127.0.0.1:53"},
	})
	if err != nil {
		t.Fatalf("AddSlaveZone: %v", err)
	}

	// Get the zone and set it to synced state
	zones := sm.GetAllSlaveZones()
	for name, sz := range zones {
		sz.Zone = &zone.Zone{
			Origin: name,
			Records: map[string][]zone.Record{
				"www." + name: {
					{Type: "A", TTL: 300, RData: "10.0.0.1"},
					{Type: "A", TTL: 300, RData: "10.0.0.2"},
				},
			},
		}
		sz.LastSerial = 2024010101
		sz.LastTransfer = time.Now()
	}

	s := newTestAPIServerV2(t)
	s.slaveManager = sm

	w := httptest.NewRecorder()
	r := withAdminCtx(httptest.NewRequest("GET", "/api/slave-zones", nil))

	s.handleSlaveZones(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp SlaveZonesResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.SlaveZones) != 1 {
		t.Fatalf("expected 1 slave zone, got %d", len(resp.SlaveZones))
	}
	if resp.SlaveZones[0].Status != "synced" {
		t.Errorf("Status = %q, want synced", resp.SlaveZones[0].Status)
	}
	if resp.SlaveZones[0].Serial != 2024010101 {
		t.Errorf("Serial = %d, want 2024010101", resp.SlaveZones[0].Serial)
	}
	if resp.SlaveZones[0].Records != 2 {
		t.Errorf("Records = %d, want 2", resp.SlaveZones[0].Records)
	}
	if resp.SlaveZones[0].LastTransfer == "" {
		t.Error("expected non-empty LastTransfer")
	}
}

// ---------------------------------------------------------------------------
// handleSlaveZones — pending zone (no zone data)
// ---------------------------------------------------------------------------

func TestHandleSlaveZones_PendingZoneV2(t *testing.T) {
	sm := transfer.NewSlaveManager(nil)

	err := sm.AddSlaveZone(transfer.SlaveZoneConfig{
		ZoneName: "pending.example.com.",
		Masters:  []string{"127.0.0.1:53"},
	})
	if err != nil {
		t.Fatalf("AddSlaveZone: %v", err)
	}

	// Explicitly nil out the zone to simulate pending state
	zones := sm.GetAllSlaveZones()
	for _, sz := range zones {
		sz.Zone = nil
	}

	s := newTestAPIServerV2(t)
	s.slaveManager = sm

	w := httptest.NewRecorder()
	r := withAdminCtx(httptest.NewRequest("GET", "/api/slave-zones", nil))

	s.handleSlaveZones(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp SlaveZonesResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp.SlaveZones) != 1 {
		t.Fatalf("expected 1 slave zone, got %d", len(resp.SlaveZones))
	}
	if resp.SlaveZones[0].Status != "pending" {
		t.Errorf("Status = %q, want pending", resp.SlaveZones[0].Status)
	}
	if resp.SlaveZones[0].Records != 0 {
		t.Errorf("Records = %d, want 0 for pending", resp.SlaveZones[0].Records)
	}
	if resp.SlaveZones[0].LastTransfer != "" {
		t.Errorf("LastTransfer should be empty for pending zone, got %q", resp.SlaveZones[0].LastTransfer)
	}
}

// ---------------------------------------------------------------------------
// handleSlaveZones — no auth context
// ---------------------------------------------------------------------------

func TestHandleSlaveZones_NoAuth(t *testing.T) {
	s := newTestAPIServerV2(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/slave-zones", nil)

	s.handleSlaveZones(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 without auth, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// handleODoHConfig — not available
// ---------------------------------------------------------------------------

func TestHandleODoHConfig_NilTarget(t *testing.T) {
	s := NewServer(config.HTTPConfig{}, nil, nil, nil, nil, nil, nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/odoh-config", nil)

	s.handleODoHConfig(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// handleDNSSECKeys — no key store
// ---------------------------------------------------------------------------

func TestHandleDNSSECKeys_NoStoreV2(t *testing.T) {
	s := NewServer(config.HTTPConfig{}, nil, nil, nil, nil, nil, nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/dnssec/keys", nil)

	s.handleDNSSECKeys(w, r)

	// Should return empty or error
	if w.Code != http.StatusOK && w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 200 or 503, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// handleDNSSECStatus — with nil validator
// ---------------------------------------------------------------------------

func TestHandleDNSSECStatus_NilValidatorV2(t *testing.T) {
	s := newTestAPIServerV2(t)

	w := httptest.NewRecorder()
	r := withAdminCtx(httptest.NewRequest("GET", "/api/dnssec/status", nil))

	s.handleDNSSECStatus(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}
