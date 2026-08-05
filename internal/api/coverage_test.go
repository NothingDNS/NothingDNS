package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/cluster"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// ---------------------------------------------------------------------------
// handleBulkPTR
// ---------------------------------------------------------------------------

func newServerWithReverseZone(t *testing.T) (*Server, *auth.User) {
	return newServerWithReverseZoneOrigin(t, "1.168.192.in-addr.arpa.")
}

func newServerWithReverseZoneOrigin(t *testing.T, origin string) (*Server, *auth.User) {
	t.Helper()
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	s.zoneManager = zone.NewManager()

	// Create a reverse zone for bulk PTR tests.
	soa := &zone.SOARecord{
		TTL:     3600,
		MName:   "ns1.example.com.",
		RName:   "admin.example.com.",
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minimum: 86400,
	}
	nsRecords := []zone.NSRecord{
		{TTL: 3600, NSDName: "ns1.example.com."},
	}
	if err := s.zoneManager.CreateZone(origin, 3600, soa, nsRecords); err != nil {
		t.Fatalf("CreateZone: %v", err)
	}

	user, _ := store.GetUser("admin")
	return s, user
}

func TestHandleBulkPTR_Preview(t *testing.T) {
	s, user := newServerWithReverseZone(t)

	body := `{"cidr":"192.168.1.0/30","pattern":"host-[A]-[B]-[C]-[D].example.com.","preview":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	if resp["preview"] != true {
		t.Error("expected preview=true")
	}
	if resp["total"] != float64(4) { // /30 = 4 IPs
		t.Errorf("expected total=4, got %v", resp["total"])
	}
	if resp["willAdd"] != float64(4) {
		t.Errorf("expected willAdd=4, got %v", resp["willAdd"])
	}
}

func TestHandleBulkPTR_Apply(t *testing.T) {
	s, user := newServerWithReverseZone(t)

	body := `{"cidr":"192.168.1.0/30","pattern":"host-[A]-[B]-[C]-[D].example.com."}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	if resp["added"] != float64(4) {
		t.Errorf("expected added=4, got %v", resp["added"])
	}
}

func TestHandleBulkPTR_ApplyUsesReverseRelativeOwnerInParentZone(t *testing.T) {
	s, user := newServerWithReverseZoneOrigin(t, "168.192.in-addr.arpa.")

	body := `{"cidr":"192.168.1.0/30","pattern":"host-[A]-[B]-[C]-[D].example.com."}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "168.192.in-addr.arpa.")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	z, ok := s.zoneManager.Get("168.192.in-addr.arpa.")
	if !ok {
		t.Fatal("expected reverse zone")
	}
	z.RLock()
	records := append([]zone.Record(nil), z.Records["0.1.168.192.in-addr.arpa."]...)
	wrongRecords := append([]zone.Record(nil), z.Records["1.0.168.192.in-addr.arpa."]...)
	z.RUnlock()

	if len(records) != 1 {
		t.Fatalf("expected PTR at 0.1.168.192.in-addr.arpa., got %d records", len(records))
	}
	if records[0].Type != "PTR" || records[0].RData != "host-192-168-1-0.example.com." {
		t.Fatalf("unexpected PTR record: %+v", records[0])
	}
	if len(wrongRecords) != 0 {
		t.Fatalf("unexpected PTR at old reversed owner 1.0.168.192.in-addr.arpa.: %+v", wrongRecords)
	}
}

func TestHandleBulkPTR_PreviewFindsExistingPTRByOwner(t *testing.T) {
	s, user := newServerWithReverseZone(t)
	if err := s.zoneManager.AddRecord("1.168.192.in-addr.arpa.", zone.Record{
		Name:  "0",
		Type:  "PTR",
		Class: "IN",
		TTL:   3600,
		RData: "existing.example.com.",
	}); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}

	body := `{"cidr":"192.168.1.0/32","pattern":"host-[A]-[B]-[C]-[D].example.com.","preview":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp ReverseDNSPreviewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	if resp.WillSkip != 1 || resp.WillAdd != 0 {
		t.Fatalf("preview counts: willSkip=%d willAdd=%d, want 1/0", resp.WillSkip, resp.WillAdd)
	}
	if len(resp.Changes) != 1 || !resp.Changes[0].PTRExist || resp.Changes[0].OldPTR != "existing.example.com." {
		t.Fatalf("preview change = %+v, want existing PTR details", resp.Changes)
	}
}

func TestHandleBulkPTR_OverrideReplacesExistingPTRByOwner(t *testing.T) {
	s, user := newServerWithReverseZone(t)
	if err := s.zoneManager.AddRecord("1.168.192.in-addr.arpa.", zone.Record{
		Name:  "0",
		Type:  "PTR",
		Class: "IN",
		TTL:   3600,
		RData: "old.example.com.",
	}); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}

	body := `{"cidr":"192.168.1.0/32","pattern":"host-[A]-[B]-[C]-[D].example.com.","override":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	z, ok := s.zoneManager.Get("1.168.192.in-addr.arpa.")
	if !ok {
		t.Fatal("expected reverse zone")
	}
	z.RLock()
	records := append([]zone.Record(nil), z.Records["0.1.168.192.in-addr.arpa."]...)
	z.RUnlock()

	if len(records) != 1 {
		t.Fatalf("expected one PTR after override, got %+v", records)
	}
	if records[0].RData != "host-192-168-1-0.example.com." {
		t.Fatalf("PTR RData = %q, want updated host", records[0].RData)
	}
}

func TestHandleBulkPTR_WithAddA(t *testing.T) {
	s, user := newServerWithReverseZone(t)

	body := `{"cidr":"192.168.1.0/30","pattern":"host-[A]-[B]-[C]-[D].example.com.","addA":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleBulkPTR_AddAExistingADoesNotSkipPTR(t *testing.T) {
	s, user := newServerWithReverseZone(t)
	existingName := "host-192-168-1-0.example.com."
	if err := s.zoneManager.AddRecord("1.168.192.in-addr.arpa.", zone.Record{
		Name:  existingName,
		Type:  "A",
		Class: "IN",
		TTL:   3600,
		RData: "192.168.1.0",
	}); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}

	body := `{"cidr":"192.168.1.0/32","pattern":"host-[A]-[B]-[C]-[D].example.com.","addA":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp BulkPTRResultResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	if resp.Added != 1 || resp.AddedA != 0 || resp.ExistsA != 1 || resp.Skipped != 0 {
		t.Fatalf("bulk result = %+v, want added PTR and existing A", resp)
	}

	z, ok := s.zoneManager.Get("1.168.192.in-addr.arpa.")
	if !ok {
		t.Fatal("expected reverse zone")
	}
	z.RLock()
	ptrRecords := append([]zone.Record(nil), z.Records["0.1.168.192.in-addr.arpa."]...)
	aRecords := append([]zone.Record(nil), z.Records[existingName]...)
	z.RUnlock()

	if len(ptrRecords) != 1 || ptrRecords[0].Type != "PTR" {
		t.Fatalf("PTR records = %+v, want one PTR", ptrRecords)
	}
	if len(aRecords) != 1 {
		t.Fatalf("A records = %+v, want existing A without duplicate", aRecords)
	}
}

// Regression test: in non-override mode, an entry whose PTR already exists is
// reported as "skipped" and must not be mutated at all — in particular, no
// forward A record may be created even when addA=true and the A is missing.
func TestHandleBulkPTR_AddASkipEntryDoesNotCreateA(t *testing.T) {
	s, user := newServerWithReverseZone(t)
	if err := s.zoneManager.AddRecord("1.168.192.in-addr.arpa.", zone.Record{
		Name:  "0",
		Type:  "PTR",
		Class: "IN",
		TTL:   3600,
		RData: "host-192-168-1-0.example.com.",
	}); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}

	body := `{"cidr":"192.168.1.0/32","pattern":"host-[A]-[B]-[C]-[D].example.com.","addA":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp BulkPTRResultResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	if resp.Added != 0 || resp.AddedA != 0 || resp.Skipped != 1 {
		t.Fatalf("bulk result = %+v, want skipped PTR and no A added", resp)
	}

	z, ok := s.zoneManager.Get("1.168.192.in-addr.arpa.")
	if !ok {
		t.Fatal("expected reverse zone")
	}
	z.RLock()
	aRecords := append([]zone.Record(nil), z.Records["host-192-168-1-0.example.com."]...)
	z.RUnlock()

	if len(aRecords) != 0 {
		t.Fatalf("A records = %+v, want no A record for a skipped entry", aRecords)
	}
}

// Preview must agree with apply: a skip entry must not be counted in willAddA.
func TestHandleBulkPTR_PreviewSkipEntryNotCountedInWillAddA(t *testing.T) {
	s, user := newServerWithReverseZone(t)
	if err := s.zoneManager.AddRecord("1.168.192.in-addr.arpa.", zone.Record{
		Name:  "0",
		Type:  "PTR",
		Class: "IN",
		TTL:   3600,
		RData: "host-192-168-1-0.example.com.",
	}); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}

	body := `{"cidr":"192.168.1.0/31","pattern":"host-[A]-[B]-[C]-[D].example.com.","addA":true,"preview":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp ReverseDNSPreviewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	// .0 has an existing PTR (skip, no A promised); .1 is a fresh add (PTR + A).
	if resp.WillSkip != 1 || resp.WillAdd != 1 || resp.WillAddA != 1 {
		t.Fatalf("preview counts: willSkip=%d willAdd=%d willAddA=%d, want 1/1/1", resp.WillSkip, resp.WillAdd, resp.WillAddA)
	}
}

func TestHandleBulkPTR_MissingFields(t *testing.T) {
	s, user := newServerWithReverseZone(t)

	body := `{"cidr":"192.168.1.0/24"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleBulkPTR_InvalidCIDR(t *testing.T) {
	s, user := newServerWithReverseZone(t)

	body := `{"cidr":"not-a-cidr","pattern":"host-[A]-[B]-[C]-[D].example.com."}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleBulkPTR_CIDRTooLarge(t *testing.T) {
	s, user := newServerWithReverseZone(t)

	body := `{"cidr":"192.168.0.0/8","pattern":"host-[A]-[B]-[C]-[D].example.com."}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleBulkPTR_PatternMissingPlaceholders(t *testing.T) {
	s, user := newServerWithReverseZone(t)

	body := `{"cidr":"192.168.1.0/30","pattern":"host.example.com."}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleBulkPTR_PatternTooLong(t *testing.T) {
	s, user := newServerWithReverseZone(t)

	pattern := strings.Repeat("a", maxBulkPTRPatternLength+1) + "-[A]-[B]-[C]-[D].example.com."
	body, err := json.Marshal(map[string]string{
		"cidr":    "192.168.1.0/30",
		"pattern": pattern,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader(body))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleBulkPTR_ZoneNotFound(t *testing.T) {
	s, user := newServerWithReverseZone(t)

	body := `{"cidr":"192.168.1.0/30","pattern":"host-[A]-[B]-[C]-[D].example.com."}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/nonexistent.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "nonexistent.in-addr.arpa.")

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestHandleBulkPTR_InvalidJSON(t *testing.T) {
	s, user := newServerWithReverseZone(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte("{bad json")))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleBulkPTR_CDIRZoneMismatch(t *testing.T) {
	// Zone is 1.168.192.in-addr.arpa but CIDR is 10.0.0.0/24 — wrong zone
	s, user := newServerWithReverseZone(t)

	body := `{"cidr":"10.0.0.0/24","pattern":"host-[A]-[B]-[C]-[D].example.com."}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/1.168.192.in-addr.arpa./ptr-bulk", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleBulkPTR(rec, req, "1.168.192.in-addr.arpa.")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for CIDR outside reverse zone, got %d body=%s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// handlePtr6Lookup
// ---------------------------------------------------------------------------

func newServerWithIPv6ReverseZone(t *testing.T) (*Server, *auth.User) {
	t.Helper()
	store := newAuthStoreWithUser(t, "admin", "testpass123", auth.RoleAdmin)
	s := newServerWithAuth(store)
	s.zoneManager = zone.NewManager()

	soa := &zone.SOARecord{
		TTL:     3600,
		MName:   "ns1.example.com.",
		RName:   "admin.example.com.",
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minimum: 86400,
	}
	nsRecords := []zone.NSRecord{
		{TTL: 3600, NSDName: "ns1.example.com."},
	}
	if err := s.zoneManager.CreateZone("ip6.arpa.", 3600, soa, nsRecords); err != nil {
		t.Fatalf("CreateZone: %v", err)
	}

	user, _ := store.GetUser("admin")
	return s, user
}

func TestHandlePtr6Lookup_MissingIP(t *testing.T) {
	s, user := newServerWithIPv6ReverseZone(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones/ip6.arpa./ptr6-lookup", nil)
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handlePtr6Lookup(rec, req, "ip6.arpa.")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandlePtr6Lookup_InvalidIPv6(t *testing.T) {
	s, user := newServerWithIPv6ReverseZone(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones/ip6.arpa./ptr6-lookup?ip=not-an-ip", nil)
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handlePtr6Lookup(rec, req, "ip6.arpa.")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandlePtr6Lookup_IPv4Rejected(t *testing.T) {
	s, user := newServerWithIPv6ReverseZone(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones/ip6.arpa./ptr6-lookup?ip=192.168.1.1", nil)
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handlePtr6Lookup(rec, req, "ip6.arpa.")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for IPv4, got %d", rec.Code)
	}
}

func TestHandlePtr6Lookup_ZoneNotFound(t *testing.T) {
	s, user := newServerWithIPv6ReverseZone(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones/nonexistent./ptr6-lookup?ip=2001:db8::1", nil)
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handlePtr6Lookup(rec, req, "nonexistent.")

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestHandlePtr6Lookup_NotIPv6Zone(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "example.com.")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com./ptr6-lookup?ip=2001:db8::1", nil)
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handlePtr6Lookup(rec, req, "example.com.")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-ip6.arpa zone, got %d", rec.Code)
	}
}

func TestHandlePtr6Lookup_Found(t *testing.T) {
	s, user := newServerWithIPv6ReverseZone(t)

	ptrName := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
	if err := s.zoneManager.AddRecord("ip6.arpa.", zone.Record{
		Name:  ptrName + ".",
		TTL:   3600,
		Class: "IN",
		Type:  "PTR",
		RData: "host.example.com.",
	}); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones/ip6.arpa./ptr6-lookup?ip=2001:db8::1", nil)
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handlePtr6Lookup(rec, req, "ip6.arpa.")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	if resp["found"] != true {
		t.Errorf("expected found=true, got %v; ptr=%v ptrFQDN=%v", resp["found"], resp["ptr"], resp["ptrFQDN"])
	}
}

func TestHandlePtr6Lookup_NotFound(t *testing.T) {
	s, user := newServerWithIPv6ReverseZone(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones/ip6.arpa./ptr6-lookup?ip=2001:db8::1", nil)
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handlePtr6Lookup(rec, req, "ip6.arpa.")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	if resp["found"] != false {
		t.Errorf("expected found=false, got %v", resp["found"])
	}
}

// ---------------------------------------------------------------------------
// validateAndPinUpstream
// ---------------------------------------------------------------------------

func TestValidateAndPinUpstream_PublicIP(t *testing.T) {
	pinned, err := validateAndPinUpstream("8.8.8.8:53")
	if err != nil {
		t.Errorf("public IP should be valid: %v", err)
	}
	if pinned != "8.8.8.8:53" {
		t.Errorf("IP literal should be returned as-is, got %q", pinned)
	}
}

func TestValidateAndPinUpstream_PrivateIP(t *testing.T) {
	_, err := validateAndPinUpstream("192.168.1.1:53")
	if err == nil {
		t.Error("private IP should be rejected")
	}
}

func TestValidateAndPinUpstream_PrivateIP10(t *testing.T) {
	_, err := validateAndPinUpstream("10.0.0.1:53")
	if err == nil {
		t.Error("10.x.x.x should be rejected")
	}
}

func TestValidateAndPinUpstream_Loopback(t *testing.T) {
	_, err := validateAndPinUpstream("127.0.0.1:53")
	if err == nil {
		t.Error("loopback should be rejected")
	}
}

func TestValidateAndPinUpstream_UnspecifiedIP(t *testing.T) {
	// 0.0.0.0 routes to localhost on Linux — must be rejected.
	_, err := validateAndPinUpstream("0.0.0.0:53")
	if err == nil {
		t.Error("0.0.0.0 should be rejected (routes to localhost)")
	}
}

func TestValidateAndPinUpstream_CGNAT(t *testing.T) {
	// 100.64.0.0/10 is CGNAT (RFC 6598) — not routable externally.
	_, err := validateAndPinUpstream("100.64.0.1:53")
	if err == nil {
		t.Error("CGNAT 100.64.0.0/10 should be rejected")
	}
}

func TestValidateAndPinUpstream_IPWithoutPort(t *testing.T) {
	// No port — SplitHostPort fails, so entire string is treated as host
	pinned, err := validateAndPinUpstream("8.8.8.8")
	if err != nil {
		t.Errorf("public IP without port should be valid: %v", err)
	}
	if pinned != "8.8.8.8" {
		t.Errorf("IP literal should be returned as-is, got %q", pinned)
	}
}

func TestValidateAndPinUpstream_BracketIPv6(t *testing.T) {
	_, err := validateAndPinUpstream("[::1]:53")
	if err == nil {
		t.Error("loopback IPv6 should be rejected")
	}
}

func TestValidateAndPinUpstream_PublicIPv6(t *testing.T) {
	pinned, err := validateAndPinUpstream("[2001:4860:4860::8888]:53")
	if err != nil {
		t.Errorf("public IPv6 should be valid: %v", err)
	}
	if pinned != "[2001:4860:4860::8888]:53" {
		t.Errorf("IPv6 literal should be returned as-is, got %q", pinned)
	}
}

func TestValidateAndPinUpstream_UnresolvableHostname(t *testing.T) {
	// Fail-closed: unresolvable hostnames must be rejected, not allowed.
	// This prevents SSRF via DNS rebinding and avoids adding dead upstreams.
	_, err := validateAndPinUpstream("this-hostname-definitely-does-not-exist.invalid.:53")
	if err == nil {
		t.Error("unresolvable hostname should be rejected (fail-closed)")
	}
}

func TestValidateAndPinUpstream_PinsHostnameToIP(t *testing.T) {
	// A resolvable public hostname must be pinned to an IP literal so that
	// subsequent dial calls bypass DNS entirely (closes rebinding TOCTOU).
	pinned, err := validateAndPinUpstream("dns.google:53")
	if err != nil {
		t.Skipf("dns.google did not resolve in this environment: %v", err)
	}
	host, _, splitErr := net.SplitHostPort(pinned)
	if splitErr != nil {
		host = pinned // no port — entire string is the host
	}
	if net.ParseIP(host) == nil {
		t.Errorf("pinned address should be an IP literal, got %q", pinned)
	}
	if !strings.HasSuffix(pinned, ":53") {
		t.Errorf("pinned address should preserve port :53, got %q", pinned)
	}
}

// ---------------------------------------------------------------------------
// handleReadiness — with upstream
// ---------------------------------------------------------------------------

func TestHandleReadiness_WithUpstreamClient(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	// We can't easily mock upstream.Client, but we can set upstreamLB and
	// upstreamClient to nil and verify the no-upstream path returns 200.
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	srv.handleReadiness(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 without upstream, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// handleSPA
// ---------------------------------------------------------------------------

func TestHandleSPA_Delegates(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	called := false
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := srv.handleSPA(mockHandler)
	req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if !called {
		t.Error("SPA handler should delegate to the provided handler")
	}
}

// ---------------------------------------------------------------------------
// handleAddRecord — edge cases
// ---------------------------------------------------------------------------

func TestHandleAddRecord_DefaultTTL(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "example.com.")

	// Add record with TTL=0 — should use zone default TTL (3600)
	body := `{"name":"test.example.com.","type":"A","ttl":0,"data":"1.2.3.4"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/example.com./records", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleAddRecord(rec, req, "example.com.")

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleAddRecord_InvalidJSON(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "example.com.")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones/example.com./records", bytes.NewReader([]byte("{bad")))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleAddRecord(rec, req, "example.com.")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// handleDeleteRecord — edge cases
// ---------------------------------------------------------------------------

func TestHandleDeleteRecord_InvalidJSON(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "example.com.")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/zones/example.com./records", bytes.NewReader([]byte("{bad")))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleDeleteRecord(rec, req, "example.com.")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleDeleteRecord_NotFound(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	createTestZone(t, s.zoneManager, "example.com.")

	body := `{"name":"nonexistent.example.com.","type":"A"}`
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/zones/example.com./records", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()

	s.handleDeleteRecord(rec, req, "example.com.")

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

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
	t.Cleanup(sm.Stop)

	err := sm.AddSlaveZone(transfer.SlaveZoneConfig{
		ZoneName: "synced.example.com.",
		Masters:  []string{"127.0.0.1:53"},
	})
	if err != nil {
		t.Fatalf("AddSlaveZone: %v", err)
	}

	// Get the zone and set it to synced state. Use the exported
	// UpdateZone setter so the assignment goes through sz.mu — the
	// AddSlaveZone goroutine is still racing performZoneTransfer,
	// which reads sz.LastSerial under that same lock.
	zones := sm.GetAllSlaveZones()
	for name, sz := range zones {
		sz.UpdateZone(&zone.Zone{
			Origin: name,
			Records: map[string][]zone.Record{
				"www." + name: {
					{Type: "A", TTL: 300, RData: "10.0.0.1"},
					{Type: "A", TTL: 300, RData: "10.0.0.2"},
				},
			},
		}, 2024010101)
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
	t.Cleanup(sm.Stop)

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

// newTestServerWithAuth creates a server with a test auth store and returns a valid admin token.
func newTestServerWithAuth(t *testing.T, cfg config.HTTPConfig, zm *zone.Manager, c *cache.Cache) (*Server, string) {
	authCfg := &auth.Config{
		Secret:      "test-secret-for-tests",
		Users:       []auth.User{{Username: "testadmin", Password: "testpass", Role: auth.RoleAdmin}},
		TokenExpiry: auth.Duration{Duration: 24 * time.Hour},
	}
	store, _ := auth.NewStore(authCfg)
	srv := NewServer(cfg, zm, c, nil, nil, nil, nil).WithAuth(store)
	token, err := store.GenerateToken("testadmin", 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate test token: %v", err)
	}
	return srv, token.Token
}

// withTestAdminAuth injects the admin user into the request context and sets the Bearer token.
func withTestAdminAuth(req *http.Request, token string) *http.Request {
	req.Header.Set("Authorization", "Bearer "+token)
	user := &auth.User{Username: "testadmin", Role: auth.RoleAdmin}
	req = req.WithContext(WithUser(req.Context(), user))
	return req
}

// attachTestAuth adds a test auth store to an existing server and returns a valid admin token.
func attachTestAuth(s *Server) string {
	authCfg := &auth.Config{
		Secret:      "test-secret-for-tests",
		Users:       []auth.User{{Username: "testadmin", Password: "testpass", Role: auth.RoleAdmin}},
		TokenExpiry: auth.Duration{Duration: 24 * time.Hour},
	}
	store, _ := auth.NewStore(authCfg)
	s.WithAuth(store)
	token, err := store.GenerateToken("testadmin", 24*time.Hour)
	if err != nil {
		panic(err)
	}
	return token.Token
}

// ---------------------------------------------------------------------------
// handleStatus: cover the s.cluster != nil branch (lines 170-178)
// ---------------------------------------------------------------------------

func TestHandleStatus_WithCluster(t *testing.T) {
	cfg := config.HTTPConfig{
		Enabled: true,
		Bind:    "127.0.0.1:0",
	}

	clusterCfg := cluster.Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key required
		NodeID:               "status-test-node",
		BindAddr:             "127.0.0.1",
		GossipPort:           0, // let OS pick
	}
	cl, err := cluster.New(clusterCfg, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create cluster: %v", err)
	}

	cacheCfg := cache.Config{Capacity: 200, MinTTL: 60, MaxTTL: 3600, DefaultTTL: 300}
	c := cache.New(cacheCfg)

	srv := NewServer(cfg, nil, c, nil, nil, cl, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rec := httptest.NewRecorder()
	srv.handleStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	clusterInfo, ok := resp["cluster"].(map[string]interface{})
	if !ok {
		t.Fatal("expected cluster info in response")
	}
	if clusterInfo["enabled"] != true {
		t.Errorf("expected cluster.enabled true, got %v", clusterInfo["enabled"])
	}
	if clusterInfo["node_id"] != "status-test-node" {
		t.Errorf("expected node_id 'status-test-node', got %v", clusterInfo["node_id"])
	}

	// cache info should also be present
	cacheInfo, ok := resp["cache"].(map[string]interface{})
	if !ok {
		t.Fatal("expected cache info in response")
	}
	if cacheInfo["capacity"].(float64) != 200 {
		t.Errorf("expected cache capacity 200, got %v", cacheInfo["capacity"])
	}
}

// TestHandleStatus_RoleTiering verifies V10: operational detail (cache stats,
// cluster topology) is exposed to operators but withheld from viewers, while
// both still get the basic running status.
func TestHandleStatus_RoleTiering(t *testing.T) {
	statusFor := func(role auth.Role) StatusResponse {
		s, user := newAuthenticatedServer(t, "u-"+string(role), role)
		s.cache = cache.New(cache.Config{Capacity: 64, MinTTL: 60, MaxTTL: 3600, DefaultTTL: 300})
		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil).
			WithContext(newAuthenticatedContext(user))
		rec := httptest.NewRecorder()
		s.handleStatus(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("role %s: expected 200, got %d", role, rec.Code)
		}
		var resp StatusResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("role %s: decode: %v", role, err)
		}
		return resp
	}

	op := statusFor(auth.RoleOperator)
	if op.Status != "running" {
		t.Errorf("operator status = %q, want running", op.Status)
	}
	if op.Cache == nil {
		t.Error("operator should see cache stats")
	}

	viewer := statusFor(auth.RoleViewer)
	if viewer.Status != "running" {
		t.Errorf("viewer status = %q, want running", viewer.Status)
	}
	if viewer.Cache != nil {
		t.Error("viewer must NOT see cache stats (V10)")
	}
}

// ---------------------------------------------------------------------------
// Start: cover DoH branch (lines 50-53) and cluster routes branch (lines 60-63)
// ---------------------------------------------------------------------------

// mockDNSHandler is a minimal server.Handler implementation for tests.
type mockDNSHandler struct{}

func (m *mockDNSHandler) ServeDNS(_ server.ResponseWriter, _ *protocol.Message) {}

func TestStart_DoHEnabled(t *testing.T) {
	addr := pickFreeAddr(t)
	cfg := config.HTTPConfig{
		Enabled:    true,
		Bind:       addr,
		DoHEnabled: true,
		DoHPath:    "/dns-query",
	}

	srv := NewServer(cfg, nil, nil, nil, &mockDNSHandler{}, nil, nil)

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Verify the DoH endpoint was registered by making an HTTP GET to it.
	// A GET to /dns-query without proper DNS wireformat should still get a
	// response (not 404), confirming the route exists.
	resp, err := http.Get("http://" + addr + "/dns-query")
	if err != nil {
		t.Fatalf("failed to reach DoH endpoint: %v", err)
	}
	resp.Body.Close()
	// We don't care about the exact status; we just need to confirm it isn't 404.
	if resp.StatusCode == http.StatusNotFound {
		t.Error("DoH endpoint returned 404 -- route may not be registered")
	}

	srv.Stop()
}

func TestStart_WithCluster(t *testing.T) {
	addr := pickFreeAddr(t)
	clusterCfg := cluster.Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key required
		NodeID:               "start-cluster-node",
		BindAddr:             "127.0.0.1",
		GossipPort:           0,
	}
	cl, err := cluster.New(clusterCfg, nil, nil)
	if err != nil {
		t.Fatalf("failed to create cluster: %v", err)
	}

	cfg := config.HTTPConfig{
		Enabled: true,
		Bind:    addr,
	}

	srv := NewServer(cfg, nil, nil, nil, nil, cl, nil)

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Verify cluster endpoints were registered.
	for _, path := range []string{"/api/v1/cluster/status", "/api/v1/cluster/nodes"} {
		resp, err := http.Get("http://" + addr + path)
		if err != nil {
			t.Fatalf("failed to reach %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			t.Errorf("cluster endpoint %s returned 404 -- route may not be registered", path)
		}
	}

	srv.Stop()
}

func TestStart_DoHEnabledWithoutDNSHandler(t *testing.T) {
	// When DoHEnabled is true but dnsHandler is nil, the DoH block should be skipped.
	// The SPA fallback handler will serve index.html for the path instead.
	addr := pickFreeAddr(t)
	cfg := config.HTTPConfig{
		Enabled:    true,
		Bind:       addr,
		DoHEnabled: true,
		DoHPath:    "/dns-query",
	}

	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// The /dns-query route is not registered as a DoH handler (dnsHandler is nil),
	// but the SPA fallback will serve index.html for the path.
	resp, err := http.Get("http://" + addr + "/dns-query")
	if err != nil {
		t.Fatalf("failed to reach server: %v", err)
	}
	resp.Body.Close()
	// SPA fallback returns 200 with HTML, not 404
	if resp.StatusCode == http.StatusNotFound {
		t.Error("SPA fallback should serve index.html, got 404")
	}

	srv.Stop()
}

// pickFreeAddr returns a free "127.0.0.1:port" address by opening a
// temporary TCP listener. This avoids Windows Hyper-V port exclusion ranges.
func pickFreeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// ---------------------------------------------------------------------------
// handleZoneReload: cover successful reload path (lines 228-235)
// ---------------------------------------------------------------------------

func TestHandleZoneReload_Success(t *testing.T) {
	// Create a temporary zone file so Reload can re-read it.
	zoneContent := `$ORIGIN testzone.com.
$TTL 3600
@ IN SOA ns1 hostmaster 2024010101 3600 900 604800 86400
@ IN NS ns1
@ IN A 10.0.0.1
`
	tmpDir := t.TempDir()
	zonePath := filepath.Join(tmpDir, "testzone.com.zone")
	if err := os.WriteFile(zonePath, []byte(zoneContent), 0644); err != nil {
		t.Fatalf("failed to write temp zone file: %v", err)
	}

	zm := zone.NewManager()
	if err := zm.Load("testzone.com.", zonePath); err != nil {
		t.Fatalf("failed to load zone: %v", err)
	}

	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv, token := newTestServerWithAuth(t, cfg, zm, nil)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodPost, "/api/v1/zones/reload?zone=testzone.com.", nil), token)
	rec := httptest.NewRecorder()
	srv.handleZoneReload(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	expectedMsg := "Zone testzone.com. reloaded"
	if resp["message"] != expectedMsg {
		t.Errorf("expected message %q, got %q", expectedMsg, resp["message"])
	}
}

func TestHandleZoneReload_PUTMethodNotAllowed(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/zones/reload?zone=example.com.", nil)
	rec := httptest.NewRecorder()
	srv.handleZoneReload(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

func TestHandleZoneReload_DeleteMethodNotAllowed(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/zones/reload?zone=example.com.", nil)
	rec := httptest.NewRecorder()
	srv.handleZoneReload(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

// ---------------------------------------------------------------------------
// handleServerConfig
// ---------------------------------------------------------------------------

func TestHandleServerConfig(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv, token := newTestServerWithAuth(t, cfg, nil, nil)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/server/config", nil), token)
	rec := httptest.NewRecorder()
	srv.handleServerConfig(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["version"] == nil {
		t.Error("expected version in response")
	}
}

func TestHandleServerConfig_MethodNotAllowed(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/api/v1/server/config", nil)
		rec := httptest.NewRecorder()
		srv.handleServerConfig(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405 for %s, got %d", method, rec.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// handleDashboardStats
// ---------------------------------------------------------------------------

func TestHandleDashboardStats(t *testing.T) {
	cacheCfg := cache.Config{Capacity: 500, MinTTL: 60, MaxTTL: 3600, DefaultTTL: 300}
	c := cache.New(cacheCfg)

	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv, token := newTestServerWithAuth(t, cfg, nil, c)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodGet, "/api/dashboard/stats", nil), token)
	rec := httptest.NewRecorder()
	srv.handleDashboardStats(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["queriesTotal"] == nil {
		t.Error("expected queriesTotal in response")
	}
}

func TestHandleDashboardStats_NoCache(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv, token := newTestServerWithAuth(t, cfg, nil, nil)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodGet, "/api/dashboard/stats", nil), token)
	rec := httptest.NewRecorder()
	srv.handleDashboardStats(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// handleDNSSECStatus
// ---------------------------------------------------------------------------

func TestHandleDNSSECStatus_Disabled(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv, token := newTestServerWithAuth(t, cfg, nil, nil)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/dnssec/status", nil), token)
	rec := httptest.NewRecorder()
	srv.handleDNSSECStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["enabled"] != false {
		t.Errorf("expected enabled=false, got %v", resp["enabled"])
	}
}

func TestHandleDNSSECStatus_MethodNotAllowed(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/api/v1/dnssec/status", nil)
		rec := httptest.NewRecorder()
		srv.handleDNSSECStatus(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405 for %s, got %d", method, rec.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// handleDNSSECKeys
// ---------------------------------------------------------------------------

func TestHandleDNSSECKeys_NoSigners(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv, token := newTestServerWithAuth(t, cfg, nil, nil)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/dnssec/keys", nil), token)
	rec := httptest.NewRecorder()
	srv.handleDNSSECKeys(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	// zones may be nil or empty slice when no signers are configured
	if zones, ok := resp["zones"].([]any); ok && zones != nil {
		if len(zones) != 0 {
			t.Errorf("expected 0 zones, got %d", len(zones))
		}
	}
}

func TestHandleDNSSECKeys_MethodNotAllowed(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/api/v1/dnssec/keys", nil)
		rec := httptest.NewRecorder()
		srv.handleDNSSECKeys(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405 for %s, got %d", method, rec.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// handleReadiness
// ---------------------------------------------------------------------------

func TestHandleReadiness_NoUpstream(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	srv.handleReadiness(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["status"] != "ready" {
		t.Errorf("expected status=ready, got %v", resp["status"])
	}
}

// ---------------------------------------------------------------------------
// handleLiveness
// ---------------------------------------------------------------------------

func TestHandleLiveness(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	rec := httptest.NewRecorder()
	srv.handleLiveness(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["status"] != "alive" {
		t.Errorf("expected status=alive, got %v", resp["status"])
	}
}

// ---------------------------------------------------------------------------
// handleRoles
// ---------------------------------------------------------------------------

func TestHandleRoles(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	store := newAuthStoreWithUser(t, "operator", "testpass123", auth.RoleOperator)
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil).WithAuth(store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/roles", nil)
	operatorUser, _ := store.GetUser("operator")
	req = req.WithContext(WithUser(req.Context(), operatorUser))
	rec := httptest.NewRecorder()
	srv.handleRoles(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	roles, ok := resp["roles"].([]interface{})
	if !ok {
		t.Fatal("expected roles array")
	}
	if len(roles) < 3 {
		t.Errorf("expected at least 3 roles, got %d", len(roles))
	}
}

// ---------------------------------------------------------------------------
// WithUser and GetUser
// ---------------------------------------------------------------------------

func TestWithUserAndGetUser(t *testing.T) {
	ctx := context.Background()

	// GetUser should return nil when no user in context
	if GetUser(ctx) != nil {
		t.Error("expected nil user from empty context")
	}

	// Create a mock user
	user := &auth.User{Username: "testuser", Role: auth.RoleAdmin}

	// WithUser should add user to context
	ctx = WithUser(ctx, user)

	// GetUser should retrieve it
	retrieved := GetUser(ctx)
	if retrieved == nil {
		t.Fatal("expected non-nil user from context")
	}
	if retrieved.Username != "testuser" {
		t.Errorf("expected username 'testuser', got %s", retrieved.Username)
	}
}

// ---------------------------------------------------------------------------
// handleListZones with zone manager
// ---------------------------------------------------------------------------

func TestHandleListZones_WithZones(t *testing.T) {
	zm := zone.NewManager()
	testZone := &zone.Zone{
		Origin:     "test.com.",
		DefaultTTL: 3600,
		Records:    map[string][]zone.Record{},
	}
	testZone.SOA = &zone.SOARecord{Serial: 12345}
	zm.LoadZone(testZone, "")

	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv, token := newTestServerWithAuth(t, cfg, zm, nil)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil), token)
	rec := httptest.NewRecorder()
	srv.handleZones(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	zones := resp["zones"].([]interface{})
	if len(zones) != 1 {
		t.Errorf("expected 1 zone, got %d", len(zones))
	}
}

// ---------------------------------------------------------------------------
// handleGetZone
// ---------------------------------------------------------------------------

func TestHandleGetZone(t *testing.T) {
	zm := zone.NewManager()
	testZone := &zone.Zone{
		Origin:     "example.com.",
		DefaultTTL: 3600,
		Records:    map[string][]zone.Record{},
	}
	testZone.SOA = &zone.SOARecord{
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minimum: 86400,
		MName:   "ns1.example.com.",
		RName:   "admin.example.com.",
	}
	testZone.NS = []zone.NSRecord{{NSDName: "ns1.example.com."}, {NSDName: "ns2.example.com."}}
	zm.LoadZone(testZone, "")

	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv, token := newTestServerWithAuth(t, cfg, zm, nil)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com.", nil), token)
	rec := httptest.NewRecorder()
	srv.handleZoneActions(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["serial"] != float64(2024010101) {
		t.Errorf("expected serial 2024010101, got %v", resp["serial"])
	}
}

func TestHandleGetZone_NotFound(t *testing.T) {
	zm := zone.NewManager()
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv, token := newTestServerWithAuth(t, cfg, zm, nil)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/zones/nonexistent.com.", nil), token)
	rec := httptest.NewRecorder()
	srv.handleZoneActions(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// handleDeleteZone
// ---------------------------------------------------------------------------

func TestHandleDeleteZone(t *testing.T) {
	zm := zone.NewManager()
	testZone := &zone.Zone{
		Origin:  "delete.me.",
		Records: map[string][]zone.Record{},
	}
	testZone.SOA = &zone.SOARecord{}
	zm.LoadZone(testZone, "")

	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv, token := newTestServerWithAuth(t, cfg, zm, nil)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodDelete, "/api/v1/zones/delete.me.", nil), token)
	rec := httptest.NewRecorder()
	srv.handleZoneActions(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	// Verify zone was deleted
	if _, ok := zm.Get("delete.me."); ok {
		t.Error("zone should have been deleted")
	}
}

func TestHandleDeleteZone_NotFound(t *testing.T) {
	zm := zone.NewManager()
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv, token := newTestServerWithAuth(t, cfg, zm, nil)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodDelete, "/api/v1/zones/nonexistent.com.", nil), token)
	rec := httptest.NewRecorder()
	srv.handleZoneActions(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// handleExportZone
// ---------------------------------------------------------------------------

func TestHandleExportZone(t *testing.T) {
	zm := zone.NewManager()
	testZone := &zone.Zone{
		Origin:     "export.com.",
		DefaultTTL: 3600,
		Records:    map[string][]zone.Record{},
	}
	testZone.SOA = &zone.SOARecord{Serial: 1}
	testZone.NS = []zone.NSRecord{{NSDName: "ns1.export.com."}}
	zm.LoadZone(testZone, "")

	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv, token := newTestServerWithAuth(t, cfg, zm, nil)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/zones/export.com./export", nil), token)
	rec := httptest.NewRecorder()
	srv.handleZoneActions(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	if !strings.Contains(rec.Body.String(), "export.com.") {
		t.Error("expected zone content in response")
	}
}

func TestHandleExportZone_NotFound(t *testing.T) {
	zm := zone.NewManager()
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv, token := newTestServerWithAuth(t, cfg, zm, nil)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/zones/nonexistent.com./export", nil), token)
	rec := httptest.NewRecorder()
	srv.handleZoneActions(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// handleConfigGet
// ---------------------------------------------------------------------------

func TestHandleConfigGet(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	getter := func() *config.Config {
		return &config.Config{}
	}
	srv, token := newTestServerWithAuth(t, cfg, nil, nil)
	srv.WithConfigGetter(getter)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/config", nil), token)
	rec := httptest.NewRecorder()
	srv.handleConfigGet(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestHandleConfigGet_NoGetter(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	rec := httptest.NewRecorder()
	srv.handleConfigGet(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", rec.Code)
	}
}

func TestHandleConfigGet_MethodNotAllowed(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	srv := NewServer(cfg, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/config", nil)
	rec := httptest.NewRecorder()
	srv.handleConfigGet(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// handleZoneActions method routing
// ---------------------------------------------------------------------------

func TestHandleZoneActions_SubpathNotFound(t *testing.T) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	zm := zone.NewManager()
	testZone := &zone.Zone{Origin: "test.com.", Records: map[string][]zone.Record{}}
	testZone.SOA = &zone.SOARecord{}
	zm.LoadZone(testZone, "")

	srv, token := newTestServerWithAuth(t, cfg, zm, nil)

	req := withTestAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/zones/test.com./invalid-subpath", nil), token)
	rec := httptest.NewRecorder()
	srv.handleZoneActions(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}
}
