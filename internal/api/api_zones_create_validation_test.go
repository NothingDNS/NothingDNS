package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateZoneValidatesEveryNameserver(t *testing.T) {
	for name, nameservers := range map[string][]string{
		"first contains newline":  {"ns1.bad.example.\ninjected 0 IN A 192.0.2.66"},
		"second contains newline": {"ns1.bad.example.", "ns2.bad.example.\ninjected 0 IN A 192.0.2.66"},
		"empty label":             {"ns1..bad.example."},
	} {
		t.Run(name, func(t *testing.T) {
			s, user := newServerWithAuthAndZones(t)
			body, err := json.Marshal(map[string]any{
				"name": "bad.example.", "admin_email": "hostmaster@example.test",
				"nameservers": nameservers,
			})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/zones", bytes.NewReader(body))
			req = req.WithContext(WithUser(req.Context(), user))
			rec := httptest.NewRecorder()
			s.handleZones(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
			}
			if got := s.zoneManager.Count(); got != 0 {
				t.Fatalf("rejected create left %d zone(s), want 0", got)
			}
		})
	}
}

func TestCreateZoneCanonicalizesValidatedRelativeNameservers(t *testing.T) {
	s, user := newServerWithAuthAndZones(t)
	body, err := json.Marshal(map[string]any{
		"name": "relative.example.", "admin_email": "hostmaster@example.test",
		"nameservers": []string{"ns1", "ns2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones", bytes.NewReader(body))
	req = req.WithContext(WithUser(req.Context(), user))
	rec := httptest.NewRecorder()
	s.handleZones(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	z, ok := s.zoneManager.Get("relative.example.")
	if !ok {
		t.Fatal("created zone is missing")
	}
	wants := []string{"ns1.relative.example.", "ns2.relative.example."}
	if len(z.NS) != len(wants) {
		t.Fatalf("created zone has %d NS records, want %d", len(z.NS), len(wants))
	}
	for i, want := range wants {
		if got := z.NS[i].NSDName; got != want {
			t.Errorf("NS[%d] = %q, want %q", i, got, want)
		}
	}
}
