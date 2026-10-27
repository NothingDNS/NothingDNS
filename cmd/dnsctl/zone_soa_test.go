package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const soaJSON = `{"mname":"ns1.example.test.","rname":"admin.example.test.","ttl":3600,"serial":2026102702,"refresh":7200,"retry":600,"expire":604800,"minimum":300}`

func TestZoneSOAShow(t *testing.T) {
	withAPIMock(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/zones/example.test/soa" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		return jsonResponse(r, http.StatusOK, soaJSON), nil
	}))
	out := captureStdout(t, func() {
		if err := cmdZone([]string{"soa", "example.test"}); err != nil {
			t.Fatal(err)
		}
	})
	for _, want := range []string{"mname    ns1.example.test.", "serial   2026102702", "minimum  300"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestZoneSOAUpdateSendsOnlyGivenFields(t *testing.T) {
	withAPIMock(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/v1/zones/example.test/soa" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body) != 2 || body["refresh"] != float64(7200) || body["rname"] != "dns@example.test" {
			t.Errorf("body = %v", body)
		}
		return jsonResponse(r, http.StatusOK, soaJSON), nil
	}))
	captureStdout(t, func() {
		if err := cmdZone([]string{"soa", "example.test", "refresh=7200", "rname=dns@example.test"}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestZoneSOARejectsBadSettings(t *testing.T) {
	withAPIMock(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Errorf("no request expected, got %s %s", r.Method, r.URL.Path)
		return jsonResponse(r, http.StatusOK, soaJSON), nil
	}))
	for _, arg := range []string{"serial=5", "refresh=soon", "colour=red", "refresh", "retry=-1"} {
		if err := cmdZone([]string{"soa", "example.test", arg}); err == nil {
			t.Errorf("%s: accepted", arg)
		}
	}
}
