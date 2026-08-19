package main

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

// withAPIMock points the dnsctl API client at a fake transport for the
// duration of the test and restores the previous globals afterwards
// (same save/restore pattern as TestCmdServer_HealthBodyReadError).
func withAPIMock(t *testing.T, h roundTripFunc) {
	t.Helper()
	origServer := globalFlags.Server
	origAPIKey := globalFlags.APIKey
	origClient := httpClient
	globalFlags.Server = "http://example.com"
	globalFlags.APIKey = ""
	httpClient = &http.Client{Transport: h}
	t.Cleanup(func() {
		globalFlags.Server = origServer
		globalFlags.APIKey = origAPIKey
		httpClient = origClient
	})
}

// jsonResponse builds a canned API response with a JSON body.
func jsonResponse(r *http.Request, status int, payload string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(payload)),
		Header:     make(http.Header),
		Request:    r,
	}
}

// captureStdout runs fn with os.Stdout redirected to a pipe and returns
// everything fn printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	fn()
	if err := w.Close(); err != nil {
		t.Fatalf("closing pipe: %v", err)
	}
	var buf strings.Builder
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("reading pipe: %v", err)
	}
	return buf.String()
}

// TestCmdDNSSECStatus_Success covers the happy path: GET
// /api/v1/dnssec/status is issued and the payload is rendered.
func TestCmdDNSSECStatus_Success(t *testing.T) {
	withAPIMock(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		if r.URL.Path != "/api/v1/dnssec/status" {
			t.Errorf("path = %q, want /api/v1/dnssec/status", r.URL.Path)
		}
		return jsonResponse(r, http.StatusOK,
			`{"enabled":true,"trust_anchors":1,"cache":{"hits":2,"misses":3}}`), nil
	}))

	out := captureStdout(t, func() {
		if err := cmdDNSSECStatus(nil); err != nil {
			t.Errorf("cmdDNSSECStatus: %v", err)
		}
	})
	for _, want := range []string{"DNSSEC Status:", "enabled", "trust_anchors", "cache"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// TestCmdDNSSECStatus_APIError covers the failure path: a non-2xx API
// response must surface as an error, not be printed as a status.
func TestCmdDNSSECStatus_APIError(t *testing.T) {
	withAPIMock(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResponse(r, http.StatusInternalServerError, `{"error":"validator unavailable"}`), nil
	}))
	if err := cmdDNSSECStatus(nil); err == nil {
		t.Fatal("expected error when the API call fails")
	}
}

// TestCmdDNSSECKeys_NoKeys covers the empty-zone-list branch: the
// command reports "No DNSSEC keys configured." instead of a bare table
// header.
func TestCmdDNSSECKeys_NoKeys(t *testing.T) {
	withAPIMock(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		if r.URL.Path != "/api/v1/dnssec/keys" {
			t.Errorf("path = %q, want /api/v1/dnssec/keys", r.URL.Path)
		}
		return jsonResponse(r, http.StatusOK, `{"zones":[]}`), nil
	}))

	var err error
	out := captureStdout(t, func() { err = cmdDNSSECKeys(nil) })
	if err != nil {
		t.Fatalf("cmdDNSSECKeys: %v", err)
	}
	if !strings.Contains(out, "No DNSSEC keys configured.") {
		t.Errorf("output missing empty-list message:\n%s", out)
	}
}

// TestCmdDNSSECKeys_Table covers the table-rendering path: header row,
// per-zone rows with key_tag/algorithm/KSK/ZSK formatting, and the
// skip branch for non-map entries in the zones array.
func TestCmdDNSSECKeys_Table(t *testing.T) {
	withAPIMock(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResponse(r, http.StatusOK, `{"zones":[
			{"zone":"example.com.","key_tag":12345,"algorithm":13,"is_ksk":true,"is_zsk":false},
			{"zone":"other.test.","key_tag":777,"algorithm":8,"is_ksk":false,"is_zsk":true},
			"not-a-map-entry"
		]}`), nil
	}))

	var err error
	out := captureStdout(t, func() { err = cmdDNSSECKeys(nil) })
	if err != nil {
		t.Fatalf("cmdDNSSECKeys: %v", err)
	}
	for _, want := range []string{
		"ZONE", "KEY-TAG", "ALGORITHM", // header
		"example.com.", "12345", "13", // first row
		"other.test.", "777", // second row
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "not-a-map-entry") {
		t.Errorf("non-map zone entry leaked into table:\n%s", out)
	}
}

// TestCmdDNSSECKeys_APIError covers the failure path for the keys query.
func TestCmdDNSSECKeys_APIError(t *testing.T) {
	withAPIMock(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResponse(r, http.StatusForbidden, `{"error":"admin role required"}`), nil
	}))
	if err := cmdDNSSECKeys(nil); err == nil {
		t.Fatal("expected error when the API call fails")
	}
}
