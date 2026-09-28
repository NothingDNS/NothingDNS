// Round-025 proof: `dnsctl record update` sends an explicit TTL even when the
// operator omitted the optional [ttl] argument, so the server cannot tell
// "keep the current TTL" from "set TTL to 0".
//
// Contract (server side, internal/api/api_zones.go handleUpdateRecord, TTL field):
//
//	// TTL is optional: omitted keeps the record's current TTL, while an
//	// explicit 0 (no caching) is honoured.
//	TTL *uint32 `json:"ttl"`
//
// ...
//
//	if req.TTL != nil { ttl = *req.TTL } else { ttl = currentRecordTTL(...) }
//
// The CLI (cmd/dnsctl/record.go, `update`) sets `ttl := uint32(0)` and always
// marshals `"ttl": ttl` into the request body. With the [ttl] argument
// omitted, the operator's intent is "just change the address, keep the TTL",
// but the wire body carries ttl:0, the server reads req.TTL != nil, and
// stamps the record with TTL 0 (no caching). `add` correctly defaults to 300;
// only `update` defaults to 0.
//
// This test drives the REAL cmdRecord (the production entrypoint the CLI
// dispatches to) against a REAL httptest server that captures the exact JSON
// body on the wire, and asserts the contract: when [ttl] is omitted the
// request must NOT carry a ttl field, so the server can preserve the current
// TTL. Pre-fix the captured body contains "ttl":0 -> FAIL.
//
// CONTROL: when [ttl] IS provided the request must carry exactly that value,
// so this harness proves the assertion is really about the omitted-TTL case
// and not a broken transport.
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// capturedUpdate is the subset of the server's request body the CLI controls.
type capturedUpdate struct {
	Name    string  `json:"name"`
	Type    string  `json:"type"`
	OldData string  `json:"old_data"`
	Data    string  `json:"data"`
	TTL     *uint32 `json:"ttl"`
}

// runRecordUpdate drives the real cmdRecord update subcommand against a real
// HTTP server, returning the request body the CLI actually put on the wire.
// args are exactly what an operator types after `dnsctl record update`.
func runRecordUpdate(t *testing.T, args ...string) capturedUpdate {
	t.Helper()

	var got capturedUpdate
	sawRequest := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading request body: %v", err)
			return
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("decoding request body %q: %v", body, err)
			return
		}
		sawRequest = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"Record updated"}`))
	}))
	defer srv.Close()

	prevServer := globalFlags.Server
	prevKey := globalFlags.APIKey
	globalFlags.Server = srv.URL
	globalFlags.APIKey = ""
	t.Cleanup(func() {
		globalFlags.Server = prevServer
		globalFlags.APIKey = prevKey
	})

	if err := cmdRecord(args); err != nil {
		t.Fatalf("cmdRecord(%v) returned error: %v", args, err)
	}
	if !sawRequest {
		t.Fatalf("CLI never issued an HTTP request for args %v", args)
	}
	return got
}

// CLAIM (the bug): omitting the optional [ttl] argument must leave the TTL
// out of the request so the server keeps the record's current TTL. The CLI
// instead always sends "ttl":0, which the server honors as "no caching",
// silently zeroing the record's TTL.
func TestRecordUpdate_OmittedTTLIsNotSentAsZero(t *testing.T) {
	got := runRecordUpdate(t, "update", "example.com.", "www.example.com.", "A", "192.0.2.1", "192.0.2.2")

	if got.TTL != nil {
		t.Fatalf("FAIL: operator omitted [ttl], so the request must omit \"ttl\" and let the "+
			"server keep the current TTL; CLI sent explicit ttl=%d, which the server "+
			"honors as \"no caching\" and zeroes the record's TTL", *got.TTL)
	}
}

// CONTROL: when [ttl] IS provided the request must carry exactly that value.
// This proves the harness/transport works and the CLAIM above is specifically
// about the omitted-TTL case (a broken harness that never sends a body, or a
// transport that drops fields, would fail here instead).
func TestRecordUpdate_ExplicitTTLIsForwarded(t *testing.T) {
	got := runRecordUpdate(t, "update", "example.com.", "www.example.com.", "A", "192.0.2.1", "192.0.2.2", "600")

	if got.TTL == nil {
		t.Fatal("CONTROL: operator supplied [ttl] 600, request must carry ttl=600, but no ttl field was sent")
	}
	if *got.TTL != 600 {
		t.Fatalf("CONTROL: operator supplied [ttl] 600, request carried ttl=%d, want 600", *got.TTL)
	}
}
