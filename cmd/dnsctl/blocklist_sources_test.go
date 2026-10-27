package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/blocklist"
)

// GET /api/v1/blocklists/sources answers a JSON array; dnsctl decoded it as an
// object and failed on every call (F746).
func TestBlocklistSourcesDecodesArray(t *testing.T) {
	for _, tc := range []struct {
		body, want string
	}{
		{func() string {
			b, _ := json.Marshal([]blocklist.SourceInfo{{ID: "/etc/nothingdns/ads.txt", Type: "file", Enabled: true, Domains: 42}})
			return string(b)
		}(), "/etc/nothingdns/ads.txt (file, 42 domains, enabled=true)"},
		{`[]`, "No blocklist sources configured"},
		{`null`, "No blocklist sources configured"},
	} {
		withAPIMock(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path != "/api/v1/blocklists/sources" {
				t.Errorf("unexpected request %s", r.URL.Path)
			}
			return jsonResponse(r, http.StatusOK, tc.body), nil
		}))
		var err error
		out := captureStdout(t, func() { err = cmdBlocklist([]string{"sources"}) })
		if err != nil || !strings.Contains(out, tc.want) {
			t.Errorf("body %s: err=%v output=%q, want %q", tc.body, err, out, tc.want)
		}
	}
}
