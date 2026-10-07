package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/upstream"
)

// F283: an upstream add/remove must not persist a server list the config
// loader drops at the next start (bad port, empty list), nor put an address
// the pool cannot dial (no port) into the live pool.
func TestHandleUpstreams_RejectsListsTheLoaderWouldDrop(t *testing.T) {
	newFixture := func(t *testing.T, servers ...string) (*overridesFixture, *upstream.Client) {
		f := newOverridesFixture(t)
		f.cfg.Upstream.Servers = append([]string(nil), servers...)
		c, err := upstream.NewClient(upstream.Config{Servers: servers, Strategy: "random", Timeout: time.Second, HealthCheck: time.Hour})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() })
		f.server.WithUpstream(c, nil)
		return f, c
	}

	for _, addr := range []string{"9.9.9.9:99999", "9.9.9.9:abc", "9.9.9.9:0", "9.9.9.9", "[2620:fe::fe]"} {
		f, c := newFixture(t, "8.8.8.8:53")
		rec := f.put(t, f.server.handleUpstreams, f.admin, "/api/v1/upstreams", `{"action":"add","server":"`+addr+`"}`)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("add %s: expected 400, got %d %s", addr, rec.Code, rec.Body.String())
		}
		if n := len(c.Servers()); n != 1 {
			t.Errorf("add %s: pool has %d servers, want 1", addr, n)
		}
		if _, err := os.Stat(f.file); !os.IsNotExist(err) {
			t.Errorf("add %s: overrides file was written", addr)
		}
	}

	f, c := newFixture(t, "8.8.8.8:53")
	rec := f.put(t, f.server.handleUpstreams, f.admin, "/api/v1/upstreams", `{"action":"remove","server":"8.8.8.8:53"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("remove last: expected 400, got %d %s", rec.Code, rec.Body.String())
	}
	if s := c.Servers(); len(s) != 1 || s[0].Address != "8.8.8.8:53" {
		t.Errorf("remove last: pool not restored")
	}

	rec = f.put(t, f.server.handleUpstreams, f.admin, "/api/v1/upstreams", `{"action":"add","server":"9.9.9.9:53"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid add: %d %s", rec.Code, rec.Body.String())
	}
	if o := f.stored(t); o.UpstreamServers == nil || len(*o.UpstreamServers) != 2 {
		t.Errorf("valid add not persisted")
	}
}

// F284: PUT /api/v1/acl without "rules" must not wipe the ACL.
func TestHandleACL_PutWithoutRulesKeepsACL(t *testing.T) {
	s, user, acl, _, file := newRecursionAPIServer(t, auth.RoleAdmin, true)
	if rec := doACLRequest(t, s, user, s.handleACL, http.MethodPut, "/api/v1/acl",
		`{"rules":[{"name":"lan","action":"allow","networks":["192.168.0.0/16"]}]}`); rec.Code != http.StatusOK {
		t.Fatalf("seed: %d %s", rec.Code, rec.Body.String())
	}
	before, _ := os.ReadFile(file)
	for _, body := range []string{`{}`, `{"rules":null}`, `{"rule":[]}`} {
		rec := doACLRequest(t, s, user, s.handleACL, http.MethodPut, "/api/v1/acl", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d", body, rec.Code)
		}
		if len(acl.GetRules()) != 1 {
			t.Errorf("%s: live ACL wiped", body)
		}
	}
	if after, _ := os.ReadFile(file); string(after) != string(before) {
		t.Error("access policy file changed")
	}
	if rec := doACLRequest(t, s, user, s.handleACL, http.MethodPut, "/api/v1/acl", `{"rules":[]}`); rec.Code != http.StatusOK || len(acl.GetRules()) != 0 {
		t.Errorf("explicit [] clear: %d", rec.Code)
	}
}

// F282: CNAME/OVERRIDE RPZ rules need usable override_data.
func TestHandleRPZRules_RejectsUnusableOverrideData(t *testing.T) {
	for body, want := range map[string]int{
		`{"pattern":"p.example","action":"CNAME"}`:                                      http.StatusBadRequest,
		`{"pattern":"p.example","action":"OVERRIDE"}`:                                   http.StatusBadRequest,
		`{"pattern":"p.example","action":"OVERRIDE","override_data":"walled.example."}`: http.StatusBadRequest,
		`{"pattern":"p.example","action":"CNAME","override_data":"walled.example."}`:    http.StatusCreated,
		`{"pattern":"p.example","action":"OVERRIDE","override_data":"192.0.2.1"}`:       http.StatusCreated,
	} {
		engine := newEnabledEngine()
		s := newRPZServer(t, engine)
		req := rpzAdminRequest(http.MethodPost, "/api/v1/rpz/rules", []byte(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.handleRPZRules(rec, req)
		if rec.Code != want {
			t.Errorf("%s: expected %d, got %d", body, want, rec.Code)
		}
		if stored := len(engine.ListQNAMERules()) > 0; stored != (want == http.StatusCreated) {
			t.Errorf("%s: stored=%v", body, stored)
		}
	}
}
