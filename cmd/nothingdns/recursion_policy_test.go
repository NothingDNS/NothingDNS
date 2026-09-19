package main

import (
	"encoding/binary"
	"net"
	"path/filepath"
	"testing"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/filter"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func newRecursionTestHandler(t *testing.T, allowed ...string) *integratedHandler {
	t.Helper()
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.10"},
	})
	policy, err := filter.NewRecursionPolicy(allowed, false)
	if err != nil {
		t.Fatal(err)
	}
	h.security.RecursionPolicy = policy
	h.cache.Set(cache.MakeKey("cached.example.net.", protocol.TypeA, false), &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Answers: []*protocol.ResourceRecord{{
			Name: mustParseName(t, "cached.example.net."), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300,
			Data: &protocol.RDataA{Address: [4]byte{198, 51, 100, 7}},
		}},
	}, 300)
	return h
}

func queryWithEDNS(t *testing.T, name string) *protocol.Message {
	t.Helper()
	q := newTestQuery(t, name, protocol.TypeA)
	q.SetEDNS0(1232, false)
	return q
}

func edeCode(t *testing.T, msg *protocol.Message) (uint16, bool) {
	t.Helper()
	for _, rr := range msg.Additionals {
		opt, ok := rr.Data.(*protocol.RDataOPT)
		if !ok {
			continue
		}
		for _, o := range opt.Options {
			if o.Code == protocol.OptionCodeExtendedError && len(o.Data) >= 2 {
				return binary.BigEndian.Uint16(o.Data[:2]), true
			}
		}
	}
	return 0, false
}

// Clients outside allow_recursion still get the server's own records.
func TestRecursionPolicy_AuthoritativeAnswersForEveryone(t *testing.T) {
	h := newRecursionTestHandler(t, "10.0.0.0/8")

	w := newCaptureWriter("203.0.113.5", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))

	if w.msg == nil || w.msg.Header.Flags.RCODE != protocol.RcodeSuccess || len(w.msg.Answers) != 1 {
		t.Fatalf("outside client: want NOERROR with the zone record, got %+v", w.msg)
	}
	if w.msg.Header.Flags.RA {
		t.Error("RA must be 0 for a client that may not recurse")
	}
}

// Names outside the zones are refused (EDE 18), and the shared cache is not
// served to clients without recursion rights.
func TestRecursionPolicy_RefusesRecursionAndCache(t *testing.T) {
	h := newRecursionTestHandler(t, "10.0.0.0/8")

	for _, name := range []string{"cached.example.net.", "unknown.example.org."} {
		w := newCaptureWriter("203.0.113.5", "udp")
		h.ServeDNS(w, queryWithEDNS(t, name))
		if w.msg == nil || w.msg.Header.Flags.RCODE != protocol.RcodeRefused {
			t.Fatalf("%s from outside client: want REFUSED, got %+v", name, w.msg)
		}
		if len(w.msg.Answers) != 0 {
			t.Errorf("%s: refused response leaked %d cached answers", name, len(w.msg.Answers))
		}
		if code, ok := edeCode(t, w.msg); !ok || code != protocol.EDEProhibited {
			t.Errorf("%s: EDE = (%d, %v), want Prohibited (18)", name, code, ok)
		}
	}
}

func TestRecursionPolicy_AllowedClientRecurses(t *testing.T) {
	h := newRecursionTestHandler(t, "10.0.0.0/8")

	w := newCaptureWriter("10.1.2.3", "udp")
	h.ServeDNS(w, newTestQuery(t, "cached.example.net.", protocol.TypeA))
	if w.msg == nil || w.msg.Header.Flags.RCODE != protocol.RcodeSuccess || len(w.msg.Answers) != 1 {
		t.Fatalf("allowed client: want the cached answer, got %+v", w.msg)
	}

	// No upstream in the test handler: an allowed client reaches the
	// no-upstream stage (NXDOMAIN) instead of being refused.
	w2 := newCaptureWriter("10.1.2.3", "udp")
	h.ServeDNS(w2, newTestQuery(t, "unknown.example.org.", protocol.TypeA))
	if w2.msg == nil || w2.msg.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Fatalf("allowed client without upstream: want NXDOMAIN, got %+v", w2.msg)
	}
}

// The general ACL still applies before recursion: a denied client gets
// REFUSED even for local zones.
func TestRecursionPolicy_GeneralACLStillApplies(t *testing.T) {
	h := newRecursionTestHandler(t, "0.0.0.0/0")
	acl := filter.NewEmptyACLChecker()
	if err := acl.UpdateRules([]config.ACLRule{{Name: "block", Action: "deny", Networks: []string{"203.0.113.0/24"}}}); err != nil {
		t.Fatal(err)
	}
	h.security.ACLChecker = acl

	w := newCaptureWriter("203.0.113.5", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))
	if w.msg == nil || w.msg.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Fatalf("ACL-denied client: want REFUSED, got %+v", w.msg)
	}
}

func TestInitAccessPolicyPrecedence(t *testing.T) {
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	outside := mustIP(t, "203.0.113.5")
	private := mustIP(t, "192.168.1.5")

	tests := []struct {
		name         string
		mutate       func(*config.Config)
		wantOutside  bool
		wantPrivate  bool
		wantACLRules int
	}{
		{
			name:        "default: private networks only",
			mutate:      func(*config.Config) {},
			wantOutside: false, wantPrivate: true,
		},
		{
			name: "explicit allow_recursion",
			mutate: func(c *config.Config) {
				c.AllowRecursion, c.AllowRecursionSet = []string{"203.0.113.0/24"}, true
			},
			wantOutside: true, wantPrivate: false,
		},
		{
			name:        "explicit empty allow_recursion denies everyone",
			mutate:      func(c *config.Config) { c.AllowRecursion, c.AllowRecursionSet = []string{}, true },
			wantOutside: false, wantPrivate: false,
		},
		{
			name:        "acl_allow_unrestricted_recursion",
			mutate:      func(c *config.Config) { c.Server.ACLAllowUnrestrictedRecursion = true },
			wantOutside: true, wantPrivate: true,
		},
		{
			name: "legacy ACL without allow_recursion keeps recursion for ACL-admitted clients",
			mutate: func(c *config.Config) {
				c.ACL = []config.ACLRule{{Name: "lan", Action: "allow", Networks: []string{"192.168.0.0/16"}}}
			},
			wantOutside: true, wantPrivate: true, wantACLRules: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			tt.mutate(cfg)
			m := &SecurityManager{logger: logger}
			if err := m.initAccessPolicy(cfg); err != nil {
				t.Fatal(err)
			}
			if got := m.result.RecursionPolicy.Allowed(outside); got != tt.wantOutside {
				t.Errorf("outside allowed = %v, want %v", got, tt.wantOutside)
			}
			if got := m.result.RecursionPolicy.Allowed(private); got != tt.wantPrivate {
				t.Errorf("private allowed = %v, want %v", got, tt.wantPrivate)
			}
			if m.result.ACLChecker == nil {
				t.Fatal("ACL checker must always exist so rules can be added at runtime")
			}
			if got := len(m.result.ACLChecker.GetRules()); got != tt.wantACLRules {
				t.Errorf("ACL rules = %d, want %d", got, tt.wantACLRules)
			}
		})
	}
}

// A stored access policy (dashboard changes) overrides the config file.
func TestInitAccessPolicyStoredPolicyWins(t *testing.T) {
	dir := t.TempDir()
	if err := filter.SaveAccessPolicy(filepath.Join(dir, "access_policy.json"), &filter.AccessPolicy{
		ACL:            []filter.StoredACLRule{{Name: "block", Action: "deny", Networks: []string{"198.51.100.0/24"}}},
		AllowRecursion: []string{"203.0.113.5"},
	}); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Storage.DataDir = dir
	cfg.AllowRecursion, cfg.AllowRecursionSet = []string{"10.0.0.0/8"}, true

	m := &SecurityManager{logger: util.NewLogger(util.ERROR, util.TextFormat, nil)}
	if err := m.initAccessPolicy(cfg); err != nil {
		t.Fatal(err)
	}
	if !m.result.RecursionPolicy.Allowed(mustIP(t, "203.0.113.5")) || m.result.RecursionPolicy.Allowed(mustIP(t, "10.1.1.1")) {
		t.Errorf("recursion networks = %v, want the stored [203.0.113.5/32]", m.result.RecursionPolicy.Networks())
	}
	if rules := m.result.ACLChecker.GetRules(); len(rules) != 1 || rules[0].Name != "block" {
		t.Errorf("ACL rules = %+v, want the stored rule", rules)
	}
}

func mustIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("invalid IP %q", s)
	}
	return ip
}
