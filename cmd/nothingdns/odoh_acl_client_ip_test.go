package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/filter"
	"github.com/nothingdns/nothingdns/internal/odoh"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
)

// odohInProcRT delivers the ODoH client's POST straight to the target's
// ServeHTTP with a chosen RemoteAddr (no network).
type odohInProcRT struct {
	h      http.Handler
	remote string
}

func (rt odohInProcRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r.RemoteAddr = rt.remote
	rec := httptest.NewRecorder()
	rt.h.ServeHTTP(rec, r)
	return rec.Result(), nil
}

func odohTestRcode(t *testing.T, target *odoh.ObliviousTarget, remote, name string) int {
	t.Helper()
	cfg := odoh.NewODoHConfig("target.invalid", "proxy.invalid")
	cfg.TargetPublicKey = target.ConfigContents()
	client, err := odoh.NewObliviousClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	q := newTestQuery(t, name, protocol.TypeA)
	buf := make([]byte, q.WireLength())
	n, err := q.Pack(buf)
	if err != nil {
		t.Fatal(err)
	}
	// The client's http.Client uses http.DefaultTransport; swap it for the
	// in-process round tripper (tests in this package do not run in parallel
	// with this one).
	old := http.DefaultTransport
	http.DefaultTransport = odohInProcRT{h: target, remote: remote}
	defer func() { http.DefaultTransport = old }()
	plain, err := client.Query(buf[:n])
	if err != nil {
		t.Fatalf("odoh query via %s: %v", remote, err)
	}
	msg, err := protocol.UnpackMessage(plain)
	if err != nil {
		t.Fatal(err)
	}
	return int(msg.Header.Flags.RCODE)
}

// F427: ODoH-target queries used to reach the pipeline with no client
// address, and aclStage skipped the ACL for a nil client IP — so an ACL
// admitting only 192.0.2.0/24 still answered anyone over ODoH. The ACL and
// allow_recursion now apply to the HTTP peer (the proxy).
func TestODoHTarget_ACLAndRecursionApplyToPeer(t *testing.T) {
	h := newRecursionTestHandler(t, "192.0.2.0/24")
	acl := filter.NewEmptyACLChecker()
	if err := acl.UpdateRules([]config.ACLRule{{Name: "lan", Action: "allow", Networks: []string{"192.0.2.0/24", "fe80::/10"}}}); err != nil {
		t.Fatal(err)
	}
	h.security.ACLChecker = acl
	target, err := odoh.NewObliviousTarget(odoh.NewODoHConfig("target.invalid", "proxy.invalid"), h)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		remote, name string
		want         int
	}{
		{"198.51.100.7:4443", "www.example.com.", protocol.RcodeRefused},
		{"[2001:db8::7]:4443", "www.example.com.", protocol.RcodeRefused},
		{"bogus", "www.example.com.", protocol.RcodeRefused},
		{"192.0.2.1:4443", "www.example.com.", protocol.RcodeSuccess},
		{"[fe80::1%eth0]:4443", "www.example.com.", protocol.RcodeSuccess},
		{"192.0.2.1:4443", "cached.example.net.", protocol.RcodeSuccess},
		{"[fe80::1%eth0]:4443", "cached.example.net.", protocol.RcodeRefused}, // ACL ok, no recursion
	}
	for _, tt := range tests {
		if got := odohTestRcode(t, target, tt.remote, tt.name); got != tt.want {
			t.Errorf("%s via %s: rcode = %d, want %d", tt.name, tt.remote, got, tt.want)
		}
	}
}

type nilClientWriter struct{ msg *protocol.Message }

func (w *nilClientWriter) Write(m *protocol.Message) (int, error) { w.msg = m; return 0, nil }
func (w *nilClientWriter) ClientInfo() *server.ClientInfo {
	return &server.ClientInfo{Protocol: "test"}
}
func (w *nilClientWriter) MaxSize() int { return 65535 }

// F427: an unknown (nil) client IP matches no ACL rule, so it is refused
// once any rule exists; with no rules it is still answered.
func TestACLStage_NilClientIPFailsClosed(t *testing.T) {
	h := newRecursionTestHandler(t, "0.0.0.0/0")
	h.security.ACLChecker = filter.NewEmptyACLChecker()
	w := &nilClientWriter{}
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))
	if w.msg == nil || w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Fatalf("empty ACL, nil client: want NOERROR, got %+v", w.msg)
	}

	if err := h.security.ACLChecker.UpdateRules([]config.ACLRule{{Name: "lan", Action: "allow", Networks: []string{"0.0.0.0/0", "::/0"}}}); err != nil {
		t.Fatal(err)
	}
	w = &nilClientWriter{}
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))
	if w.msg == nil || w.msg.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Fatalf("ACL rules present, nil client: want REFUSED, got %+v", w.msg)
	}
}
