package main

import (
	"os"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/rpz"
	"github.com/nothingdns/nothingdns/internal/upstream"
)

// An out-of-zone CNAME target fetched for a local alias is cached under the
// target's own key, which a direct query reads from the cache stage without
// RPZ response checks: an answer an rpz-ip rule stops must not be cached
// there (F888). A walled garden covered by the rule that sends clients to it
// resolves without recursing (draft-vixie-dnsop-dns-rpz-00 §6).
func TestRPZCNAMETargetNotCachedPastPolicy(t *testing.T) {
	setup := func(t *testing.T, rule string) *integratedHandler {
		h := newTestHandler()
		h.cache = cache.New(cache.Config{Capacity: 100, DefaultTTL: time.Minute, MaxTTL: time.Hour})
		uc, err := upstream.NewClient(upstream.Config{Servers: []string{adUpstream(t, false)}, Timeout: 2 * time.Second}) // every name: A 192.0.2.7
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { uc.Close() })
		h.upstream = uc
		h.zones["local.test."] = loadTestZoneFile(t, "local.test.", `$ORIGIN local.test.
$TTL 300
@   IN SOA ns1.local.test. admin.local.test. ( 1 3600 600 86400 120 )
@   IN NS  ns1.local.test.
ns1 IN A   192.0.2.53
alias IN CNAME evil.example.net.
`)
		h.RebuildZoneTree()
		f := t.TempDir() + "/p.rpz"
		if err := os.WriteFile(f, []byte("$TTL 60\n@ IN SOA ns.rpz. admin.rpz. 1 3600 600 86400 60\n@ IN NS ns.rpz.\n"+rule), 0o600); err != nil {
			t.Fatal(err)
		}
		eng := rpz.NewEngine(rpz.Config{Enabled: true, Files: []string{f}})
		if err := eng.Load(); err != nil {
			t.Fatal(err)
		}
		h.security.RPZEngine = eng
		return h
	}
	ask := func(h *integratedHandler, name string) *protocol.Message {
		w := newCaptureWriter("10.0.0.1", "udp")
		h.ServeDNS(w, newTestQuery(t, name, protocol.TypeA))
		if w.msg == nil {
			t.Fatalf("%s: no response", name)
		}
		return w.msg
	}
	h := setup(t, "32.7.2.0.192.rpz-ip CNAME .\n")
	ask(h, "alias.local.test.")
	if m := ask(h, "evil.example.net."); m.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Errorf("evil.example.net after the alias: rcode %d answers %v, want the rpz-ip NXDOMAIN", m.Header.Flags.RCODE, m.Answers)
	}
	h = setup(t, "32.7.2.0.192.rpz-ip CNAME garden.example.net.\n")
	if m := ask(h, "alias.local.test."); len(m.Answers) != 2 || m.Answers[0].Type != protocol.TypeCNAME {
		t.Errorf("walled garden: %v", m.Answers)
	}
}
