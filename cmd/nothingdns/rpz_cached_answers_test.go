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

// RPZ policies apply to every response (draft-vixie-dnsop-dns-rpz-00 §4): a
// response-IP rule loaded after an answer was cached applies to that cached
// answer too, as blocklist CNAME inspection does (F890).
func TestRPZResponseRuleAppliesToCachedAnswers(t *testing.T) {
	h := newTestHandler()
	h.cache = cache.New(cache.Config{Capacity: 100, DefaultTTL: time.Minute, MaxTTL: time.Hour})
	uc, err := upstream.NewClient(upstream.Config{Servers: []string{cnameUpstream(t, "cdn.example.net.")}, Timeout: 2 * time.Second}) // A 192.0.2.80
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	h.upstream = uc
	rcode := func() uint8 {
		w := newCaptureWriter("10.0.0.1", "udp")
		h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))
		if w.msg == nil {
			t.Fatal("no response")
		}
		return w.msg.Header.Flags.RCODE
	}
	if rc := rcode(); rc != protocol.RcodeSuccess {
		t.Fatalf("before the rule: rcode %d", rc)
	}
	f := t.TempDir() + "/p.rpz"
	if err := os.WriteFile(f, []byte("$TTL 60\n@ IN SOA ns.rpz. admin.rpz. 1 3600 600 86400 60\n@ IN NS ns.rpz.\n32.80.2.0.192.rpz-ip CNAME .\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	eng := rpz.NewEngine(rpz.Config{Enabled: true, Files: []string{f}})
	if err := eng.Load(); err != nil {
		t.Fatal(err)
	}
	h.security.RPZEngine = eng // as a reload swaps the engine
	if rc := rcode(); rc != protocol.RcodeNameError {
		t.Fatalf("cached answer after the rpz-ip rule: rcode %d, want NXDOMAIN", rc)
	}
}
