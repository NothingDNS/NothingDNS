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

// draft-vixie-dnsop-dns-rpz-00 §5.1/§5.4: a QNAME PASSTHRU outranks a
// response-IP rule of the same zone, and a client-IP PASSTHRU exempts that
// client only — its answer is not cached for others (F885).
func TestRPZPassthruOutranksLaterTriggers(t *testing.T) {
	f := t.TempDir() + "/z.rpz"
	body := "$TTL 60\n@ IN SOA ns.rpz. admin.rpz. 1 3600 600 86400 60\n@ IN NS ns.rpz.\n" +
		"ok.example.com CNAME rpz-passthru.\n" +
		"32.5.0.0.10.rpz-client-ip CNAME rpz-passthru.\n" +
		"32.80.2.0.192.rpz-ip CNAME .\n"
	if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newTestHandler()
	h.cache = cache.New(cache.Config{Capacity: 100, DefaultTTL: time.Minute, MaxTTL: time.Hour})
	uc, err := upstream.NewClient(upstream.Config{Servers: []string{cnameUpstream(t, "cdn.example.net.")}, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	h.upstream = uc
	eng := rpz.NewEngine(rpz.Config{Enabled: true, Files: []string{f}})
	if err := eng.Load(); err != nil {
		t.Fatal(err)
	}
	h.security.RPZEngine = eng
	rcode := func(client, name string) uint8 {
		w := newCaptureWriter(client, "udp")
		h.ServeDNS(w, newTestQuery(t, name, protocol.TypeA))
		if w.msg == nil {
			t.Fatalf("%s from %s: no response", name, client)
		}
		return w.msg.Header.Flags.RCODE
	}
	if got := rcode("10.0.0.1", "ok.example.com."); got != protocol.RcodeSuccess {
		t.Errorf("QNAME PASSTHRU name: rcode %d, want NOERROR", got)
	}
	if got := rcode("10.0.0.1", "other.example.com."); got != protocol.RcodeNameError {
		t.Errorf("unexempt name: rcode %d, want NXDOMAIN", got)
	}
	if got := rcode("10.0.0.5", "x.example.com."); got != protocol.RcodeSuccess {
		t.Errorf("client PASSTHRU: rcode %d, want NOERROR", got)
	}
	if got := rcode("10.0.0.1", "x.example.com."); got != protocol.RcodeNameError {
		t.Errorf("other client after an exempt one: rcode %d, want NXDOMAIN (not from the cache)", got)
	}
}
