package main

import (
	"os"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/rpz"
)

// RPZ Local Data as draft-vixie-dnsop-dns-rpz-00 §3.6 specifies it: a
// wildcard CNAME target is the QNAME prepended to it (F880), records of any
// type answer their own type and others get NODATA (F881), an IP trigger's
// records all answer (F882), and $TTL is the TTL of records stating none
// (F883, RFC 2308 §4).
func TestRPZLocalData(t *testing.T) {
	h := newTestHandler()
	h.config.Resolution.AuthoritativeOnly = true
	h.zones["local.test."] = loadTestZoneFile(t, "local.test.", `$ORIGIN local.test.
$TTL 300
@   IN SOA ns1.local.test. admin.local.test. ( 1 3600 600 86400 120 )
@   IN NS  ns1.local.test.
ns1 IN A   192.0.2.53
infected IN A 192.0.2.128
`)
	h.RebuildZoneTree()
	f := t.TempDir() + "/p.rpz"
	body := "$TTL 60\n@ IN SOA ns.rpz. admin.rpz. 1 3600 600 86400 60\n@ IN NS ns.rpz.\n" +
		"bad.example.com CNAME *.garden.example.net.\n" +
		"info.example.com TXT \"blocked by policy\"\n" +
		"mail.example.com MX 10 mx1.example.com.\n" +
		"25.128.2.0.192.rpz-ip A 172.16.0.1\n" +
		"25.128.2.0.192.rpz-ip A 172.16.0.2\n"
	if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	eng := rpz.NewEngine(rpz.Config{Enabled: true, Files: []string{f}})
	if err := eng.Load(); err != nil {
		t.Fatal(err)
	}
	h.security.RPZEngine = eng
	ask := func(name string, qt uint16) string {
		w := newCaptureWriter("10.0.0.1", "tcp")
		h.ServeDNS(w, newTestQuery(t, name, qt))
		if w.msg == nil {
			return "no response"
		}
		var rrs []string
		for _, rr := range w.msg.Answers {
			rrs = append(rrs, strings.Join(strings.Fields(rr.String()), " "))
		}
		return protocol.RcodeToString[int(w.msg.Header.Flags.RCODE)] + " " + strings.Join(rrs, " | ")
	}
	for _, tc := range []struct {
		name string
		qt   uint16
		want string
	}{
		{"bad.example.com.", protocol.TypeA, "NOERROR bad.example.com. 60 IN CNAME bad.example.com.garden.example.net."},
		{"info.example.com.", protocol.TypeTXT, `NOERROR info.example.com. 60 IN TXT "blocked by policy"`},
		{"info.example.com.", protocol.TypeA, "NOERROR "},
		{"mail.example.com.", protocol.TypeMX, "NOERROR mail.example.com. 60 IN MX 10 mx1.example.com."},
		{"infected.local.test.", protocol.TypeA, "NOERROR infected.local.test. 60 IN A 172.16.0.1 | infected.local.test. 60 IN A 172.16.0.2"},
	} {
		if got := ask(tc.name, tc.qt); got != tc.want {
			t.Errorf("%s type %d: %q, want %q", tc.name, tc.qt, got, tc.want)
		}
	}
	if n := eng.Stats().ParseErrors; n != 0 {
		t.Errorf("parse errors %d, want 0 ($TTL is a directive, not a malformed rule)", n)
	}
}
