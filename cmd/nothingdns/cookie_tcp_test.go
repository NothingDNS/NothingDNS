package main

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/dnscookie"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// An invalid server cookie (here: one issued before the secret changed) gets
// BADCOOKIE over UDP only. Over connection transports the request is answered
// with a fresh cookie (RFC 7873 §5.2.3/§5.2.4, F736).
func TestStaleServerCookieOverConnectionTransports(t *testing.T) {
	h := newTestHandler()
	jar, err := dnscookie.NewCookieJar(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	h.cookieJar = jar
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "example.com.", Type: "SOA", TTL: 300, RData: "ns1.example.com. admin.example.com. 1 3600 600 604800 300"},
		{Name: "www.example.com.", Type: "A", TTL: 300, RData: "192.0.2.1"},
	})
	stale := make([]byte, 16)
	stale[0] = 1
	binary.BigEndian.PutUint32(stale[4:8], uint32(time.Now().Unix()))

	for _, tc := range []struct {
		proto string
		rcode uint8
	}{
		{"udp", protocol.RcodeBadCookie},
		{"tcp", protocol.RcodeSuccess},
		{"dot", protocol.RcodeSuccess},
		{"https", protocol.RcodeSuccess},
		{"quic", protocol.RcodeSuccess},
	} {
		msg := newTestQuery(t, "www.example.com.", protocol.TypeA)
		msg.SetEDNS0(4096, false)
		msg.GetOPT().Data.(*protocol.RDataOPT).AddOption(protocol.OptionCodeCookie, append([]byte("clientck"), stale...))
		w := newCaptureWriter("10.0.0.1", tc.proto)
		h.ServeDNS(w, msg)
		if w.msg == nil {
			t.Fatalf("%s: no response", tc.proto)
		}
		if w.msg.Header.Flags.RCODE != tc.rcode {
			t.Fatalf("%s: rcode %d, want %d", tc.proto, w.msg.Header.Flags.RCODE, tc.rcode)
		}
		opt := w.msg.GetOPT()
		if opt == nil {
			t.Fatalf("%s: response carries no OPT", tc.proto)
		}
		o := opt.Data.(*protocol.RDataOPT).GetOption(protocol.OptionCodeCookie)
		if o == nil {
			t.Fatalf("%s: response carries no cookie", tc.proto)
		}
		c, err := dnscookie.ParseCookieOption(o.Data)
		if err != nil || !jar.ValidateServerCookie(c.ClientCookie, c.ServerCookie, w.client.IP()) {
			t.Fatalf("%s: response cookie is not a fresh server cookie (%v)", tc.proto, err)
		}
	}
}
