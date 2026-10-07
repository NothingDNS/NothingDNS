package doh

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
)

type clientIPCapture struct {
	ip   net.IP
	resp *protocol.Message
}

func (c *clientIPCapture) ServeDNS(w server.ResponseWriter, r *protocol.Message) {
	c.ip = w.ClientInfo().IP()
	resp := c.resp
	if resp == nil {
		resp = &protocol.Message{Header: protocol.Header{ID: r.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)}, Questions: r.Questions}
	}
	_, _ = w.Write(resp)
}

// F292: a link-local client's RemoteAddr is zoned ("[fe80::1%eth0]:port");
// it must reach the DNS pipeline as fe80::1, not a 0.0.0.0 placeholder that
// slips past IPv6 ACL rules and shares one rate-limit bucket.
func TestDoHClientInfo_ZonedIPv6RemoteAddr(t *testing.T) {
	queryData, _ := createTestQuery()
	for _, tc := range []struct{ remote, want string }{
		{"[fe80::1%eth0]:4443", "fe80::1"},
		{"[2001:db8::1]:4443", "2001:db8::1"},
		{"192.0.2.7:53", "192.0.2.7"},
	} {
		c := &clientIPCapture{}
		req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+base64.RawURLEncoding.EncodeToString(queryData), nil)
		req.RemoteAddr = tc.remote
		NewHandler(c).ServeHTTP(httptest.NewRecorder(), req)
		if !c.ip.Equal(net.ParseIP(tc.want)) {
			t.Errorf("wire %s: client IP = %v, want %s", tc.remote, c.ip, tc.want)
		}

		c = &clientIPCapture{}
		req = httptest.NewRequest(http.MethodGet, "/dns-query?name=www.example.com&type=A", nil)
		req.RemoteAddr = tc.remote
		NewHandler(c).ServeHTTP(httptest.NewRecorder(), req)
		if !c.ip.Equal(net.ParseIP(tc.want)) {
			t.Errorf("json %s: client IP = %v, want %s", tc.remote, c.ip, tc.want)
		}

		ws := (&wsResponseWriter{httpReq: &http.Request{RemoteAddr: tc.remote}}).ClientInfo().IP()
		if !ws.Equal(net.ParseIP(tc.want)) {
			t.Errorf("ws %s: client IP = %v, want %s", tc.remote, ws, tc.want)
		}
	}
}

// F293: RFC 8484 §5.1 — the HTTP freshness lifetime must not exceed the
// smallest Answer TTL, or the SOA MINIMUM / TTL for a negative answer.
func TestDoHCacheControl_MaxAgeFromTTL(t *testing.T) {
	a := func(ttl uint32) *protocol.ResourceRecord {
		return &protocol.ResourceRecord{Name: mustName("www.example.com."), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: ttl, Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}}}
	}
	soa := func(ttl, minimum uint32) *protocol.ResourceRecord {
		return &protocol.ResourceRecord{Name: mustName("example.com."), Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: ttl,
			Data: &protocol.RDataSOA{MName: mustName("ns.example.com."), RName: mustName("h.example.com."), Serial: 1, Refresh: 1, Retry: 1, Expire: 1, Minimum: minimum}}
	}
	queryData, query := createTestQuery()
	for _, tc := range []struct {
		name string
		resp *protocol.Message
		want string
	}{
		{"min answer ttl", &protocol.Message{Answers: []*protocol.ResourceRecord{a(30), a(600), a(300)}}, "max-age=30"},
		{"zero ttl", &protocol.Message{Answers: []*protocol.ResourceRecord{a(0)}}, "max-age=0"},
		{"negative soa minimum", &protocol.Message{Authorities: []*protocol.ResourceRecord{soa(3600, 60)}}, "max-age=60"},
		{"negative soa ttl", &protocol.Message{Authorities: []*protocol.ResourceRecord{soa(10, 60)}}, "max-age=10"},
		{"no records", &protocol.Message{}, "max-age=0"},
	} {
		tc.resp.Header = protocol.Header{ID: query.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)}
		tc.resp.Questions = query.Questions
		req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+base64.RawURLEncoding.EncodeToString(queryData), nil)
		rec := httptest.NewRecorder()
		NewHandler(&clientIPCapture{resp: tc.resp}).ServeHTTP(rec, req)
		if got := rec.Header().Get("Cache-Control"); rec.Code != http.StatusOK || got != tc.want {
			t.Errorf("%s: status %d Cache-Control %q, want 200 %q", tc.name, rec.Code, got, tc.want)
		}
	}
}
