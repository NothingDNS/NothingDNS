package odoh

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
)

type peerCaptureHandler struct{ ip chan net.IP }

func (c *peerCaptureHandler) ServeDNS(w server.ResponseWriter, r *protocol.Message) {
	c.ip <- w.ClientInfo().IP()
	resp := &protocol.Message{Header: protocol.Header{ID: r.Header.ID, Flags: protocol.NewResponseFlags(0)}, Questions: r.Questions}
	_, _ = w.Write(resp)
}

type peerRT struct {
	h      http.Handler
	remote string
}

func (rt peerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r.RemoteAddr = rt.remote
	rec := httptest.NewRecorder()
	rt.h.ServeHTTP(rec, r)
	return rec.Result(), nil
}

// F427: the ODoH target must report its HTTP peer (the proxy) as the client
// address so ACL / allow_recursion / RPZ client-IP / rate limiting apply.
// Previously ClientInfo carried no address and the pipeline skipped the ACL.
func TestObliviousTarget_ReportsHTTPPeerAsClient(t *testing.T) {
	capture := &peerCaptureHandler{ip: make(chan net.IP, 1)}
	target, err := NewObliviousTarget(NewODoHConfig("target.invalid", "proxy.invalid"), capture)
	if err != nil {
		t.Fatal(err)
	}
	q, err := protocol.NewQuery(1, "www.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, q.WireLength())
	n, err := q.Pack(buf)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ remote, want string }{
		{"198.51.100.7:4443", "198.51.100.7"},
		{"[2001:db8::7]:4443", "2001:db8::7"},
		{"[fe80::1%eth0]:4443", "fe80::1"},
		{"bogus", "<nil>"},
	} {
		cfg := NewODoHConfig("target.invalid", "proxy.invalid")
		cfg.TargetPublicKey = target.ConfigContents()
		client, err := NewObliviousClient(cfg)
		if err != nil {
			t.Fatal(err)
		}
		client.client.Transport = peerRT{h: target, remote: tt.remote}
		if _, err := client.Query(buf[:n]); err != nil {
			t.Fatalf("%s: query: %v", tt.remote, err)
		}
		if got := <-capture.ip; got.String() != tt.want {
			t.Errorf("RemoteAddr %q: client IP = %v, want %s", tt.remote, got, tt.want)
		}
	}
}
