package main

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/upstream"
)

// The query sent upstream carries this server's own OPT (1232 bytes, the
// client's DO bit) and none of the client's EDNS options or other additional
// records: OPT is hop-by-hop (RFC 6891 §6.1.1) (F749).

type fwdCapture struct {
	mu  sync.Mutex
	got *protocol.Message
}

func fwdUpstream(t *testing.T, c *fwdCapture) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q, err := protocol.UnpackMessage(buf[:n])
			if err != nil || len(q.Questions) != 1 {
				continue
			}
			c.mu.Lock()
			c.got = q
			c.mu.Unlock()
			resp := &protocol.Message{Header: protocol.Header{ID: q.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)}, Questions: q.Questions}
			resp.Header.Flags.RA = true
			out := make([]byte, 4096)
			if m, err := resp.Pack(out); err == nil {
				_, _ = pc.WriteTo(out[:m], addr)
			}
		}
	}()
	return pc.LocalAddr().String()
}

func fwdForward(t *testing.T, do bool, opts ...protocol.EDNS0Option) *protocol.Message {
	h := newTestHandler()
	c := &fwdCapture{}
	uc, err := upstream.NewClient(upstream.Config{Servers: []string{fwdUpstream(t, c)}, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { uc.Close() })
	h.upstream = uc
	q := newTestQuery(t, "www.example.org.", protocol.TypeA)
	q.SetEDNS0(4096, do)
	for _, o := range opts {
		q.GetOPT().Data.(*protocol.RDataOPT).AddOption(o.Code, o.Data)
	}
	w := newCaptureWriter("192.0.2.10", "udp")
	h.ServeDNS(w, q)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.got == nil {
		t.Fatal("nothing reached the upstream")
	}
	return c.got
}

func TestForwardedQueryDropsClientOptions(t *testing.T) {
	ecs := protocol.EDNS0Option{Code: protocol.OptionCodeClientSubnet, Data: []byte{0, 1, 24, 0, 198, 51, 100}}
	cookie := protocol.EDNS0Option{Code: protocol.OptionCodeCookie, Data: []byte("clientck0123456789abcdef")}
	pad := protocol.EDNS0Option{Code: protocol.OptionCodePadding, Data: make([]byte, 32)}
	got := fwdForward(t, false, ecs, cookie, pad)
	opt := got.GetOPT()
	if opt == nil || len(opt.Data.(*protocol.RDataOPT).Options) != 0 || opt.Class != forwardedEDNSBufferSize {
		t.Fatalf("upstream query OPT = %+v", opt)
	}
}

func TestForwardedQueryHeaderAndDO(t *testing.T) {
	// The function on its own: header kept, additionals dropped.
	q := newTestQuery(t, "www.example.org.", protocol.TypeA)
	q.Header.Flags.CD = true
	tsigName, _ := protocol.ParseName("key.example.")
	q.Additionals = append(q.Additionals, &protocol.ResourceRecord{Name: tsigName, Type: protocol.TypeTSIG, Class: protocol.ClassANY, Data: &protocol.RDataRaw{Data: []byte{1, 2, 3}}})
	q.Header.ARCount = 1
	f := forwardedQuery(q, false)
	if len(f.Additionals) != 0 || !f.Header.Flags.CD || f.Header.ID != q.Header.ID || len(q.Additionals) != 1 {
		t.Fatalf("no-EDNS client: additionals %d CD %v (client message changed: %d)", len(f.Additionals), f.Header.Flags.CD, len(q.Additionals))
	}
	f = forwardedQuery(q, true)
	if opt := f.GetOPT(); opt == nil || !protocol.ParseEDNS0Header(opt).DO || opt.Class != forwardedEDNSBufferSize || len(f.Additionals) != 1 {
		t.Fatalf("forceDO: %+v", f.Additionals)
	}
	// End to end: the client still gets its answer with EDNS.
	got := fwdForward(t, true, protocol.EDNS0Option{Code: protocol.OptionCodeCookie, Data: []byte("clientck")})
	if opt := got.GetOPT(); opt == nil || !protocol.ParseEDNS0Header(opt).DO || len(opt.Data.(*protocol.RDataOPT).Options) != 0 {
		t.Fatal("DO=1 client query forwarded wrongly")
	}
}
