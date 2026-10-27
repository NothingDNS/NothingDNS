package main

import (
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/blocklist"
	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/upstream"
)

// cnameUpstream answers every query with "<qname> CNAME target" and
// "target A 192.0.2.80".
func cnameUpstream(t *testing.T, target string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	tgt := ttlName(t, target)
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
			resp := &protocol.Message{
				Header:    protocol.Header{ID: q.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
				Questions: q.Questions,
				Answers: []*protocol.ResourceRecord{
					{Name: q.Questions[0].Name, Type: protocol.TypeCNAME, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataCNAME{CName: tgt}},
					{Name: tgt, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 80}}},
				},
			}
			out := make([]byte, 4096)
			if m, err := resp.Pack(out); err == nil {
				_, _ = pc.WriteTo(out[:m], addr)
			}
		}
	}()
	return pc.LocalAddr().String()
}

// CNAME cloaking: metrics.example.com is not listed, but its answer leads to
// a listed tracker. With blocklist.cname_inspection (the default) the answer
// is blocked like a listed name, also when it comes from the cache; with it
// off the chain is served.
func TestBlocklistCNAMEInspection(t *testing.T) {
	const qname = "metrics.example.com."
	serve := func(t *testing.T, inspect bool) *protocol.Message {
		t.Helper()
		h := newTestHandler()
		h.cache = cache.New(cache.Config{Capacity: 100, DefaultTTL: time.Minute, MaxTTL: time.Hour})
		bl := blocklist.New(blocklist.Config{Enabled: true, CNAMEInspection: inspect})
		bl.AddDomain("tracker.example.net")
		h.security.Blocklist = bl
		uc, err := upstream.NewClient(upstream.Config{Servers: []string{cnameUpstream(t, "cdn.tracker.example.net.")}, Timeout: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer uc.Close()
		h.upstream = uc
		w := newCaptureWriter("10.0.0.1", "udp")
		h.ServeDNS(w, queryWithEDNS(t, qname))
		if w.msg == nil {
			t.Fatal("no response")
		}
		return w.msg
	}

	got := serve(t, true)
	if got.Header.Flags.RCODE != protocol.RcodeNameError || len(got.Answers) != 0 {
		t.Fatalf("inspection on: rcode=%d answers=%d, want NXDOMAIN", got.Header.Flags.RCODE, len(got.Answers))
	}
	if code, ok := edeCode(t, got); !ok || code != protocol.EDEFiltered {
		t.Errorf("inspection on: EDE = %d (%v), want Filtered", code, ok)
	}
	if got := serve(t, false); got.Header.Flags.RCODE != protocol.RcodeSuccess || len(got.Answers) != 2 {
		t.Fatalf("inspection off: rcode=%d answers=%d, want the CNAME chain", got.Header.Flags.RCODE, len(got.Answers))
	}

	t.Run("a cached chain is blocked once its target is listed", func(t *testing.T) {
		h := newTestHandler()
		h.cache = cache.New(cache.Config{Capacity: 100, DefaultTTL: time.Minute, MaxTTL: time.Hour})
		bl := blocklist.New(blocklist.Config{Enabled: true, CNAMEInspection: true})
		h.security.Blocklist = bl
		tgt := ttlName(t, "cdn.tracker.example.net.")
		h.cache.Set(cache.MakeKey(qname, protocol.TypeA, false), &protocol.Message{
			Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Answers: []*protocol.ResourceRecord{
				{Name: ttlName(t, qname), Type: protocol.TypeCNAME, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataCNAME{CName: tgt}},
				{Name: tgt, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 80}}},
			},
		}, 300)
		query := func() *protocol.Message {
			w := newCaptureWriter("10.0.0.1", "udp")
			h.ServeDNS(w, newTestQuery(t, qname, protocol.TypeA))
			if w.msg == nil {
				t.Fatal("no response")
			}
			return w.msg
		}
		if got := query(); got.Header.Flags.RCODE != protocol.RcodeSuccess || len(got.Answers) != 2 {
			t.Fatalf("before listing: rcode=%d answers=%d", got.Header.Flags.RCODE, len(got.Answers))
		}
		bl.AddDomain("tracker.example.net")
		if got := query(); got.Header.Flags.RCODE != protocol.RcodeNameError {
			t.Fatalf("after listing: rcode=%d, want NXDOMAIN", got.Header.Flags.RCODE)
		}
	})
}
