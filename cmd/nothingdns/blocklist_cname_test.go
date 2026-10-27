package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/blocklist"
	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/dns64"
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

// F728: prefetch must not store (or refresh) a chain a client miss would
// block; otherwise a blocked tracker keeps being resolved upstream.
func TestBlocklistCNAMEInspectionPrefetch(t *testing.T) {
	const qname = "metrics.example.com."
	key := cache.MakeKey(qname, protocol.TypeA, false)
	setup := func(t *testing.T, target string, listed, enabled bool) *integratedHandler {
		h := newTestHandler()
		h.cache = cache.New(cache.Config{Capacity: 100, DefaultTTL: time.Minute, MaxTTL: time.Hour})
		bl := blocklist.New(blocklist.Config{Enabled: true, CNAMEInspection: true})
		if listed {
			bl.AddDomain("tracker.example.net")
		}
		bl.SetEnabled(enabled)
		h.security.Blocklist = bl
		uc, err := upstream.NewClient(upstream.Config{Servers: []string{cnameUpstream(t, target)}, Timeout: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { uc.Close() })
		h.upstream = uc
		return h
	}
	answerTTL := func(h *integratedHandler) uint32 {
		e := h.cache.Get(key)
		if e == nil || e.Message == nil || len(e.Message.Answers) == 0 {
			return 0
		}
		return e.Message.Answers[0].TTL
	}

	t.Run("blocked chain already cached is not refreshed", func(t *testing.T) {
		h := setup(t, "cdn.tracker.example.net.", true, true)
		tgt := ttlName(t, "cdn.tracker.example.net.")
		h.cache.Set(key, &protocol.Message{
			Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Answers: []*protocol.ResourceRecord{
				{Name: ttlName(t, qname), Type: protocol.TypeCNAME, Class: protocol.ClassIN, TTL: 5, Data: &protocol.RDataCNAME{CName: tgt}},
				{Name: tgt, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 5, Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 80}}},
			},
		}, 5)
		h.prefetch(key, protocol.TypeA)
		if ttl := answerTTL(h); ttl > 5 {
			t.Fatalf("blocked entry refreshed to TTL %d", ttl)
		}
	})
	t.Run("blocklist disabled: refreshed", func(t *testing.T) {
		h := setup(t, "cdn.tracker.example.net.", true, false)
		h.prefetch(key, protocol.TypeA)
		if answerTTL(h) == 0 {
			t.Fatal("not stored with the blocklist disabled")
		}
	})
	t.Run("unlisted target: refreshed", func(t *testing.T) {
		h := setup(t, "cdn.example.org.", true, true)
		h.prefetch(key, protocol.TypeA)
		if answerTTL(h) == 0 {
			t.Fatal("unlisted chain not stored")
		}
	})
	t.Run("blocked target not stored", func(t *testing.T) {
		h := setup(t, "x.tracker.example.net.", true, true)
		h.prefetch(key, protocol.TypeA)
		if h.cache.Get(key) != nil {
			t.Fatal("blocked chain stored")
		}
	})
}

// F729: DNS64 synthesises from a separate A query, whose chain is checked
// like the AAAA answer's.
func TestBlocklistCNAMEInspectionDNS64(t *testing.T) {
	const qname = "metrics.example.com."
	run := func(t *testing.T, target string, inspect, enabled bool) *protocol.Message {
		h := newTestHandler()
		uc, err := upstream.NewClient(upstream.Config{Servers: []string{cnameUpstream(t, target)}, Timeout: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer uc.Close()
		h.upstream = uc
		synth, err := dns64.NewSynthesizer("", 0)
		if err != nil {
			t.Fatal(err)
		}
		h.security.DNS64Synth = synth
		bl := blocklist.New(blocklist.Config{Enabled: true, CNAMEInspection: inspect})
		bl.AddDomain("tracker.example.net")
		bl.SetEnabled(enabled)
		h.security.Blocklist = bl
		r := newTestQuery(t, qname, protocol.TypeAAAA)
		r.SetEDNS0(1232, false)
		resp := &protocol.Message{Header: protocol.Header{ID: r.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)}}
		w := newCaptureWriter("10.0.0.1", "udp")
		h.tryDNS64Synthesis(context.Background(), w, r, r.Questions[0], resp)
		if w.msg == nil {
			t.Fatal("no response written")
		}
		return w.msg
	}
	got := run(t, "cdn.tracker.example.net.", true, true)
	if got.Header.Flags.RCODE != protocol.RcodeNameError || len(got.Answers) != 0 {
		t.Fatalf("blocked: rcode=%d answers=%d", got.Header.Flags.RCODE, len(got.Answers))
	}
	if code, ok := edeCode(t, got); !ok || code != protocol.EDEFiltered {
		t.Fatalf("blocked: EDE %d %v", code, ok)
	}
	for _, c := range []struct {
		name            string
		target          string
		inspect, enable bool
	}{
		{"inspection off", "cdn.tracker.example.net.", false, true},
		{"blocklist disabled", "cdn.tracker.example.net.", true, false},
		{"unlisted target", "cdn.example.org.", true, true},
	} {
		if m := run(t, c.target, c.inspect, c.enable); len(aaaaAddrs(m)) == 0 {
			t.Fatalf("%s: AAAA not synthesized (rcode %d)", c.name, m.Header.Flags.RCODE)
		}
	}
}
