package main

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/upstream"
	"github.com/nothingdns/nothingdns/internal/util"
)

// prefetchUpstream answers every A query for the name with TTL 2 and counts
// the queries it receives.
func prefetchUpstream(t *testing.T, hits *atomic.Int32) string {
	t.Helper()
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
			hits.Add(1)
			resp := &protocol.Message{
				Header:    protocol.Header{ID: q.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
				Questions: q.Questions,
				Answers: []*protocol.ResourceRecord{{
					Name: q.Questions[0].Name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 2,
					Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
				}},
			}
			out := make([]byte, 4096)
			if m, err := resp.Pack(out); err == nil {
				_, _ = pc.WriteTo(out[:m], addr)
			}
		}
	}()
	return pc.LocalAddr().String()
}

// cache.prefetch is a documented, hot-reloadable option ("prefetch entries that
// are about to expire", docs/CONFIG_REFERENCE.md; API PUT /api/v1/config/cache).
// With it on, a popular entry that is hit inside the prefetch window must be
// refreshed from the upstream in the background, before it expires — the cache
// fires a callback for that, and the server has to supply the callback.
func TestCachePrefetchIsWiredToTheUpstream(t *testing.T) {
	const qname = "popular.example.com."

	var hits atomic.Int32
	cfg := config.DefaultConfig()
	cfg.Cache.Prefetch = true
	cfg.Cache.PrefetchThreshold = 1 // seconds before expiry
	cfg.Cache.MinTTL = 0
	cfg.Cache.MaxTTL = 3600

	mgr := NewCacheManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	defer mgr.Stop()

	h := newTestHandler()
	h.config = cfg
	h.cache = mgr.Cache
	uc, err := upstream.NewClient(upstream.Config{Servers: []string{prefetchUpstream(t, &hits)}, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	h.upstream = uc
	h.wirePrefetch()

	ask := func() {
		w := newCaptureWriter("10.0.0.1", "udp")
		h.ServeDNS(w, newTestQuery(t, qname, protocol.TypeA))
		if w.msg == nil || len(w.msg.Answers) == 0 {
			t.Fatalf("no answer: %+v", w.msg)
		}
	}

	ask() // miss: one upstream query, entry cached with TTL 2
	if got := hits.Load(); got != 1 {
		t.Fatalf("control: first query should reach the upstream once, got %d", got)
	}
	time.Sleep(1200 * time.Millisecond) // inside the 1s prefetch window
	ask()                               // hit inside the window: must trigger a background refresh

	deadline := time.Now().Add(2 * time.Second)
	for hits.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := hits.Load(); got < 2 {
		t.Fatalf("FAIL: cache.prefetch is on and a hot entry was hit inside the prefetch window, but the upstream was never asked to refresh it (upstream queries = %d)", got)
	}

	// The refreshed entry replaced the old one: it is fresh again past the
	// original expiry.
	time.Sleep(1200 * time.Millisecond)
	if e := mgr.Cache.Get(cache.MakeKey(qname, protocol.TypeA, false)); e == nil {
		t.Fatal("entry expired although it was prefetched")
	}
}

// With cache.prefetch off the same traffic must not cause any background query.
func TestCachePrefetchOffDoesNotRefresh(t *testing.T) {
	const qname = "popular.example.com."

	var hits atomic.Int32
	cfg := config.DefaultConfig()
	cfg.Cache.Prefetch = false
	cfg.Cache.PrefetchThreshold = 1
	cfg.Cache.MinTTL = 0
	cfg.Cache.MaxTTL = 3600

	mgr := NewCacheManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	defer mgr.Stop()

	h := newTestHandler()
	h.config = cfg
	h.cache = mgr.Cache
	uc, err := upstream.NewClient(upstream.Config{Servers: []string{prefetchUpstream(t, &hits)}, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	h.upstream = uc
	h.wirePrefetch()

	for i := 0; i < 2; i++ {
		w := newCaptureWriter("10.0.0.1", "udp")
		h.ServeDNS(w, newTestQuery(t, qname, protocol.TypeA))
		if i == 0 {
			time.Sleep(1200 * time.Millisecond)
		}
	}
	time.Sleep(300 * time.Millisecond)
	if got := hits.Load(); got != 1 {
		t.Fatalf("prefetch is off, upstream queries = %d, want exactly 1", got)
	}
}
