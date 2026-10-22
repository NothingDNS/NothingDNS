package main

import (
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/rpz"
	"github.com/nothingdns/nothingdns/internal/upstream"
	"github.com/nothingdns/nothingdns/internal/util"
)

// prefetchRig is a handler with prefetch on, a cache holding a fresh entry for
// name and an upstream whose answer can be changed between the first query and
// the refresh.
type prefetchRig struct {
	h    *integratedHandler
	mgr  *CacheManager
	key  string
	hits atomic.Int32
	// reply decides the upstream's answer for the n-th query (1-based).
	reply func(n int32, q *protocol.Question) *protocol.Message
}

func newPrefetchRig(t *testing.T, name string, reply func(n int32, q *protocol.Question) *protocol.Message) *prefetchRig {
	t.Helper()
	r := &prefetchRig{key: cache.MakeKey(name, protocol.TypeA, false), reply: reply}

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
			msg := r.reply(r.hits.Add(1), q.Questions[0])
			msg.Header.ID = q.Header.ID
			msg.Questions = q.Questions
			out := make([]byte, 4096)
			if m, err := msg.Pack(out); err == nil {
				_, _ = pc.WriteTo(out[:m], addr)
			}
		}
	}()

	cfg := config.DefaultConfig()
	cfg.Cache.Prefetch = true
	cfg.Cache.PrefetchThreshold = 5
	cfg.Cache.MinTTL = 0
	cfg.Cache.MaxTTL = 3600
	r.mgr = NewCacheManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	t.Cleanup(r.mgr.Stop)

	r.h = newTestHandler()
	r.h.config = cfg
	r.h.cache = r.mgr.Cache
	uc, err := upstream.NewClient(upstream.Config{Servers: []string{pc.LocalAddr().String()}, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { uc.Close() })
	r.h.upstream = uc
	return r
}

func aMsg(t *testing.T, owner string, ttl uint32, last byte) *protocol.Message {
	t.Helper()
	return &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Answers: []*protocol.ResourceRecord{{
			Name: ttlName(t, owner), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: ttl,
			Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, last}},
		}},
	}
}

func (r *prefetchRig) cachedAddr() (byte, bool) {
	e := r.mgr.Cache.Get(r.key)
	if e == nil || e.Message == nil {
		return 0, false
	}
	for _, rr := range e.Message.Answers {
		if a, ok := rr.Data.(*protocol.RDataA); ok {
			return a.Address[3], true
		}
	}
	return 0, false
}

func (r *prefetchRig) seed(t *testing.T, name string, ttl uint32, last byte) {
	t.Helper()
	r.mgr.Cache.Set(r.key, aMsg(t, name, ttl, last), ttl)
}

func TestPrefetchReplacesTheEntryWithTheFreshAnswer(t *testing.T) {
	const name = "pf.example.com."
	r := newPrefetchRig(t, name, func(n int32, q *protocol.Question) *protocol.Message {
		return &protocol.Message{
			Header:  protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Answers: aMsg(t, name, 600, 99).Answers,
		}
	})
	r.seed(t, name, 30, 10)

	r.h.prefetch(r.key, protocol.TypeA)

	if got := r.hits.Load(); got != 1 {
		t.Fatalf("upstream queries = %d, want 1", got)
	}
	last, ok := r.cachedAddr()
	if !ok || last != 99 {
		t.Fatalf("cached address = %d (present=%v), want the refreshed 99", last, ok)
	}
	e := r.mgr.Cache.Get(r.key)
	if e.CanPrefetch {
		t.Error("a prefetched entry must not be prefetchable again (infinite refresh loop)")
	}
}

// A refresh that a client query would not have accepted must leave the old
// entry alone: it simply expires on schedule.
func TestPrefetchDropsAnswersAClientMissWouldNotCache(t *testing.T) {
	const name = "pf.example.com."

	cases := []struct {
		name  string
		reply func(t *testing.T) *protocol.Message
	}{
		{"SERVFAIL", func(t *testing.T) *protocol.Message {
			return &protocol.Message{Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeServerFailure)}}
		}},
		{"NXDOMAIN replaces nothing", func(t *testing.T) *protocol.Message {
			return &protocol.Message{Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeNameError)}}
		}},
		{"empty NOERROR", func(t *testing.T) *protocol.Message {
			return &protocol.Message{Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)}}
		}},
		{"TTL 0 answer is not cacheable", func(t *testing.T) *protocol.Message {
			return aMsg(t, name, 0, 99)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newPrefetchRig(t, name, func(int32, *protocol.Question) *protocol.Message { return tc.reply(t) })
			r.seed(t, name, 30, 10)

			r.h.prefetch(r.key, protocol.TypeA)

			if r.hits.Load() != 1 {
				t.Fatalf("upstream queries = %d, want 1", r.hits.Load())
			}
			if last, ok := r.cachedAddr(); !ok || last != 10 {
				t.Fatalf("cached address = %d (present=%v), want the original 10 left in place", last, ok)
			}
		})
	}
}

func TestPrefetchHonoursRPZResponsePolicy(t *testing.T) {
	const name = "pf.example.com."
	r := newPrefetchRig(t, name, func(int32, *protocol.Question) *protocol.Message { return aMsg(t, name, 600, 66) })
	r.seed(t, name, 30, 10)

	dir := t.TempDir()
	zoneFile := dir + "/p.rpz"
	// 192.0.2.66 is on the response-IP blocklist: NXDOMAIN.
	body := "$TTL 60\n@ IN SOA ns.rpz. admin.rpz. 1 3600 600 86400 60\n@ IN NS ns.rpz.\n32.66.2.0.192.rpz-ip IN CNAME .\n"
	if err := os.WriteFile(zoneFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	eng := rpz.NewEngine(rpz.Config{Enabled: true, Files: []string{zoneFile}})
	if err := eng.Load(); err != nil {
		t.Fatalf("rpz load: %v", err)
	}
	r.h.security.RPZEngine = eng

	r.h.prefetch(r.key, protocol.TypeA)

	if last, ok := r.cachedAddr(); !ok || last != 10 {
		t.Fatalf("RPZ-blocked refresh was stored: cached address = %d (present=%v), want the original 10", last, ok)
	}
}

func TestPrefetchRejectsMismatchedAndUnrecoverableKeys(t *testing.T) {
	const name = "pf.example.com."
	r := newPrefetchRig(t, name, func(int32, *protocol.Question) *protocol.Message { return aMsg(t, name, 600, 99) })
	r.seed(t, name, 30, 10)

	// qtype disagrees with the key.
	r.h.prefetch(r.key, protocol.TypeAAAA)
	// Not a cache key at all.
	r.h.prefetch("garbage", protocol.TypeA)
	// A name over the key length limit is stored hashed and cannot be recovered.
	long := make([]byte, 0, 200)
	for len(long) < 150 {
		long = append(long, "abcdefghi."...)
	}
	r.h.prefetch(cache.MakeKey(string(long)+"example.com.", protocol.TypeA, false), protocol.TypeA)

	if got := r.hits.Load(); got != 0 {
		t.Fatalf("upstream was queried %d times for keys that cannot be refreshed, want 0", got)
	}
	if last, _ := r.cachedAddr(); last != 10 {
		t.Fatalf("entry changed to %d, want untouched", last)
	}
}

func TestPrefetchWithoutAnyUpstreamIsANoOp(t *testing.T) {
	const name = "pf.example.com."
	r := newPrefetchRig(t, name, func(int32, *protocol.Question) *protocol.Message { return aMsg(t, name, 600, 99) })
	r.seed(t, name, 30, 10)
	r.h.upstream = nil

	r.h.prefetch(r.key, protocol.TypeA) // must neither panic nor change the entry

	if last, _ := r.cachedAddr(); last != 10 {
		t.Fatalf("entry changed to %d, want untouched", last)
	}
}
