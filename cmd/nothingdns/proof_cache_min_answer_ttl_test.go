package main

import (
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/upstream"
)

// ttlUpstream answers every A query for qname with the given answer records.
func ttlUpstream(t *testing.T, answers func(q *protocol.Question) []*protocol.ResourceRecord) string {
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
			resp := &protocol.Message{
				Header:    protocol.Header{ID: q.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
				Questions: q.Questions,
				Answers:   answers(q.Questions[0]),
			}
			out := make([]byte, 4096)
			if m, err := resp.Pack(out); err == nil {
				_, _ = pc.WriteTo(out[:m], addr)
			}
		}
	}()
	return pc.LocalAddr().String()
}

func ttlName(t *testing.T, s string) *protocol.Name {
	t.Helper()
	n, err := protocol.ParseName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// A cache entry must not outlive any record it holds (RFC 1035 §3.2.1,
// RFC 2181 §8: the TTL is the longest time a record may be cached). With a
// CNAME chain the answer section carries RRsets with different TTLs — a
// long-lived CNAME in front of a short-lived CDN A record is the everyday
// shape — so the entry's lifetime is the SMALLEST positive TTL in the answer,
// not the TTL of whichever record happens to come first. The resolver's own
// cacheResponse already uses the minimum; the forwarded path took the first.
func TestForwardedAnswerCacheLifetimeIsMinimumTTL(t *testing.T) {
	const qname = "www.example.com."

	lifetime := func(t *testing.T, build func() []*protocol.ResourceRecord) time.Duration {
		t.Helper()
		h := newTestHandler()
		h.cache = cache.New(cache.Config{Capacity: 100, DefaultTTL: time.Minute, MinTTL: time.Second, MaxTTL: time.Hour})
		uc, err := upstream.NewClient(upstream.Config{
			Servers: []string{ttlUpstream(t, func(*protocol.Question) []*protocol.ResourceRecord { return build() })},
			Timeout: 2 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer uc.Close()
		h.upstream = uc

		w := newCaptureWriter("10.0.0.1", "udp")
		h.ServeDNS(w, newTestQuery(t, qname, protocol.TypeA))
		if w.msg == nil || len(w.msg.Answers) == 0 {
			t.Fatalf("no answer forwarded: %+v", w.msg)
		}
		entry := h.cache.Get(cache.MakeKey(qname, protocol.TypeA, false))
		if entry == nil {
			t.Fatal("answer was not cached")
		}
		return time.Until(entry.ExpireTime)
	}

	cname := func(ttl uint32) *protocol.ResourceRecord {
		return &protocol.ResourceRecord{Name: ttlName(t, qname), Type: protocol.TypeCNAME, Class: protocol.ClassIN, TTL: ttl,
			Data: &protocol.RDataCNAME{CName: ttlName(t, "cdn.example.com.")}}
	}
	addr := func(owner string, ttl uint32) *protocol.ResourceRecord {
		return &protocol.ResourceRecord{Name: ttlName(t, owner), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: ttl,
			Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}}}
	}

	t.Run("control: single record keeps its own TTL", func(t *testing.T) {
		got := lifetime(t, func() []*protocol.ResourceRecord { return []*protocol.ResourceRecord{addr(qname, 30)} })
		if got > 31*time.Second || got < 20*time.Second {
			t.Fatalf("lifetime = %v, want about 30s", got)
		}
	})

	t.Run("CNAME 3600 then A 30 expires with the A record", func(t *testing.T) {
		got := lifetime(t, func() []*protocol.ResourceRecord {
			return []*protocol.ResourceRecord{cname(3600), addr("cdn.example.com.", 30)}
		})
		if got > 31*time.Second {
			t.Fatalf("FAIL: entry cached for %v although its A record's TTL is 30s (first-record TTL 3600 was used)", got)
		}
	})

	t.Run("short record first, long second: still the minimum", func(t *testing.T) {
		got := lifetime(t, func() []*protocol.ResourceRecord {
			return []*protocol.ResourceRecord{addr(qname, 45), addr(qname, 3000)}
		})
		if got > 46*time.Second || got < 30*time.Second {
			t.Fatalf("lifetime = %v, want about 45s", got)
		}
	})
}
