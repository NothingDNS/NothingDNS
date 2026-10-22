package main

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/upstream"
)

// changingUpstream answers the A query for qname with the address held in
// *addr (last octet) and the TTL held in *ttl, and counts the queries.
func changingUpstream(t *testing.T, qname string, last *atomic.Uint32, ttls func() []uint32, hits *atomic.Int32) string {
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
			}
			owner := q.Questions[0].Name
			for i, ttl := range ttls() {
				if i == 0 && len(ttls()) == 2 {
					// two-record shape: CNAME first, then the address at the target
					resp.Answers = append(resp.Answers, &protocol.ResourceRecord{
						Name: owner, Type: protocol.TypeCNAME, Class: protocol.ClassIN, TTL: ttl,
						Data: &protocol.RDataCNAME{CName: ttlName(t, "target.example.com.")},
					})
					continue
				}
				name := owner
				if len(ttls()) == 2 {
					name = ttlName(t, "target.example.com.")
				}
				resp.Answers = append(resp.Answers, &protocol.ResourceRecord{
					Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: ttl,
					Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, byte(last.Load())}},
				})
			}
			out := make([]byte, 4096)
			if m, err := resp.Pack(out); err == nil {
				_, _ = pc.WriteTo(out[:m], addr)
			}
		}
	}()
	return pc.LocalAddr().String()
}

// RFC 1035 §3.2.1 / RFC 8767 §4: "Zero values are interpreted to mean that the
// RR can only be used for the transaction in progress, and should not be
// cached." A record the authority publishes with TTL 0 (a health-checked
// load-balancer answer, an ACME challenge, a failover address) must therefore
// be re-fetched on the next query, not replayed from the cache.
func TestZeroTTLAnswerIsNotCached(t *testing.T) {
	const qname = "dyn.example.com."

	run := func(t *testing.T, ttls func() []uint32) (first, second byte, upstreamHits int32) {
		t.Helper()
		h := newTestHandler()
		h.cache = cache.New(cache.Config{Capacity: 100, DefaultTTL: time.Minute, MinTTL: 0, MaxTTL: time.Hour})
		var last atomic.Uint32
		var hits atomic.Int32
		last.Store(10)
		uc, err := upstream.NewClient(upstream.Config{
			Servers: []string{changingUpstream(t, qname, &last, ttls, &hits)},
			Timeout: 2 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer uc.Close()
		h.upstream = uc

		addrOf := func() byte {
			w := newCaptureWriter("10.0.0.1", "udp")
			h.ServeDNS(w, newTestQuery(t, qname, protocol.TypeA))
			if w.msg == nil {
				t.Fatal("no response")
			}
			for _, rr := range w.msg.Answers {
				if a, ok := rr.Data.(*protocol.RDataA); ok {
					return a.Address[3]
				}
			}
			t.Fatalf("no A record in %+v", w.msg.Answers)
			return 0
		}
		first = addrOf()
		last.Store(20) // the authority fails over to a new address
		second = addrOf()
		return first, second, hits.Load()
	}

	t.Run("control: a 300s answer is served from cache", func(t *testing.T) {
		first, second, hits := run(t, func() []uint32 { return []uint32{300} })
		if first != 10 || second != 10 || hits != 1 {
			t.Fatalf("first=%d second=%d upstreamHits=%d, want 10/10/1 (cached)", first, second, hits)
		}
	})

	t.Run("a TTL 0 answer is re-fetched on the next query", func(t *testing.T) {
		first, second, hits := run(t, func() []uint32 { return []uint32{0} })
		if first != 10 {
			t.Fatalf("first answer = %d, want 10", first)
		}
		if second != 20 || hits != 2 {
			t.Fatalf("FAIL: TTL 0 answer was cached: second=%d (want 20, the failed-over address), upstreamHits=%d (want 2)", second, hits)
		}
	})

	t.Run("CNAME 3600 + A 0: the zero-TTL address still is not cached", func(t *testing.T) {
		first, second, hits := run(t, func() []uint32 { return []uint32{3600, 0} })
		if first != 10 {
			t.Fatalf("first answer = %d, want 10", first)
		}
		if second != 20 || hits != 2 {
			t.Fatalf("FAIL: answer holding a TTL 0 record was cached for the CNAME's TTL: second=%d (want 20), upstreamHits=%d (want 2)", second, hits)
		}
	})
}
