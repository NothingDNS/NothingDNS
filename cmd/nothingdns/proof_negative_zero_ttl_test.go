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

// negUpstream answers the first query with the negative response built by
// first(), and every later query with a positive A answer. It counts queries.
func negUpstream(t *testing.T, first func(q *protocol.Question) *protocol.Message, hits *atomic.Int32) string {
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
			var resp *protocol.Message
			if hits.Add(1) == 1 {
				resp = first(q.Questions[0])
			} else {
				resp = &protocol.Message{
					Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
					Answers: []*protocol.ResourceRecord{{
						Name: q.Questions[0].Name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300,
						Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
					}},
				}
			}
			resp.Header.ID = q.Header.ID
			resp.Questions = q.Questions
			out := make([]byte, 4096)
			if m, err := resp.Pack(out); err == nil {
				_, _ = pc.WriteTo(out[:m], addr)
			}
		}
	}()
	return pc.LocalAddr().String()
}

func soaAuthority(t *testing.T, ttl, minimum uint32) []*protocol.ResourceRecord {
	t.Helper()
	return []*protocol.ResourceRecord{{
		Name: ttlName(t, "example.com."), Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: ttl,
		Data: &protocol.RDataSOA{
			MName: ttlName(t, "ns.example.com."), RName: ttlName(t, "admin.example.com."),
			Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: minimum,
		},
	}}
}

// RFC 2308 §5: the negative TTL is the SOA's min(TTL, MINIMUM), and a zero TTL
// means "can only be used for the transaction in progress, and should not be
// cached" (RFC 1035 §3.2.1, RFC 8767 §4). A negative answer whose SOA says 0 —
// an operator who publishes a name before it is live, a short-lived NODATA —
// must not be replayed from the cache for the configured negative_ttl.
func TestNegativeAnswerWithZeroSOATTLIsNotCached(t *testing.T) {
	const qname = "fresh.example.com."

	run := func(t *testing.T, rcode uint8, soaTTL, soaMin uint32) (firstRcode, secondRcode uint8, secondAnswers int, hits int32) {
		t.Helper()
		h := newTestHandler()
		h.cache = cache.New(cache.Config{
			Capacity: 100, DefaultTTL: time.Minute, MinTTL: 0, MaxTTL: time.Hour, NegativeTTL: time.Minute,
		})
		var n atomic.Int32
		uc, err := upstream.NewClient(upstream.Config{
			Servers: []string{negUpstream(t, func(*protocol.Question) *protocol.Message {
				return &protocol.Message{
					Header:      protocol.Header{Flags: protocol.Flags{QR: true, AA: true, RA: true, RCODE: rcode}},
					Authorities: soaAuthority(t, soaTTL, soaMin),
				}
			}, &n)},
			Timeout: 2 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer uc.Close()
		h.upstream = uc

		ask := func() *protocol.Message {
			w := newCaptureWriter("10.0.0.1", "udp")
			h.ServeDNS(w, newTestQuery(t, qname, protocol.TypeA))
			if w.msg == nil {
				t.Fatal("no response")
			}
			return w.msg
		}
		a := ask()
		b := ask()
		return a.Header.Flags.RCODE, b.Header.Flags.RCODE, len(b.Answers), n.Load()
	}

	t.Run("control: SOA 300/300 negative is served from cache", func(t *testing.T) {
		first, second, answers, hits := run(t, protocol.RcodeNameError, 300, 300)
		if first != protocol.RcodeNameError || second != protocol.RcodeNameError || answers != 0 || hits != 1 {
			t.Fatalf("first=%d second=%d answers=%d upstreamHits=%d, want NXDOMAIN twice from one upstream query", first, second, answers, hits)
		}
	})

	for _, tc := range []struct {
		name         string
		rcode        uint8
		soaTTL, soaM uint32
	}{
		{"NXDOMAIN, SOA TTL 0 MINIMUM 0", protocol.RcodeNameError, 0, 0},
		{"NXDOMAIN, SOA TTL 300 MINIMUM 0", protocol.RcodeNameError, 300, 0},
		{"NXDOMAIN, SOA TTL 0 MINIMUM 300", protocol.RcodeNameError, 0, 300},
		{"NODATA, SOA TTL 0 MINIMUM 0", protocol.RcodeSuccess, 0, 0},
	} {
		t.Run(tc.name+" is re-asked", func(t *testing.T) {
			_, second, answers, hits := run(t, tc.rcode, tc.soaTTL, tc.soaM)
			if second != protocol.RcodeSuccess || answers != 1 || hits != 2 {
				t.Fatalf("FAIL: negative answer with SOA TTL=%d MINIMUM=%d was cached: second query rcode=%d answers=%d upstreamHits=%d (want NOERROR, 1 answer, 2 hits)",
					tc.soaTTL, tc.soaM, second, answers, hits)
			}
		})
	}
}
