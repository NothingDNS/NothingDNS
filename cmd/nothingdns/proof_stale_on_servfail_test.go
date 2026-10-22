package main

import (
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/resolver"
	"github.com/nothingdns/nothingdns/internal/upstream"
)

// rcodeUpstream answers every query with the given RCODE and no data.
func rcodeUpstream(t *testing.T, rcode uint8) string {
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
				Header:    protocol.Header{ID: q.Header.ID, Flags: protocol.NewResponseFlags(rcode)},
				Questions: q.Questions,
			}
			out := make([]byte, 4096)
			if m, err := resp.Pack(out); err == nil {
				_, _ = pc.WriteTo(out[:m], addr)
			}
		}
	}()
	return pc.LocalAddr().String()
}

// RFC 8767 §4: when the data cannot be refreshed, an expired record MAY be
// used; an answer from the upstream with an error RCODE (SERVFAIL, REFUSED)
// is a failure to refresh and "leaves any previous state intact". The
// documented serve_stale contract (docs/CONFIG_REFERENCE.md) is "serve the
// expired entry while the upstream is failing". An upstream that is up but
// answering SERVFAIL — the typical shape of an upstream outage, since a
// recursive upstream cannot reach the authority — must therefore be served
// the stale answer, exactly like an upstream that does not answer at all.
func TestServeStaleOnUpstreamServerFailure(t *testing.T) {
	const qname = "stale.example.com."

	serve := func(t *testing.T, upstreamRcode uint8, withStale bool) *protocol.Message {
		t.Helper()
		h := newTestHandler()
		c := cache.New(cache.Config{
			Capacity: 100, DefaultTTL: time.Minute, MinTTL: 0, MaxTTL: time.Hour,
			ServeStale: true, StaleGrace: time.Hour,
		})
		h.cache = c
		if withStale {
			c.Set(cache.MakeKey(qname, protocol.TypeA, false), &protocol.Message{
				Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
				Answers: []*protocol.ResourceRecord{{
					Name: ttlName(t, qname), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 10,
					Data: &protocol.RDataA{Address: [4]byte{203, 0, 113, 7}},
				}},
			}, 0) // ttl 0 with no min_ttl floor: the entry is already expired, but within the stale grace
		}
		uc, err := upstream.NewClient(upstream.Config{Servers: []string{rcodeUpstream(t, upstreamRcode)}, Timeout: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer uc.Close()
		h.upstream = uc

		w := newCaptureWriter("10.0.0.1", "udp")
		h.ServeDNS(w, newTestQuery(t, qname, protocol.TypeA))
		if w.msg == nil {
			t.Fatal("no response")
		}
		return w.msg
	}

	t.Run("SERVFAIL with a stale entry serves the stale answer", func(t *testing.T) {
		got := serve(t, protocol.RcodeServerFailure, true)
		if got.Header.Flags.RCODE != protocol.RcodeSuccess || len(got.Answers) != 1 {
			t.Fatalf("FAIL: upstream SERVFAIL with a stale entry cached returned rcode=%d answers=%d, want the stale NOERROR answer",
				got.Header.Flags.RCODE, len(got.Answers))
		}
		if ttl := got.Answers[0].TTL; ttl == 0 || ttl > 30 {
			t.Errorf("stale answer TTL = %d, want 1..30 (RFC 8767 §4)", ttl)
		}
	})

	t.Run("control: SERVFAIL with nothing cached stays SERVFAIL", func(t *testing.T) {
		got := serve(t, protocol.RcodeServerFailure, false)
		if got.Header.Flags.RCODE != protocol.RcodeServerFailure {
			t.Fatalf("rcode = %d, want SERVFAIL when there is no stale data to serve", got.Header.Flags.RCODE)
		}
	})
}

// The iterative resolver reports an unreachable or lame authority as a
// SERVFAIL *response* (resolver.servfail), not as an error, so the resolver
// stage must treat that outcome as a failed refresh as well.
func TestServeStaleOnResolverServerFailure(t *testing.T) {
	const qname = "stale.example.com."

	serve := func(t *testing.T, withStale bool) *protocol.Message {
		t.Helper()
		h := newTestHandler()
		c := cache.New(cache.Config{
			Capacity: 100, DefaultTTL: time.Minute, MinTTL: 0, MaxTTL: time.Hour,
			ServeStale: true, StaleGrace: time.Hour,
		})
		h.cache = c
		if withStale {
			c.Set(cache.MakeKey(qname, protocol.TypeA, false), &protocol.Message{
				Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
				Answers: []*protocol.ResourceRecord{{
					Name: ttlName(t, qname), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 10,
					Data: &protocol.RDataA{Address: [4]byte{203, 0, 113, 7}},
				}},
			}, 0)
		}
		// Every authority answers SERVFAIL: the resolver ends in resolver.servfail.
		bad := &protocol.Message{Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeServerFailure)}}
		h.resolver = resolver.NewResolver(resolver.Config{Timeout: 2 * time.Second}, nil, &mockResolverTransport{resp: bad})

		w := newCaptureWriter("10.0.0.1", "udp")
		h.ServeDNS(w, newTestQuery(t, qname, protocol.TypeA))
		if w.msg == nil {
			t.Fatal("no response")
		}
		return w.msg
	}

	t.Run("resolver SERVFAIL with a stale entry serves the stale answer", func(t *testing.T) {
		got := serve(t, true)
		if got.Header.Flags.RCODE != protocol.RcodeSuccess || len(got.Answers) != 1 {
			t.Fatalf("FAIL: resolver SERVFAIL with a stale entry cached returned rcode=%d answers=%d, want the stale NOERROR answer",
				got.Header.Flags.RCODE, len(got.Answers))
		}
	})

	t.Run("control: resolver SERVFAIL with nothing cached stays SERVFAIL", func(t *testing.T) {
		got := serve(t, false)
		if got.Header.Flags.RCODE != protocol.RcodeServerFailure {
			t.Fatalf("rcode = %d, want SERVFAIL", got.Header.Flags.RCODE)
		}
	})
}

func TestFailedRefresh(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rcode uint8
		want  bool
	}{
		{"NOERROR is an answer", protocol.RcodeSuccess, false},
		{"NXDOMAIN is an answer (RFC 8767 §4)", protocol.RcodeNameError, false},
		{"SERVFAIL is a failed refresh", protocol.RcodeServerFailure, true},
		{"REFUSED is a failed refresh", protocol.RcodeRefused, true},
		{"FORMERR is a failed refresh", protocol.RcodeFormatError, true},
		{"NOTIMP is a failed refresh", protocol.RcodeNotImplemented, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := &protocol.Message{Header: protocol.Header{Flags: protocol.NewResponseFlags(tc.rcode)}}
			if got := failedRefresh(resp); got != tc.want {
				t.Fatalf("failedRefresh(rcode %d) = %v, want %v", tc.rcode, got, tc.want)
			}
		})
	}
	if failedRefresh(nil) {
		t.Error("a nil response is not a failed refresh")
	}
}

// The remaining outcomes around the stale path: REFUSED counts as a failed
// refresh too; NXDOMAIN is a real answer and must reach the client instead of
// the stale record; with serve-stale off the upstream's SERVFAIL goes out.
func TestServeStaleOnUpstreamRcodeBoundaries(t *testing.T) {
	const qname = "stale.example.com."

	serve := func(t *testing.T, upstreamRcode uint8, serveStale bool) *protocol.Message {
		t.Helper()
		h := newTestHandler()
		c := cache.New(cache.Config{
			Capacity: 100, DefaultTTL: time.Minute, MinTTL: 0, MaxTTL: time.Hour,
			ServeStale: serveStale, StaleGrace: time.Hour,
		})
		h.cache = c
		c.Set(cache.MakeKey(qname, protocol.TypeA, false), &protocol.Message{
			Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Answers: []*protocol.ResourceRecord{{
				Name: ttlName(t, qname), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 10,
				Data: &protocol.RDataA{Address: [4]byte{203, 0, 113, 7}},
			}},
		}, 0)
		uc, err := upstream.NewClient(upstream.Config{Servers: []string{rcodeUpstream(t, upstreamRcode)}, Timeout: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer uc.Close()
		h.upstream = uc
		w := newCaptureWriter("10.0.0.1", "udp")
		h.ServeDNS(w, newTestQuery(t, qname, protocol.TypeA))
		if w.msg == nil {
			t.Fatal("no response")
		}
		return w.msg
	}

	if got := serve(t, protocol.RcodeRefused, true); got.Header.Flags.RCODE != protocol.RcodeSuccess || len(got.Answers) != 1 {
		t.Errorf("REFUSED with stale data: rcode=%d answers=%d, want the stale answer", got.Header.Flags.RCODE, len(got.Answers))
	}
	if got := serve(t, protocol.RcodeNameError, true); got.Header.Flags.RCODE != protocol.RcodeNameError || len(got.Answers) != 0 {
		t.Errorf("NXDOMAIN is a real answer, got rcode=%d answers=%d, want NXDOMAIN with no stale record", got.Header.Flags.RCODE, len(got.Answers))
	}
	if got := serve(t, protocol.RcodeServerFailure, false); got.Header.Flags.RCODE != protocol.RcodeServerFailure {
		t.Errorf("serve-stale off: rcode=%d, want the upstream SERVFAIL", got.Header.Flags.RCODE)
	}
}
