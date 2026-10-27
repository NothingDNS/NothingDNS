package main

import (
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/upstream"
)

// A resolution failure is cached (RFC 9520 §3.2): no outgoing query for it
// until it expires, answered SERVFAIL with EDE 13 meanwhile (F750).

func failUpstream(t *testing.T, rcode uint8, count *atomic.Int32) string {
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
			count.Add(1)
			resp := &protocol.Message{Header: protocol.Header{ID: q.Header.ID, Flags: protocol.NewResponseFlags(rcode)}, Questions: q.Questions}
			resp.Header.Flags.RA = true
			if rcode == protocol.RcodeSuccess {
				resp.Answers = append(resp.Answers, &protocol.ResourceRecord{Name: q.Questions[0].Name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}}})
			}
			out := make([]byte, 4096)
			if m, err := resp.Pack(out); err == nil {
				_, _ = pc.WriteTo(out[:m], addr)
			}
		}
	}()
	return pc.LocalAddr().String()
}

func failHandler(t *testing.T, rcode uint8, count *atomic.Int32) *integratedHandler {
	h := newTestHandler()
	uc, err := upstream.NewClient(upstream.Config{Servers: []string{failUpstream(t, rcode, count)}, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { uc.Close() })
	h.upstream = uc
	return h
}

func failAsk(t *testing.T, h *integratedHandler, name string) *protocol.Message {
	w := newCaptureWriter("192.0.2.10", "udp")
	h.ServeDNS(w, newTestQuery(t, name, protocol.TypeA))
	if w.msg == nil {
		t.Fatal("no response")
	}
	return w.msg
}

func TestFailingNameQueriedOnceWhileCached(t *testing.T) {
	var n atomic.Int32
	h := failHandler(t, protocol.RcodeServerFailure, &n)
	for i := 0; i < 3; i++ {
		failAsk(t, h, "broken.example.")
	}
	if n.Load() != 1 {
		t.Fatalf("3 client queries sent %d upstream queries, want 1", n.Load())
	}
}

func TestFailureCacheExpiryCDAndBounds(t *testing.T) {
	var n atomic.Int32
	h := failHandler(t, protocol.RcodeServerFailure, &n)
	now := time.Unix(1_800_000_000, 0)
	h.failures.now = func() time.Time { return now }

	failAsk(t, h, "broken.example.")
	m := failAsk(t, h, "broken.example.")
	if n.Load() != 1 || m.Header.Flags.RCODE != protocol.RcodeServerFailure {
		t.Fatalf("cached failure: upstream %d rcode %d", n.Load(), m.Header.Flags.RCODE)
	}
	if opt := m.GetOPT(); opt != nil {
		if o := opt.Data.(*protocol.RDataOPT).GetOption(protocol.OptionCodeExtendedError); o == nil || o.Data[1] != byte(protocol.EDECachedError) {
			t.Fatalf("cached failure EDE = %+v", o)
		}
	}
	// CD=1 is its own key: it goes out.
	q := newTestQuery(t, "broken.example.", protocol.TypeA)
	q.Header.Flags.CD = true
	h.ServeDNS(newCaptureWriter("192.0.2.10", "udp"), q)
	if n.Load() != 2 {
		t.Fatalf("CD=1 query not forwarded (%d)", n.Load())
	}
	// After the TTL the name is asked again.
	now = now.Add(failureCacheTTL)
	failAsk(t, h, "broken.example.")
	if n.Load() != 3 {
		t.Fatalf("after expiry: upstream %d, want 3", n.Load())
	}

	// A working upstream: nothing is cached as a failure.
	var ok atomic.Int32
	g := failHandler(t, protocol.RcodeSuccess, &ok)
	for i := 0; i < 3; i++ {
		if r := failAsk(t, g, "fine.example."); r.Header.Flags.RCODE != 0 {
			t.Fatalf("working name rcode %d", r.Header.Flags.RCODE)
		}
	}
	if len(g.failures.until) != 0 {
		t.Fatalf("success recorded as failure: %v", g.failures.until)
	}

	// Bounded.
	var c failureCache
	for i := 0; i <= maxFailureCacheEntries+10; i++ {
		c.add("k" + strconv.Itoa(i))
	}
	if len(c.until) > maxFailureCacheEntries {
		t.Fatalf("failure cache holds %d entries", len(c.until))
	}
}
