package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/dns64"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/upstream"
)

// dns64AUpstream answers every query NOERROR; A queries carry one A record
// (192.0.2.1) when withA is set, otherwise the answer is empty.
func dns64AUpstream(t *testing.T, withA bool) string {
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
			}
			if withA && q.Questions[0].QType == protocol.TypeA {
				resp.Answers = append(resp.Answers, &protocol.ResourceRecord{
					Name: q.Questions[0].Name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300,
					Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
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

func aaaaRR(t *testing.T, owner, ip string) *protocol.ResourceRecord {
	t.Helper()
	name, err := protocol.ParseName(owner)
	if err != nil {
		t.Fatal(err)
	}
	var addr [16]byte
	copy(addr[:], net.ParseIP(ip).To16())
	return &protocol.ResourceRecord{Name: name, Type: protocol.TypeAAAA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataAAAA{Address: addr}}
}

func aaaaAddrs(m *protocol.Message) []string {
	var out []string
	for _, rr := range m.Answers {
		if a, ok := rr.Data.(*protocol.RDataAAAA); ok && rr.Type == protocol.TypeAAAA {
			out = append(out, net.IP(a.Address[:]).String())
		}
	}
	return out
}

// RFC 6147 §5.1.4: AAAA records inside the exclusion set are unusable for
// IPv6-only clients. An answer holding only such records MUST be treated as an
// empty answer (so synthesis from A proceeds), and the offending records MUST
// NOT be returned to the client.
func TestDNS64ExcludedAAAAIsTreatedAsEmpty(t *testing.T) {
	const prefixed = "64:ff9b::c000:201" // 64:ff9b::/96 + 192.0.2.1

	run := func(t *testing.T, withA bool, aaaa ...string) (handled bool, written, resp *protocol.Message) {
		t.Helper()
		h := newTestHandler()
		uc, err := upstream.NewClient(upstream.Config{Servers: []string{dns64AUpstream(t, withA)}, Timeout: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer uc.Close()
		h.upstream = uc
		synth, err := dns64.NewSynthesizer("", 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, cidr := range []string{"::ffff:0:0/96", "2001:db8::/32"} {
			if err := synth.AddExcludeNet(cidr); err != nil {
				t.Fatal(err)
			}
		}
		h.security.DNS64Synth = synth

		r := newTestQuery(t, "example.com.", protocol.TypeAAAA)
		resp = &protocol.Message{Header: protocol.Header{ID: r.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)}}
		for _, ip := range aaaa {
			resp.Answers = append(resp.Answers, aaaaRR(t, "example.com.", ip))
		}
		w := newCaptureWriter("10.0.0.1", "udp")
		handled = h.tryDNS64Synthesis(context.Background(), w, r, r.Questions[0], resp)
		return handled, w.msg, resp
	}

	t.Run("control: usable AAAA passes through untouched", func(t *testing.T) {
		handled, _, resp := run(t, true, "2606:4700::1")
		if handled {
			t.Fatal("a real, non-excluded AAAA must not be replaced by synthesis")
		}
		if got := aaaaAddrs(resp); len(got) != 1 || got[0] != "2606:4700::1" {
			t.Fatalf("usable AAAA changed: %v", got)
		}
	})

	for _, ex := range []string{"::ffff:192.0.2.9", "2001:db8::1"} {
		t.Run("only excluded AAAA "+ex+" is replaced by synthesis", func(t *testing.T) {
			handled, written, _ := run(t, true, ex)
			if !handled || written == nil {
				t.Fatalf("FAIL: AAAA %s is in the exclusion set but the answer was not treated as empty (handled=%v)", ex, handled)
			}
			got := aaaaAddrs(written)
			if len(got) != 1 || got[0] != net.ParseIP(prefixed).String() {
				t.Fatalf("answer = %v, want exactly the synthesized %s", got, prefixed)
			}
		})
		t.Run("only excluded AAAA "+ex+" and no A leaves NODATA, never the excluded record", func(t *testing.T) {
			handled, _, resp := run(t, false, ex)
			if handled {
				t.Fatalf("nothing to synthesize from, handled should be false")
			}
			if got := aaaaAddrs(resp); len(got) != 0 {
				t.Fatalf("FAIL: excluded AAAA still returned to the client: %v", got)
			}
		})
	}

	t.Run("mixed answer keeps only the usable AAAA", func(t *testing.T) {
		handled, _, resp := run(t, true, "2001:db8::1", "2606:4700::1", "::ffff:192.0.2.9")
		if handled {
			t.Fatal("a usable AAAA exists, synthesis must not run")
		}
		if got := aaaaAddrs(resp); len(got) != 1 || got[0] != "2606:4700::1" {
			t.Fatalf("FAIL: excluded AAAA records returned alongside the usable one: %v", got)
		}
	})
}
