package main

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/upstream"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// localhost., invalid., test. and onion. are answered locally and never
// forwarded (RFC 6761 §6.2-6.4, RFC 7686); a configured zone still wins (F747).

type specialUseUpstream struct {
	mu   sync.Mutex
	seen []string
	addr string
}

func specialUseStartUpstream(t *testing.T) *specialUseUpstream {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	u := &specialUseUpstream{addr: pc.LocalAddr().String()}
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
			u.mu.Lock()
			u.seen = append(u.seen, strings.ToLower(q.Questions[0].Name.String()))
			u.mu.Unlock()
			resp := &protocol.Message{Header: protocol.Header{ID: q.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeNameError)}, Questions: q.Questions}
			resp.Header.Flags.RA = true
			out := make([]byte, 4096)
			if m, err := resp.Pack(out); err == nil {
				_, _ = pc.WriteTo(out[:m], addr)
			}
		}
	}()
	return u
}

func (u *specialUseUpstream) asked(name string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, s := range u.seen {
		if s == name {
			return true
		}
	}
	return false
}

func specialUseHandler(t *testing.T) (*integratedHandler, *specialUseUpstream) {
	h := newTestHandler()
	u := specialUseStartUpstream(t)
	uc, err := upstream.NewClient(upstream.Config{Servers: []string{u.addr}, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { uc.Close() })
	h.upstream = uc
	return h, u
}

func specialUseAsk(t *testing.T, h *integratedHandler, name string, qt uint16) *protocol.Message {
	w := newCaptureWriter("127.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, name, qt))
	if w.msg == nil {
		t.Fatalf("%s: no response", name)
	}
	return w.msg
}

func TestSpecialUseNamesAnsweredLocally(t *testing.T) {
	h, u := specialUseHandler(t)
	type want struct {
		rcode   uint8
		atype   uint16 // 0: no answer
		soaAuth bool
	}
	for _, tc := range []struct {
		name string
		qt   uint16
		want want
	}{
		{"localhost.", protocol.TypeAAAA, want{0, protocol.TypeAAAA, false}},
		{"sub.localhost.", protocol.TypeA, want{0, protocol.TypeA, false}},
		{"localhost.", protocol.TypeMX, want{0, 0, true}},
		{"localhost.", protocol.TypeSOA, want{0, protocol.TypeSOA, false}},
		{"invalid.", protocol.TypeSOA, want{0, protocol.TypeSOA, false}},
		{"invalid.", protocol.TypeA, want{0, 0, true}},
		{"foo.invalid.", protocol.TypeA, want{protocol.RcodeNameError, 0, true}},
		{"foo.test.", protocol.TypeAAAA, want{protocol.RcodeNameError, 0, true}},
		{"x.y.onion.", protocol.TypeTXT, want{protocol.RcodeNameError, 0, true}},
		{"1.0.0.127.in-addr.arpa.", protocol.TypePTR, want{0, protocol.TypePTR, false}},
		{"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.", protocol.TypePTR, want{0, protocol.TypePTR, false}},
	} {
		m := specialUseAsk(t, h, tc.name, tc.qt)
		gotType := uint16(0)
		if len(m.Answers) > 0 {
			gotType = m.Answers[0].Type
		}
		soa := len(m.Authorities) == 1 && m.Authorities[0].Type == protocol.TypeSOA
		if m.Header.Flags.RCODE != tc.want.rcode || gotType != tc.want.atype || soa != tc.want.soaAuth || !m.Header.Flags.AA {
			t.Fatalf("%s %s: rcode %d answer %d soa %v aa %v", tc.name, typeToString(tc.qt), m.Header.Flags.RCODE, gotType, soa, m.Header.Flags.AA)
		}
		if u.asked(tc.name) {
			t.Fatalf("%s forwarded upstream", tc.name)
		}
	}
	// 0x20: the answer owner keeps the client's spelling.
	if m := specialUseAsk(t, h, "LocalHost.", protocol.TypeA); m.Answers[0].Name.String() != "LocalHost." {
		t.Fatalf("owner %s", m.Answers[0].Name)
	}
	// A configured zone wins over the built-in answer.
	addZoneRecords(t, h, "test.", []zone.Record{
		{Name: "test.", Type: "SOA", TTL: 300, RData: "ns1.test. h.test. 1 3600 600 604800 300"},
		{Name: "www.test.", Type: "A", TTL: 300, RData: "192.0.2.77"},
	})
	if m := specialUseAsk(t, h, "www.test.", protocol.TypeA); len(m.Answers) != 1 || m.Answers[0].Data.(*protocol.RDataA).Address != [4]byte{192, 0, 2, 77} {
		t.Fatalf("configured test. zone not served: %+v", m.Answers)
	}
	// An ordinary reverse name still follows the ordinary path.
	specialUseAsk(t, h, "2.0.0.127.in-addr.arpa.", protocol.TypePTR)
	if !u.asked("2.0.0.127.in-addr.arpa.") {
		t.Fatal("2.0.0.127.in-addr.arpa. was answered locally")
	}
}
