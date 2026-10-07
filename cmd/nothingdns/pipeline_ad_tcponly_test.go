package main

import (
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/rpz"
	"github.com/nothingdns/nothingdns/internal/upstream"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// adUpstream starts a loopback UDP upstream answering every A query with one
// record and the given AD bit.
func adUpstream(t *testing.T, ad bool) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			msg, err := protocol.UnpackMessage(buf[:n])
			if err != nil || len(msg.Questions) == 0 {
				continue
			}
			flags := protocol.NewResponseFlags(protocol.RcodeSuccess)
			flags.AD = ad
			resp := &protocol.Message{
				Header:    protocol.Header{ID: msg.Header.ID, Flags: flags},
				Questions: msg.Questions,
				Answers: []*protocol.ResourceRecord{{
					Name: msg.Questions[0].Name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300,
					Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 7}},
				}},
			}
			out := make([]byte, 4096)
			if n, err = resp.Pack(out); err == nil {
				_, _ = pc.WriteTo(out[:n], addr)
			}
		}
	}()
	return pc.LocalAddr().String()
}

func adHandler(t *testing.T, addr string, withValidator bool) *integratedHandler {
	t.Helper()
	h := newTestHandler()
	if withValidator {
		h.config.DNSSEC.Enabled = true
		h.validator = dnssec.NewValidator(
			dnssec.ValidatorConfig{Enabled: true, RequireDNSSEC: false},
			dnssec.NewTrustAnchorStore(), // no anchors: every name is Insecure
			&stubValidateResolver{},
		)
	}
	c, err := upstream.NewClient(upstream.Config{Servers: []string{addr}, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	h.upstream = c
	return h
}

func adAsk(t *testing.T, h *integratedHandler, qname string, do bool) *protocol.Message {
	t.Helper()
	q := newTestQuery(t, qname, protocol.TypeA)
	q.SetEDNS0(4096, do)
	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, q)
	if w.msg == nil || len(w.msg.Answers) == 0 {
		t.Fatalf("no answer for %s: %v", qname, w.msg)
	}
	return w.msg
}

// TestUpstreamAD_InsecureVerdictClearsUpstreamAD: with a validator configured,
// an upstream AD=1 must not survive an Insecure verdict — neither to the
// client nor into the cache (RFC 4035 §3.2.3: AD is this server's own claim).
func TestUpstreamAD_InsecureVerdictClearsUpstreamAD(t *testing.T) {
	h := adHandler(t, adUpstream(t, true), true)

	for _, do := range []bool{true, false} {
		qname := "insecure-do.example."
		if !do {
			qname = "insecure-nodo.example."
		}
		if resp := adAsk(t, h, qname, do); resp.Header.Flags.AD {
			t.Errorf("DO=%v: client got AD=1 for an Insecure answer", do)
		}
		if e := h.cache.Get(cache.MakeKey(qname, protocol.TypeA, do)); e == nil || e.Message == nil {
			t.Errorf("DO=%v: answer was not cached", do)
		} else if e.Message.Header.Flags.AD {
			t.Errorf("DO=%v: cached entry carries AD=1", do)
		}
		// Repeated query is a cache hit and must stay AD=0.
		if resp := adAsk(t, h, qname, do); resp.Header.Flags.AD {
			t.Errorf("DO=%v: cache hit served AD=1", do)
		}
	}
}

// TestUpstreamAD_NoValidatorUnchanged documents the boundary of the fix: a
// pure forwarder without a validator keeps its existing behavior.
func TestUpstreamAD_NoValidatorUnchanged(t *testing.T) {
	h := adHandler(t, adUpstream(t, true), false)
	if resp := adAsk(t, h, "fwd.example.", true); !resp.Header.Flags.AD {
		t.Error("forwarder without validator changed its AD passthrough")
	}
}

func tcpOnlyHandler(t *testing.T) *integratedHandler {
	t.Helper()
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "example.com.", Type: "SOA", TTL: 300, RData: "ns1.example.com. admin.example.com. 1 3600 600 86400 300"},
		{Name: "example.com.", Type: "NS", TTL: 300, RData: "ns1.example.com."},
		{Name: "www.example.com.", Type: "A", TTL: 300, RData: "192.0.2.10"},
		{Name: "gone.example.com.", Type: "A", TTL: 300, RData: "192.0.2.11"},
	})
	h.security.RPZEngine = rpz.NewEngine(rpz.Config{Enabled: true})
	h.security.RPZEngine.AddQNAMERule("www.example.com", rpz.ActionTCPOnly, "")
	h.security.RPZEngine.AddQNAMERule("gone.example.com", rpz.ActionNXDOMAIN, "")
	return h
}

// TestRPZTCPOnly_OnlyTruncatesUDP: rpz-tcp-only answers TC=1 over UDP only;
// over stream transports the query must be answered, or the name never
// resolves (every TCP retry got TC=1 again).
func TestRPZTCPOnly_OnlyTruncatesUDP(t *testing.T) {
	for _, proto := range []string{"udp", "tcp", "dot", "https", "quic"} {
		h := tcpOnlyHandler(t)
		w := newCaptureWriter("10.0.0.1", proto)
		h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))
		if w.msg == nil {
			t.Fatalf("%s: no response", proto)
		}
		if proto == "udp" {
			if !w.msg.Header.Flags.TC || len(w.msg.Answers) != 0 {
				t.Errorf("udp: want TC=1 with no answers, got TC=%v answers=%d", w.msg.Header.Flags.TC, len(w.msg.Answers))
			}
			continue
		}
		if w.msg.Header.Flags.TC || len(w.msg.Answers) != 1 {
			t.Errorf("%s: want TC=0 with the answer, got TC=%v answers=%d", proto, w.msg.Header.Flags.TC, len(w.msg.Answers))
		}
	}

	// Other RPZ actions are unaffected by the transport.
	h := tcpOnlyHandler(t)
	w := newCaptureWriter("10.0.0.1", "tcp")
	h.ServeDNS(w, newTestQuery(t, "gone.example.com.", protocol.TypeA))
	if w.msg == nil || w.msg.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Errorf("tcp NXDOMAIN rule: got %v", w.msg)
	}
}
