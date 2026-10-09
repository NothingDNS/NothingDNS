package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/dns64"
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/upstream"
)

// signedAUpstream answers A queries with fx's signed answer, sending the
// RRSIGs only when the query sets DO=1 like a real server (RFC 4035 §3.1.1).
func signedAUpstream(t *testing.T, fx *validateFixture) string {
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
			do := false
			if opt := q.GetOPT(); opt != nil {
				if h := protocol.ParseEDNS0Header(opt); h != nil {
					do = h.DO
				}
			}
			resp := &protocol.Message{
				Header:    protocol.Header{ID: q.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
				Questions: q.Questions,
			}
			if q.Questions[0].QType == protocol.TypeA {
				for _, rr := range fx.resp.Answers {
					if rr.Type != protocol.TypeRRSIG || do {
						resp.Answers = append(resp.Answers, rr)
					}
				}
			}
			if do {
				resp.SetEDNS0(4096, true)
			}
			out := make([]byte, 4096)
			if m, err := resp.Pack(out); err == nil {
				_, _ = pc.WriteTo(out[:m], addr)
			}
		}
	}()
	return pc.LocalAddr().String()
}

// F655: with validation on, the DNS64 A query went upstream without DO=1, so
// the A answer of a signed zone arrived without RRSIGs and was rejected as
// Bogus — SERVFAIL instead of a synthesized AAAA.
func TestDNS64SynthesisWithDNSSECValidation(t *testing.T) {
	fx := buildSecureFixture(t)
	h := newTestHandler()
	uc, err := upstream.NewClient(upstream.Config{Servers: []string{signedAUpstream(t, fx)}, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	h.upstream = uc
	h.config.DNSSEC.Enabled = true
	h.validator = dnssec.NewValidator(dnssec.ValidatorConfig{Enabled: true}, fx.anchors, fx.resolver)
	synth, _ := dns64.NewSynthesizer("", 0)
	h.security.DNS64Synth = synth

	w := newCaptureWriter("10.0.0.1", "udp")
	r := newTestQuery(t, "example.com.", protocol.TypeAAAA)
	nodata := &protocol.Message{Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)}}
	if !h.tryDNS64Synthesis(context.Background(), w, r, r.Questions[0], nodata) || w.msg == nil {
		t.Fatal("expected a DNS64 response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess || len(w.msg.Answers) == 0 || w.msg.Answers[0].Type != protocol.TypeAAAA {
		t.Fatalf("got rcode=%d answers=%v, want NOERROR with a synthesized AAAA", w.msg.Header.Flags.RCODE, w.msg.Answers)
	}
	if w.msg.Header.Flags.AD {
		t.Error("synthesized AAAA must not carry AD (RFC 6147 §5.5)")
	}
}
