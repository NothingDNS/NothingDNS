package main

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
)

// ============================================================================
// integratedHandler.validateDNSSECResponse (handler.go:194) — the live
// query path's DNSSEC verdict dispatcher.
//
// Each ValidationResult maps to a distinct caller contract:
//   Secure       -> (false, true)  AD set, response passed through
//   Bogus        -> enforced: SERVFAIL+EDE (true, false); else (false, false)
//   Indeterminate-> enforced: SERVFAIL+EDE (true, false); else (false, false)
//   Insecure     -> (false, false), no AD
//
// The Secure fixture is a real ECDSA-signed chain built from the exported
// signer API (NewSigner/GenerateKeyPair/SignRRSet/CreateDS), modeled on
// the dnssec package's own chain_regression fixtures.
// ============================================================================

// stubValidateResolver serves canned DNSSEC records for the validator's
// chain fetches. errFor forces fetch failures (Indeterminate fixtures).
type stubValidateResolver struct {
	responses map[string]*protocol.Message
	errFor    map[string]error
}

func (s *stubValidateResolver) Query(_ context.Context, name string, qtype uint16) (*protocol.Message, error) {
	key := name + "|" + strconv.Itoa(int(qtype))
	if err, ok := s.errFor[key]; ok {
		return nil, err
	}
	if resp, ok := s.responses[key]; ok {
		return resp, nil
	}
	return protocol.NewMessage(protocol.Header{
		ID:      1,
		Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
		QDCount: 1,
	}), nil
}

type validateFixture struct {
	anchors  *dnssec.TrustAnchorStore
	resolver *stubValidateResolver
	resp     *protocol.Message
}

// buildSecureFixture builds a signed example.com. A response, the zone's
// self-signed DNSKEY RRset, and the matching DS trust anchor.
func buildSecureFixture(t *testing.T) *validateFixture {
	t.Helper()
	const zoneName = "example.com."

	signer := dnssec.NewSigner(zoneName, dnssec.DefaultSignerConfig())
	ksk, err := signer.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, true)
	if err != nil {
		t.Fatalf("generate KSK: %v", err)
	}
	zsk, err := signer.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false)
	if err != nil {
		t.Fatalf("generate ZSK: %v", err)
	}

	name, _ := protocol.ParseName(zoneName)
	now := uint32(time.Now().Unix())

	// DNSKEY RRset (KSK + ZSK), self-signed by the KSK — what buildChain
	// fetches and verifies against the anchor.
	dnskeyRRs := []*protocol.ResourceRecord{
		{Name: name, Type: protocol.TypeDNSKEY, Class: protocol.ClassIN, TTL: 3600, Data: ksk.DNSKEY},
		{Name: name, Type: protocol.TypeDNSKEY, Class: protocol.ClassIN, TTL: 3600, Data: zsk.DNSKEY},
	}
	dnskeyRRSIG, err := signer.SignRRSet(dnskeyRRs, ksk, now-3600, now+3600)
	if err != nil {
		t.Fatalf("sign DNSKEY RRset: %v", err)
	}
	dnskeyResp := protocol.NewMessage(protocol.Header{
		ID:      1,
		Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
		QDCount: 1,
	})
	dnskeyResp.Answers = append(dnskeyRRs, dnskeyRRSIG)

	// Trust anchor derived from the KSK (SHA-256 DS).
	anchor, err := dnssec.CreateDS(zoneName, ksk.DNSKEY, 2)
	if err != nil {
		t.Fatalf("CreateDS anchor: %v", err)
	}
	anchors := dnssec.NewTrustAnchorStore()
	anchors.AddAnchor(anchor)

	// Signed A answer for the zone apex.
	aRRs := []*protocol.ResourceRecord{{
		Name:  name,
		Type:  protocol.TypeA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
	}}
	aRRSIG, err := signer.SignRRSet(aRRs, zsk, now-3600, now+3600)
	if err != nil {
		t.Fatalf("sign A RRset: %v", err)
	}
	resp := protocol.NewMessage(protocol.Header{
		ID:      7,
		Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
		QDCount: 1,
	})
	resp.Questions = []*protocol.Question{{Name: name, QType: protocol.TypeA, QClass: protocol.ClassIN}}
	resp.Answers = append(aRRs, aRRSIG)

	return &validateFixture{
		anchors: anchors,
		resolver: &stubValidateResolver{
			responses: map[string]*protocol.Message{
				zoneName + "|" + strconv.Itoa(int(protocol.TypeDNSKEY)): dnskeyResp,
			},
		},
		resp: resp,
	}
}

func TestValidateDNSSECResponse_NilValidator(t *testing.T) {
	h := newTestHandler() // validator nil
	w := newCaptureWriter("10.0.0.1", "udp")
	r := newTestQuery(t, "example.com.", protocol.TypeA)

	handled, validated := h.validateDNSSECResponse(context.Background(), w, r, "example.com.", nil)
	if handled || validated {
		t.Errorf("nil validator = (%v, %v), want (false, false)", handled, validated)
	}
	if w.msg != nil {
		t.Errorf("nil validator wrote a response: %v", w.msg)
	}
}

func TestValidateDNSSECResponse_SecureSetsAD(t *testing.T) {
	fx := buildSecureFixture(t)
	h := newTestHandler()
	h.config.DNSSEC.Enabled = true
	h.validator = dnssec.NewValidator(dnssec.ValidatorConfig{Enabled: true}, fx.anchors, fx.resolver)
	w := newCaptureWriter("10.0.0.1", "udp")
	r := newTestQuery(t, "example.com.", protocol.TypeA)

	handled, validated := h.validateDNSSECResponse(context.Background(), w, r, "example.com.", fx.resp)
	if handled || !validated {
		t.Fatalf("secure = (%v, %v), want (false, true)", handled, validated)
	}
	if w.msg != nil {
		t.Fatalf("secure path must pass the response through, wrote: %v", w.msg)
	}
	if !fx.resp.Header.Flags.AD {
		t.Error("secure validation must set the AD bit")
	}
}

func TestValidateDNSSECResponse_BogusEnforced(t *testing.T) {
	fx := buildSecureFixture(t)
	// Tamper the signed answer after signing: the RRSIG no longer covers
	// the data -> signature verification fails -> Bogus.
	fx.resp.Answers[0].Data = &protocol.RDataA{Address: [4]byte{198, 51, 100, 99}}

	h := newTestHandler()
	h.config.DNSSEC.Enabled = true
	h.validator = dnssec.NewValidator(dnssec.ValidatorConfig{Enabled: true}, fx.anchors, fx.resolver)
	w := newCaptureWriter("10.0.0.1", "udp")
	r := newTestQuery(t, "example.com.", protocol.TypeA)

	handled, validated := h.validateDNSSECResponse(context.Background(), w, r, "example.com.", fx.resp)
	if !handled || validated {
		t.Fatalf("bogus enforced = (%v, %v), want (true, false)", handled, validated)
	}
	if w.msg == nil {
		t.Fatal("bogus enforced must write SERVFAIL")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeServerFailure {
		t.Errorf("bogus RCODE = %d, want SERVFAIL", w.msg.Header.Flags.RCODE)
	}
}

func TestValidateDNSSECResponse_BogusNotEnforced(t *testing.T) {
	fx := buildSecureFixture(t)
	fx.resp.Answers[0].Data = &protocol.RDataA{Address: [4]byte{198, 51, 100, 99}}

	h := newTestHandler()
	h.config.DNSSEC.Enabled = false // validation on, enforcement off
	h.validator = dnssec.NewValidator(dnssec.ValidatorConfig{Enabled: true}, fx.anchors, fx.resolver)
	w := newCaptureWriter("10.0.0.1", "udp")
	r := newTestQuery(t, "example.com.", protocol.TypeA)

	handled, validated := h.validateDNSSECResponse(context.Background(), w, r, "example.com.", fx.resp)
	if handled || validated {
		t.Fatalf("bogus unenforced = (%v, %v), want (false, false)", handled, validated)
	}
	if w.msg != nil {
		t.Errorf("unenforced bogus must not write an error: %v", w.msg)
	}
	if fx.resp.Header.Flags.AD {
		t.Error("bogus response must never carry AD")
	}
}

func TestValidateDNSSECResponse_IndeterminateEnforced(t *testing.T) {
	fx := buildSecureFixture(t)
	// Force the DNSKEY chain fetch to fail: a transport error proves
	// nothing about the zone -> Indeterminate (not Bogus).
	fx.resolver.errFor = map[string]error{
		"example.com.|" + strconv.Itoa(int(protocol.TypeDNSKEY)): context.DeadlineExceeded,
	}

	h := newTestHandler()
	h.config.DNSSEC.Enabled = true
	h.validator = dnssec.NewValidator(dnssec.ValidatorConfig{Enabled: true}, fx.anchors, fx.resolver)
	w := newCaptureWriter("10.0.0.1", "udp")
	r := newTestQuery(t, "example.com.", protocol.TypeA)

	handled, validated := h.validateDNSSECResponse(context.Background(), w, r, "example.com.", fx.resp)
	if !handled || validated {
		t.Fatalf("indeterminate enforced = (%v, %v), want (true, false)", handled, validated)
	}
	if w.msg == nil || w.msg.Header.Flags.RCODE != protocol.RcodeServerFailure {
		t.Fatalf("indeterminate enforced must write SERVFAIL, got %+v", w.msg)
	}
}

func TestValidateDNSSECResponse_IndeterminateNotEnforced(t *testing.T) {
	fx := buildSecureFixture(t)
	fx.resolver.errFor = map[string]error{
		"example.com.|" + strconv.Itoa(int(protocol.TypeDNSKEY)): context.DeadlineExceeded,
	}

	h := newTestHandler()
	h.config.DNSSEC.Enabled = false
	h.validator = dnssec.NewValidator(dnssec.ValidatorConfig{Enabled: true}, fx.anchors, fx.resolver)
	w := newCaptureWriter("10.0.0.1", "udp")
	r := newTestQuery(t, "example.com.", protocol.TypeA)

	handled, validated := h.validateDNSSECResponse(context.Background(), w, r, "example.com.", fx.resp)
	if handled || validated {
		t.Fatalf("indeterminate unenforced = (%v, %v), want (false, false)", handled, validated)
	}
	if w.msg != nil {
		t.Errorf("unenforced indeterminate must not write an error: %v", w.msg)
	}
}

func TestValidateDNSSECResponse_InsecureNoAnchor(t *testing.T) {
	fx := buildSecureFixture(t)
	// Empty anchor store: the zone is provably uncovered -> Insecure, and
	// with RequireDNSSEC=false the response passes through unsigned.
	h := newTestHandler()
	h.config.DNSSEC.Enabled = true
	h.validator = dnssec.NewValidator(
		dnssec.ValidatorConfig{Enabled: true, RequireDNSSEC: false},
		dnssec.NewTrustAnchorStore(), // no anchors
		fx.resolver,
	)
	w := newCaptureWriter("10.0.0.1", "udp")
	r := newTestQuery(t, "example.com.", protocol.TypeA)

	handled, validated := h.validateDNSSECResponse(context.Background(), w, r, "example.com.", fx.resp)
	if handled || validated {
		t.Fatalf("insecure = (%v, %v), want (false, false)", handled, validated)
	}
	if w.msg != nil {
		t.Errorf("insecure must pass the response through, wrote: %v", w.msg)
	}
	if fx.resp.Header.Flags.AD {
		t.Error("unsigned zone response must not carry AD")
	}
}
