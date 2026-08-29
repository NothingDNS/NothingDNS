package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
)

const denialZoneFile = `$ORIGIN denial.test.
$TTL 3600
@                 IN  SOA ns1.denial.test. admin.denial.test. ( 1 3600 600 86400 300 )
@                 IN  NS  ns1.denial.test.
ns1               IN  A   192.0.2.1
www               IN  A   192.0.2.10
www               IN  AAAA 2001:db8::10
deep.ent          IN  A   192.0.2.20
`

func denialTestHandler(t *testing.T) *integratedHandler {
	t.Helper()
	h := newTestHandler()
	h.zones["denial.test."] = loadTestZoneFile(t, "denial.test.", denialZoneFile)
	h.RebuildZoneTree()

	signer := dnssec.NewSigner("denial.test.", dnssec.DefaultSignerConfig())
	for _, isKSK := range []bool{true, false} {
		key, err := signer.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, isKSK)
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		signer.AddKey(key)
		signer.SetKeyState(key.KeyTag, dnssec.KeyStateActive)
	}
	h.zoneSigners = map[string]*dnssec.Signer{"denial.test.": signer}
	return h
}

func authoritySection(resp *protocol.Message) (nsecs, rrsigs, soas []*protocol.ResourceRecord) {
	for _, rr := range resp.Authorities {
		switch rr.Type {
		case protocol.TypeNSEC:
			nsecs = append(nsecs, rr)
		case protocol.TypeRRSIG:
			rrsigs = append(rrsigs, rr)
		case protocol.TypeSOA:
			soas = append(soas, rr)
		}
	}
	return
}

func askDNSSEC(t *testing.T, h *integratedHandler, qname string, qtype uint16) *protocol.Message {
	t.Helper()
	w := newCaptureWriter("192.0.2.100", "tcp")
	h.ServeDNS(w, queryWithDO(t, qname, qtype, true))
	if w.msg == nil {
		t.Fatal("no response")
	}
	return w.msg
}

// TestDenial_NXDOMAINCarriesProof is the regression for negative answers from
// a signed zone being unprovable. RFC 4035 §3.1.3.2 wants two things denied:
// the name itself, and the wildcard at its closest encloser — without the
// second, a validator cannot tell a real NXDOMAIN from one that suppressed a
// wildcard match. Before this, the authority section held an unsigned SOA and
// nothing else, and `delv` called the whole answer insecure.
func TestDenial_NXDOMAINCarriesProof(t *testing.T) {
	h := denialTestHandler(t)
	resp := askDNSSEC(t, h, "nothere.denial.test.", protocol.TypeA)

	if resp.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN", resp.Header.Flags.RCODE)
	}
	nsecs, rrsigs, soas := authoritySection(resp)
	if len(soas) != 1 {
		t.Errorf("%d SOA records, want 1", len(soas))
	}
	if len(nsecs) == 0 {
		t.Fatal("no NSEC record: the denial is unprovable")
	}
	// One NSEC may cover both the name and the wildcard, so the count is 1 or
	// 2; what matters is that every RRset present is signed.
	if len(rrsigs) < len(nsecs)+1 {
		t.Errorf("%d RRSIGs for %d NSEC RRsets plus the SOA — every RRset must be signed",
			len(rrsigs), len(nsecs))
	}

	for _, rr := range nsecs {
		if _, ok := rr.Data.(*protocol.RDataNSEC); !ok {
			t.Errorf("NSEC rdata is %T", rr.Data)
		}
	}
}

// TestDenial_NODATACarriesProof covers RFC 4035 §3.1.3.1: the NSEC at the
// queried name, whose type bitmap is what proves the type absent.
func TestDenial_NODATACarriesProof(t *testing.T) {
	h := denialTestHandler(t)
	resp := askDNSSEC(t, h, "www.denial.test.", protocol.TypeMX)

	if resp.Header.Flags.RCODE != protocol.RcodeSuccess || len(resp.Answers) != 0 {
		t.Fatalf("want NODATA, got rcode=%d answers=%d", resp.Header.Flags.RCODE, len(resp.Answers))
	}
	nsecs, rrsigs, _ := authoritySection(resp)
	if len(nsecs) != 1 {
		t.Fatalf("%d NSEC records, want exactly 1 (the queried name's)", len(nsecs))
	}
	if got := nsecs[0].Name.String(); got != "www.denial.test." {
		t.Errorf("NSEC owner = %q, want the queried name", got)
	}
	if len(rrsigs) < 2 {
		t.Errorf("%d RRSIGs, want at least 2 (SOA and NSEC)", len(rrsigs))
	}

	nsec, ok := nsecs[0].Data.(*protocol.RDataNSEC)
	if !ok {
		t.Fatalf("NSEC rdata is %T", nsecs[0].Data)
	}
	for _, tp := range nsec.TypeBitMap {
		if tp == protocol.TypeMX {
			t.Error("the bitmap lists MX — that would prove the opposite of the answer")
		}
	}
	var hasA bool
	for _, tp := range nsec.TypeBitMap {
		if tp == protocol.TypeA {
			hasA = true
		}
	}
	if !hasA {
		t.Errorf("bitmap %v omits A, which the name does own", nsec.TypeBitMap)
	}
}

// TestDenial_EmptyNonTerminal: an ENT is a NODATA, and its NSEC must still
// list its own NSEC and RRSIG types or validators go looking for a delegation.
func TestDenial_EmptyNonTerminal(t *testing.T) {
	h := denialTestHandler(t)
	resp := askDNSSEC(t, h, "ent.denial.test.", protocol.TypeA)

	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR (NODATA)", resp.Header.Flags.RCODE)
	}
	nsecs, _, _ := authoritySection(resp)
	if len(nsecs) != 1 {
		t.Fatalf("%d NSEC records, want 1", len(nsecs))
	}
	nsec := nsecs[0].Data.(*protocol.RDataNSEC)
	var hasNSEC, hasRRSIG bool
	for _, tp := range nsec.TypeBitMap {
		switch tp {
		case protocol.TypeNSEC:
			hasNSEC = true
		case protocol.TypeRRSIG:
			hasRRSIG = true
		}
	}
	if !hasNSEC || !hasRRSIG {
		t.Errorf("ENT bitmap %v must contain NSEC and RRSIG", nsec.TypeBitMap)
	}
}

// TestDenial_NotSentWithoutDO: a client that did not ask for DNSSEC gets a
// plain negative answer (RFC 4035 §3.2.2).
func TestDenial_NotSentWithoutDO(t *testing.T) {
	h := denialTestHandler(t)
	w := newCaptureWriter("192.0.2.100", "tcp")
	h.ServeDNS(w, queryWithDO(t, "nothere.denial.test.", protocol.TypeA, false))

	if w.msg == nil {
		t.Fatal("no response")
	}
	nsecs, rrsigs, soas := authoritySection(w.msg)
	if len(nsecs) != 0 || len(rrsigs) != 0 {
		t.Errorf("client without DO received %d NSEC and %d RRSIG records", len(nsecs), len(rrsigs))
	}
	if len(soas) != 1 {
		t.Errorf("%d SOA records, want 1 (negative caching still applies)", len(soas))
	}
}

// TestDenial_UnsignedZoneUnchanged: an unsigned zone must keep answering
// plain NXDOMAIN/NODATA.
func TestDenial_UnsignedZoneUnchanged(t *testing.T) {
	h := newTestHandler()
	h.zones["denial.test."] = loadTestZoneFile(t, "denial.test.", denialZoneFile)
	h.RebuildZoneTree()

	resp := askDNSSEC(t, h, "nothere.denial.test.", protocol.TypeA)
	if resp.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN", resp.Header.Flags.RCODE)
	}
	nsecs, rrsigs, soas := authoritySection(resp)
	if len(nsecs) != 0 || len(rrsigs) != 0 {
		t.Errorf("unsigned zone emitted %d NSEC and %d RRSIG records", len(nsecs), len(rrsigs))
	}
	if len(soas) != 1 {
		t.Errorf("%d SOA records, want 1", len(soas))
	}
}

// TestDenial_NSECOwnersBracketTheName: the proof has to be about the queried
// name, not merely present. A validator checks exactly this.
func TestDenial_NSECOwnersBracketTheName(t *testing.T) {
	h := denialTestHandler(t)
	z := h.zones["denial.test."]

	for _, qname := range []string{"aaa.denial.test.", "mmm.denial.test.", "zzz.denial.test."} {
		resp := askDNSSEC(t, h, qname, protocol.TypeA)
		nsecs, _, _ := authoritySection(resp)
		if len(nsecs) == 0 {
			t.Errorf("%s: no NSEC", qname)
			continue
		}
		var covers bool
		for _, rr := range nsecs {
			data, ok := z.NSECCovering(qname)
			if ok && rr.Name.String() == data.Owner {
				covers = true
			}
		}
		if !covers {
			t.Errorf("%s: no NSEC in the response actually covers the name", qname)
		}
	}
}
