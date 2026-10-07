package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
)

func dnssecRegSigner(t *testing.T, origin string) *dnssec.Signer {
	t.Helper()
	s := dnssec.NewSigner(origin, dnssec.DefaultSignerConfig())
	for _, ksk := range []bool{true, false} {
		k, err := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, ksk)
		if err != nil {
			t.Fatal(err)
		}
		s.AddKey(k)
		s.SetKeyState(k.KeyTag, dnssec.KeyStateActive)
	}
	return s
}

func dnssecRegAsk(t *testing.T, h *integratedHandler, name string, qt uint16) *protocol.Message {
	t.Helper()
	q := newTestQuery(t, name, qt)
	q.SetEDNS0(4096, true)
	w := newCaptureWriter("192.0.2.100", "udp")
	h.ServeDNS(w, q)
	if w.msg == nil {
		t.Fatalf("no response for %s/%s", name, typeToString(qt))
	}
	return w.msg
}

func dnssecRegSigCovers(rrs []*protocol.ResourceRecord, typ uint16) bool {
	for _, rr := range rrs {
		if s, ok := rr.Data.(*protocol.RDataRRSIG); ok && s.TypeCovered == typ {
			return true
		}
	}
	return false
}

func dnssecRegCount(rrs []*protocol.ResourceRecord, typ uint16) int {
	n := 0
	for _, rr := range rrs {
		if rr.Type == typ {
			n++
		}
	}
	return n
}

// TestDNAME_SignedZoneIncludesDNAMERRSIG is the F382 regression: a DO=1 answer
// produced by DNAME substitution in a signed zone carried the DNAME without
// its RRSIG, so a validator could not authenticate the redirection (RFC 6672
// §5.3.1). The synthesized CNAME stays unsigned.
func TestDNAME_SignedZoneIncludesDNAMERRSIG(t *testing.T) {
	h := newTestHandler()
	h.zones["dnreg.test."] = loadTestZoneFile(t, "dnreg.test.", `$ORIGIN dnreg.test.
$TTL 3600
@        IN SOA ns1.dnreg.test. admin.dnreg.test. ( 1 3600 600 86400 300 )
@        IN NS  ns1.dnreg.test.
ns1      IN A   192.0.2.1
old      IN DNAME new.dnreg.test.
host.new IN A   192.0.2.9
`)
	h.RebuildZoneTree()
	h.zoneSigners = map[string]*dnssec.Signer{"dnreg.test.": dnssecRegSigner(t, "dnreg.test.")}

	m := dnssecRegAsk(t, h, "host.old.dnreg.test.", protocol.TypeA)
	if dnssecRegCount(m.Answers, protocol.TypeDNAME) != 1 || !dnssecRegSigCovers(m.Answers, protocol.TypeDNAME) {
		t.Fatalf("want DNAME with RRSIG(DNAME) in answer, got %v", m.Answers)
	}
	if dnssecRegSigCovers(m.Answers, protocol.TypeCNAME) {
		t.Fatal("synthesized CNAME must not be signed")
	}
}

// TestDS_CoHostedChildApexAnsweredByParent is the F383 regression: with parent
// and child both loaded, a DS query for the child apex was answered by the
// child zone (NODATA + child SOA) instead of the parent's DS RRset
// (RFC 4035 §3.1.4.1).
func TestDS_CoHostedChildApexAnsweredByParent(t *testing.T) {
	h := newTestHandler()
	h.zones["preg.test."] = loadTestZoneFile(t, "preg.test.", `$ORIGIN preg.test.
$TTL 3600
@   IN SOA ns1.preg.test. admin.preg.test. ( 1 3600 600 86400 300 )
@   IN NS  ns1.preg.test.
ns1 IN A   192.0.2.1
sub IN NS  ns1.preg.test.
sub IN DS  12345 13 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
`)
	h.zones["sub.preg.test."] = loadTestZoneFile(t, "sub.preg.test.", `$ORIGIN sub.preg.test.
$TTL 3600
@   IN SOA ns1.preg.test. admin.sub.preg.test. ( 7 3600 600 86400 300 )
@   IN NS  ns1.preg.test.
www IN A   192.0.2.7
`)
	h.RebuildZoneTree()

	m := dnssecRegAsk(t, h, "sub.preg.test.", protocol.TypeDS)
	if !m.Header.Flags.AA || dnssecRegCount(m.Answers, protocol.TypeDS) != 1 {
		t.Fatalf("want the parent's DS answer, got AA=%v answers=%v auth=%v", m.Header.Flags.AA, m.Answers, m.Authorities)
	}
	m = dnssecRegAsk(t, h, "sub.preg.test.", protocol.TypeSOA)
	if len(m.Answers) == 0 || m.Answers[0].Type != protocol.TypeSOA || m.Answers[0].Name.String() != "sub.preg.test." {
		t.Fatalf("child apex SOA must still come from the child, got %v", m.Answers)
	}
}

// TestReferral_SignedZoneCarriesDSOrNSECProof is the F384 regression: a DO=1
// referral out of a signed zone carried only NS, with neither the signed DS
// RRset (secure delegation) nor the signed NSEC proving its absence (insecure
// delegation), so a validator could not establish the child's status
// (RFC 4035 §3.1.4).
func TestReferral_SignedZoneCarriesDSOrNSECProof(t *testing.T) {
	h := newTestHandler()
	h.zones["rfreg.test."] = loadTestZoneFile(t, "rfreg.test.", `$ORIGIN rfreg.test.
$TTL 3600
@       IN SOA ns1.rfreg.test. admin.rfreg.test. ( 1 3600 600 86400 300 )
@       IN NS  ns1.rfreg.test.
ns1     IN A   192.0.2.1
sec     IN NS  ns1.sec.rfreg.test.
sec     IN DS  12345 13 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
ns1.sec IN A   192.0.2.50
ins     IN NS  ns1.ins.rfreg.test.
ns1.ins IN A   192.0.2.51
`)
	h.RebuildZoneTree()
	h.zoneSigners = map[string]*dnssec.Signer{"rfreg.test.": dnssecRegSigner(t, "rfreg.test.")}

	for _, c := range []struct {
		name  string
		proof uint16
	}{
		{"www.sec.rfreg.test.", protocol.TypeDS},
		{"www.ins.rfreg.test.", protocol.TypeNSEC},
	} {
		m := dnssecRegAsk(t, h, c.name, protocol.TypeA)
		if m.Header.Flags.AA || dnssecRegCount(m.Authorities, protocol.TypeNS) != 1 ||
			dnssecRegCount(m.Authorities, c.proof) != 1 || !dnssecRegSigCovers(m.Authorities, c.proof) {
			t.Errorf("%s: want referral with signed %s, got AA=%v auth=%v",
				c.name, typeToString(c.proof), m.Header.Flags.AA, m.Authorities)
		}
	}
}
