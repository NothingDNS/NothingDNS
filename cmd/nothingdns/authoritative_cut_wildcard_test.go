package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

const cutReferralZone = `$ORIGIN cut.test.
$TTL 3600
@       IN  SOA ns1.cut.test. admin.cut.test. ( 1 3600 600 86400 300 )
@       IN  NS  ns1.cut.test.
ns1     IN  A   192.0.2.1
sub     IN  NS  ns1.sub.cut.test.
sub     IN  DS  12345 13 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
ns1.sub IN  A   192.0.2.50
`

// TestAuthoritative_QueryAtZoneCutIsReferral is the F302 regression. The
// delegation check only looked strictly above the query name, so a query AT a
// cut was answered as authoritative parent data: AA=1 NODATA for A/MX (which a
// resolver caches against the child apex) and the delegation NS RRset in the
// answer section with AA=1. Everything at the cut except DS is child data
// (RFC 1034 §4.3.2, RFC 4035 §3.1.4.1).
func TestAuthoritative_QueryAtZoneCutIsReferral(t *testing.T) {
	h := newTestHandler()
	h.zones["cut.test."] = loadTestZoneFile(t, "cut.test.", cutReferralZone)
	h.RebuildZoneTree()

	for _, qt := range []uint16{protocol.TypeA, protocol.TypeNS, protocol.TypeMX} {
		w := newCaptureWriter("192.0.2.100", "udp")
		h.ServeDNS(w, newTestQuery(t, "sub.cut.test.", qt))
		m := w.msg
		if m == nil {
			t.Fatalf("%s: no response", typeToString(qt))
		}
		if m.Header.Flags.AA || m.Header.Flags.RCODE != protocol.RcodeSuccess || len(m.Answers) != 0 ||
			len(m.Authorities) != 1 || m.Authorities[0].Type != protocol.TypeNS ||
			len(m.Additionals) != 1 || m.Additionals[0].Type != protocol.TypeA {
			t.Errorf("sub.cut.test. %s: want referral (AA=0, NS authority, glue), got AA=%v rcode=%d ans=%d auth=%d add=%d",
				typeToString(qt), m.Header.Flags.AA, m.Header.Flags.RCODE, len(m.Answers), len(m.Authorities), len(m.Additionals))
		}
	}

	// DS at the cut stays authoritative parent data.
	w := newCaptureWriter("192.0.2.100", "udp")
	h.ServeDNS(w, newTestQuery(t, "sub.cut.test.", protocol.TypeDS))
	if w.msg == nil || !w.msg.Header.Flags.AA || len(w.msg.Answers) != 1 || w.msg.Answers[0].Type != protocol.TypeDS {
		t.Errorf("sub.cut.test. DS: want authoritative DS answer from the parent")
	}
}

const wildcardCNAMEZone = `$ORIGIN wcn.test.
$TTL 3600
@       IN  SOA ns1.wcn.test. admin.wcn.test. ( 1 3600 600 86400 300 )
@       IN  NS  ns1.wcn.test.
ns1     IN  A   192.0.2.1
target  IN  A   192.0.2.77
*       IN  CNAME target
`

// TestAuthoritative_WildcardCNAMEAnswersEveryType is the F303 regression. A
// wildcard owning a CNAME was only used for QTYPE=CNAME; every other type got
// NODATA, so "*.zone CNAME target" made the whole wildcard unresolvable
// (RFC 4592 §2.2.1, RFC 1034 §4.3.2 step 3c).
func TestAuthoritative_WildcardCNAMEAnswersEveryType(t *testing.T) {
	h := newTestHandler()
	h.zones["wcn.test."] = loadTestZoneFile(t, "wcn.test.", wildcardCNAMEZone)
	h.RebuildZoneTree()

	w := newCaptureWriter("192.0.2.100", "udp")
	h.ServeDNS(w, newTestQuery(t, "foo.wcn.test.", protocol.TypeA))
	m := w.msg
	if m == nil {
		t.Fatal("no response")
	}
	if !m.Header.Flags.AA || m.Header.Flags.RCODE != protocol.RcodeSuccess || len(m.Answers) != 2 {
		t.Fatalf("want AA NOERROR with CNAME+A, got AA=%v rcode=%d answers=%d", m.Header.Flags.AA, m.Header.Flags.RCODE, len(m.Answers))
	}
	cn, ok := m.Answers[0].Data.(*protocol.RDataCNAME)
	if !ok || m.Answers[0].Name.String() != "foo.wcn.test." || cn.CName.String() != "target.wcn.test." {
		t.Errorf("answer[0] = %v, want foo.wcn.test. CNAME target.wcn.test.", m.Answers[0])
	}
	if m.Answers[1].Type != protocol.TypeA || m.Answers[1].Name.String() != "target.wcn.test." {
		t.Errorf("answer[1] = %v, want target.wcn.test. A", m.Answers[1])
	}
}
