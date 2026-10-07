package main

// Regression tests for F517–F520 (CNAME / DNAME chains from signed zones).

import (
	"context"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
)

func ccSetup(t *testing.T, nsec3 *config.NSEC3Config) *odcEnv {
	t.Helper()
	e := wdSetup(t, nsec3)
	z := e.h.zones["odc.test."]
	extra := loadTestZoneFile(t, "odc.test.", `$ORIGIN odc.test.
$TTL 3600
@         IN SOA ns1.odc.test. admin.odc.test. ( 1 3600 600 86400 300 )
alias     IN CNAME www
alias2    IN CNAME alias
nx        IN CNAME nothere.odc.test.
gl        IN CNAME ns1.sec.odc.test.
xznx      IN CNAME nope.sec.odc.test.
out       IN CNAME target.example.
dn2       IN DNAME tgt.odc.test.
a.tgt     IN A     192.0.2.99
gl2       IN CNAME ns1.ins.odc.test.
gl3       IN CNAME stale.sec.odc.test.
stale.sec IN A     192.0.2.77
od        IN CNAME x.dn.odc.test.
sub.dn    IN NS    ns.elsewhere.example.
`)
	for name, recs := range extra.Records {
		for _, r := range recs {
			if r.Type != "SOA" {
				z.Records[name] = append(z.Records[name], r)
			}
		}
	}
	e.h.RebuildZoneTree()
	return e
}

func ccAsk(t *testing.T, h *integratedHandler, n string, qt uint16, do bool) *protocol.Message {
	t.Helper()
	q := newTestQuery(t, n, qt)
	q.SetEDNS0(4096, do)
	w := newCaptureWriter("192.0.2.100", "udp")
	h.ServeDNS(w, q)
	if w.msg == nil {
		t.Fatalf("no response for %s", n)
	}
	return w.msg
}

// ccSub validates (name, qt) with only the given records — the part of a
// chain response that belongs to name.
func (e *odcEnv) ccSub(t *testing.T, name string, qt uint16, rcode uint8, ans, auth []*protocol.ResourceRecord) string {
	t.Helper()
	n, err := protocol.ParseName(name)
	if err != nil {
		t.Fatal(err)
	}
	m := &protocol.Message{
		Header:    protocol.Header{Flags: protocol.NewResponseFlags(rcode)},
		Questions: []*protocol.Question{{Name: n, QType: qt, QClass: protocol.ClassIN}},
		Answers:   ans, Authorities: auth,
	}
	res, _ := e.v.ValidateResponse(context.Background(), m, name)
	return res.String()
}

func ccOwned(rrs []*protocol.ResourceRecord, name string) []*protocol.ResourceRecord {
	var out []*protocol.ResourceRecord
	for _, rr := range rrs {
		if strings.EqualFold(canonicalize(rr.Name.String()), canonicalize(name)) {
			out = append(out, rr)
		}
	}
	return out
}

func ccSigner(rrs []*protocol.ResourceRecord, name string, typ uint16) string {
	for _, rr := range ccOwned(rrs, name) {
		if s, ok := rr.Data.(*protocol.RDataRRSIG); ok && s.TypeCovered == typ {
			return s.SignerNameString()
		}
	}
	return ""
}

func ccCount(rrs []*protocol.ResourceRecord, typ uint16) int {
	n := 0
	for _, rr := range rrs {
		if rr.Type == typ {
			n++
		}
	}
	return n
}

// TestCNAMEChain_SignedPerZone_F517: every CNAME RRset and the chased target
// RRset carry an RRSIG from their own zone for DO=1 (before: none -> BOGUS).
func TestCNAMEChain_SignedPerZone_F517(t *testing.T) {
	for _, m := range wdModes {
		e := ccSetup(t, m.nsec3)
		// out.odc.test. is a CNAME to target.example., outside every trust
		// anchor: the target's absence cannot be authenticated, so the whole
		// response is INSECURE (P2-E9 validator change; was SECURE).
		for n, want := range map[string]string{"alias.odc.test.": "SECURE", "alias2.odc.test.": "SECURE", "gl.odc.test.": "SECURE", "out.odc.test.": "INSECURE"} {
			r := ccAsk(t, e.h, n, protocol.TypeA, true)
			if v := e.verdict(r, n); v != want {
				t.Errorf("%s %s/A: %s, want %s %v", m.name, n, v, want, p2eTypesReg(r.Answers))
			}
		}
		r := ccAsk(t, e.h, "gl.odc.test.", protocol.TypeA, true)
		if s := ccSigner(r.Answers, "ns1.sec.odc.test.", protocol.TypeA); s != "sec.odc.test." {
			t.Errorf("%s gl: target signed by %q, want the child zone", m.name, s)
		}
		// Wildcard CNAME answering A: the target www is signed too.
		r = ccAsk(t, e.h, "q.wc.odc.test.", protocol.TypeA, true)
		if ccSigner(r.Answers, "www.odc.test.", protocol.TypeA) != "odc.test." {
			t.Errorf("%s q.wc/A: target unsigned %v", m.name, p2eTypesReg(r.Answers))
		}
		// DNAME into the zone: target RRset authenticates on its own.
		r = ccAsk(t, e.h, "a.dn2.odc.test.", protocol.TypeA, true)
		if v := e.ccSub(t, "a.tgt.odc.test.", protocol.TypeA, protocol.RcodeSuccess, ccOwned(r.Answers, "a.tgt.odc.test."), nil); v != "SECURE" {
			t.Errorf("%s a.dn2: target %s", m.name, v)
		}
		// DO=0: no DNSSEC records.
		r = ccAsk(t, e.h, "alias2.odc.test.", protocol.TypeA, false)
		if ccCount(r.Answers, protocol.TypeRRSIG) != 0 || ccCount(r.Answers, protocol.TypeA) != 1 {
			t.Errorf("%s DO=0: %v", m.name, p2eTypesReg(r.Answers))
		}
	}
}

// TestCNAMEChain_NegativeTargetProven_F518: a chain ending at a non-existent
// (NXDOMAIN) or type-less (NODATA) local name carries the target zone's SOA,
// RCODE of the last name, and for DO=1 its signed denial proof.
func TestCNAMEChain_NegativeTargetProven_F518(t *testing.T) {
	for _, m := range wdModes {
		e := ccSetup(t, m.nsec3)
		for _, c := range []struct {
			q, target string
			qt        uint16
			rcode     uint8
		}{
			{"nx.odc.test.", "nothere.odc.test.", protocol.TypeA, protocol.RcodeNameError},
			{"alias.odc.test.", "www.odc.test.", protocol.TypeMX, protocol.RcodeSuccess},
			{"xznx.odc.test.", "nope.sec.odc.test.", protocol.TypeA, protocol.RcodeNameError},
		} {
			want := "SECURE"
			if m.nsec3 != nil && m.nsec3.OptOut && c.rcode == protocol.RcodeNameError {
				want = "INSECURE" // RFC 5155 §9.2
			}
			r := ccAsk(t, e.h, c.q, c.qt, true)
			if r.Header.Flags.RCODE != c.rcode || ccCount(r.Authorities, protocol.TypeSOA) != 1 {
				t.Errorf("%s %s: rcode %d auth %v", m.name, c.q, r.Header.Flags.RCODE, p2eTypesReg(r.Authorities))
			}
			if v := e.ccSub(t, c.target, c.qt, c.rcode, nil, r.Authorities); v != want {
				t.Errorf("%s %s: target proof %s, want %s", m.name, c.q, v, want)
			}
			r = ccAsk(t, e.h, c.q, c.qt, false)
			if r.Header.Flags.RCODE != c.rcode || len(r.Authorities) != 1 || ccCount(r.Authorities, protocol.TypeSOA) != 1 {
				t.Errorf("%s DO=0 %s: rcode %d auth %v", m.name, c.q, r.Header.Flags.RCODE, p2eTypesReg(r.Authorities))
			}
		}
	}
}

// TestCNAMEChain_TargetHonoursCutsAndDNAME_F519: a CNAME target is answered
// only by the zone authoritative for it — never from parent data below a
// cut (glue / stale) nor from data occluded by a DNAME.
func TestCNAMEChain_TargetHonoursCutsAndDNAME_F519(t *testing.T) {
	for _, do := range []bool{false, true} {
		e := ccSetup(t, nil)
		r := ccAsk(t, e.h, "gl3.odc.test.", protocol.TypeA, do)
		if ccCount(r.Answers, protocol.TypeA) != 0 || r.Header.Flags.RCODE != protocol.RcodeNameError {
			t.Errorf("DO=%v gl3: %v rcode %d", do, p2eTypesReg(r.Answers), r.Header.Flags.RCODE)
		}
		r = ccAsk(t, e.h, "gl2.odc.test.", protocol.TypeA, do)
		if ccCount(r.Answers, protocol.TypeA) != 0 {
			t.Errorf("DO=%v gl2: glue answered %v", do, p2eTypesReg(r.Answers))
		}
		r = ccAsk(t, e.h, "od.odc.test.", protocol.TypeA, do)
		if ccCount(r.Answers, protocol.TypeA) != 0 || ccCount(r.Answers, protocol.TypeDNAME) != 1 {
			t.Errorf("DO=%v od: %v", do, p2eTypesReg(r.Answers))
		}
	}
}

// TestDNAME_OccludesDelegationBelow_F520: a cut below a DNAME owner is
// occluded; queries at/below it are redirected, not referred.
func TestDNAME_OccludesDelegationBelow_F520(t *testing.T) {
	for _, do := range []bool{false, true} {
		e := ccSetup(t, nil)
		for _, n := range []string{"a.sub.dn.odc.test.", "sub.dn.odc.test."} {
			r := ccAsk(t, e.h, n, protocol.TypeA, do)
			if !r.Header.Flags.AA || len(r.Answers) == 0 || r.Answers[0].Type != protocol.TypeDNAME {
				t.Errorf("DO=%v %s: AA=%v %v", do, n, r.Header.Flags.AA, p2eTypesReg(r.Answers))
			}
		}
		r := ccAsk(t, e.h, "ns1.ins.odc.test.", protocol.TypeA, do)
		if r.Header.Flags.AA || ccCount(r.Authorities, protocol.TypeNS) == 0 {
			t.Errorf("DO=%v control ins referral lost", do)
		}
	}
}

func p2eTypesReg(rrs []*protocol.ResourceRecord) []string {
	var out []string
	for _, rr := range rrs {
		out = append(out, typeToString(rr.Type))
	}
	return out
}
