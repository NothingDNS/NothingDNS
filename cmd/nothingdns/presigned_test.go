package main

// A zone carrying its own signatures (signed offline, or transferred signed)
// is served with them: stored RRSIGs on answers and stored NSEC proofs on
// negative answers, which the DNSSEC validator accepts as Secure (F753).

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

type presignedTestResolver struct{ answers []*protocol.ResourceRecord }

func (r *presignedTestResolver) Query(_ context.Context, name string, qtype uint16) (*protocol.Message, error) {
	resp := &protocol.Message{Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)}}
	resp.Header.Flags.AA = true
	if q, err := protocol.NewQuery(1, name, qtype); err == nil {
		resp.Questions = q.Questions
	}
	if qtype == protocol.TypeDNSKEY && strings.EqualFold(canonicalize(name), "pre.test.") {
		for _, rr := range r.answers {
			resp.Answers = append(resp.Answers, rr.Copy())
		}
	}
	return resp, nil
}

func TestPresignedZoneAnswersValidate(t *testing.T) {
	signer := dnssecRegSigner(t, "pre.test.")
	n := func(x string) *protocol.Name { y, _ := protocol.ParseName(x); return y }
	mk := func(name string, typ uint16, d protocol.RData) *protocol.ResourceRecord {
		rr, _ := protocol.NewResourceRecord(name, typ, protocol.ClassIN, 300, d)
		return rr
	}
	signed, err := signer.SignZone([]*protocol.ResourceRecord{
		mk("pre.test.", protocol.TypeSOA, &protocol.RDataSOA{MName: n("ns1.pre.test."), RName: n("h.pre.test."), Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300}),
		mk("pre.test.", protocol.TypeNS, &protocol.RDataNS{NSDName: n("ns1.pre.test.")}),
		mk("ns1.pre.test.", protocol.TypeA, &protocol.RDataA{Address: [4]byte{192, 0, 2, 53}}),
		mk("www.pre.test.", protocol.TypeA, &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}}),
		mk("*.wild.pre.test.", protocol.TypeTXT, &protocol.RDataTXT{Strings: []string{"wild"}}),
	})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	var dnskeys []*protocol.ResourceRecord
	for _, rr := range signed {
		fmt.Fprintf(&b, "%s %d IN %s %s\n", rr.Name.String(), rr.TTL, typeToString(rr.Type), rr.Data.String())
		if rr.Name.String() == "pre.test." && (rr.Type == protocol.TypeDNSKEY || (rr.Type == protocol.TypeRRSIG && rr.Data.(*protocol.RDataRRSIG).TypeCovered == protocol.TypeDNSKEY)) {
			dnskeys = append(dnskeys, rr)
		}
	}
	z, err := zone.ParseFile("pre.test.zone", strings.NewReader(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	h := newTestHandler()
	h.zones["pre.test."] = z
	h.RebuildZoneTree()

	ksk := signer.GetKSKs()[0]
	store := dnssec.NewTrustAnchorStore()
	store.AddAnchor(&dnssec.TrustAnchor{Zone: "pre.test.", KeyTag: ksk.KeyTag, Algorithm: ksk.DNSKEY.Algorithm, PublicKey: ksk.DNSKEY.PublicKey})
	cfg := dnssec.DefaultValidatorConfig()
	cfg.IgnoreTime = true
	v := dnssec.NewValidator(cfg, store, &presignedTestResolver{answers: dnskeys})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, tc := range []struct {
		name string
		qt   uint16
	}{
		{"www.pre.test.", protocol.TypeA},
		{"pre.test.", protocol.TypeDNSKEY},
		{"nx.pre.test.", protocol.TypeA},
		{"www.pre.test.", protocol.TypeAAAA},
	} {
		m := dnssecRegAsk(t, h, tc.name, tc.qt)
		res, verr := v.ValidateResponse(ctx, m, tc.name)
		if res != dnssec.ValidationSecure {
			t.Fatalf("%s %s: validated %v (%v); rcode %d answers %d authority %d", tc.name, typeToString(tc.qt), res, verr, m.Header.Flags.RCODE, len(m.Answers), len(m.Authorities))
		}
	}
	// Wildcard answer (BIND delv validates it fully; the in-repo validator
	// rejects wildcard answers, F754): the stored RRSIG with the wildcard's
	// label count, owned by QNAME, and the stored NSEC proving no closer match.
	wm := dnssecRegAsk(t, h, "foo.wild.pre.test.", protocol.TypeTXT)
	var wsig *protocol.RDataRRSIG
	for _, rr := range wm.Answers {
		if s, ok := rr.Data.(*protocol.RDataRRSIG); ok {
			wsig = s
			if rr.Name.String() != "foo.wild.pre.test." {
				t.Fatalf("wildcard RRSIG owner %s", rr.Name)
			}
		}
	}
	if wsig == nil || wsig.Labels != 3 || dnssecRegCount(wm.Authorities, protocol.TypeNSEC) != 1 || dnssecRegCount(wm.Authorities, protocol.TypeRRSIG) != 1 {
		t.Fatalf("wildcard answer: sig %+v, authority %d", wsig, len(wm.Authorities))
	}
	// DO=0: no DNSSEC records.
	w := newCaptureWriter("192.0.2.100", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.pre.test.", protocol.TypeA))
	if dnssecRegCount(w.msg.Answers, protocol.TypeRRSIG) != 0 {
		t.Fatal("DO=0 answer carries RRSIG")
	}
}
