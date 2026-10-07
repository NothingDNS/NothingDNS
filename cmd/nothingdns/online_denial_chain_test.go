package main

// Regression tests for P2-E1 (F487–F490): the online denial chain is built
// from the zone's authoritative nodes only, follows dnssec.signing.nsec3
// (including opt_out), and lists the apex types the server serves. Verdicts
// come from internal/dnssec's Validator, whose fetches are answered by the
// real handler.

import (
	"context"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

type odcEnv struct {
	h      *integratedHandler
	parent *dnssec.Signer
	v      *dnssec.Validator
}

type odcResolver struct {
	t *testing.T
	h *integratedHandler
}

func (r odcResolver) Query(_ context.Context, name string, qtype uint16) (*protocol.Message, error) {
	return odcStrip(dnssecRegAsk(r.t, r.h, name, qtype)), nil
}

func odcStrip(m *protocol.Message) *protocol.Message {
	out := *m
	out.Additionals = nil
	for _, rr := range m.Additionals {
		if rr.Type != protocol.TypeOPT {
			out.Additionals = append(out.Additionals, rr)
		}
	}
	return &out
}

func (e *odcEnv) verdict(m *protocol.Message, qname string) string {
	res, _ := e.v.ValidateResponse(context.Background(), odcStrip(m), qname)
	return res.String()
}

// odcSetup: signed parent odc.test. with a signed co-hosted child (sec, DS in
// the parent, glue ns1.sec) and an unsigned delegation (ins) with glue and
// deep glue.
func odcSetup(t *testing.T, nsec3 *config.NSEC3Config) *odcEnv {
	t.Helper()
	h := newTestHandler()
	h.config.DNSSEC.Enabled = true
	h.config.DNSSEC.Signing.Enabled = true
	h.config.DNSSEC.Signing.NSEC3 = nsec3
	parent := dnssecRegSigner(t, "odc.test.")
	child := dnssecRegSigner(t, "sec.odc.test.")
	ds, err := dnssec.CreateDS("sec.odc.test.", child.GetKSKs()[0].DNSKEY, 2)
	if err != nil {
		t.Fatal(err)
	}
	h.zones["odc.test."] = loadTestZoneFile(t, "odc.test.", fmt.Sprintf(`$ORIGIN odc.test.
$TTL 3600
@             IN SOA ns1.odc.test. admin.odc.test. ( 1 3600 600 86400 300 )
@             IN NS  ns1.odc.test.
ns1           IN A   192.0.2.1
www           IN A   192.0.2.2
sec           IN NS  ns1.sec.odc.test.
sec           IN DS  %d %d 2 %s
ns1.sec       IN A   192.0.2.50
ins           IN NS  ns1.ins.odc.test.
ns1.ins       IN A   192.0.2.51
deep.glue.ins IN A   192.0.2.52
`, ds.KeyTag, ds.Algorithm, strings.ToUpper(hex.EncodeToString(ds.Digest))))
	h.zones["sec.odc.test."] = loadTestZoneFile(t, "sec.odc.test.", `$ORIGIN sec.odc.test.
$TTL 3600
@     IN SOA ns1.sec.odc.test. admin.sec.odc.test. ( 1 3600 600 86400 300 )
@     IN NS  ns1.sec.odc.test.
ns1   IN A   192.0.2.50
ns1   IN AAAA 2001:db8::50
`)
	h.RebuildZoneTree()
	h.zoneSigners = map[string]*dnssec.Signer{"odc.test.": parent, "sec.odc.test.": child}

	ta, err := dnssec.CreateDS("odc.test.", parent.GetKSKs()[0].DNSKEY, 2)
	if err != nil {
		t.Fatal(err)
	}
	store := dnssec.NewTrustAnchorStore()
	store.AddAnchor(ta)
	vcfg := dnssec.DefaultValidatorConfig()
	vcfg.ValidationCacheTTL = 0
	return &odcEnv{h: h, parent: parent, v: dnssec.NewValidator(vcfg, store, odcResolver{t: t, h: h})}
}

// TestOnlineDenial_NoGlueOrOccludedNames_F489: served NSEC/NSEC3 records never
// own, point at, or hash a name below a zone cut (RFC 4035 §2.3, RFC 5155
// §7.1). Before the fix the parent's NSEC owned by glue ns1.sec.odc.test.
// was served, and replaying it as a NODATA for ns1.sec.odc.test./AAAA — which
// exists in the signed child — validated SECURE.
func TestOnlineDenial_NoGlueOrOccludedNames_F489(t *testing.T) {
	occluded := []string{"ns1.sec.odc.test.", "ns1.ins.odc.test.", "deep.glue.ins.odc.test.", "glue.ins.odc.test."}
	for _, nsec3 := range []*config.NSEC3Config{nil, {Iterations: 0}} {
		e := odcSetup(t, nsec3)
		occ := map[string]bool{}
		for _, n := range occluded {
			occ[n] = true
			if nsec3 != nil {
				hash, _ := dnssec.NSEC3Hash(n, 1, 0, nil)
				occ[strings.ToLower(odcB32.EncodeToString(hash))+".odc.test."] = true
			}
		}
		for _, q := range []struct {
			n  string
			qt uint16
		}{
			{"t.odc.test.", protocol.TypeA}, {"a.odc.test.", protocol.TypeA}, {"j.odc.test.", protocol.TypeA},
			{"ins.odc.test.", protocol.TypeDS}, {"www.ins.odc.test.", protocol.TypeA}, {"www.odc.test.", protocol.TypeAAAA},
		} {
			m := dnssecRegAsk(t, e.h, q.n, q.qt)
			for _, rr := range m.Authorities {
				owner := strings.ToLower(rr.Name.String())
				next := ""
				switch d := rr.Data.(type) {
				case *protocol.RDataNSEC:
					next = strings.ToLower(d.NextDomain.String())
				case *protocol.RDataNSEC3:
					next = strings.ToLower(odcB32.EncodeToString(d.NextHashed)) + ".odc.test."
				default:
					continue
				}
				if occ[owner] || occ[next] {
					t.Errorf("nsec3=%v %s/%s: denial record %s -> %s names an occluded name", nsec3 != nil, q.n, typeToString(q.qt), owner, next)
				}
			}
		}

		nx := dnssecRegAsk(t, e.h, "t.odc.test.", protocol.TypeA)
		if v := e.verdict(nx, "t.odc.test."); v != "SECURE" {
			t.Errorf("nsec3=%v: NXDOMAIN t.odc.test. = %s, want SECURE", nsec3 != nil, v)
		}
		real := dnssecRegAsk(t, e.h, "ns1.sec.odc.test.", protocol.TypeAAAA)
		if v := e.verdict(real, "ns1.sec.odc.test."); v != "SECURE" || dnssecRegCount(real.Answers, protocol.TypeAAAA) != 1 {
			t.Fatalf("control: child AAAA verdict %s answers %v", v, real.Answers)
		}
		qn, _ := protocol.ParseName("ns1.sec.odc.test.")
		forged := &protocol.Message{Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Questions: []*protocol.Question{{Name: qn, QType: protocol.TypeAAAA, QClass: protocol.ClassIN}}}
		forged.Header.Flags.AA = true
		for _, rr := range nx.Authorities {
			forged.Authorities = append(forged.Authorities, rr.Copy())
		}
		if v := e.verdict(forged, "ns1.sec.odc.test."); v == "SECURE" {
			t.Errorf("nsec3=%v: parent denial replayed as NODATA for existing child data validated SECURE", nsec3 != nil)
		}
	}
}

// TestOnlineDenial_ApexBitmapListsServedDNSKEY_F490: the DNSKEY RRset served
// from the signing keys must be in the apex NSEC bitmap.
func TestOnlineDenial_ApexBitmapListsServedDNSKEY_F490(t *testing.T) {
	e := odcSetup(t, nil)
	if dnssecRegCount(dnssecRegAsk(t, e.h, "odc.test.", protocol.TypeDNSKEY).Answers, protocol.TypeDNSKEY) == 0 {
		t.Fatal("control: DNSKEY not served")
	}
	m := dnssecRegAsk(t, e.h, "odc.test.", protocol.TypeTXT)
	for _, rr := range m.Authorities {
		if d, ok := rr.Data.(*protocol.RDataNSEC); ok && rr.Name.String() == "odc.test." {
			for _, ty := range d.TypeBitMap {
				if ty == protocol.TypeDNSKEY {
					return
				}
			}
			t.Fatalf("apex NSEC bitmap %v denies the served DNSKEY RRset", d.TypeBitMap)
		}
	}
	t.Fatalf("no apex NSEC in %v", m.Authorities)
}

// TestOnlineDenial_NSEC3WhenConfigured_F488: with dnssec.signing.nsec3 set the
// server serves NSEC3 (never NSEC), honours opt_out, and publishes
// NSEC3PARAM; answers validate.
func TestOnlineDenial_NSEC3WhenConfigured_F488(t *testing.T) {
	for _, optOut := range []bool{false, true} {
		e := odcSetup(t, &config.NSEC3Config{Iterations: 1, Salt: "ABCD", OptOut: optOut})
		for _, q := range []struct {
			n     string
			qt    uint16
			rcode uint8
		}{
			{"t.odc.test.", protocol.TypeA, protocol.RcodeNameError},
			{"www.odc.test.", protocol.TypeAAAA, protocol.RcodeSuccess},
			{"ins.odc.test.", protocol.TypeDS, protocol.RcodeSuccess},
		} {
			m := dnssecRegAsk(t, e.h, q.n, q.qt)
			if m.Header.Flags.RCODE != q.rcode || dnssecRegCount(m.Authorities, protocol.TypeNSEC) != 0 ||
				dnssecRegCount(m.Authorities, protocol.TypeNSEC3) == 0 || !dnssecRegSigCovers(m.Authorities, protocol.TypeNSEC3) {
				t.Fatalf("optOut=%v %s/%s: rcode=%d authority %v, want signed NSEC3 only", optOut, q.n, typeToString(q.qt), m.Header.Flags.RCODE, m.Authorities)
			}
			for _, rr := range m.Authorities {
				if d, ok := rr.Data.(*protocol.RDataNSEC3); ok {
					if (d.Flags&1 != 0) != optOut || d.Iterations != 1 || hex.EncodeToString(d.Salt) != "abcd" {
						t.Errorf("optOut=%v: NSEC3 %s flags=%d iterations=%d salt=%x", optOut, rr.Name, d.Flags, d.Iterations, d.Salt)
					}
				}
			}
			want := "SECURE"
			if optOut && q.n != "www.odc.test." {
				want = "SECURE|INSECURE" // RFC 5155 §9.2: opt-out next-closer cover
			}
			if v := e.verdict(m, q.n); !strings.Contains(want, v) {
				t.Errorf("optOut=%v %s/%s verdict %s, want %s", optOut, q.n, typeToString(q.qt), v, want)
			}
		}
		pm := dnssecRegAsk(t, e.h, "odc.test.", protocol.TypeNSEC3PARAM)
		if dnssecRegCount(pm.Answers, protocol.TypeNSEC3PARAM) != 1 || !dnssecRegSigCovers(pm.Answers, protocol.TypeNSEC3PARAM) {
			t.Errorf("optOut=%v: NSEC3PARAM answers %v", optOut, pm.Answers)
		}
	}
}

// TestLoadZoneSigner_WiresNSEC3OptOut_F487: dnssec.signing.nsec3.opt_out
// reaches the zone signer.
func TestLoadZoneSigner_WiresNSEC3OptOut_F487(t *testing.T) {
	rr := func(name string, typ uint16, text string) *protocol.ResourceRecord {
		r, err := protocol.NewResourceRecord(name, typ, protocol.ClassIN, 300, protocol.ParseRDataText(protocol.TypeString(typ), text))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	for _, optOut := range []bool{false, true} {
		signer, err := loadZoneSigner(zone.NewZone("oo.test."), config.SigningConfig{Enabled: true, NSEC3: &config.NSEC3Config{OptOut: optOut}})
		if err != nil || signer == nil {
			t.Fatalf("loadZoneSigner: %v", err)
		}
		for _, ksk := range []bool{true, false} {
			if _, err := signer.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, ksk); err != nil {
				t.Fatal(err)
			}
		}
		signed, err := signer.SignZone([]*protocol.ResourceRecord{
			rr("oo.test.", protocol.TypeSOA, "ns1.oo.test. admin.oo.test. 1 3600 600 86400 300"),
			rr("oo.test.", protocol.TypeNS, "ns1.oo.test."),
			rr("ns1.oo.test.", protocol.TypeA, "192.0.2.1"),
			rr("unsigned.oo.test.", protocol.TypeNS, "ns.example.net."),
		})
		if err != nil {
			t.Fatal(err)
		}
		set := 0
		for _, r := range signed {
			if d, ok := r.Data.(*protocol.RDataNSEC3); ok && d.Flags&1 != 0 {
				set++
			}
		}
		if (set > 0) != optOut {
			t.Errorf("opt_out=%v: %d NSEC3 records carry Opt-Out", optOut, set)
		}
	}
}

var odcB32 = base32.HexEncoding.WithPadding(base32.NoPadding)
