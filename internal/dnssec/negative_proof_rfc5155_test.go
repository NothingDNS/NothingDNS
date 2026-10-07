package dnssec

import (
	"context"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// Regression tests for the negative-response round of validator.go:
//   - F377: a closest-encloser proof whose next-closer cover is Opt-Out (DS
//     NODATA §8.6, wildcard NODATA §8.7, NXDOMAIN §8.4) was returned Secure;
//     RFC 5155 §9.2 forbids AD there, so the result is Insecure.
//   - F378: NODATA proofs ignored the CNAME bit (RFC 6840 §4.3, RFC 5155
//     §8.5/§8.7), so a stripped CNAME answer became an authenticated NODATA.
//   - F379: the child's own apex NSEC/NSEC3 was accepted as proof that the
//     parent has no DS for the child (RFC 4035 §3.1.4.1, §5.2).
// Fixtures are signed in-process; IgnoreTime removes wall-clock dependence.

func TestNSEC3OptOutDenialNotSecureRFC5155(t *testing.T) {
	f := newNSEC3DenialFixture(t)
	names := map[string][]uint16{
		"example.com.":   {protocol.TypeSOA, protocol.TypeNS, protocol.TypeDNSKEY, protocol.TypeRRSIG, protocol.TypeNSEC3PARAM},
		"*.example.com.": {protocol.TypeA, protocol.TypeRRSIG},
		"w.example.com.": {protocol.TypeA, protocol.TypeRRSIG},
		"y.example.com.": {protocol.TypeA, protocol.TypeRRSIG},
		"s.example.com.": {protocol.TypeNS, protocol.TypeDS, protocol.TypeRRSIG},
	}
	z := nsec3TestZone(t, names)
	var all []string
	for n := range names {
		all = append(all, n)
	}
	zOpt := nsec3TestZone(t, names, all...)
	// Opt-Out on every NSEC3 EXCEPT the one covering x.example.com.: the
	// flag on a record that is not the next-closer cover does not matter.
	coverX := nsec3TestCover(t, z, "x.example.com.")
	var others []string
	for n, rr := range z {
		if rr != coverX {
			others = append(others, n)
		}
	}
	zOther := nsec3TestZone(t, names, others...)
	noWild := map[string][]uint16{}
	for n, types := range names {
		if n != "*.example.com." {
			noWild[n] = types
		}
	}
	var noWildAll []string
	for n := range noWild {
		noWildAll = append(noWildAll, n)
	}
	zNX := nsec3TestZone(t, noWild)
	zNXOpt := nsec3TestZone(t, noWild, noWildAll...)

	cases := []struct {
		name  string
		rcode uint8
		qname string
		qtype uint16
		auth  []*protocol.ResourceRecord
		want  ValidationResult
	}{
		{"DS NODATA via Opt-Out cover", protocol.RcodeSuccess, "x.example.com.", protocol.TypeDS,
			nsec3TestAuth(t, f, zOpt["example.com."], nsec3TestCover(t, zOpt, "x.example.com.")), ValidationInsecure},
		{"NXDOMAIN with Opt-Out next-closer cover", protocol.RcodeNameError, "x.b.example.com.", protocol.TypeA,
			nsec3TestAuth(t, f, zNXOpt["example.com."], nsec3TestCover(t, zNXOpt, "b.example.com."), nsec3TestCover(t, zNXOpt, "*.example.com.")), ValidationInsecure},
		{"NXDOMAIN without Opt-Out", protocol.RcodeNameError, "x.b.example.com.", protocol.TypeA,
			nsec3TestAuth(t, f, zNX["example.com."], nsec3TestCover(t, zNX, "b.example.com."), nsec3TestCover(t, zNX, "*.example.com.")), ValidationSecure},
		{"wildcard NODATA with Opt-Out next-closer cover", protocol.RcodeSuccess, "x.example.com.", protocol.TypeAAAA,
			nsec3TestAuth(t, f, zOpt["example.com."], nsec3TestCover(t, zOpt, "x.example.com."), zOpt["*.example.com."]), ValidationInsecure},
		{"wildcard NODATA, cover not Opt-Out", protocol.RcodeSuccess, "x.example.com.", protocol.TypeAAAA,
			nsec3TestAuth(t, f, zOther["example.com."], nsec3TestCover(t, zOther, "x.example.com."), zOther["*.example.com."]), ValidationSecure},
		{"wildcard NODATA, no Opt-Out", protocol.RcodeSuccess, "x.example.com.", protocol.TypeAAAA,
			nsec3TestAuth(t, f, z["example.com."], coverX, z["*.example.com."]), ValidationSecure},
		{"DS exact match in Opt-Out zone", protocol.RcodeSuccess, "w.example.com.", protocol.TypeDS,
			nsec3TestAuth(t, f, zOpt["w.example.com."]), ValidationSecure},
		{"DS NODATA, cover not Opt-Out", protocol.RcodeSuccess, "x.example.com.", protocol.TypeDS,
			nsec3TestAuth(t, f, zOther["example.com."], nsec3TestCover(t, zOther, "x.example.com.")), ValidationBogus},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := negMsg(tc.rcode, tc.qname, tc.auth)
			m.Questions[0].QType = tc.qtype
			for i := 0; i < 2; i++ {
				// validateMessage is what sets the AD-relevant verdict.
				if got := f.v.validateMessage(context.Background(), m, tc.qname, f.chain); got != tc.want {
					t.Fatalf("call %d: got %v, want %v", i, got, tc.want)
				}
			}
		})
	}
}

func TestNoDataCNAMEBitRFC6840(t *testing.T) {
	f := newNSEC3DenialFixture(t)
	nsec := func(owner, next string, types ...uint16) *protocol.ResourceRecord {
		return &protocol.ResourceRecord{Name: mustName(t, owner), Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300,
			Data: &protocol.RDataNSEC{NextDomain: mustName(t, next), TypeBitMap: types}}
	}
	cname := []uint16{protocol.TypeCNAME, protocol.TypeRRSIG, protocol.TypeNSEC}
	a := []uint16{protocol.TypeA, protocol.TypeRRSIG, protocol.TypeNSEC}
	soa := []uint16{protocol.TypeSOA, protocol.TypeNS, protocol.TypeRRSIG, protocol.TypeNSEC}
	names := map[string][]uint16{
		"example.com.":   {protocol.TypeSOA, protocol.TypeNS, protocol.TypeDNSKEY, protocol.TypeRRSIG, protocol.TypeNSEC3PARAM},
		"c.example.com.": {protocol.TypeCNAME, protocol.TypeRRSIG},
		"*.example.com.": {protocol.TypeCNAME, protocol.TypeRRSIG},
		"w.example.com.": {protocol.TypeA, protocol.TypeRRSIG},
	}
	z := nsec3TestZone(t, names)
	cases := []struct {
		name  string
		qname string
		qtype uint16
		rrs   []*protocol.ResourceRecord
		want  ValidationResult
	}{
		{"NSEC exact has CNAME", "c.example.com.", protocol.TypeA, []*protocol.ResourceRecord{nsec("c.example.com.", "w.example.com.", cname...)}, ValidationBogus},
		{"NSEC exact has CNAME, qtype CNAME", "c.example.com.", protocol.TypeCNAME, []*protocol.ResourceRecord{nsec("c.example.com.", "w.example.com.", cname...)}, ValidationBogus},
		{"NSEC3 exact has CNAME", "c.example.com.", protocol.TypeA, []*protocol.ResourceRecord{z["c.example.com."]}, ValidationBogus},
		{"NSEC wildcard has CNAME", "x.example.com.", protocol.TypeA,
			[]*protocol.ResourceRecord{nsec("w.example.com.", "y.example.com.", a...), nsec("*.example.com.", "c.example.com.", cname...)}, ValidationBogus},
		{"NSEC3 wildcard has CNAME", "x.example.com.", protocol.TypeA,
			[]*protocol.ResourceRecord{z["example.com."], nsec3TestCover(t, z, "x.example.com."), z["*.example.com."]}, ValidationBogus},
		{"NSEC exact without CNAME", "w.example.com.", protocol.TypeAAAA, []*protocol.ResourceRecord{nsec("w.example.com.", "y.example.com.", a...)}, ValidationSecure},
		{"NSEC3 exact without CNAME", "w.example.com.", protocol.TypeAAAA, []*protocol.ResourceRecord{z["w.example.com."]}, ValidationSecure},
		{"NSEC wildcard without CNAME", "x.example.com.", protocol.TypeAAAA,
			[]*protocol.ResourceRecord{nsec("w.example.com.", "y.example.com.", a...), nsec("*.example.com.", "c.example.com.", a...)}, ValidationSecure},
		{"ENT NODATA (no bitmap)", "sub.example.com.", protocol.TypeA, []*protocol.ResourceRecord{nsec("example.com.", "a.sub.example.com.", soa...)}, ValidationSecure},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auth := nsec3TestAuth(t, f, tc.rrs...)
			for i := 0; i < 2; i++ {
				if got := nsec3TestNoData(f, tc.qname, tc.qtype, auth); got != tc.want {
					t.Fatalf("call %d: got %v, want %v", i, got, tc.want)
				}
			}
		})
	}
}

func TestDSNoDataFromChildApexRejectedRFC4035(t *testing.T) {
	v, keys := dsChainFixture(t, nil)
	nsec := func(owner, next string, types ...uint16) *protocol.ResourceRecord {
		return &protocol.ResourceRecord{Name: mustName(t, owner), Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300,
			Data: &protocol.RDataNSEC{NextDomain: mustName(t, next), TypeBitMap: types}}
	}
	childNSEC3 := nsec3TestZone(t, map[string][]uint16{
		"example.com.":     {protocol.TypeSOA, protocol.TypeNS, protocol.TypeDNSKEY, protocol.TypeRRSIG, protocol.TypeNSEC3PARAM},
		"www.example.com.": {protocol.TypeA, protocol.TypeRRSIG},
	})["example.com."]
	apexNSEC := nsec("example.com.", "www.example.com.", protocol.TypeSOA, protocol.TypeNS, protocol.TypeDNSKEY, protocol.TypeRRSIG, protocol.TypeNSEC)
	query := func(qtype uint16, signer string, rr *protocol.ResourceRecord) ValidationResult {
		sig := keys[signer].sign(t, signer, []*protocol.ResourceRecord{rr})
		m := negMsg(protocol.RcodeSuccess, "example.com.", []*protocol.ResourceRecord{rr, sig})
		m.Questions[0].QType = qtype
		res, _ := v.ValidateResponse(context.Background(), m, "example.com.")
		return res
	}
	cases := []struct {
		name   string
		qtype  uint16
		signer string
		rr     *protocol.ResourceRecord
		want   ValidationResult
	}{
		{"child apex NSEC denies DS", protocol.TypeDS, "example.com.", apexNSEC, ValidationBogus},
		{"child apex NSEC3 denies DS", protocol.TypeDS, "example.com.", childNSEC3, ValidationBogus},
		{"parent NSEC, NS without DS", protocol.TypeDS, "com.", nsec("example.com.", "f.com.", protocol.TypeNS, protocol.TypeRRSIG, protocol.TypeNSEC), ValidationSecure},
		{"parent NSEC, NS with DS", protocol.TypeDS, "com.", nsec("example.com.", "f.com.", protocol.TypeNS, protocol.TypeDS, protocol.TypeRRSIG, protocol.TypeNSEC), ValidationBogus},
		{"child apex NSEC, AAAA NODATA unaffected", protocol.TypeAAAA, "example.com.", apexNSEC, ValidationSecure},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < 2; i++ {
				if got := query(tc.qtype, tc.signer, tc.rr); got != tc.want {
					t.Fatalf("call %d: got %v, want %v", i, got, tc.want)
				}
			}
		})
	}
}
