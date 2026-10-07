package dnssec

// Regression tests for F77-F79 (RFC 4034 §6.1 canonical order and RFC 4035
// §3.1.3 / §5.4 NSEC denial proofs). Each case was red against 80ea9a2:
//   - F77: canonicalNameCompare compared whole wire names left-to-right, so a
//     genuine NSEC from an RFC-ordered zone covered an existing name and a
//     forged NXDOMAIN validated Secure; the signer emitted non-RFC chains.
//   - F78: an NSEC owned by qname counted as an NXDOMAIN name proof, the
//     wildcard proof accepted any ancestor (not the closest encloser), and
//     an honest single NSEC covering qname and *.CE was rejected.
//   - F79: any covering NSEC proved NODATA, erasing wildcard answers.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestNSECCanonicalOrderRFC4034(t *testing.T) {
	ok := true
	sign := func(c int) int {
		switch {
		case c < 0:
			return -1
		case c > 0:
			return 1
		}
		return 0
	}
	cases := []struct {
		a, b string
		want int
	}{
		{"example.", "a.example.", -1},
		{"a.example.", "yljkjljk.a.example.", -1},
		{"yljkjljk.a.example.", "Z.a.example.", -1},
		{"Z.a.example.", "zABC.a.EXAMPLE.", -1},
		{"zABC.a.EXAMPLE.", "z.example.", -1},
		{"z.example.", "*.z.example.", -1},
		{"aa.example.com.", "b.example.com.", -1},
		{"sub.a.example.", "b.example.", -1},
		{".", "com.", -1}, // root first (boundary)
		{"", ".", 0},      // empty == root
		{"EXAMPLE.COM", "example.com.", 0},
		{"z.", "a.a.", 1},
	}
	for _, c := range cases {
		got := sign(canonicalNameCompare(c.a, c.b))
		rev := sign(canonicalNameCompare(c.b, c.a))
		if got != c.want || rev != -c.want {
			fmt.Printf("compare(%q,%q): EXPECTED %d/%d | ACTUAL %d/%d\n", c.a, c.b, c.want, -c.want, got, rev)
			ok = false
		}
	}
	// Signer chain is in RFC order and the validator accepts its gaps.
	signer := NewSigner("example.com.", DefaultSignerConfig())
	if _, err := signer.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, true); err != nil {
		t.Fatal(err)
	}
	if _, err := signer.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false); err != nil {
		t.Fatal(err)
	}
	var recs []*protocol.ResourceRecord
	for _, n := range []string{"example.com.", "b.example.com.", "aa.example.com.", "z.a.example.com.", "a.example.com."} {
		recs = append(recs, &protocol.ResourceRecord{Name: mustName(t, n), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}}})
	}
	signed, err := signer.SignZone(recs)
	if err != nil {
		t.Fatal(err)
	}
	next := map[string]string{}
	for _, rr := range signed {
		if n, isNSEC := rr.Data.(*protocol.RDataNSEC); isNSEC && rr.Type == protocol.TypeNSEC {
			next[strings.ToLower(rr.Name.String())] = strings.ToLower(n.NextDomain.String())
		}
	}
	want := map[string]string{
		"example.com.": "a.example.com.", "a.example.com.": "z.a.example.com.",
		"z.a.example.com.": "aa.example.com.", "aa.example.com.": "b.example.com.", "b.example.com.": "example.com.",
	}
	for k, v := range want {
		if next[k] != v {
			fmt.Printf("signer NSEC %s ->: EXPECTED %s | ACTUAL %s\n", k, v, next[k])
			ok = false
		}
	}
	// Wrap-around gap in RFC order: (b.example.com. -> example.com.) covers c.example.com. but not a.example.com.
	if !nameInRange("c.example.com.", "b.example.com.", "example.com.") || nameInRange("a.example.com.", "b.example.com.", "example.com.") {
		fmt.Println("wrap-around gap: EXPECTED c in / a out | ACTUAL mismatch")
		ok = false
	}
	for i := 0; i < 3; i++ { // repeated call
		if canonicalNameCompare("sub.a.example.", "b.example.") >= 0 {
			ok = false
		}
	}
	if !ok {
		t.Fatal("regression: see output above")
	}
}

func TestNSECNameErrorProofRFC4035(t *testing.T) {
	f := newDenialFixture(t)
	cfg := DefaultValidatorConfig()
	cfg.IgnoreTime = true
	f.v = NewValidator(cfg, nil, nil)
	nsec := func(owner, next string, types ...uint16) *protocol.ResourceRecord {
		return &protocol.ResourceRecord{Name: mustName(t, owner), Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300,
			Data: &protocol.RDataNSEC{NextDomain: mustName(t, next), TypeBitMap: types}}
	}
	auth := func(rrs ...*protocol.ResourceRecord) []*protocol.ResourceRecord {
		var out []*protocol.ResourceRecord
		for _, rr := range rrs {
			set, sig := f.signDenialSet(t, []*protocol.ResourceRecord{rr})
			out = append(append(out, set...), sig)
		}
		return out
	}
	soa := []uint16{protocol.TypeSOA, protocol.TypeNS, protocol.TypeRRSIG, protocol.TypeNSEC}
	a := []uint16{protocol.TypeA, protocol.TypeRRSIG, protocol.TypeNSEC}
	ok := true
	run := func(name, q string, qtype uint16, want ValidationResult, rrs ...*protocol.ResourceRecord) {
		m := negMsg(protocol.RcodeNameError, q, auth(rrs...))
		m.Questions[0].QType = qtype
		for i := 0; i < 3; i++ { // repeated call is stable
			if got := f.v.validateNegativeResponse(m, q, f.chain); got != want {
				fmt.Printf("%s: EXPECTED %v | ACTUAL %v\n", name, want, got)
				ok = false
				return
			}
		}
	}
	// Original reproduction.
	run("existing name via own NSEC", "a.example.com.", protocol.TypeAAAA, ValidationBogus,
		nsec("a.example.com.", "c.example.com.", a...), nsec("example.com.", "a.example.com.", soa...))
	run("root wildcard as proof", "x.example.com.", protocol.TypeA, ValidationBogus,
		nsec("w.example.com.", "y.example.com.", a...), nsec("y.example.com.", "example.com.", a...))
	run("single NSEC covers qname and *.CE", "b.example.com.", protocol.TypeA, ValidationSecure,
		nsec("example.com.", "z.example.com.", soa...))
	run("two-NSEC honest", "b.example.com.", protocol.TypeA, ValidationSecure,
		nsec("a.example.com.", "c.example.com.", a...), nsec("example.com.", "a.example.com.", soa...))
	// Edge: empty non-terminal sub.example.com. (a.sub.example.com. exists) forged NXDOMAIN.
	run("ENT forged NXDOMAIN", "sub.example.com.", protocol.TypeA, ValidationBogus,
		nsec("example.com.", "a.sub.example.com.", soa...))
	// Edge: CE depth binding. Zone: example, y, *.y, z. x.y.example.com is
	// synthesized from *.y; the apex wildcard cover must not substitute.
	run("shallower wildcard cover than CE", "x.y.example.com.", protocol.TypeA, ValidationBogus,
		nsec("*.y.example.com.", "z.example.com.", a...), nsec("example.com.", "y.example.com.", soa...))
	// Edge: deeper CE legit: zone example, y, z; x.y.example.com absent; (y->z) covers x.y and *.y.
	run("deeper CE honest", "x.y.example.com.", protocol.TypeA, ValidationSecure,
		nsec("y.example.com.", "z.example.com.", a...))
	// Edge: empty authority.
	run("no NSEC at all", "b.example.com.", protocol.TypeA, ValidationBogus)
	if !ok {
		t.Fatal("regression: see output above")
	}
}

func TestNSECNoDataProofRFC4035(t *testing.T) {
	f := newDenialFixture(t)
	cfg := DefaultValidatorConfig()
	cfg.IgnoreTime = true
	f.v = NewValidator(cfg, nil, nil)
	nsec := func(owner, next string, types ...uint16) *protocol.ResourceRecord {
		return &protocol.ResourceRecord{Name: mustName(t, owner), Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300,
			Data: &protocol.RDataNSEC{NextDomain: mustName(t, next), TypeBitMap: types}}
	}
	auth := func(rrs ...*protocol.ResourceRecord) []*protocol.ResourceRecord {
		var out []*protocol.ResourceRecord
		for _, rr := range rrs {
			set, sig := f.signDenialSet(t, []*protocol.ResourceRecord{rr})
			out = append(append(out, set...), sig)
		}
		return out
	}
	soa := []uint16{protocol.TypeSOA, protocol.TypeNS, protocol.TypeRRSIG, protocol.TypeNSEC}
	a := []uint16{protocol.TypeA, protocol.TypeRRSIG, protocol.TypeNSEC}
	wild := nsec("*.example.com.", "w.example.com.", a...)
	wy := nsec("w.example.com.", "y.example.com.", a...)
	ok := true
	run := func(name, q string, qtype uint16, want ValidationResult, rrs ...*protocol.ResourceRecord) {
		m := negMsg(protocol.RcodeSuccess, q, auth(rrs...))
		m.Questions[0].QType = qtype
		for i := 0; i < 3; i++ {
			if got := f.v.validateNegativeResponse(m, q, f.chain); got != want {
				fmt.Printf("%s: EXPECTED %v | ACTUAL %v\n", name, want, got)
				ok = false
				return
			}
		}
	}
	run("cover only (wildcard answer erased)", "x.example.com.", protocol.TypeA, ValidationBogus, wy)
	run("wildcard NSEC has qtype", "x.example.com.", protocol.TypeA, ValidationBogus, wy, wild)
	run("wildcard NODATA honest", "x.example.com.", protocol.TypeAAAA, ValidationSecure, wy, wild)
	run("exact NODATA", "w.example.com.", protocol.TypeAAAA, ValidationSecure, wy)
	run("exact NSEC has qtype", "w.example.com.", protocol.TypeA, ValidationBogus, wy)
	// Edge: empty non-terminal NODATA (only a.sub.example.com exists).
	run("ENT NODATA", "sub.example.com.", protocol.TypeA, ValidationSecure, nsec("example.com.", "a.sub.example.com.", soa...))
	// Edge: wildcard NSEC at a shallower level than the CE does not count.
	// Zone: example, *.example, y, z; x.y.example.com: CE y.example.com.
	run("wildcard at wrong CE", "x.y.example.com.", protocol.TypeAAAA, ValidationBogus,
		nsec("y.example.com.", "z.example.com.", a...), nsec("*.example.com.", "y.example.com.", a...))
	if !ok {
		t.Fatal("regression: see output above")
	}
}
