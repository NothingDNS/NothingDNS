package dnssec

import (
	"context"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// This suite closes the denial-proof coverage gaps in validator.go using
// REAL signed fixtures: chain_regression_test.go's newTestZoneKeys/sign
// helpers generate an ECDSA ZSK, sign NSEC/NSEC3 RRsets, and
// authenticatedDenialRRs/verifyDSDenial verify those signatures. The
// pre-existing tests covered only the unsigned/rejection paths (and
// noted the signed-fixture follow-up in a comment).

// denialFixture bundles a signed-zone setup for denial tests.
type denialFixture struct {
	v     *Validator
	keys  *testZoneKeys
	chain []*chainLink // one authenticated link: example.com. with its DNSKEY
}

func newDenialFixture(t *testing.T) *denialFixture {
	t.Helper()
	keys := newTestZoneKeys(t, "example.com.")
	link := &chainLink{
		zone:      "example.com.",
		dnsKeys:   []*protocol.ResourceRecord{keys.keyRR},
		validated: true,
	}
	return &denialFixture{
		v:     NewValidator(DefaultValidatorConfig(), nil, nil),
		keys:  keys,
		chain: []*chainLink{link},
	}
}

// signDenialSet signs one NSEC/NSEC3 RRset and returns (rrset, rrsigRR).
func (f *denialFixture) signDenialSet(t *testing.T, rrs []*protocol.ResourceRecord) ([]*protocol.ResourceRecord, *protocol.ResourceRecord) {
	t.Helper()
	rrsig := f.keys.sign(t, "example.com.", rrs)
	return rrs, rrsig
}

func negMsg(rcode uint8, qname string, authorities []*protocol.ResourceRecord) *protocol.Message {
	qn, _ := protocol.ParseName(qname)
	return &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(rcode)},
		Questions: []*protocol.Question{
			{Name: qn, QType: protocol.TypeA, QClass: protocol.ClassIN},
		},
		Authorities: authorities,
	}
}

// ---------------------------------------------------------------------------
// validateNegativeResponse — signed success paths
// ---------------------------------------------------------------------------

// NODATA: a signed NSEC owned by the query name with the qtype absent
// from its bitmap proves NoData (RFC 4035 §3.1.3.1) → Secure.
func TestValidateNegativeResponse_SignedNODATA(t *testing.T) {
	f := newDenialFixture(t)
	owner, _ := protocol.ParseName("www.example.com.")
	nsec := &protocol.ResourceRecord{
		Name:  owner,
		Type:  protocol.TypeNSEC,
		Class: protocol.ClassIN,
		TTL:   300,
		Data: &protocol.RDataNSEC{
			NextDomain: mustName(t, "www.example.com."),
			TypeBitMap: []uint16{protocol.TypeNS, protocol.TypeRRSIG}, // A absent
		},
	}
	rrset, rrsig := f.signDenialSet(t, []*protocol.ResourceRecord{nsec})
	msg := negMsg(protocol.RcodeSuccess, "www.example.com.", append(rrset, rrsig))
	if got := f.v.validateNegativeResponse(msg, "www.example.com.", f.chain); got != ValidationSecure {
		t.Errorf("signed NODATA denial = %v, want Secure", got)
	}
}

// NXDOMAIN via NSEC: name-cover + wildcard-cover from two distinct signed
// owners → Secure (RFC 4035 §5.4 two-proof requirement).
func TestValidateNegativeResponse_SignedNXDOMAINTwoNSEC(t *testing.T) {
	f := newDenialFixture(t)
	// Covers b.example.com. (a < b < c).
	nsecA := &protocol.ResourceRecord{
		Name: mustName(t, "a.example.com."), Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataNSEC{NextDomain: mustName(t, "c.example.com."), TypeBitMap: []uint16{protocol.TypeRRSIG}},
	}
	// Covers *.example.com.: canonical order puts the parent zone name
	// (example.com.) before its children, and "*" sorts before letters,
	// so [example.com., a.example.com.) contains *.example.com.
	nsecW := &protocol.ResourceRecord{
		Name: mustName(t, "example.com."), Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataNSEC{NextDomain: mustName(t, "a.example.com."), TypeBitMap: []uint16{protocol.TypeSOA, protocol.TypeRRSIG}},
	}
	setA, sigA := f.signDenialSet(t, []*protocol.ResourceRecord{nsecA})
	setW, sigW := f.signDenialSet(t, []*protocol.ResourceRecord{nsecW})
	auth := append(append(setA, sigA), append(setW, sigW)...)
	msg := negMsg(protocol.RcodeNameError, "b.example.com.", auth)
	if got := f.v.validateNegativeResponse(msg, "b.example.com.", f.chain); got != ValidationSecure {
		t.Errorf("signed two-NSEC NXDOMAIN = %v, want Secure", got)
	}
}

// NXDOMAIN with a validly-SIGNED single NSEC (name-cover only, no
// wildcard-cover) must still be Bogus — a good signature does not relax
// the two-proof rule.
func TestValidateNegativeResponse_SignedSingleNSECStillBogus(t *testing.T) {
	f := newDenialFixture(t)
	nsecA := &protocol.ResourceRecord{
		Name: mustName(t, "a.example.com."), Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataNSEC{NextDomain: mustName(t, "c.example.com."), TypeBitMap: []uint16{protocol.TypeRRSIG}},
	}
	setA, sigA := f.signDenialSet(t, []*protocol.ResourceRecord{nsecA})
	msg := negMsg(protocol.RcodeNameError, "b.example.com.", append(setA, sigA))
	if got := f.v.validateNegativeResponse(msg, "b.example.com.", f.chain); got != ValidationBogus {
		t.Errorf("signed single-NSEC NXDOMAIN = %v, want Bogus", got)
	}
}

// NXDOMAIN via NSEC3 closest-encloser proof (RFC 5155 §8.4): CE exact
// match + next-closer cover + wildcard cover, all signed → Secure.
// Ranges are TIGHT (H±1) so each cover proves exactly one hash —
// degenerate owner==next records would cover everything and make the
// negative cases below meaningless.
func TestValidateNegativeResponse_SignedNSEC3ClosestEncloser(t *testing.T) {
	f := newDenialFixture(t)
	hashRaw := func(name string) []byte {
		raw, err := NSEC3Hash(name, 1, 0, nil)
		if err != nil {
			t.Fatalf("NSEC3Hash(%q): %v", name, err)
		}
		return raw
	}
	mkNSEC3 := func(ownerHash, nextHash []byte) *protocol.ResourceRecord {
		return &protocol.ResourceRecord{
			Name: mustName(t, strings.ToUpper(protocol.Base32Encode(ownerHash))+".example.com."),
			Type: protocol.TypeNSEC3, Class: protocol.ClassIN, TTL: 300,
			Data: &protocol.RDataNSEC3{
				HashAlgorithm: 1, Iterations: 0, Salt: nil,
				HashLength: uint8(len(nextHash)), NextHashed: nextHash,
			},
		}
	}
	tight := func(raw []byte) []byte { // raw+1
		n := make([]byte, len(raw))
		copy(n, raw)
		n[len(n)-1]++
		return n
	}
	before := func(raw []byte) []byte { // raw-1
		n := make([]byte, len(raw))
		copy(n, raw)
		n[len(n)-1]--
		return n
	}
	// CE: owner == H(example.com.), next == H+1 → exact match only.
	ceRR := mkNSEC3(hashRaw("example.com."), tight(hashRaw("example.com.")))
	// Covers: [H(x)-1, H(x)+1) → proves exactly H(x).
	ncRR := mkNSEC3(before(hashRaw("nx.example.com")), tight(hashRaw("nx.example.com")))
	wcRR := mkNSEC3(before(hashRaw("*.example.com")), tight(hashRaw("*.example.com")))

	var auth []*protocol.ResourceRecord
	for _, rr := range []*protocol.ResourceRecord{ceRR, ncRR, wcRR} {
		set, sig := f.signDenialSet(t, []*protocol.ResourceRecord{rr})
		auth = append(auth, set...)
		auth = append(auth, sig)
	}
	msg := negMsg(protocol.RcodeNameError, "nx.example.com.", auth)
	if got := f.v.validateNegativeResponse(msg, "nx.example.com.", f.chain); got != ValidationSecure {
		t.Errorf("signed NSEC3 closest-encloser NXDOMAIN = %v, want Secure", got)
	}
}

// NXDOMAIN where the ONLY authenticated records are NSEC3s that fail the
// closest-encloser proof: must be Bogus with no fallback to the NSEC path
// (mix-and-match guard). A TIGHT CE match is present (exact-match only,
// next = H+1), but no record covers the next-closer hash.
func TestValidateNegativeResponse_NSEC3ProofFailureNoFallback(t *testing.T) {
	f := newDenialFixture(t)
	ceRaw, err := NSEC3Hash("example.com.", 1, 0, nil)
	if err != nil {
		t.Fatalf("NSEC3Hash: %v", err)
	}
	ceNext := make([]byte, len(ceRaw))
	copy(ceNext, ceRaw)
	ceNext[len(ceNext)-1]++ // tight: proves CE match, covers nothing else
	ceRR := &protocol.ResourceRecord{
		Name: mustName(t, strings.ToUpper(protocol.Base32Encode(ceRaw))+".example.com."),
		Type: protocol.TypeNSEC3, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataNSEC3{
			HashAlgorithm: 1, Iterations: 0, Salt: nil,
			HashLength: uint8(len(ceNext)), NextHashed: ceNext,
		},
	}
	set, sig := f.signDenialSet(t, []*protocol.ResourceRecord{ceRR})
	msg := negMsg(protocol.RcodeNameError, "nx.example.com.", append(set, sig))
	if got := f.v.validateNegativeResponse(msg, "nx.example.com.", f.chain); got != ValidationBogus {
		t.Errorf("failed NSEC3 closest-encloser with no NSEC fallback = %v, want Bogus", got)
	}
}

// ---------------------------------------------------------------------------
// validateNSEC3ClosestEncloser — three-part proof
// ---------------------------------------------------------------------------

func TestValidateNSEC3ClosestEncloser_FullProofAndGaps(t *testing.T) {
	v := NewValidator(DefaultValidatorConfig(), nil, nil)
	hashRaw := func(name string) []byte {
		raw, err := NSEC3Hash(name, 1, 0, nil)
		if err != nil {
			t.Fatalf("NSEC3Hash(%q): %v", name, err)
		}
		return raw
	}
	// Tight ranges so each record proves exactly one fact:
	// CE = exact match at H(example.com.); nc/wc = single-hash covers.
	tight := func(raw []byte) []byte {
		n := make([]byte, len(raw))
		copy(n, raw)
		n[len(n)-1]++
		return n
	}
	before := func(raw []byte) []byte {
		n := make([]byte, len(raw))
		copy(n, raw)
		n[len(n)-1]--
		return n
	}
	mkNSEC3 := func(ownerHash, nextHash []byte) *protocol.ResourceRecord {
		return &protocol.ResourceRecord{
			Name: mustName(t, strings.ToUpper(protocol.Base32Encode(ownerHash))+".example.com."),
			Type: protocol.TypeNSEC3, Class: protocol.ClassIN,
			Data: &protocol.RDataNSEC3{
				HashAlgorithm: 1, Iterations: 0, Salt: nil,
				HashLength: uint8(len(nextHash)), NextHashed: nextHash,
			},
		}
	}
	qname := "nx.example.com."
	ce := mkNSEC3(hashRaw("example.com."), tight(hashRaw("example.com.")))
	nc := mkNSEC3(before(hashRaw("nx.example.com")), tight(hashRaw("nx.example.com")))
	wc := mkNSEC3(before(hashRaw("*.example.com")), tight(hashRaw("*.example.com")))

	if !v.validateNSEC3ClosestEncloser(qname, []*protocol.ResourceRecord{ce, nc, wc}) {
		t.Error("full three-part NSEC3 proof (CE + next-closer + wildcard) should succeed")
	}
	if v.validateNSEC3ClosestEncloser(qname, []*protocol.ResourceRecord{ce, nc}) {
		t.Error("proof without wildcard cover must fail for NXDOMAIN")
	}
	if v.validateNSEC3ClosestEncloser(qname, []*protocol.ResourceRecord{ce, wc}) {
		t.Error("proof without next-closer cover must fail")
	}
	if v.validateNSEC3ClosestEncloser(qname, []*protocol.ResourceRecord{nc, wc}) {
		t.Error("proof without closest-encloser match must fail")
	}
}

// ---------------------------------------------------------------------------
// verifyDSDenial
// ---------------------------------------------------------------------------

func TestVerifyDSDenial_SignedNSECProvesInsecureDelegation(t *testing.T) {
	f := newDenialFixture(t)
	// NSEC at the delegation name with NS set, DS/SOA clear.
	nsec := &protocol.ResourceRecord{
		Name: mustName(t, "child.example.com."), Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataNSEC{
			NextDomain: mustName(t, "d.child.example.com."),
			TypeBitMap: []uint16{protocol.TypeNS, protocol.TypeRRSIG},
		},
	}
	set, sig := f.signDenialSet(t, []*protocol.ResourceRecord{nsec})
	msg := negMsg(protocol.RcodeSuccess, "child.example.com.", append(set, sig))
	if !f.v.verifyDSDenial(msg, "child.example.com.", f.chain) {
		t.Error("signed delegation NSEC (NS set, DS/SOA clear) should verify DS denial")
	}
}

func TestVerifyDSDenial_ApexReplayRejected(t *testing.T) {
	f := newDenialFixture(t)
	// Same owner, but SOA set → zone-apex replay must be rejected.
	nsec := &protocol.ResourceRecord{
		Name: mustName(t, "child.example.com."), Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataNSEC{
			NextDomain: mustName(t, "d.child.example.com."),
			TypeBitMap: []uint16{protocol.TypeNS, protocol.TypeSOA, protocol.TypeRRSIG},
		},
	}
	set, sig := f.signDenialSet(t, []*protocol.ResourceRecord{nsec})
	msg := negMsg(protocol.RcodeSuccess, "child.example.com.", append(set, sig))
	if f.v.verifyDSDenial(msg, "child.example.com.", f.chain) {
		t.Error("NSEC with SOA set must not prove insecure delegation (apex replay)")
	}
}

func TestVerifyDSDenial_UnsignedRejected(t *testing.T) {
	f := newDenialFixture(t)
	nsec := &protocol.ResourceRecord{
		Name: mustName(t, "child.example.com."), Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataNSEC{
			NextDomain: mustName(t, "d.child.example.com."),
			TypeBitMap: []uint16{protocol.TypeNS, protocol.TypeRRSIG},
		},
	}
	msg := negMsg(protocol.RcodeSuccess, "child.example.com.", []*protocol.ResourceRecord{nsec})
	if f.v.verifyDSDenial(msg, "child.example.com.", f.chain) {
		t.Error("unsigned NSEC must never verify DS denial")
	}
}

func TestVerifyDSDenial_SignedNSEC3ProvesInsecureDelegation(t *testing.T) {
	f := newDenialFixture(t)
	raw, err := NSEC3Hash("child.example.com.", 1, 0, nil)
	if err != nil {
		t.Fatalf("NSEC3Hash: %v", err)
	}
	nsec3 := &protocol.ResourceRecord{
		Name: mustName(t, strings.ToUpper(protocol.Base32Encode(raw))+".example.com."),
		Type: protocol.TypeNSEC3, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataNSEC3{
			HashAlgorithm: 1, Iterations: 0, Salt: nil,
			HashLength: uint8(len(raw)), NextHashed: raw,
			TypeBitMap: []uint16{protocol.TypeNS, protocol.TypeRRSIG},
		},
	}
	set, sig := f.signDenialSet(t, []*protocol.ResourceRecord{nsec3})
	msg := negMsg(protocol.RcodeSuccess, "child.example.com.", append(set, sig))
	if !f.v.verifyDSDenial(msg, "child.example.com.", f.chain) {
		t.Error("signed matching NSEC3 (NS set, DS/SOA clear) should verify DS denial")
	}
}

func TestVerifyDSDenial_GuardClauses(t *testing.T) {
	f := newDenialFixture(t)
	if f.v.verifyDSDenial(nil, "child.example.com.", f.chain) {
		t.Error("nil msg must fail")
	}
	if f.v.verifyDSDenial(negMsg(0, "child.example.com.", nil), "child.example.com.", nil) {
		t.Error("empty chain must fail")
	}
	emptyKeys := []*chainLink{{zone: "example.com.", dnsKeys: nil, validated: true}}
	if f.v.verifyDSDenial(negMsg(0, "child.example.com.", nil), "child.example.com.", emptyKeys) {
		t.Error("chain with no parent keys must fail")
	}
}

// ---------------------------------------------------------------------------
// fetchNSEC3PARAM
// ---------------------------------------------------------------------------

type nsec3paramStubResolver struct {
	msg *protocol.Message
	err error
}

func (r *nsec3paramStubResolver) Query(_ context.Context, _ string, _ uint16) (*protocol.Message, error) {
	return r.msg, r.err
}

func TestFetchNSEC3PARAM(t *testing.T) {
	param := &protocol.RDataNSEC3PARAM{HashAlgorithm: 1, Flags: 0, Iterations: 0, Salt: nil}
	paramRR := &protocol.ResourceRecord{
		Name: mustName(t, "example.com."), Type: protocol.TypeNSEC3PARAM, Class: protocol.ClassIN,
		Data: param,
	}
	okMsg := &protocol.Message{Answers: []*protocol.ResourceRecord{paramRR}}
	emptyMsg := &protocol.Message{}

	t.Run("nil resolver returns error", func(t *testing.T) {
		v := NewValidator(DefaultValidatorConfig(), nil, nil)
		if _, err := v.fetchNSEC3PARAM(context.Background(), "example.com."); err == nil {
			t.Error("expected error with nil resolver")
		}
	})
	t.Run("resolver error propagates", func(t *testing.T) {
		v := NewValidator(DefaultValidatorConfig(), nil, &nsec3paramStubResolver{err: context.DeadlineExceeded})
		if _, err := v.fetchNSEC3PARAM(context.Background(), "example.com."); err == nil {
			t.Error("expected resolver error to propagate")
		}
	})
	t.Run("returns first NSEC3PARAM", func(t *testing.T) {
		v := NewValidator(DefaultValidatorConfig(), nil, &nsec3paramStubResolver{msg: okMsg})
		got, err := v.fetchNSEC3PARAM(context.Background(), "example.com.")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != param {
			t.Errorf("returned param = %v, want the zone's NSEC3PARAM", got)
		}
	})
	t.Run("no NSEC3PARAM means zone is not NSEC3", func(t *testing.T) {
		v := NewValidator(DefaultValidatorConfig(), nil, &nsec3paramStubResolver{msg: emptyMsg})
		got, err := v.fetchNSEC3PARAM(context.Background(), "example.com.")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil param for zone without NSEC3, got %v", got)
		}
	})
}
