// Regression tests for F407 (non-root trust anchor: chain building asked for
// DS/DNSKEY at names relative to the anchor) and F408 (one per-response
// budget of signature verifications and NSEC3 hashes across chain building
// and message validation).

package dnssec

// Fixtures: an honest signed root, an attacker-controlled signed zone
// "attack." and a legitimate root -> example. -> sub.example. chain in the
// middle of a KSK + ZSK rollover, all served from a mockResolver map.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

type rbKey struct {
	sk  *SigningKey
	rr  *protocol.ResourceRecord
	tag uint16
}

func rbNewKey(t *testing.T, zone string, ksk bool) *rbKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := packECDSAPublicKey(&PublicKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: &priv.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	flags := uint16(protocol.DNSKEYFlagZone)
	if ksk {
		flags |= protocol.DNSKEYFlagSEP
	}
	dk := &protocol.RDataDNSKEY{Flags: flags, Protocol: 3, Algorithm: protocol.AlgorithmECDSAP256SHA256, PublicKey: pub}
	tag := protocol.CalculateKeyTag(dk.Flags, dk.Algorithm, dk.PublicKey)
	n, _ := protocol.ParseName(zone)
	return &rbKey{
		sk:  &SigningKey{PrivateKey: &PrivateKey{Algorithm: dk.Algorithm, Key: priv}, DNSKEY: dk, KeyTag: tag, IsKSK: ksk},
		rr:  &protocol.ResourceRecord{Name: n, Type: protocol.TypeDNSKEY, Class: protocol.ClassIN, TTL: 300, Data: dk},
		tag: tag,
	}
}

func rbSign(t *testing.T, zone string, k *rbKey, rrs []*protocol.ResourceRecord) *protocol.ResourceRecord {
	t.Helper()
	now := uint32(time.Now().Unix())
	sig, err := NewSigner(zone, DefaultSignerConfig()).SignRRSet(rrs, k.sk, now-3600, now+3600)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// rbJunk returns n RRSIGs over rrs that carry k's key tag, algorithm,
// correct Labels and validity window but a (well-formed) signature over
// other data: each forces one full signature verification that fails.
func rbJunk(t *testing.T, zone string, k *rbKey, rrs []*protocol.ResourceRecord, n int) []*protocol.ResourceRecord {
	t.Helper()
	other := []*protocol.ResourceRecord{rbA(t, "junk."+strings.TrimPrefix(zone, "."), "192.0.2.250")}
	donor := rbSign(t, zone, k, other).Data.(*protocol.RDataRRSIG)
	good := rbSign(t, zone, k, rrs)
	var out []*protocol.ResourceRecord
	for i := 0; i < n; i++ {
		c := *good.Data.(*protocol.RDataRRSIG)
		c.Signature = append([]byte(nil), donor.Signature...)
		c.Signature[0] ^= byte(i + 1)
		out = append(out, &protocol.ResourceRecord{Name: good.Name.Copy(), Type: protocol.TypeRRSIG, Class: protocol.ClassIN, TTL: 300, Data: &c})
	}
	return out
}

func rbA(t *testing.T, owner, ip string) *protocol.ResourceRecord {
	t.Helper()
	rr, err := protocol.NewResourceRecord(owner, protocol.TypeA, protocol.ClassIN, 300, protocol.ParseRDataText("A", ip))
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

func rbDS(t *testing.T, child string, k *rbKey) *protocol.ResourceRecord {
	t.Helper()
	n, _ := protocol.ParseName(child)
	return &protocol.ResourceRecord{Name: n, Type: protocol.TypeDS, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataDS{
		KeyTag: k.tag, Algorithm: k.sk.DNSKEY.Algorithm, DigestType: 2, Digest: calculateDSDigestFromDNSKEY(child, k.sk.DNSKEY, 2)}}
}

func rbMsg(rcode uint8, ans, auth []*protocol.ResourceRecord) *protocol.Message {
	return &protocol.Message{Header: protocol.Header{Flags: protocol.NewResponseFlags(rcode)}, Answers: ans, Authorities: auth}
}

func rbKey2(name string, qtype uint16) string { return name + "|" + strconv.Itoa(int(qtype)) }

type rbWorld struct {
	v    *Validator
	mock *mockResolver
	root *rbKey
	atk  *rbKey // attacker zone key (KSK, signs everything)
}

// rbNewWorld: honest root (anchor) delegating securely to attack.
// attackDNSKEYJunk junk RRSIGs precede the valid one on attack.'s DNSKEY RRset.
func rbNewWorld(t *testing.T, attackDNSKEYJunk int) *rbWorld {
	t.Helper()
	w := &rbWorld{mock: &mockResolver{responses: map[string]*protocol.Message{}}}
	w.root = rbNewKey(t, ".", true)
	w.atk = rbNewKey(t, "attack.", true)
	w.mock.responses[rbKey2(".", protocol.TypeDNSKEY)] = rbMsg(0, []*protocol.ResourceRecord{w.root.rr, rbSign(t, ".", w.root, []*protocol.ResourceRecord{w.root.rr})}, nil)
	ds := rbDS(t, "attack.", w.atk)
	w.mock.responses[rbKey2("attack.", protocol.TypeDS)] = rbMsg(0, []*protocol.ResourceRecord{ds, rbSign(t, ".", w.root, []*protocol.ResourceRecord{ds})}, nil)
	keys := []*protocol.ResourceRecord{w.atk.rr}
	ans := append([]*protocol.ResourceRecord{w.atk.rr}, rbJunk(t, "attack.", w.atk, keys, attackDNSKEYJunk)...)
	w.mock.responses[rbKey2("attack.", protocol.TypeDNSKEY)] = rbMsg(0, append(ans, rbSign(t, "attack.", w.atk, keys)), nil)
	w.v = rbValidator(w.mock, ".", w.root)
	return w
}

func rbValidator(mock *mockResolver, zone string, k *rbKey) *Validator {
	store := NewTrustAnchorStore()
	store.AddAnchor(&TrustAnchor{Zone: zone, KeyTag: k.tag, Algorithm: k.sk.DNSKEY.Algorithm, DigestType: 2,
		Digest: calculateDSDigestFromDNSKEY(zone, k.sk.DNSKEY, 2), ValidFrom: time.Now().Add(-time.Hour)})
	cfg := DefaultValidatorConfig()
	cfg.ValidationCacheTTL = 0
	return NewValidator(cfg, store, mock)
}

// rbAnswerFlood: 32 Answer RRsets in attack., each carrying 7 junk RRSIGs
// before its valid one; DNSKEY RRset likewise. Secure ⇒ every junk RRSIG was
// verified (anyRRSIGValidates stops at the first success).
func rbAnswerFlood(t *testing.T) (*Validator, *protocol.Message, string) {
	w := rbNewWorld(t, 7)
	var ans []*protocol.ResourceRecord
	for i := 0; i < maxRRsetsValidated; i++ {
		a := rbA(t, fmt.Sprintf("o%d.attack.", i), "192.0.2.1")
		set := []*protocol.ResourceRecord{a}
		ans = append(ans, a)
		ans = append(ans, rbJunk(t, "attack.", w.atk, set, 7)...)
		ans = append(ans, rbSign(t, "attack.", w.atk, set))
	}
	return w.v, rbMsg(0, ans, nil), "o0.attack."
}

// rbDeepInsecureFan: qname www.attack. (signed) plus `owners` unsigned
// RRsets whose owners sit `depth` labels below nN.attack.; every label on the
// way is proven "not a zone cut" by a signed NSEC3 (150 iterations) and the
// owner itself is proven an unsigned delegation. Each owner's chain is built
// separately (chainFor), so the work grows with owners × depth and the
// response still validates (Insecure).
func rbDeepInsecureFan(t *testing.T, owners, depth int) (*Validator, *protocol.Message, string) {
	w := rbNewWorld(t, 0)
	salt := []byte{0xaa, 0xbb}
	const iter = 150
	www := rbA(t, "www.attack.", "192.0.2.1")
	ans := []*protocol.ResourceRecord{www, rbSign(t, "attack.", w.atk, []*protocol.ResourceRecord{www})}
	for n := 0; n < owners; n++ {
		owner := "x." + strings.Repeat("a.", depth) + fmt.Sprintf("n%d.attack.", n)
		ans = append(ans, rbA(t, owner, "198.51.100.1"))
		labels := splitLabels(owner)
		for i := len(labels) - 2; i >= 0; i-- { // suffixes below attack.
			name := joinLabels(labels[i:])
			h, err := NSEC3Hash(name, 1, iter, salt)
			if err != nil {
				t.Fatal(err)
			}
			next := append([]byte(nil), h...)
			next[len(next)-1]++
			types := []uint16{protocol.TypeA, protocol.TypeRRSIG}
			if i == 0 {
				types = []uint16{protocol.TypeNS}
			}
			on, _ := protocol.ParseName(strings.ToLower(protocol.Base32Encode(h)) + ".attack.")
			rr := &protocol.ResourceRecord{Name: on, Type: protocol.TypeNSEC3, Class: protocol.ClassIN, TTL: 300,
				Data: &protocol.RDataNSEC3{HashAlgorithm: 1, Iterations: iter, Salt: salt, HashLength: 20, NextHashed: next, TypeBitMap: types}}
			w.mock.responses[rbKey2(name, protocol.TypeDS)] = rbMsg(0, nil,
				[]*protocol.ResourceRecord{rr, rbSign(t, "attack.", w.atk, []*protocol.ResourceRecord{rr})})
		}
	}
	return w.v, rbMsg(0, ans, nil), "www.attack."
}

// rbLegitRollover: root → example. → sub.example., each child mid KSK
// rollover (double-signed DNSKEY RRset, DS for the old KSK only, the new
// KSK's RRSIG listed first) and ZSK rollover (both ZSKs published, data
// double-signed with the new ZSK's RRSIG first). 10 Answer RRsets.
func rbLegitRollover(t *testing.T) (*Validator, *protocol.Message, string) {
	mock := &mockResolver{responses: map[string]*protocol.Message{}}
	root := rbNewKey(t, ".", true)
	mock.responses[rbKey2(".", protocol.TypeDNSKEY)] = rbMsg(0, []*protocol.ResourceRecord{root.rr, rbSign(t, ".", root, []*protocol.ResourceRecord{root.rr})}, nil)
	parentZSKs := []*rbKey{root}
	var zsksOf []*rbKey
	for _, zone := range []string{"example.", "sub.example."} {
		oldKSK, newKSK := rbNewKey(t, zone, true), rbNewKey(t, zone, true)
		oldZSK, newZSK := rbNewKey(t, zone, false), rbNewKey(t, zone, false)
		keys := []*protocol.ResourceRecord{oldKSK.rr, newKSK.rr, oldZSK.rr, newZSK.rr}
		mock.responses[rbKey2(zone, protocol.TypeDNSKEY)] = rbMsg(0, append(append([]*protocol.ResourceRecord(nil), keys...),
			rbSign(t, zone, newKSK, keys), rbSign(t, zone, oldKSK, keys)), nil)
		ds := rbDS(t, zone, oldKSK)
		parentZone := "."
		if zone == "sub.example." {
			parentZone = "example."
		}
		dsAns := []*protocol.ResourceRecord{ds}
		for i := len(parentZSKs) - 1; i >= 0; i-- {
			dsAns = append(dsAns, rbSign(t, parentZone, parentZSKs[i], []*protocol.ResourceRecord{ds}))
		}
		mock.responses[rbKey2(zone, protocol.TypeDS)] = rbMsg(0, dsAns, nil)
		parentZSKs = []*rbKey{oldZSK, newZSK}
		zsksOf = parentZSKs
	}
	var ans []*protocol.ResourceRecord
	for i := 0; i < 10; i++ {
		a := rbA(t, fmt.Sprintf("h%d.sub.example.", i), "192.0.2.10")
		set := []*protocol.ResourceRecord{a}
		ans = append(ans, a, rbSign(t, "sub.example.", zsksOf[1], set), rbSign(t, "sub.example.", zsksOf[0], set))
	}
	return rbValidator(mock, ".", root), rbMsg(0, ans, nil), "h0.sub.example."
}

// rbLogResolver records every query the validator issues.
type rbLogResolver struct {
	inner Resolver
	mu    sync.Mutex
	log   []string
}

func (r *rbLogResolver) Query(ctx context.Context, name string, qtype uint16) (*protocol.Message, error) {
	r.mu.Lock()
	r.log = append(r.log, protocol.TypeString(qtype)+" "+name)
	r.mu.Unlock()
	return r.inner.Query(ctx, name, qtype)
}

// F407: below a non-root trust anchor (example.com.) the child zones are
// secure.example.com. / insecure.example.com.; buildChain used to ask for DS
// at "secure." / "insecure." and returned Bogus for both.
func TestBuildChain_NonRootAnchorUsesAbsoluteChildNames_F407(t *testing.T) {
	mock := &mockResolver{responses: map[string]*protocol.Message{}}
	parent := rbNewKey(t, "example.com.", true)
	child := rbNewKey(t, "secure.example.com.", true)
	mock.responses[rbKey2("example.com.", protocol.TypeDNSKEY)] = rbMsg(0, []*protocol.ResourceRecord{parent.rr, rbSign(t, "example.com.", parent, []*protocol.ResourceRecord{parent.rr})}, nil)
	ds := rbDS(t, "secure.example.com.", child)
	mock.responses[rbKey2("secure.example.com.", protocol.TypeDS)] = rbMsg(0, []*protocol.ResourceRecord{ds, rbSign(t, "example.com.", parent, []*protocol.ResourceRecord{ds})}, nil)
	mock.responses[rbKey2("secure.example.com.", protocol.TypeDNSKEY)] = rbMsg(0, []*protocol.ResourceRecord{child.rr, rbSign(t, "secure.example.com.", child, []*protocol.ResourceRecord{child.rr})}, nil)
	insecureName, _ := protocol.ParseName("insecure.example.com.")
	nextName, _ := protocol.ParseName("secure.example.com.")
	nsec := &protocol.ResourceRecord{Name: insecureName, Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataNSEC{NextDomain: nextName, TypeBitMap: []uint16{protocol.TypeNS, protocol.TypeRRSIG, protocol.TypeNSEC}}}
	mock.responses[rbKey2("insecure.example.com.", protocol.TypeDS)] = rbMsg(0, nil, []*protocol.ResourceRecord{nsec, rbSign(t, "example.com.", parent, []*protocol.ResourceRecord{nsec})})

	v := rbValidator(mock, "example.com.", parent)
	lr := &rbLogResolver{inner: mock}
	v.resolver = lr
	ctx := context.Background()

	a := rbA(t, "www.secure.example.com.", "192.0.2.20")
	res, err := v.ValidateResponse(ctx, rbMsg(0, []*protocol.ResourceRecord{a, rbSign(t, "secure.example.com.", child, []*protocol.ResourceRecord{a})}, nil), "www.secure.example.com.")
	if res != ValidationSecure {
		t.Errorf("signed answer in secure child: %v (%v), want SECURE", res, err)
	}
	res, err = v.ValidateResponse(ctx, rbMsg(0, []*protocol.ResourceRecord{rbA(t, "www.insecure.example.com.", "198.51.100.1")}, nil), "www.insecure.example.com.")
	if res != ValidationInsecure {
		t.Errorf("unsigned answer below insecure delegation: %v (%v), want INSECURE", res, err)
	}
	res, err = v.ValidateResponse(ctx, rbMsg(0, []*protocol.ResourceRecord{rbA(t, "www.secure.example.com.", "203.0.113.66")}, nil), "www.secure.example.com.")
	if res != ValidationBogus {
		t.Errorf("stripped RRSIG below secure child: %v (%v), want BOGUS", res, err)
	}
	for _, q := range lr.log {
		if strings.HasPrefix(q, "DS ") && !strings.HasSuffix(q, ".example.com.") {
			t.Errorf("DS query at a name relative to the anchor: %q", q)
		}
	}
}

// F408: the per-RRset/per-section caps multiplied across 32 RRsets, their
// separate chains and per-label denial proofs. One budget now covers the
// whole response and exceeding it is Bogus.
func TestValidateResponse_PerResponseWorkBudget_F408(t *testing.T) {
	ctx := context.Background()

	v, m, q := rbAnswerFlood(t) // needs 8 + 32x8 = 264 verifications
	b := newResponseBudget()
	res, err := v.validateResponseBudget(ctx, m, q, b)
	if res != ValidationBogus || !errors.Is(err, errWorkBudgetExceeded) || b.sigs != maxSigVerificationsPerResponse {
		t.Errorf("answer flood: %v err=%v sigs=%d, want BOGUS / budget exceeded / %d", res, err, b.sigs, maxSigVerificationsPerResponse)
	}

	v, m, q = rbDeepInsecureFan(t, 8, 40) // 8 owners x 42-label walks
	b = &responseBudget{sigLimit: 1 << 30, hashLimit: 1 << 30}
	if res, err = v.validateResponseBudget(ctx, m, q, b); res != ValidationInsecure || err != nil {
		t.Fatalf("deep fan with unlimited budget: %v (%v), want INSECURE", res, err)
	}
	if b.sigs <= maxSigVerificationsPerResponse || b.hashes == 0 {
		t.Fatalf("deep fan must exceed the signature budget unbounded: sigs=%d hashes=%d", b.sigs, b.hashes)
	}
	if res, err = v.ValidateResponse(ctx, m, q); res != ValidationBogus || !errors.Is(err, errWorkBudgetExceeded) {
		t.Errorf("deep fan with default budget: %v (%v), want BOGUS / budget exceeded", res, err)
	}
	b = &responseBudget{sigLimit: 1 << 30, hashLimit: 10}
	if res, err = v.validateResponseBudget(ctx, m, q, b); res != ValidationBogus || !errors.Is(err, errWorkBudgetExceeded) || b.hashes != 10 {
		t.Errorf("hash budget alone: %v (%v) hashes=%d, want BOGUS / budget exceeded / 10", res, err, b.hashes)
	}

	// Legitimate: 10 RRsets behind root -> example. -> sub.example. in the
	// middle of a KSK + ZSK rollover.
	v, m, q = rbLegitRollover(t)
	b = newResponseBudget()
	if res, err = v.validateResponseBudget(ctx, m, q, b); res != ValidationSecure || err != nil {
		t.Fatalf("legit rollover response: %v (%v), want SECURE", res, err)
	}
	need := b.sigs
	if res, _ = v.validateResponseBudget(ctx, m, q, &responseBudget{sigLimit: need, hashLimit: 1}); res != ValidationSecure {
		t.Errorf("budget == need (%d): %v, want SECURE", need, res)
	}
	if res, _ = v.validateResponseBudget(ctx, m, q, &responseBudget{sigLimit: need - 1, hashLimit: 1}); res != ValidationBogus {
		t.Errorf("budget == need-1: %v, want BOGUS", res)
	}

	// The budget is per call: concurrent calls on the shared Validator each
	// get a fresh allowance (run with -race).
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]ValidationResult, 2*maxSigVerificationsPerResponse/need+2)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], _ = v.ValidateResponse(ctx, m, q)
		}(i)
	}
	close(start)
	wg.Wait()
	for i, r := range results {
		if r != ValidationSecure {
			t.Errorf("concurrent call %d: %v, want SECURE", i, r)
		}
	}
}
