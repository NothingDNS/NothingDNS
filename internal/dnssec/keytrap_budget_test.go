package dnssec

// Regression tests for the KeyTrap-class work bounds (CVE-2023-50387,
// CVE-2023-50868): F392 per-RRset signature verification budget, F393
// denial RRset count checked before verification, F394 one authentication
// of the Authority denial per response, F395 Labels-anchored NSEC3 wildcard
// proof (no closest-encloser search).

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

type keytrapKey struct {
	priv   ed25519.PrivateKey
	dk     *protocol.RDataDNSKEY
	rr     *protocol.ResourceRecord
	tag    uint16
	zone   string
	signer *Signer
}

func newKeytrapKey(t *testing.T, zone string, flags uint16) *keytrapKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dk := &protocol.RDataDNSKEY{Flags: flags, Protocol: 3, Algorithm: protocol.AlgorithmED25519, PublicKey: append([]byte(nil), pub...)}
	return &keytrapKey{priv: priv, dk: dk, zone: zone, signer: NewSigner(zone, DefaultSignerConfig()),
		rr:  &protocol.ResourceRecord{Name: mustName(t, zone), Type: protocol.TypeDNSKEY, Class: protocol.ClassIN, TTL: 300, Data: dk},
		tag: protocol.CalculateKeyTag(dk.Flags, dk.Algorithm, dk.PublicKey)}
}

func (k *keytrapKey) sign(t *testing.T, rrs []*protocol.ResourceRecord) *protocol.ResourceRecord {
	t.Helper()
	now := uint32(time.Now().Unix())
	sk := &SigningKey{PrivateKey: &PrivateKey{Algorithm: protocol.AlgorithmED25519, Key: k.priv}, DNSKEY: k.dk, KeyTag: k.tag}
	rr, err := k.signer.SignRRSet(rrs, sk, now-3600, now+3600)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

func (k *keytrapKey) chain() []*chainLink {
	return []*chainLink{{zone: k.zone, dnsKeys: []*protocol.ResourceRecord{k.rr}, validated: true}}
}

// collidingKeys returns n distinct DNSKEYs sharing k's key tag and algorithm
// (+d/-d on two high-order bytes keeps the RFC 4034 Appendix B word sum).
func (k *keytrapKey) collidingKeys(t *testing.T, n int) []*protocol.ResourceRecord {
	t.Helper()
	seen := map[string]bool{string(k.dk.PublicKey): true}
	var out []*protocol.ResourceRecord
	for i := 0; i < 32 && len(out) < n; i += 2 {
		for j := i + 2; j < 32 && len(out) < n; j += 2 {
			for d := 1; d <= 8 && len(out) < n; d++ {
				pk := append([]byte(nil), k.dk.PublicKey...)
				if int(pk[i])+d > 255 || int(pk[j])-d < 0 {
					continue
				}
				pk[i] += byte(d)
				pk[j] -= byte(d)
				if seen[string(pk)] || protocol.CalculateKeyTag(k.dk.Flags, k.dk.Algorithm, pk) != k.tag {
					continue
				}
				seen[string(pk)] = true
				out = append(out, &protocol.ResourceRecord{Name: mustName(t, k.zone), Type: protocol.TypeDNSKEY, Class: protocol.ClassIN, TTL: 300,
					Data: &protocol.RDataDNSKEY{Flags: k.dk.Flags, Protocol: 3, Algorithm: k.dk.Algorithm, PublicKey: pk}})
			}
		}
	}
	if len(out) != n {
		t.Fatalf("built %d of %d colliding keys", len(out), n)
	}
	return out
}

// corruptRRSIGs returns n copies of sig (same key tag) with broken signatures.
func corruptRRSIGs(sig *protocol.ResourceRecord, n int) []*protocol.ResourceRecord {
	g := sig.Data.(*protocol.RDataRRSIG)
	var out []*protocol.ResourceRecord
	for i := 0; i < n; i++ {
		c := *g
		c.Signature = append([]byte(nil), g.Signature...)
		c.Signature[i%len(c.Signature)] ^= 0xa5
		c.Signature[(i+7)%len(c.Signature)] ^= 0x5a
		out = append(out, &protocol.ResourceRecord{Name: sig.Name, Type: protocol.TypeRRSIG, Class: protocol.ClassIN, TTL: sig.TTL, Data: &c})
	}
	return out
}

// F392: N same-tag DNSKEYs x M same-tag RRSIGs must not cost N*M
// verifications; the RRset fails once the per-RRset budget is spent, while a
// rollover zone (2 KSK + 2 ZSK, one colliding tag, stale double signature)
// still validates.
func TestKeyTrap_RRSIGVerificationBudget_F392(t *testing.T) {
	const zone = "example.com."
	v := NewValidator(DefaultValidatorConfig(), nil, nil)
	zsk := newKeytrapKey(t, zone, protocol.DNSKEYFlagZone)
	a := aRecord(t, "www.example.com.")
	good := zsk.sign(t, []*protocol.ResourceRecord{a})
	resp := func(sigs ...*protocol.ResourceRecord) *protocol.Message {
		return &protocol.Message{Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Answers: append([]*protocol.ResourceRecord{a}, sigs...)}
	}

	// Attack: the only verifying pair is last in both lists (64*64 attempts).
	keys := append(zsk.collidingKeys(t, 63), zsk.rr)
	attack := resp(append(corruptRRSIGs(good, 63), good)...)
	if got := v.validateMessage(context.Background(), attack, "www.example.com.", []*chainLink{{zone: zone, dnsKeys: keys, validated: true}}); got != ValidationBogus {
		t.Fatalf("64 same-tag DNSKEYs x 64 RRSIGs = %v, want BOGUS (verification budget)", got)
	}
	ksk := newKeytrapKey(t, zone, protocol.DNSKEYFlagZone|protocol.DNSKEYFlagSEP)
	keySet := []*protocol.ResourceRecord{ksk.rr, zsk.rr}
	kgood := ksk.sign(t, keySet)
	if v.verifyDNSKEYSelfSignature(keySet, append(corruptRRSIGs(kgood, 63), kgood), []*protocol.ResourceRecord{ksk.rr}) {
		t.Fatal("64 RRSIG(DNSKEY) accepted; want the self-signature budget to stop the scan")
	}

	// Boundary: exactly maxSigVerificationsPerRRset attempts still validate.
	atBudget := append(zsk.collidingKeys(t, maxSigVerificationsPerRRset-1), zsk.rr)
	if _, ok := v.anyRRSIGValidates([]*protocol.ResourceRecord{a}, []*protocol.RDataRRSIG{good.Data.(*protocol.RDataRRSIG)}, atBudget); !ok {
		t.Fatal("RRSIG valid on the budget-th attempt was rejected")
	}

	// Control: legitimate rollover zone stays Secure.
	ksk2 := newKeytrapKey(t, zone, protocol.DNSKEYFlagZone|protocol.DNSKEYFlagSEP)
	zskOld := newKeytrapKey(t, zone, protocol.DNSKEYFlagZone)
	rollKeys := []*protocol.ResourceRecord{ksk.rr, ksk2.rr, zskOld.rr, zsk.collidingKeys(t, 1)[0], zsk.rr}
	stale := corruptRRSIGs(zskOld.sign(t, []*protocol.ResourceRecord{a}), 1)[0]
	if got := v.validateMessage(context.Background(), resp(stale, good), "www.example.com.", []*chainLink{{zone: zone, dnsKeys: rollKeys, validated: true}}); got != ValidationSecure {
		t.Fatalf("rollover zone = %v, want SECURE", got)
	}
	if !v.verifyDNSKEYSelfSignature(rollKeys, []*protocol.ResourceRecord{ksk2.sign(t, rollKeys), ksk.sign(t, rollKeys)}, []*protocol.ResourceRecord{ksk.rr}) {
		t.Fatal("double-signed DNSKEY RRset rejected")
	}
}

// F393: more denial RRsets than maxNSECValidations are refused before any
// signature is verified.
func TestKeyTrap_DenialRRsetCountBeforeVerify_F393(t *testing.T) {
	k := newKeytrapKey(t, "example.com.", protocol.DNSKEYFlagZone)
	v := NewValidator(DefaultValidatorConfig(), nil, nil)
	build := func(n int) *protocol.Message {
		msg := &protocol.Message{}
		for i := 0; i < n; i++ {
			nsec := &protocol.ResourceRecord{Name: mustName(t, "n"+strconv.Itoa(i)+".example.com."), Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300,
				Data: &protocol.RDataNSEC{NextDomain: mustName(t, "n"+strconv.Itoa(i)+"a.example.com.")}}
			msg.Authorities = append(msg.Authorities, nsec, k.sign(t, []*protocol.ResourceRecord{nsec}))
		}
		return msg
	}
	if got := len(v.authenticatedDenialRRs(build(maxNSECValidations), k.chain())); got != maxNSECValidations {
		t.Fatalf("%d signed sets -> %d authenticated, want all", maxNSECValidations, got)
	}
	if got := len(v.authenticatedDenialRRs(build(maxNSECValidations+1), k.chain())); got != 0 {
		t.Fatalf("%d signed sets -> %d authenticated, want 0 (refused before verification)", maxNSECValidations+1, got)
	}
}

// F394: the Authority denial is authenticated once per response (per chain
// link), not once per wildcard-expanded RRset.
func TestKeyTrap_WildcardDenialAuthenticatedOnce_F394(t *testing.T) {
	k := newKeytrapKey(t, "example.com.", protocol.DNSKEYFlagZone)
	v := NewValidator(DefaultValidatorConfig(), nil, nil)
	nsec := &protocol.ResourceRecord{Name: mustName(t, "example.com."), Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataNSEC{NextDomain: mustName(t, "x.example.com."), TypeBitMap: []uint16{protocol.TypeNS, protocol.TypeSOA}}}
	msg := &protocol.Message{Authorities: []*protocol.ResourceRecord{nsec, k.sign(t, []*protocol.ResourceRecord{nsec})}}
	chain := k.chain()
	memo := map[*chainLink][]*protocol.ResourceRecord{}
	if !v.wildcardExpansionProven(msg, "w1.example.com.", 2, protocol.TypeA, chain, memo) {
		t.Fatal("signed covering NSEC did not prove the wildcard expansion")
	}
	// Strip the signature: a re-verification would now fail, the memo must not.
	msg.Authorities = msg.Authorities[:1]
	if !v.wildcardExpansionProven(msg, "w2.example.com.", 2, protocol.TypeA, chain, memo) {
		t.Fatal("second wildcard RRset re-authenticated the Authority section (want one authentication per response)")
	}
	if v.wildcardExpansionProven(msg, "w2.example.com.", 2, protocol.TypeA, chain, map[*chainLink][]*protocol.ResourceRecord{}) {
		t.Fatal("unsigned NSEC accepted with a fresh memo")
	}
}

// F395: the NSEC3 wildcard proof hashes only the Labels-derived closest
// encloser and the next closer, and still rejects a depth-mismatched replay.
func TestKeyTrap_NSEC3WildcardProofAnchoredOnLabels_F395(t *testing.T) {
	k := newKeytrapKey(t, "example.com.", protocol.DNSKEYFlagZone)
	v := NewValidator(DefaultValidatorConfig(), nil, nil)
	salt := []byte{9, 9}
	hash := func(n string) []byte {
		h, err := NSEC3Hash(n, 1, 5, salt)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	add := func(b []byte, d int) []byte { c := append([]byte(nil), b...); c[len(c)-1] += byte(d); return c }
	nsec3 := func(owner, next []byte) []*protocol.ResourceRecord {
		rr := &protocol.ResourceRecord{Name: mustName(t, strings.ToLower(protocol.Base32Encode(owner))+".example.com."), Type: protocol.TypeNSEC3, Class: protocol.ClassIN, TTL: 300,
			Data: &protocol.RDataNSEC3{HashAlgorithm: 1, Iterations: 5, Salt: salt, HashLength: uint8(len(next)), NextHashed: next}}
		return []*protocol.ResourceRecord{rr, k.sign(t, []*protocol.ResourceRecord{rr})}
	}
	wild := &protocol.ResourceRecord{Name: mustName(t, "*.example.com."), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 7}}}
	wsig := k.sign(t, []*protocol.ResourceRecord{wild})
	run := func(owner string, auth ...[]*protocol.ResourceRecord) ValidationResult {
		msg := &protocol.Message{Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Answers: []*protocol.ResourceRecord{
				{Name: mustName(t, owner), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: wild.Data},
				{Name: mustName(t, owner), Type: protocol.TypeRRSIG, Class: protocol.ClassIN, TTL: 300, Data: wsig.Data}}}
		for _, a := range auth {
			msg.Authorities = append(msg.Authorities, a...)
		}
		return v.validateMessage(context.Background(), msg, owner, k.chain())
	}
	apex, sub := hash("example.com"), hash("sub.example.com")
	ce := nsec3(apex, add(apex, 1))
	cover := nsec3(add(sub, -1), add(sub, 1))
	if got := run("a.b.sub.example.com.", ce, cover); got != ValidationSecure {
		t.Fatalf("deep wildcard answer with CE match + next-closer cover = %v, want SECURE", got)
	}
	if got := run("a.sub.example.com.", ce, nsec3(sub, add(sub, 1))); got != ValidationBogus {
		t.Fatalf("next closer exists (depth-mismatched wildcard replay) = %v, want BOGUS", got)
	}
	// RFC 5155 §8.8 needs only the next-closer cover; an NSEC3 matching the
	// closest encloser is not required (F522).
	if got := run("a.sub.example.com.", cover); got != ValidationSecure {
		t.Fatalf("next-closer cover without closest-encloser match = %v, want SECURE (F522)", got)
	}
}
