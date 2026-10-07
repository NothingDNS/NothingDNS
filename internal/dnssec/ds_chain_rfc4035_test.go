package dnssec

import (
	"context"
	"strconv"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// Regression tests for the chain-of-trust round:
//   - F372: a wildcard-expanded NSEC (RRSIG Labels < owner labels) was
//     accepted as a denial record, so the genuine NSEC of a literal "*.zone"
//     owner could be renamed anywhere (forged NXDOMAIN, forged insecure
//     delegation).
//   - F373: an authenticated DS RRset listing only unsupported algorithms or
//     digest types made the chain Bogus instead of Insecure (RFC 4035 §5.2).
//   - F374: a SHA-1 DS authenticated the child even when the DS RRset had a
//     SHA-256 DS (RFC 4509 §3).
// Fixtures are signed in-process; IgnoreTime removes wall-clock dependence.

func dsChainRename(t *testing.T, rr *protocol.ResourceRecord, owner string) *protocol.ResourceRecord {
	t.Helper()
	return &protocol.ResourceRecord{Name: mustName(t, owner), Type: rr.Type, Class: rr.Class, TTL: rr.TTL, Data: rr.Data}
}

// dsChainFixture returns an IgnoreTime validator over buildTwoLevelFixture.
// mutate may return a replacement DS RRset for example.com. (signed by com.
// here) and/or a replacement example.com. DNSKEY answer.
func dsChainFixture(t *testing.T, mutate func(keys map[string]*testZoneKeys) (ds, dnskey []*protocol.ResourceRecord)) (*Validator, map[string]*testZoneKeys) {
	t.Helper()
	v0, keys := buildTwoLevelFixture(t)
	cfg := DefaultValidatorConfig()
	cfg.IgnoreTime = true
	v := NewValidator(cfg, v0.trustAnchors, v0.resolver)
	mock := v.resolver.(*mockResolver)
	if mutate != nil {
		ds, dnskey := mutate(keys)
		if ds != nil {
			sig := keys["com."].sign(t, "com.", ds)
			mock.responses["example.com.|"+strconv.Itoa(int(protocol.TypeDS))] = &protocol.Message{
				Header:  protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
				Answers: append(append([]*protocol.ResourceRecord{}, ds...), sig),
			}
		}
		if dnskey != nil {
			mock.responses["example.com.|"+strconv.Itoa(int(protocol.TypeDNSKEY))] = &protocol.Message{
				Header:  protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
				Answers: dnskey,
			}
		}
	}
	return v, keys
}

func dsChainOutcome(t *testing.T, v *Validator) string {
	t.Helper()
	anchor, remaining := v.trustAnchors.FindClosestAnchor("example.com.")
	_, insecure, err := v.buildChain(context.Background(), anchor, remaining)
	switch {
	case err != nil:
		return "BOGUS"
	case insecure:
		return "INSECURE"
	default:
		return "SECURE"
	}
}

// dsChainDS returns a DS for example.com.'s key with the given algorithm and
// digest type; corrupt zeroes the digest.
func dsChainDS(t *testing.T, keys map[string]*testZoneKeys, alg, digestType uint8, corrupt bool) *protocol.ResourceRecord {
	t.Helper()
	ds := keys["com."].dsFor(t, "example.com.", keys["example.com."])
	d := *ds.Data.(*protocol.RDataDS)
	d.Algorithm = alg
	d.DigestType = digestType
	d.Digest = calculateDSDigestFromDNSKEY("example.com.", keys["example.com."].dnskey, digestType)
	if d.Digest == nil || corrupt {
		d.Digest = make([]byte, 32)
	}
	ds.Data = &d
	ds.Class = protocol.ClassIN
	return ds
}

func TestWildcardExpandedNSECRejectedRFC4035(t *testing.T) {
	f := newNSEC3DenialFixture(t)
	wild := &protocol.ResourceRecord{
		Name: mustName(t, "*.example.com."), Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataNSEC{NextDomain: mustName(t, "a.example.com."),
			TypeBitMap: []uint16{protocol.TypeA, protocol.TypeRRSIG, protocol.TypeNSEC}},
	}
	wildSig := f.keys.sign(t, "example.com.", []*protocol.ResourceRecord{wild})

	t.Run("literal wildcard NSEC still authenticates", func(t *testing.T) {
		msg := negMsg(protocol.RcodeSuccess, "*.example.com.", []*protocol.ResourceRecord{wild, wildSig})
		msg.Questions[0].QType = protocol.TypeAAAA
		for i := 0; i < 3; i++ {
			if got := f.v.validateNegativeResponse(msg, "*.example.com.", f.chain); got != ValidationSecure {
				t.Fatalf("call %d: literal wildcard NODATA = %v, want SECURE", i, got)
			}
		}
	})

	for _, owner := range []string{"b.example.com.", "x.y.example.com."} {
		t.Run("forged NXDOMAIN via renamed wildcard NSEC "+owner, func(t *testing.T) {
			msg := negMsg(protocol.RcodeNameError, "www.example.com.", []*protocol.ResourceRecord{
				dsChainRename(t, wild, owner), dsChainRename(t, wildSig, owner),
			})
			if got := f.v.validateNegativeResponse(msg, "www.example.com.", f.chain); got != ValidationBogus {
				t.Fatalf("forged NXDOMAIN = %v, want BOGUS", got)
			}
		})
	}

	t.Run("renamed wildcard NSEC cannot deny DS (NameError)", func(t *testing.T) {
		msg := negMsg(protocol.RcodeSuccess, "sub.example.com.", []*protocol.ResourceRecord{
			dsChainRename(t, wild, "b.example.com."), dsChainRename(t, wildSig, "b.example.com."),
		})
		if got := f.v.classifyDSDenial(msg, "sub.example.com.", f.chain); got != dsDenialNone {
			t.Fatalf("classifyDSDenial = %d, want dsDenialNone", got)
		}
	})

	// End to end: a renamed *.com. NSEC (NS set, DS/SOA clear) must not prove
	// the signed child example.com. insecure.
	v, keys := dsChainFixture(t, nil)
	com := keys["com."]
	wildNS := &protocol.ResourceRecord{
		Name: mustName(t, "*.com."), Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataNSEC{NextDomain: mustName(t, "a.com."),
			TypeBitMap: []uint16{protocol.TypeNS, protocol.TypeRRSIG, protocol.TypeNSEC}},
	}
	wildNSSig := com.sign(t, "com.", []*protocol.ResourceRecord{wildNS})
	forgedA := &protocol.ResourceRecord{
		Name: mustName(t, "example.com."), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataA{Address: [4]byte{203, 0, 113, 66}},
	}
	answer := &protocol.Message{
		Header:    protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Questions: []*protocol.Question{{Name: mustName(t, "example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN}},
		Answers:   []*protocol.ResourceRecord{forgedA},
	}
	v.resolver.(*mockResolver).responses["example.com.|"+strconv.Itoa(int(protocol.TypeDS))] = &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Authorities: []*protocol.ResourceRecord{
			dsChainRename(t, wildNS, "example.com."), dsChainRename(t, wildNSSig, "example.com."),
		},
	}
	t.Run("forged insecure delegation via renamed *.com. NSEC", func(t *testing.T) {
		if res, _ := v.ValidateResponse(context.Background(), answer, "example.com."); res != ValidationBogus {
			t.Fatalf("forged unsigned answer under renamed-NSEC 'insecure' delegation = %v, want BOGUS", res)
		}
	})
}

func TestUnsupportedDSAlgorithmInsecureRFC4035(t *testing.T) {
	ed448 := func(t *testing.T) (ds, dnskey []*protocol.ResourceRecord) {
		pub := make([]byte, 57)
		for i := range pub {
			pub[i] = byte(i*7 + 1)
		}
		key := &protocol.RDataDNSKEY{Flags: protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP, Protocol: 3,
			Algorithm: protocol.AlgorithmED448, PublicKey: pub}
		keyRR := &protocol.ResourceRecord{Name: mustName(t, "example.com."), Type: protocol.TypeDNSKEY, Class: protocol.ClassIN, TTL: 300, Data: key}
		tag := protocol.CalculateKeyTag(key.Flags, key.Algorithm, key.PublicKey)
		sigRR := &protocol.ResourceRecord{Name: mustName(t, "example.com."), Type: protocol.TypeRRSIG, Class: protocol.ClassIN, TTL: 300,
			Data: &protocol.RDataRRSIG{TypeCovered: protocol.TypeDNSKEY, Algorithm: protocol.AlgorithmED448, Labels: 2,
				OriginalTTL: 300, Expiration: 2, Inception: 1, KeyTag: tag, SignerName: mustName(t, "example.com."),
				Signature: make([]byte, 114)}}
		dsRR := &protocol.ResourceRecord{Name: mustName(t, "example.com."), Type: protocol.TypeDS, Class: protocol.ClassIN, TTL: 300,
			Data: &protocol.RDataDS{KeyTag: tag, Algorithm: protocol.AlgorithmED448, DigestType: 2,
				Digest: calculateDSDigestFromDNSKEY("example.com.", key, 2)}}
		return []*protocol.ResourceRecord{dsRR}, []*protocol.ResourceRecord{keyRR, sigRR}
	}
	alg13 := uint8(protocol.AlgorithmECDSAP256SHA256)
	cases := []struct {
		name string
		want string
		mut  func(t *testing.T, k map[string]*testZoneKeys) (ds, dnskey []*protocol.ResourceRecord)
	}{
		{"supported chain", "SECURE", nil},
		{"supported DS with wrong digest", "BOGUS", func(t *testing.T, k map[string]*testZoneKeys) (ds, dnskey []*protocol.ResourceRecord) {
			return []*protocol.ResourceRecord{dsChainDS(t, k, alg13, 2, true)}, nil
		}},
		{"Ed448 only", "INSECURE", func(t *testing.T, _ map[string]*testZoneKeys) (ds, dnskey []*protocol.ResourceRecord) {
			return ed448(t)
		}},
		{"RSASHA1 (alg 5) only", "INSECURE", func(t *testing.T, k map[string]*testZoneKeys) (ds, dnskey []*protocol.ResourceRecord) {
			return []*protocol.ResourceRecord{dsChainDS(t, k, protocol.AlgorithmRSASHA1, 2, false)}, nil
		}},
		{"digest type 3 only", "INSECURE", func(t *testing.T, k map[string]*testZoneKeys) (ds, dnskey []*protocol.ResourceRecord) {
			return []*protocol.ResourceRecord{dsChainDS(t, k, alg13, 3, false)}, nil
		}},
		{"Ed448 DS + matching alg 13 DS", "SECURE", func(t *testing.T, k map[string]*testZoneKeys) (ds, dnskey []*protocol.ResourceRecord) {
			edDS, _ := ed448(t)
			return append(edDS, dsChainDS(t, k, alg13, 2, false)), nil
		}},
		{"Ed448 DS + non-matching alg 13 DS stays Bogus", "BOGUS", func(t *testing.T, k map[string]*testZoneKeys) (ds, dnskey []*protocol.ResourceRecord) {
			edDS, _ := ed448(t)
			return append(edDS, dsChainDS(t, k, alg13, 2, true)), nil
		}},
		{"digest 3 DS + non-matching SHA-256 DS stays Bogus", "BOGUS", func(t *testing.T, k map[string]*testZoneKeys) (ds, dnskey []*protocol.ResourceRecord) {
			return []*protocol.ResourceRecord{dsChainDS(t, k, alg13, 3, false), dsChainDS(t, k, alg13, 2, true)}, nil
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mut func(map[string]*testZoneKeys) (ds, dnskey []*protocol.ResourceRecord)
			if tc.mut != nil {
				mut = func(k map[string]*testZoneKeys) (ds, dnskey []*protocol.ResourceRecord) { return tc.mut(t, k) }
			}
			v, _ := dsChainFixture(t, mut)
			for i := 0; i < 2; i++ {
				if got := dsChainOutcome(t, v); got != tc.want {
					t.Fatalf("call %d: chain = %s, want %s", i, got, tc.want)
				}
			}
		})
	}

	// End to end: an unsigned answer below an Ed448-only delegation is
	// Insecure (no AD), not SERVFAIL.
	v, _ := dsChainFixture(t, func(map[string]*testZoneKeys) (ds, dnskey []*protocol.ResourceRecord) { return ed448(t) })
	a := &protocol.ResourceRecord{
		Name: mustName(t, "example.com."), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
	}
	msg := &protocol.Message{
		Header:    protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Questions: []*protocol.Question{{Name: mustName(t, "example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN}},
		Answers:   []*protocol.ResourceRecord{a},
	}
	if res, err := v.ValidateResponse(context.Background(), msg, "example.com."); res != ValidationInsecure {
		t.Fatalf("answer under Ed448-only delegation = %v (%v), want INSECURE", res, err)
	}
}

func TestSHA1DSIgnoredWithSHA256RFC4509(t *testing.T) {
	alg13 := uint8(protocol.AlgorithmECDSAP256SHA256)
	cases := []struct {
		name string
		want string
		ds   func(t *testing.T, k map[string]*testZoneKeys) []*protocol.ResourceRecord
	}{
		{"SHA-1 only", "SECURE", func(t *testing.T, k map[string]*testZoneKeys) []*protocol.ResourceRecord {
			return []*protocol.ResourceRecord{dsChainDS(t, k, alg13, 1, false)}
		}},
		{"SHA-256 + SHA-1 both matching", "SECURE", func(t *testing.T, k map[string]*testZoneKeys) []*protocol.ResourceRecord {
			return []*protocol.ResourceRecord{dsChainDS(t, k, alg13, 2, false), dsChainDS(t, k, alg13, 1, false)}
		}},
		{"SHA-256 matching + SHA-1 garbage", "SECURE", func(t *testing.T, k map[string]*testZoneKeys) []*protocol.ResourceRecord {
			return []*protocol.ResourceRecord{dsChainDS(t, k, alg13, 2, false), dsChainDS(t, k, alg13, 1, true)}
		}},
		{"SHA-256 non-matching + SHA-1 matching", "BOGUS", func(t *testing.T, k map[string]*testZoneKeys) []*protocol.ResourceRecord {
			return []*protocol.ResourceRecord{dsChainDS(t, k, alg13, 2, true), dsChainDS(t, k, alg13, 1, false)}
		}},
		{"SHA-384 non-matching + SHA-1 matching", "BOGUS", func(t *testing.T, k map[string]*testZoneKeys) []*protocol.ResourceRecord {
			return []*protocol.ResourceRecord{dsChainDS(t, k, alg13, 4, true), dsChainDS(t, k, alg13, 1, false)}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, _ := dsChainFixture(t, func(k map[string]*testZoneKeys) (ds, dnskey []*protocol.ResourceRecord) {
				return tc.ds(t, k), nil
			})
			if got := dsChainOutcome(t, v); got != tc.want {
				t.Fatalf("chain = %s, want %s", got, tc.want)
			}
		})
	}
}
