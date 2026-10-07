package dnssec

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// IANA root KSK-2024 (root-anchors.xml KeyDigest id Kmyv6jo).
const (
	ksk2024PublicKeyB64 = "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc="
	ksk2024DigestHex    = "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"
)

// TestBuiltInRootAnchors_IncludeKSK2024_F457: the built-in root anchors must
// authenticate root KSK-2024, or every answer validated without a configured
// trust_anchor goes Bogus once the root DNSKEY RRset is signed by it alone.
// (The full signed-chain case needs the IANA private key; it is covered in
// .temp_files/prove_F457_builtin_root_ksk2024 with a signature oracle.)
func TestBuiltInRootAnchors_IncludeKSK2024_F457(t *testing.T) {
	pub, err := base64.StdEncoding.DecodeString(ksk2024PublicKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	dnskey := &protocol.RDataDNSKEY{Flags: 257, Protocol: 3, Algorithm: protocol.AlgorithmRSASHA256, PublicKey: pub}

	// Self-consistency of the IANA data: tag and SHA-256 over "." + RDATA.
	if tag := protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey); tag != 38696 {
		t.Fatalf("key tag = %d, want 38696", tag)
	}
	if got := strings.ToUpper(hex.EncodeToString(calculateDSDigestFromDNSKEY(".", dnskey, 2))); got != ksk2024DigestHex {
		t.Fatalf("digest = %s, want %s", got, ksk2024DigestHex)
	}

	root, _ := protocol.ParseName(".")
	keyRR := &protocol.ResourceRecord{Name: root, Type: protocol.TypeDNSKEY, Class: protocol.ClassIN, TTL: 172800, Data: dnskey}
	store := NewTrustAnchorStoreWithBuiltIn()
	anchor, _ := store.FindClosestAnchor(".")
	if anchor == nil {
		t.Fatal("no valid built-in root anchor")
	}
	v := NewValidator(DefaultValidatorConfig(), store, &mockResolver{})
	if got := v.keysMatchingAnyAnchor(anchor, []*protocol.ResourceRecord{keyRR}); len(got) != 1 || got[0] != keyRR {
		t.Fatalf("built-in anchors do not authenticate KSK-2024 (matched %d keys)", len(got))
	}

	// The chain gets past the anchor stage; only the (unforgeable) RRSIG fails.
	now := time.Now()
	sig := &protocol.ResourceRecord{Name: root, Type: protocol.TypeRRSIG, Class: protocol.ClassIN, TTL: 172800,
		Data: &protocol.RDataRRSIG{TypeCovered: protocol.TypeDNSKEY, Algorithm: 8, OriginalTTL: 172800,
			Expiration: uint32(now.Add(time.Hour).Unix()), Inception: uint32(now.Add(-time.Hour).Unix()),
			KeyTag: 38696, SignerName: root, Signature: make([]byte, 256)}}
	v = NewValidator(DefaultValidatorConfig(), store, &mockResolver{responses: map[string]*protocol.Message{
		".|" + strconv.Itoa(int(protocol.TypeDNSKEY)): {Answers: []*protocol.ResourceRecord{keyRR, sig}}}})
	_, _, err = v.buildChain(context.Background(), anchor, nil)
	if err == nil || strings.Contains(err.Error(), "trust anchor validation failed") {
		t.Fatalf("buildChain error = %v, want a self-signature failure (anchor stage passed)", err)
	}

	// Validity: from 2024-07-18 on, never before.
	vf := time.Date(2024, 7, 18, 0, 0, 0, 0, time.UTC)
	for _, a := range BuiltInRootAnchors {
		if a.KeyTag == 38696 && (a.isValidAt(vf.Add(-time.Second)) || !a.isValidAt(vf)) {
			t.Fatal("KSK-2024 validity window wrong")
		}
	}
}

// TestSignZone_DelegationNSAndGlueUnsigned_F459: RFC 4035 §2.2/§2.3 — the
// delegation NS RRset and glue are not signed and glue owners are not in the
// NSEC/NSEC3 chain; only the DS RRset at a cut is signed. Signing them made
// the parent's glue for a name in an unsigned child validate as Secure.
func TestSignZone_DelegationNSAndGlueUnsigned_F459(t *testing.T) {
	mk := func(name string, rrtype uint16, text string) *protocol.ResourceRecord {
		rr, err := protocol.NewResourceRecord(name, rrtype, protocol.ClassIN, 300, protocol.ParseRDataText(protocol.TypeString(rrtype), text))
		if err != nil {
			t.Fatal(err)
		}
		return rr
	}
	for _, nsec3 := range []bool{false, true} {
		cfg := DefaultSignerConfig()
		cfg.NSEC3Enabled = nsec3
		s := NewSigner("example.com.", cfg)
		if _, err := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, true); err != nil {
			t.Fatal(err)
		}
		signed, err := s.SignZone([]*protocol.ResourceRecord{
			mk("example.com.", protocol.TypeSOA, "ns1.example.com. hostmaster.example.com. 1 3600 600 86400 300"),
			mk("example.com.", protocol.TypeNS, "ns1.example.com."),
			mk("ns1.example.com.", protocol.TypeA, "192.0.2.53"),
			mk("sub.example.com.", protocol.TypeNS, "ns1.sub.example.com."),
			mk("sub.example.com.", protocol.TypeDS, "12345 13 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
			mk("ns1.sub.example.com.", protocol.TypeA, "192.0.2.66"),
		})
		if err != nil {
			t.Fatal(err)
		}
		covered := map[string]bool{}
		var nsecOwners []string
		var cutBitmap []uint16
		for _, rr := range signed {
			owner := strings.ToLower(rr.Name.String())
			switch d := rr.Data.(type) {
			case *protocol.RDataRRSIG:
				covered[owner+"/"+protocol.TypeString(d.TypeCovered)] = true
			case *protocol.RDataNSEC:
				nsecOwners = append(nsecOwners, owner)
				if owner == "sub.example.com." {
					cutBitmap = d.TypeBitMap
				}
			}
		}
		for _, want := range []string{"example.com./NS", "ns1.example.com./A", "sub.example.com./DS"} {
			if !covered[want] {
				t.Errorf("nsec3=%v: %s not signed", nsec3, want)
			}
		}
		for _, bad := range []string{"sub.example.com./NS", "ns1.sub.example.com./A"} {
			if covered[bad] {
				t.Errorf("nsec3=%v: non-authoritative %s signed", nsec3, bad)
			}
		}
		if nsec3 {
			if nsec3RecordForOwner(t, s, signed, "ns1.sub.example.com.") != nil {
				t.Errorf("glue owner has an NSEC3")
			}
			if rr := nsec3RecordForOwner(t, s, signed, "sub.example.com."); rr == nil {
				t.Errorf("delegation has no NSEC3")
			}
			continue
		}
		for _, o := range nsecOwners {
			if o == "ns1.sub.example.com." {
				t.Errorf("glue owner in NSEC chain: %v", nsecOwners)
			}
		}
		want := []uint16{protocol.TypeNS, protocol.TypeDS, protocol.TypeRRSIG, protocol.TypeNSEC}
		if len(cutBitmap) != len(want) {
			t.Errorf("cut NSEC bitmap = %v, want %v", cutBitmap, want)
		}
		for i := range want {
			if i < len(cutBitmap) && cutBitmap[i] != want[i] {
				t.Errorf("cut NSEC bitmap = %v, want %v", cutBitmap, want)
				break
			}
		}
	}
}
