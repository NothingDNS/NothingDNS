package dnssec

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func fakeKey(tag uint16, ksk bool, material byte) *SigningKey {
	return &SigningKey{
		KeyTag: tag, IsKSK: ksk, IsZSK: !ksk,
		DNSKEY: &protocol.RDataDNSKEY{Flags: 256, Protocol: 3, Algorithm: protocol.AlgorithmECDSAP256SHA256, PublicKey: []byte{material}},
	}
}

// Signer.keys is keyed by key tag, so two different keys with the same tag
// used to overwrite each other silently: a freshly generated ZSK could drop the
// KSK and GetKSKs came back empty (about 1 in 65,000 key pairs).
func TestAddKeyRefusesDifferentKeyWithSameTag(t *testing.T) {
	s := NewSigner("example.test.", DefaultSignerConfig())
	ksk := fakeKey(7, true, 1)
	if err := s.AddKey(ksk); err != nil {
		t.Fatal(err)
	}
	if err := s.AddKey(fakeKey(7, false, 2)); err == nil {
		t.Fatal("a different key with the same tag was accepted")
	}
	if got := s.GetKSKs(); len(got) != 1 || got[0].KeyTag != 7 {
		t.Fatalf("KSK lost after the refused add: %v", got)
	}
	if len(s.GetZSKs()) != 0 {
		t.Fatal("refused key was stored")
	}
	// Re-adding the very same key stays idempotent (reload paths do this).
	if err := s.AddKey(fakeKey(7, true, 1)); err != nil {
		t.Fatalf("re-adding the same key: %v", err)
	}
	if err := s.AddKey(nil); err == nil {
		t.Fatal("nil key accepted")
	}
}

// GenerateKeyPair must retry when the generated tag is already taken instead
// of overwriting the existing key.
func TestGenerateKeyPairRetriesOnTagCollision(t *testing.T) {
	s := NewSigner("example.test.", DefaultSignerConfig())
	first, err := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, true)
	if err != nil {
		t.Fatal(err)
	}

	calls := 0
	s.keyGen = func(alg uint8, ksk bool) (*SigningKey, error) {
		calls++
		k, err := s.generateKeyPairOnce(alg, ksk)
		if err != nil {
			return nil, err
		}
		if calls <= 2 { // pretend the first two ZSKs collide with the KSK
			k.KeyTag = first.KeyTag
		}
		return k, nil
	}
	zsk, err := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("generator called %d times, want 3 (two collisions then a fresh key)", calls)
	}
	if zsk.KeyTag == first.KeyTag {
		t.Fatal("ZSK reused the KSK's tag")
	}
	if len(s.GetKSKs()) != 1 || len(s.GetZSKs()) != 1 {
		t.Fatalf("keys after generation: %d KSK, %d ZSK", len(s.GetKSKs()), len(s.GetZSKs()))
	}

	// Every attempt colliding is an error, never a silent overwrite.
	s.keyGen = func(alg uint8, ksk bool) (*SigningKey, error) {
		k, err := s.generateKeyPairOnce(alg, ksk)
		if err != nil {
			return nil, err
		}
		k.KeyTag = first.KeyTag
		return k, nil
	}
	if _, err := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false); err == nil {
		t.Fatal("expected an error when every generated tag collides")
	}
	if got := s.GetKSKs(); len(got) != 1 || got[0].KeyTag != first.KeyTag {
		t.Fatal("KSK lost after repeated collisions")
	}
}
