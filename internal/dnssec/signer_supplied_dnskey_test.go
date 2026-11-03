package dnssec

import (
	"bytes"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestSignZonePublishesConfiguredKeysWithSuppliedDNSKEY_F823(t *testing.T) {
	signer := NewSigner("example.com.", DefaultSignerConfig())
	if _, err := signer.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, true); err != nil {
		t.Fatal(err)
	}
	if _, err := signer.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false); err != nil {
		t.Fatal(err)
	}

	foreignSigner := NewSigner("example.com.", DefaultSignerConfig())
	foreign, err := foreignSigner.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, true)
	if err != nil {
		t.Fatal(err)
	}
	apex, _ := protocol.ParseName("example.com.")
	www, _ := protocol.ParseName("www.example.com.")
	input := []*protocol.ResourceRecord{
		{Name: apex, Type: protocol.TypeDNSKEY, Class: protocol.ClassIN, TTL: 7200, Data: foreign.DNSKEY.Copy()},
		{Name: www, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}}},
	}

	out, err := signer.SignZone(input)
	if err != nil {
		t.Fatal(err)
	}
	configured := signer.GetKeys()
	for _, key := range configured {
		found := false
		for _, rr := range out {
			dnskey, ok := rr.Data.(*protocol.RDataDNSKEY)
			if rr.Type == protocol.TypeDNSKEY && ok && dnskey.Flags == key.DNSKEY.Flags &&
				dnskey.Algorithm == key.DNSKEY.Algorithm && bytes.Equal(dnskey.PublicKey, key.DNSKEY.PublicKey) {
				found = true
				if rr.TTL != 7200 {
					t.Fatalf("generated DNSKEY TTL = %d, want supplied RRset TTL 7200", rr.TTL)
				}
				break
			}
		}
		if !found {
			t.Fatalf("configured key tag %d was not published", key.KeyTag)
		}
	}
}
