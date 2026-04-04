package dnssec

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func BenchmarkSignData_ECDSA_P256(b *testing.B) {
	priv, _, err := GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false)
	if err != nil {
		b.Fatalf("keygen: %v", err)
	}
	data := make([]byte, 256)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = SignData(protocol.AlgorithmECDSAP256SHA256, priv, data)
	}
}

func BenchmarkVerifySignature_ECDSA_P256(b *testing.B) {
	priv, pub, err := GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false)
	if err != nil {
		b.Fatalf("keygen: %v", err)
	}
	data := make([]byte, 256)
	sig, err := SignData(protocol.AlgorithmECDSAP256SHA256, priv, data)
	if err != nil {
		b.Fatalf("sign: %v", err)
	}
	rrsig := &protocol.RDataRRSIG{
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		Signature: sig,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = VerifySignature(rrsig, data, pub)
	}
}

func BenchmarkSignData_Ed25519(b *testing.B) {
	priv, _, err := GenerateKeyPair(protocol.AlgorithmED25519, false)
	if err != nil {
		b.Fatalf("keygen: %v", err)
	}
	data := make([]byte, 256)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = SignData(protocol.AlgorithmED25519, priv, data)
	}
}

func BenchmarkVerifySignature_Ed25519(b *testing.B) {
	priv, pub, err := GenerateKeyPair(protocol.AlgorithmED25519, false)
	if err != nil {
		b.Fatalf("keygen: %v", err)
	}
	data := make([]byte, 256)
	sig, err := SignData(protocol.AlgorithmED25519, priv, data)
	if err != nil {
		b.Fatalf("sign: %v", err)
	}
	rrsig := &protocol.RDataRRSIG{
		Algorithm: protocol.AlgorithmED25519,
		Signature: sig,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = VerifySignature(rrsig, data, pub)
	}
}

func BenchmarkSignData_RSA_SHA256(b *testing.B) {
	priv, _, err := GenerateKeyPair(protocol.AlgorithmRSASHA256, false)
	if err != nil {
		b.Fatalf("keygen: %v", err)
	}
	data := make([]byte, 256)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = SignData(protocol.AlgorithmRSASHA256, priv, data)
	}
}

func BenchmarkVerifySignature_RSA_SHA256(b *testing.B) {
	priv, pub, err := GenerateKeyPair(protocol.AlgorithmRSASHA256, false)
	if err != nil {
		b.Fatalf("keygen: %v", err)
	}
	data := make([]byte, 256)
	sig, err := SignData(protocol.AlgorithmRSASHA256, priv, data)
	if err != nil {
		b.Fatalf("sign: %v", err)
	}
	rrsig := &protocol.RDataRRSIG{
		Algorithm: protocol.AlgorithmRSASHA256,
		Signature: sig,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = VerifySignature(rrsig, data, pub)
	}
}

func BenchmarkSignRRSet_Ed25519(b *testing.B) {
	s := NewSigner("example.com.", DefaultSignerConfig())
	key, err := s.GenerateKeyPair(protocol.AlgorithmED25519, false)
	if err != nil {
		b.Fatalf("keygen: %v", err)
	}

	name, _ := protocol.ParseName("www.example.com.")
	rrSet := []*protocol.ResourceRecord{
		{
			Name:  name,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataA{Address: [4]byte{10, 0, 0, 1}},
		},
	}

	inception := uint32(1700000000)
	expiration := uint32(1700086400)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = s.SignRRSet(rrSet, key, inception, expiration)
	}
}

func BenchmarkParseDNSKEYPublicKey_Ed25519(b *testing.B) {
	_, pub, err := GenerateKeyPair(protocol.AlgorithmED25519, true)
	if err != nil {
		b.Fatalf("keygen: %v", err)
	}
	keyData, err := PackDNSKEYPublicKey(pub)
	if err != nil {
		b.Fatalf("pack: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = ParseDNSKEYPublicKey(protocol.AlgorithmED25519, keyData)
	}
}
