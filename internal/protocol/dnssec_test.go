package protocol

import (
	"bytes"
	"testing"
)

func TestRDataDSRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		ds   *RDataDS
	}{
		{
			name: "SHA256_digest",
			ds: &RDataDS{
				KeyTag:     20326,
				Algorithm:  AlgorithmRSASHA256,
				DigestType: 2,
				Digest: []byte{
					0xE0, 0x6D, 0x44, 0xB8, 0x0B, 0x8F, 0x1D, 0x39,
					0xA9, 0x5C, 0x0B, 0x0D, 0x7C, 0x65, 0xD0, 0x84,
					0x58, 0xE8, 0x80, 0x40, 0x9B, 0xBC, 0x68, 0x34,
					0x57, 0x10, 0x42, 0x37, 0xC7, 0xF8, 0xEC, 0x8D,
				},
			},
		},
		{
			name: "SHA384_digest",
			ds: &RDataDS{
				KeyTag:     12345,
				Algorithm:  AlgorithmECDSAP384SHA384,
				DigestType: 4,
				Digest: []byte{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
					0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
					0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
					0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
				},
			},
		},
		{
			name: "minimal",
			ds: &RDataDS{
				KeyTag:     1,
				Algorithm:  AlgorithmED25519,
				DigestType: 2,
				Digest:     []byte{0xAB, 0xCD},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Pack
			buf := make([]byte, tt.ds.Len())
			n, err := tt.ds.Pack(buf, 0)
			if err != nil {
				t.Fatalf("Pack failed: %v", err)
			}
			if n != tt.ds.Len() {
				t.Errorf("Packed %d bytes, expected %d", n, tt.ds.Len())
			}

			// Unpack
			unpacked := &RDataDS{}
			n2, err := unpacked.Unpack(buf, 0, uint16(n))
			if err != nil {
				t.Fatalf("Unpack failed: %v", err)
			}
			if n2 != n {
				t.Errorf("Unpacked %d bytes, expected %d", n2, n)
			}

			// Verify
			if unpacked.KeyTag != tt.ds.KeyTag {
				t.Errorf("KeyTag mismatch: got %d, want %d", unpacked.KeyTag, tt.ds.KeyTag)
			}
			if unpacked.Algorithm != tt.ds.Algorithm {
				t.Errorf("Algorithm mismatch: got %d, want %d", unpacked.Algorithm, tt.ds.Algorithm)
			}
			if unpacked.DigestType != tt.ds.DigestType {
				t.Errorf("DigestType mismatch: got %d, want %d", unpacked.DigestType, tt.ds.DigestType)
			}
			if !bytes.Equal(unpacked.Digest, tt.ds.Digest) {
				t.Errorf("Digest mismatch: got %x, want %x", unpacked.Digest, tt.ds.Digest)
			}

			// Verify Copy
			copied := unpacked.Copy().(*RDataDS)
			if !bytes.Equal(copied.Digest, tt.ds.Digest) {
				t.Error("Copy failed to preserve digest")
			}
		})
	}
}

func TestRDataDNSKEYRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		dnskey *RDataDNSKEY
	}{
		{
			name: "KSK_RSASHA256",
			dnskey: &RDataDNSKEY{
				Flags:     DNSKEYFlagZone | DNSKEYFlagSEP,
				Protocol:  3,
				Algorithm: AlgorithmRSASHA256,
				PublicKey: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			},
		},
		{
			name: "ZSK_ECDSA_P256",
			dnskey: &RDataDNSKEY{
				Flags:     DNSKEYFlagZone,
				Protocol:  3,
				Algorithm: AlgorithmECDSAP256SHA256,
				PublicKey: make([]byte, 64), // P-256 public key is 64 bytes (X + Y)
			},
		},
		{
			name: "Ed25519_key",
			dnskey: &RDataDNSKEY{
				Flags:     DNSKEYFlagZone,
				Protocol:  3,
				Algorithm: AlgorithmED25519,
				PublicKey: make([]byte, 32), // Ed25519 public key is 32 bytes
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Pack
			buf := make([]byte, tt.dnskey.Len())
			n, err := tt.dnskey.Pack(buf, 0)
			if err != nil {
				t.Fatalf("Pack failed: %v", err)
			}

			// Unpack
			unpacked := &RDataDNSKEY{}
			n2, err := unpacked.Unpack(buf, 0, uint16(n))
			if err != nil {
				t.Fatalf("Unpack failed: %v", err)
			}
			if n2 != n {
				t.Errorf("Unpacked %d bytes, expected %d", n2, n)
			}

			// Verify
			if unpacked.Flags != tt.dnskey.Flags {
				t.Errorf("Flags mismatch: got %d, want %d", unpacked.Flags, tt.dnskey.Flags)
			}
			if unpacked.Protocol != tt.dnskey.Protocol {
				t.Errorf("Protocol mismatch: got %d, want %d", unpacked.Protocol, tt.dnskey.Protocol)
			}
			if unpacked.Algorithm != tt.dnskey.Algorithm {
				t.Errorf("Algorithm mismatch: got %d, want %d", unpacked.Algorithm, tt.dnskey.Algorithm)
			}
			if !bytes.Equal(unpacked.PublicKey, tt.dnskey.PublicKey) {
				t.Errorf("PublicKey mismatch")
			}

			// Verify KSK/ZSK detection
			if tt.dnskey.IsKSK() != (tt.dnskey.Flags&DNSKEYFlagSEP != 0) {
				t.Error("IsKSK() returned incorrect value")
			}
			if tt.dnskey.IsZSK() != (tt.dnskey.Flags&DNSKEYFlagSEP == 0) {
				t.Error("IsZSK() returned incorrect value")
			}
		})
	}
}

func TestCalculateKeyTag(t *testing.T) {
	// Test vector from RFC 4034 Appendix B
	tests := []struct {
		name      string
		flags     uint16
		algorithm uint8
		key       []byte
		expected  uint16
	}{
		{
			name:      "RFC_4034_example",
			flags:     0x0100,
			algorithm: 8,
			key:       []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			expected:  3342, // Verified: RDATA=010003080102030405, sum=256+776+258+772+1280=3342
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tag := CalculateKeyTag(tt.flags, tt.algorithm, tt.key)
			if tag != tt.expected {
				t.Errorf("KeyTag mismatch: got %d, want %d", tag, tt.expected)
			}
		})
	}
}

func TestRDataRRSIGRoundTrip(t *testing.T) {
	signer, _ := ParseName("example.com.")

	tests := []struct {
		name  string
		rrsig *RDataRRSIG
	}{
		{
			name: "A_record_signature",
			rrsig: &RDataRRSIG{
				TypeCovered: TypeA,
				Algorithm:   AlgorithmRSASHA256,
				Labels:      3,
				OriginalTTL: 3600,
				Expiration:  1609459200, // 2021-01-01 00:00:00 UTC
				Inception:   1606780800, // 2020-12-01 00:00:00 UTC
				KeyTag:      12345,
				SignerName:  signer,
				Signature:   []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Pack
			buf := make([]byte, tt.rrsig.Len())
			n, err := tt.rrsig.Pack(buf, 0)
			if err != nil {
				t.Fatalf("Pack failed: %v", err)
			}

			// Unpack
			unpacked := &RDataRRSIG{}
			n2, err := unpacked.Unpack(buf, 0, uint16(n))
			if err != nil {
				t.Fatalf("Unpack failed: %v", err)
			}
			if n2 != n {
				t.Errorf("Unpacked %d bytes, expected %d", n2, n)
			}

			// Verify
			if unpacked.TypeCovered != tt.rrsig.TypeCovered {
				t.Errorf("TypeCovered mismatch")
			}
			if unpacked.Algorithm != tt.rrsig.Algorithm {
				t.Errorf("Algorithm mismatch")
			}
			if unpacked.KeyTag != tt.rrsig.KeyTag {
				t.Errorf("KeyTag mismatch")
			}
			if !bytes.Equal(unpacked.Signature, tt.rrsig.Signature) {
				t.Errorf("Signature mismatch")
			}
		})
	}
}

func TestRDataNSECRoundTrip(t *testing.T) {
	next, _ := ParseName("z.example.com.")

	tests := []struct {
		name string
		nsec *RDataNSEC
	}{
		{
			name: "with_multiple_types",
			nsec: &RDataNSEC{
				NextDomain: next,
				TypeBitMap: []uint16{TypeA, TypeNS, TypeSOA, TypeMX, TypeTXT, TypeRRSIG, TypeNSEC, TypeDNSKEY},
			},
		},
		{
			name: "single_type",
			nsec: &RDataNSEC{
				NextDomain: next,
				TypeBitMap: []uint16{TypeA},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Pack
			buf := make([]byte, tt.nsec.Len())
			n, err := tt.nsec.Pack(buf, 0)
			if err != nil {
				t.Fatalf("Pack failed: %v", err)
			}

			// Unpack
			unpacked := &RDataNSEC{}
			n2, err := unpacked.Unpack(buf, 0, uint16(n))
			if err != nil {
				t.Fatalf("Unpack failed: %v", err)
			}

			// Verify
			if unpacked.NextDomain.String() != tt.nsec.NextDomain.String() {
				t.Errorf("NextDomain mismatch")
			}
			if len(unpacked.TypeBitMap) != len(tt.nsec.TypeBitMap) {
				t.Errorf("TypeBitMap length mismatch: got %d, want %d", len(unpacked.TypeBitMap), len(tt.nsec.TypeBitMap))
			}

			// Verify all types are present
			for _, ty := range tt.nsec.TypeBitMap {
				if !unpacked.HasType(ty) {
					t.Errorf("Type %d missing from bitmap", ty)
				}
			}
			if n2 != n {
				t.Errorf("Unpacked %d bytes, expected %d", n2, n)
			}
		})
	}
}

func TestRDataNSEC3RoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		nsec3 *RDataNSEC3
	}{
		{
			name: "standard_params",
			nsec3: &RDataNSEC3{
				HashAlgorithm: NSEC3HashSHA1,
				Flags:         0,
				Iterations:    10,
				Salt:          []byte{0xAA, 0xBB, 0xCC, 0xDD},
				NextHashed:    []byte{0x01, 0x02, 0x03, 0x04},
				TypeBitMap:    []uint16{TypeA, TypeNS, TypeSOA, TypeRRSIG, TypeNSEC3, TypeDNSKEY},
			},
		},
		{
			name: "opt_out",
			nsec3: &RDataNSEC3{
				HashAlgorithm: NSEC3HashSHA1,
				Flags:         NSEC3FlagOptOut,
				Iterations:    0,
				Salt:          []byte{},
				NextHashed:    []byte{0xFF},
				TypeBitMap:    []uint16{TypeNS, TypeDS},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Pack
			buf := make([]byte, tt.nsec3.Len())
			n, err := tt.nsec3.Pack(buf, 0)
			if err != nil {
				t.Fatalf("Pack failed: %v", err)
			}

			// Unpack
			unpacked := &RDataNSEC3{}
			n2, err := unpacked.Unpack(buf, 0, uint16(n))
			if err != nil {
				t.Fatalf("Unpack failed: %v", err)
			}

			// Verify
			if unpacked.HashAlgorithm != tt.nsec3.HashAlgorithm {
				t.Errorf("HashAlgorithm mismatch")
			}
			if unpacked.Flags != tt.nsec3.Flags {
				t.Errorf("Flags mismatch")
			}
			if unpacked.Iterations != tt.nsec3.Iterations {
				t.Errorf("Iterations mismatch")
			}
			if !bytes.Equal(unpacked.Salt, tt.nsec3.Salt) {
				t.Errorf("Salt mismatch")
			}
			if !bytes.Equal(unpacked.NextHashed, tt.nsec3.NextHashed) {
				t.Errorf("NextHashed mismatch")
			}
			if unpacked.IsOptOut() != (tt.nsec3.Flags&NSEC3FlagOptOut != 0) {
				t.Error("IsOptOut() returned incorrect value")
			}
			if n2 != n {
				t.Errorf("Unpacked %d bytes, expected %d", n2, n)
			}
		})
	}
}

func TestRDataNSEC3PARAMRoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		nsec3param *RDataNSEC3PARAM
	}{
		{
			name: "with_salt",
			nsec3param: &RDataNSEC3PARAM{
				HashAlgorithm: NSEC3HashSHA1,
				Flags:         0,
				Iterations:    10,
				Salt:          []byte{0xAA, 0xBB, 0xCC, 0xDD},
			},
		},
		{
			name: "no_salt",
			nsec3param: &RDataNSEC3PARAM{
				HashAlgorithm: NSEC3HashSHA1,
				Flags:         0,
				Iterations:    0,
				Salt:          []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Pack
			buf := make([]byte, tt.nsec3param.Len())
			n, err := tt.nsec3param.Pack(buf, 0)
			if err != nil {
				t.Fatalf("Pack failed: %v", err)
			}

			// Unpack
			unpacked := &RDataNSEC3PARAM{}
			n2, err := unpacked.Unpack(buf, 0, uint16(n))
			if err != nil {
				t.Fatalf("Unpack failed: %v", err)
			}

			// Verify
			if unpacked.HashAlgorithm != tt.nsec3param.HashAlgorithm {
				t.Errorf("HashAlgorithm mismatch")
			}
			if unpacked.Flags != tt.nsec3param.Flags {
				t.Errorf("Flags mismatch")
			}
			if unpacked.Iterations != tt.nsec3param.Iterations {
				t.Errorf("Iterations mismatch")
			}
			if !bytes.Equal(unpacked.Salt, tt.nsec3param.Salt) {
				t.Errorf("Salt mismatch")
			}
			if n2 != n {
				t.Errorf("Unpacked %d bytes, expected %d", n2, n)
			}
		})
	}
}

func TestAlgorithmToString(t *testing.T) {
	tests := []struct {
		algorithm uint8
		expected  string
	}{
		{AlgorithmRSASHA256, "RSASHA256"},
		{AlgorithmRSASHA512, "RSASHA512"},
		{AlgorithmECDSAP256SHA256, "ECDSAP256SHA256"},
		{AlgorithmECDSAP384SHA384, "ECDSAP384SHA384"},
		{AlgorithmED25519, "ED25519"},
		{AlgorithmED448, "ED448"},
		{99, "ALG99"}, // Unknown algorithm
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := AlgorithmToString(tt.algorithm)
			if result != tt.expected {
				t.Errorf("AlgorithmToString(%d) = %s, want %s", tt.algorithm, result, tt.expected)
			}
		})
	}
}

func TestIsAlgorithmSupported(t *testing.T) {
	supported := []uint8{
		AlgorithmRSASHA256,
		AlgorithmRSASHA512,
		AlgorithmECDSAP256SHA256,
		AlgorithmECDSAP384SHA384,
		AlgorithmED25519,
	}
	unsupported := []uint8{
		AlgorithmRSAMD5,
		AlgorithmRSASHA1,
		AlgorithmECCGOST,
	}

	for _, alg := range supported {
		if !IsAlgorithmSupported(alg) {
			t.Errorf("Algorithm %d should be supported", alg)
		}
	}

	for _, alg := range unsupported {
		if IsAlgorithmSupported(alg) {
			t.Errorf("Algorithm %d should not be supported", alg)
		}
	}
}

func TestNSECHasType(t *testing.T) {
	nsec := &RDataNSEC{
		NextDomain: nil,
		TypeBitMap: []uint16{TypeA, TypeNS, TypeSOA},
	}

	if !nsec.HasType(TypeA) {
		t.Error("Expected HasType(A) to be true")
	}
	if !nsec.HasType(TypeNS) {
		t.Error("Expected HasType(NS) to be true")
	}
	if nsec.HasType(TypeMX) {
		t.Error("Expected HasType(MX) to be false")
	}
}

func TestNSECAddRemoveType(t *testing.T) {
	nsec := &RDataNSEC{
		NextDomain: nil,
		TypeBitMap: []uint16{},
	}

	// Add type
	nsec.AddType(TypeA)
	if !nsec.HasType(TypeA) {
		t.Error("Expected type to be added")
	}

	// Add duplicate (should not add again)
	originalLen := len(nsec.TypeBitMap)
	nsec.AddType(TypeA)
	if len(nsec.TypeBitMap) != originalLen {
		t.Error("Duplicate type should not be added")
	}

	// Remove type
	nsec.RemoveType(TypeA)
	if nsec.HasType(TypeA) {
		t.Error("Expected type to be removed")
	}
}
