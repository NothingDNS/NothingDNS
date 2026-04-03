package dnssec

import (
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestDefaultSignerConfig(t *testing.T) {
	cfg := DefaultSignerConfig()

	if cfg.NSEC3Enabled {
		t.Error("Expected NSEC3Enabled to be false")
	}
	if cfg.NSEC3Algorithm != 1 {
		t.Errorf("Expected NSEC3Algorithm to be 1, got %d", cfg.NSEC3Algorithm)
	}
	if cfg.SignatureValidity != 30*24*time.Hour {
		t.Errorf("Expected SignatureValidity to be 30 days, got %v", cfg.SignatureValidity)
	}
	if cfg.InceptionOffset != 1*time.Hour {
		t.Errorf("Expected InceptionOffset to be 1 hour, got %v", cfg.InceptionOffset)
	}
}

func TestNewSigner(t *testing.T) {
	cfg := DefaultSignerConfig()
	s := NewSigner("example.com.", cfg)

	if s == nil {
		t.Fatal("NewSigner returned nil")
	}
	if s.zone != "example.com." {
		t.Errorf("Expected zone 'example.com.', got '%s'", s.zone)
	}
	if len(s.keys) != 0 {
		t.Error("Expected empty keys map")
	}
}

func TestSignerAddRemoveKey(t *testing.T) {
	s := NewSigner("example.com.", DefaultSignerConfig())

	key := &SigningKey{
		KeyTag: 12345,
		IsKSK:  true,
		IsZSK:  false,
	}

	s.AddKey(key)

	if len(s.keys) != 1 {
		t.Errorf("Expected 1 key, got %d", len(s.keys))
	}

	retrieved := s.GetKeys()
	if len(retrieved) != 1 {
		t.Errorf("Expected 1 key from GetKeys, got %d", len(retrieved))
	}

	s.RemoveKey(12345)

	if len(s.keys) != 0 {
		t.Errorf("Expected 0 keys after removal, got %d", len(s.keys))
	}
}

func TestSignerGetKSKsAndZSKs(t *testing.T) {
	s := NewSigner("example.com.", DefaultSignerConfig())

	ksk := &SigningKey{KeyTag: 1, IsKSK: true, IsZSK: false}
	zsk := &SigningKey{KeyTag: 2, IsKSK: false, IsZSK: true}
	both := &SigningKey{KeyTag: 3, IsKSK: true, IsZSK: true}

	s.AddKey(ksk)
	s.AddKey(zsk)
	s.AddKey(both)

	ksks := s.GetKSKs()
	if len(ksks) != 2 {
		t.Errorf("Expected 2 KSKs, got %d", len(ksks))
	}

	zsks := s.GetZSKs()
	if len(zsks) != 2 {
		t.Errorf("Expected 2 ZSKs, got %d", len(zsks))
	}
}

func TestSignerGenerateKeyPair(t *testing.T) {
	s := NewSigner("example.com.", DefaultSignerConfig())

	// Generate KSK
	ksk, err := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, true)
	if err != nil {
		t.Fatalf("GenerateKeyPair for KSK failed: %v", err)
	}

	if ksk == nil {
		t.Fatal("Generated KSK is nil")
	}
	if !ksk.IsKSK {
		t.Error("Expected IsKSK to be true")
	}
	if ksk.PrivateKey == nil {
		t.Error("Expected PrivateKey to not be nil")
	}
	if ksk.DNSKEY == nil {
		t.Error("Expected DNSKEY to not be nil")
	}
	if ksk.KeyTag == 0 {
		t.Error("Expected non-zero KeyTag")
	}

	// Generate ZSK
	zsk, err := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false)
	if err != nil {
		t.Fatalf("GenerateKeyPair for ZSK failed: %v", err)
	}

	if zsk == nil {
		t.Fatal("Generated ZSK is nil")
	}
	if !zsk.IsZSK {
		t.Error("Expected IsZSK to be true")
	}
}

func TestSignerSignZoneNoKeys(t *testing.T) {
	s := NewSigner("example.com.", DefaultSignerConfig())

	_, err := s.SignZone(nil)
	if err == nil {
		t.Error("Expected error when signing with no keys")
	}
}

func TestSignerSignZoneNoKSK(t *testing.T) {
	s := NewSigner("example.com.", DefaultSignerConfig())

	// Add only ZSK
	zsk, _ := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false)
	s.AddKey(zsk)

	// Create a simple A record
	name, _ := protocol.ParseName("www.example.com.")
	records := []*protocol.ResourceRecord{
		{
			Name:  name,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
		},
	}

	_, err := s.SignZone(records)
	if err == nil {
		t.Error("Expected error when signing with no KSK")
	}
}

func TestSignerSignZone(t *testing.T) {
	s := NewSigner("example.com.", DefaultSignerConfig())

	// Generate keys
	ksk, _ := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, true)
	zsk, _ := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false)
	s.AddKey(ksk)
	s.AddKey(zsk)

	// Create records
	name, _ := protocol.ParseName("www.example.com.")
	records := []*protocol.ResourceRecord{
		{
			Name:  name,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
		},
	}

	signed, err := s.SignZone(records)
	if err != nil {
		t.Fatalf("SignZone failed: %v", err)
	}

	// Should have: A record + RRSIG for A + DNSKEYs + RRSIG for DNSKEY + NSEC records
	if len(signed) < 4 {
		t.Errorf("Expected at least 4 signed records, got %d", len(signed))
	}

	// Check for DNSKEY records
	var dnskeyCount int
	for _, rr := range signed {
		if rr.Type == protocol.TypeDNSKEY {
			dnskeyCount++
		}
	}
	if dnskeyCount != 2 {
		t.Errorf("Expected 2 DNSKEY records, got %d", dnskeyCount)
	}

	// Check for RRSIG records
	var rrsigCount int
	for _, rr := range signed {
		if rr.Type == protocol.TypeRRSIG {
			rrsigCount++
		}
	}
	if rrsigCount < 2 {
		t.Errorf("Expected at least 2 RRSIG records, got %d", rrsigCount)
	}
}

func TestSignerSignZoneWithNSEC3(t *testing.T) {
	cfg := DefaultSignerConfig()
	cfg.NSEC3Enabled = true
	cfg.NSEC3Iterations = 10
	cfg.NSEC3Salt = []byte{0xAA, 0xBB}

	s := NewSigner("example.com.", cfg)

	// Generate keys
	ksk, _ := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, true)
	zsk, _ := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false)
	s.AddKey(ksk)
	s.AddKey(zsk)

	// Create records
	name, _ := protocol.ParseName("www.example.com.")
	records := []*protocol.ResourceRecord{
		{
			Name:  name,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
		},
	}

	signed, err := s.SignZone(records)
	if err != nil {
		t.Fatalf("SignZone with NSEC3 failed: %v", err)
	}

	// Check for NSEC3 records
	var nsec3Count int
	for _, rr := range signed {
		if rr.Type == protocol.TypeNSEC3 {
			nsec3Count++
		}
	}
	if nsec3Count == 0 {
		t.Error("Expected NSEC3 records")
	}
}

func TestGenerateNSEC(t *testing.T) {
	s := NewSigner("example.com.", DefaultSignerConfig())

	name1, _ := protocol.ParseName("example.com.")
	name2, _ := protocol.ParseName("www.example.com.")

	records := []*protocol.ResourceRecord{
		{
			Name:  name1,
			Type:  protocol.TypeNS,
			Class: protocol.ClassIN,
			TTL:   86400,
			Data:  &protocol.RDataNS{NSDName: name1},
		},
		{
			Name:  name1,
			Type:  protocol.TypeSOA,
			Class: protocol.ClassIN,
			TTL:   86400,
			Data:  &protocol.RDataSOA{MName: name1, RName: name1},
		},
		{
			Name:  name2,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
		},
	}

	nsecRecords := s.generateNSEC(records)

	// Should have one NSEC per unique name
	if len(nsecRecords) != 2 {
		t.Errorf("Expected 2 NSEC records, got %d", len(nsecRecords))
	}

	// Verify NSEC structure
	for _, rr := range nsecRecords {
		if rr.Type != protocol.TypeNSEC {
			t.Errorf("Expected NSEC type, got %d", rr.Type)
		}

		nsec, ok := rr.Data.(*protocol.RDataNSEC)
		if !ok {
			t.Error("Expected RDataNSEC")
			continue
		}

		if nsec.NextDomain == nil {
			t.Error("Expected NextDomain to be set")
		}

		if len(nsec.TypeBitMap) == 0 {
			t.Error("Expected non-empty TypeBitMap")
		}
	}
}

func TestGenerateNSEC3(t *testing.T) {
	cfg := DefaultSignerConfig()
	cfg.NSEC3Iterations = 5
	cfg.NSEC3Salt = []byte{0x01, 0x02}

	s := NewSigner("example.com.", cfg)

	name1, _ := protocol.ParseName("example.com.")
	name2, _ := protocol.ParseName("www.example.com.")

	records := []*protocol.ResourceRecord{
		{
			Name:  name1,
			Type:  protocol.TypeNS,
			Class: protocol.ClassIN,
			TTL:   86400,
			Data:  &protocol.RDataNS{NSDName: name1},
		},
		{
			Name:  name2,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
		},
	}

	nsec3Records := s.generateNSEC3(records)

	// Should have one NSEC3 per unique name
	if len(nsec3Records) != 2 {
		t.Errorf("Expected 2 NSEC3 records, got %d", len(nsec3Records))
	}

	// Verify NSEC3 structure
	for _, rr := range nsec3Records {
		if rr.Type != protocol.TypeNSEC3 {
			t.Errorf("Expected NSEC3 type, got %d", rr.Type)
		}

		nsec3, ok := rr.Data.(*protocol.RDataNSEC3)
		if !ok {
			t.Error("Expected RDataNSEC3")
			continue
		}

		if nsec3.HashAlgorithm != 1 {
			t.Errorf("Expected HashAlgorithm 1, got %d", nsec3.HashAlgorithm)
		}

		if nsec3.Iterations != 5 {
			t.Errorf("Expected Iterations 5, got %d", nsec3.Iterations)
		}

		if len(nsec3.Salt) != 2 {
			t.Errorf("Expected Salt length 2, got %d", len(nsec3.Salt))
		}

		if len(nsec3.NextHashed) == 0 {
			t.Error("Expected non-empty NextHashed")
		}
	}
}

func TestCreateDS(t *testing.T) {
	// Create a DNSKEY
	dnskey := &protocol.RDataDNSKEY{
		Flags:     protocol.DNSKEYFlagZone | protocol.DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: protocol.AlgorithmECDSAP256SHA256,
		PublicKey: []byte{0x01, 0x02, 0x03, 0x04},
	}

	ds, err := CreateDS("example.com.", dnskey, 2) // SHA-256
	if err != nil {
		t.Fatalf("CreateDS failed: %v", err)
	}

	if ds == nil {
		t.Fatal("DS is nil")
	}

	if ds.Zone != "example.com." {
		t.Errorf("Expected zone 'example.com.', got '%s'", ds.Zone)
	}

	if ds.Algorithm != protocol.AlgorithmECDSAP256SHA256 {
		t.Errorf("Expected algorithm %d, got %d", protocol.AlgorithmECDSAP256SHA256, ds.Algorithm)
	}

	if ds.DigestType != 2 {
		t.Errorf("Expected digest type 2, got %d", ds.DigestType)
	}

	if len(ds.Digest) == 0 {
		t.Error("Expected non-empty digest")
	}
}

func TestCanonicalWireName(t *testing.T) {
	tests := []struct {
		input    string
		expected []byte
	}{
		{
			input:    "example.com.",
			expected: []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
		{
			input:    "www.EXAMPLE.COM",
			expected: []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
	}

	for _, tt := range tests {
		result := protocol.CanonicalWireName(tt.input)

		if len(result) != len(tt.expected) {
			t.Errorf("canonicalWireName(%s): expected length %d, got %d", tt.input, len(tt.expected), len(result))
			continue
		}

		for i := range tt.expected {
			if result[i] != tt.expected[i] {
				t.Errorf("canonicalWireName(%s): byte %d expected %d, got %d", tt.input, i, tt.expected[i], result[i])
				break
			}
		}
	}
}

func TestCanonicalSort(t *testing.T) {
	name1, _ := protocol.ParseName("a.example.com.")
	name2, _ := protocol.ParseName("b.example.com.")

	records := []*protocol.ResourceRecord{
		{Name: name2, Type: protocol.TypeA},
		{Name: name1, Type: protocol.TypeA},
	}

	canonicalSort(records)

	if records[0].Name.String() != "a.example.com." {
		t.Errorf("Expected first record to be a.example.com., got %s", records[0].Name.String())
	}
	if records[1].Name.String() != "b.example.com." {
		t.Errorf("Expected second record to be b.example.com., got %s", records[1].Name.String())
	}
}

func TestSignRRSet(t *testing.T) {
	s := NewSigner("example.com.", DefaultSignerConfig())

	zsk, err := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	s.AddKey(zsk)

	name, _ := protocol.ParseName("www.example.com.")
	rrSet := []*protocol.ResourceRecord{
		{
			Name:  name,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
		},
	}

	now := uint32(time.Now().Unix())
	rrsig, err := s.SignRRSet(rrSet, zsk, now, now+86400)
	if err != nil {
		t.Fatalf("SignRRSet failed: %v", err)
	}
	if rrsig == nil {
		t.Fatal("Expected non-nil RRSIG record")
	}
	if rrsig.Type != protocol.TypeRRSIG {
		t.Errorf("Expected TypeRRSIG, got %d", rrsig.Type)
	}

	rdata, ok := rrsig.Data.(*protocol.RDataRRSIG)
	if !ok {
		t.Fatal("Expected RDataRRSIG")
	}
	if rdata.TypeCovered != protocol.TypeA {
		t.Errorf("Expected TypeCovered=A(%d), got %d", protocol.TypeA, rdata.TypeCovered)
	}
	if rdata.Algorithm != protocol.AlgorithmECDSAP256SHA256 {
		t.Errorf("Expected Algorithm ECDSAP256SHA256, got %d", rdata.Algorithm)
	}
	if len(rdata.Signature) == 0 {
		t.Error("Expected non-empty Signature")
	}
	if rdata.KeyTag != zsk.KeyTag {
		t.Errorf("Expected KeyTag %d, got %d", zsk.KeyTag, rdata.KeyTag)
	}
}

func TestSignRRSetEmpty(t *testing.T) {
	s := NewSigner("example.com.", DefaultSignerConfig())
	zsk, _ := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false)

	_, err := s.SignRRSet(nil, zsk, 0, 0)
	if err == nil {
		t.Error("Expected error for empty RRSet")
	}
}

func TestSignRRSetMultipleRecords(t *testing.T) {
	s := NewSigner("example.com.", DefaultSignerConfig())

	zsk, err := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	s.AddKey(zsk)

	name, _ := protocol.ParseName("www.example.com.")
	rrSet := []*protocol.ResourceRecord{
		{
			Name:  name,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
		},
		{
			Name:  name,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 2}},
		},
	}

	now := uint32(time.Now().Unix())
	rrsig, err := s.SignRRSet(rrSet, zsk, now, now+86400)
	if err != nil {
		t.Fatalf("SignRRSet with multiple records failed: %v", err)
	}
	if rrsig == nil {
		t.Fatal("Expected non-nil RRSIG record")
	}

	rdata, ok := rrsig.Data.(*protocol.RDataRRSIG)
	if !ok {
		t.Fatal("Expected RDataRRSIG")
	}
	if len(rdata.Signature) == 0 {
		t.Error("Expected non-empty Signature for multi-record RRSet")
	}
}
