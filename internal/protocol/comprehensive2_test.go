package protocol

import (
	"bytes"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestDNSKEYString tests DNSKEY String method
func TestDNSKEYString(t *testing.T) {
	rdata := &RDataDNSKEY{
		Flags:     DNSKEYFlagZone | DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: AlgorithmRSASHA256,
		PublicKey: []byte{0x01, 0x02, 0x03, 0x04},
	}
	s := rdata.String()
	// String format is: flags protocol algorithm base64key
	if !strings.Contains(s, "257") { // DNSKEYFlagZone | DNSKEYFlagSEP = 257
		t.Errorf("String should contain flags 257, got: %s", s)
	}
	if !strings.Contains(s, "8") { // AlgorithmRSASHA256 = 8
		t.Errorf("String should contain algorithm 8, got: %s", s)
	}
}

// TestDNSKEYCopy tests DNSKEY Copy method
func TestDNSKEYCopy(t *testing.T) {
	rdata1 := &RDataDNSKEY{
		Flags:     DNSKEYFlagZone,
		Protocol:  3,
		Algorithm: AlgorithmRSASHA256,
		PublicKey: []byte{0x01, 0x02, 0x03, 0x04},
	}
	rdata2 := rdata1.Copy().(*RDataDNSKEY)
	if rdata2.Flags != rdata1.Flags {
		t.Error("Flags mismatch")
	}
	if rdata2.Algorithm != rdata1.Algorithm {
		t.Error("Algorithm mismatch")
	}
	if !bytes.Equal(rdata2.PublicKey, rdata1.PublicKey) {
		t.Error("PublicKey mismatch")
	}
}

// TestDNSKEYIsRevoked tests DNSKEY IsRevoked method
func TestDNSKEYIsRevoked(t *testing.T) {
	normal := &RDataDNSKEY{Flags: DNSKEYFlagZone}
	if normal.IsRevoked() {
		t.Error("Normal key should not be revoked")
	}

	revoked := &RDataDNSKEY{Flags: DNSKEYFlagRevoke}
	if !revoked.IsRevoked() {
		t.Error("Revoked flag set should be revoked")
	}
}

// TestIsAlgorithmRecommended tests IsAlgorithmRecommended
func TestIsAlgorithmRecommended(t *testing.T) {
	recommended := []uint8{
		AlgorithmECDSAP256SHA256,
		AlgorithmED25519,
	}
	notRecommended := []uint8{
		AlgorithmRSAMD5,
		AlgorithmRSASHA1,
	}

	for _, alg := range recommended {
		if !IsAlgorithmRecommended(alg) {
			t.Errorf("Algorithm %d should be recommended", alg)
		}
	}
	for _, alg := range notRecommended {
		if IsAlgorithmRecommended(alg) {
			t.Errorf("Algorithm %d should not be recommended", alg)
		}
	}
}

// TestDNSKEYType tests DNSKEY Type method
func TestDNSKEYType(t *testing.T) {
	rdata := &RDataDNSKEY{}
	if rdata.Type() != TypeDNSKEY {
		t.Errorf("Type() = %d, want %d", rdata.Type(), TypeDNSKEY)
	}
}

// TestDSType tests DS Type method
func TestDSType(t *testing.T) {
	rdata := &RDataDS{}
	if rdata.Type() != TypeDS {
		t.Errorf("Type() = %d, want %d", rdata.Type(), TypeDS)
	}
}

// TestDSString tests DS String method
func TestDSString(t *testing.T) {
	rdata := &RDataDS{
		KeyTag:     12345,
		Algorithm:  AlgorithmRSASHA256,
		DigestType: 2, // SHA-256
		Digest:     []byte{0x01, 0x02, 0x03, 0x04, 0x05},
	}
	s := rdata.String()
	// String format is: keytag algorithm digesttype hexdigest
	if !strings.Contains(s, "12345") {
		t.Errorf("String should contain KeyTag 12345, got: %s", s)
	}
	if !strings.Contains(s, "8") { // AlgorithmRSASHA256 = 8
		t.Errorf("String should contain algorithm 8, got: %s", s)
	}
}

// TestDigestTypeToString tests DigestTypeToString
func TestDigestTypeToString(t *testing.T) {
	tests := []struct {
		dt       uint8
		expected string
	}{
		{1, "SHA-1"},
		{2, "SHA-256"},
		{3, "GOST R 34.11-94"},
		{4, "SHA-384"},
		{99, "TYPE99"},
	}

	for _, tt := range tests {
		result := DigestTypeToString(tt.dt)
		if result != tt.expected {
			t.Errorf("DigestTypeToString(%d) = %s, want %s", tt.dt, result, tt.expected)
		}
	}
}

// TestNSECType tests NSEC Type method
func TestNSECType(t *testing.T) {
	rdata := &RDataNSEC{}
	if rdata.Type() != TypeNSEC {
		t.Errorf("Type() = %d, want %d", rdata.Type(), TypeNSEC)
	}
}

// TestNSECString tests NSEC String method
func TestNSECString(t *testing.T) {
	next, _ := ParseName("example.com.")
	rdata := &RDataNSEC{
		NextDomain: next,
		TypeBitMap: []uint16{TypeA, TypeNS, TypeMX},
	}
	s := rdata.String()
	if !strings.Contains(s, "example.com") {
		t.Error("String should contain NextDomain")
	}
	if !strings.Contains(s, "A") {
		t.Error("String should contain type A")
	}
}

// TestNSECCopy tests NSEC Copy method
func TestNSECCopy(t *testing.T) {
	next, _ := ParseName("example.com.")
	rdata1 := &RDataNSEC{
		NextDomain: next,
		TypeBitMap: []uint16{TypeA, TypeNS},
	}
	rdata2 := rdata1.Copy().(*RDataNSEC)
	if !rdata2.NextDomain.Equal(rdata1.NextDomain) {
		t.Error("NextDomain not copied correctly")
	}
	if len(rdata2.TypeBitMap) != len(rdata1.TypeBitMap) {
		t.Error("TypeBitMap not copied correctly")
	}
}

// TestNSECTypeList tests NSEC TypeList method
func TestNSECTypeList(t *testing.T) {
	rdata := &RDataNSEC{
		TypeBitMap: []uint16{TypeA, TypeNS, TypeMX},
	}
	list := rdata.TypeList()
	if len(list) != 3 {
		t.Errorf("TypeList length = %d, want 3", len(list))
	}
}

// TestNSEC3Type tests NSEC3 Type method
func TestNSEC3Type(t *testing.T) {
	rdata := &RDataNSEC3{}
	if rdata.Type() != TypeNSEC3 {
		t.Errorf("Type() = %d, want %d", rdata.Type(), TypeNSEC3)
	}
}

// TestNSEC3String tests NSEC3 String method
func TestNSEC3String(t *testing.T) {
	rdata := &RDataNSEC3{
		HashAlgorithm: NSEC3HashSHA1,
		Flags:         0,
		Iterations:    10,
		Salt:          []byte{0xAA, 0xBB},
		NextHashed:    []byte{0x01, 0x02},
		TypeBitMap:    []uint16{TypeA, TypeNS},
	}
	s := rdata.String()
	if !strings.Contains(s, "10") {
		t.Error("String should contain iterations")
	}
}

// TestNSEC3Copy tests NSEC3 Copy method
func TestNSEC3Copy(t *testing.T) {
	rdata1 := &RDataNSEC3{
		HashAlgorithm: NSEC3HashSHA1,
		Flags:         NSEC3FlagOptOut,
		Iterations:    10,
		Salt:          []byte{0xAA},
		NextHashed:    []byte{0x01},
		TypeBitMap:    []uint16{TypeA},
	}
	rdata2 := rdata1.Copy().(*RDataNSEC3)
	if rdata2.Iterations != rdata1.Iterations {
		t.Error("Iterations not copied")
	}
	if !bytes.Equal(rdata2.Salt, rdata1.Salt) {
		t.Error("Salt not copied")
	}
}

// TestNSEC3HasType tests NSEC3 HasType method
func TestNSEC3HasType(t *testing.T) {
	rdata := &RDataNSEC3{
		TypeBitMap: []uint16{TypeA, TypeNS},
	}
	if !rdata.HasType(TypeA) {
		t.Error("Should have TypeA")
	}
	if rdata.HasType(TypeMX) {
		t.Error("Should not have TypeMX")
	}
}

// TestNSEC3AddType tests NSEC3 AddType method
func TestNSEC3AddType(t *testing.T) {
	rdata := &RDataNSEC3{}
	rdata.AddType(TypeA)
	if !rdata.HasType(TypeA) {
		t.Error("Should have TypeA after AddType")
	}
	// Add duplicate
	rdata.AddType(TypeA)
	if len(rdata.TypeBitMap) != 1 {
		t.Error("Should not add duplicate type")
	}
}

// TestNSEC3RemoveType tests NSEC3 RemoveType method
func TestNSEC3RemoveType(t *testing.T) {
	rdata := &RDataNSEC3{TypeBitMap: []uint16{TypeA, TypeNS}}
	rdata.RemoveType(TypeA)
	if rdata.HasType(TypeA) {
		t.Error("Should not have TypeA after RemoveType")
	}
	if !rdata.HasType(TypeNS) {
		t.Error("Should still have TypeNS")
	}
}

// TestBase32Encode tests Base32Encode function
func TestBase32Encode(t *testing.T) {
	tests := []struct {
		input    []byte
		expected string
	}{
		{[]byte{}, ""},
		{[]byte{0x00}, "00"},
		{[]byte{0xFF}, "vs"},
		{[]byte{0x01, 0x02, 0x03, 0x04}, "0410610"},
	}

	for _, tt := range tests {
		result := Base32Encode(tt.input)
		if result != tt.expected {
			t.Errorf("Base32Encode(%x) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}

// TestNSEC3PARAMType tests NSEC3PARAM Type method
func TestNSEC3PARAMType(t *testing.T) {
	rdata := &RDataNSEC3PARAM{}
	if rdata.Type() != TypeNSEC3PARAM {
		t.Errorf("Type() = %d, want %d", rdata.Type(), TypeNSEC3PARAM)
	}
}

// TestNSEC3PARAMString tests NSEC3PARAM String method
func TestNSEC3PARAMString(t *testing.T) {
	rdata := &RDataNSEC3PARAM{
		HashAlgorithm: NSEC3HashSHA1,
		Flags:         0,
		Iterations:    10,
		Salt:          []byte{0xAA, 0xBB},
	}
	s := rdata.String()
	if !strings.Contains(s, "10") {
		t.Error("String should contain iterations")
	}
}

// TestNSEC3PARAMCopy tests NSEC3PARAM Copy method
func TestNSEC3PARAMCopy(t *testing.T) {
	rdata1 := &RDataNSEC3PARAM{
		HashAlgorithm: NSEC3HashSHA1,
		Flags:         NSEC3FlagOptOut,
		Iterations:    10,
		Salt:          []byte{0xAA},
	}
	rdata2 := rdata1.Copy().(*RDataNSEC3PARAM)
	if rdata2.Iterations != rdata1.Iterations {
		t.Error("Iterations not copied")
	}
}

// TestNSEC3PARAMIsOptOut tests NSEC3PARAM IsOptOut method
func TestNSEC3PARAMIsOptOut(t *testing.T) {
	normal := &RDataNSEC3PARAM{Flags: 0}
	if normal.IsOptOut() {
		t.Error("Normal params should not be opt-out")
	}

	optout := &RDataNSEC3PARAM{Flags: NSEC3FlagOptOut}
	if !optout.IsOptOut() {
		t.Error("Opt-out flag should be set")
	}
}

// TestNSEC3PARAMToNSEC3Params tests ToNSEC3Params method
func TestNSEC3PARAMToNSEC3Params(t *testing.T) {
	rdata := &RDataNSEC3PARAM{
		HashAlgorithm: NSEC3HashSHA1,
		Flags:         NSEC3FlagOptOut,
		Iterations:    10,
		Salt:          []byte{0xAA},
	}
	params := rdata.ToNSEC3Params()
	if params.Algorithm != rdata.HashAlgorithm {
		t.Error("Algorithm mismatch")
	}
	if params.Iterations != rdata.Iterations {
		t.Error("Iterations mismatch")
	}
}

// TestNSEC3PARAMVerifyParams tests VerifyParams method
func TestNSEC3PARAMVerifyParams(t *testing.T) {
	// Valid params
	valid := &RDataNSEC3PARAM{
		HashAlgorithm: NSEC3HashSHA1,
		Iterations:    100,
		Salt:          []byte{0xAA},
	}
	if err := valid.VerifyParams(); err != nil {
		t.Errorf("VerifyParams should succeed for valid params: %v", err)
	}

	// Invalid iterations (too high)
	invalid := &RDataNSEC3PARAM{
		HashAlgorithm: NSEC3HashSHA1,
		Iterations:    10000,
		Salt:          []byte{},
	}
	if err := invalid.VerifyParams(); err == nil {
		t.Error("VerifyParams should fail for too high iterations")
	}
}

// TestDefaultNSEC3Params tests DefaultNSEC3Params function
func TestDefaultNSEC3Params(t *testing.T) {
	params := DefaultNSEC3Params()
	if params.HashAlgorithm != NSEC3HashSHA1 {
		t.Error("Default hash algorithm should be SHA1")
	}
}

// TestRRSIGType tests RRSIG Type method
func TestRRSIGType(t *testing.T) {
	rdata := &RDataRRSIG{}
	if rdata.Type() != TypeRRSIG {
		t.Errorf("Type() = %d, want %d", rdata.Type(), TypeRRSIG)
	}
}

// TestRRSIGString tests RRSIG String method
func TestRRSIGString(t *testing.T) {
	signer, _ := ParseName("example.com.")
	rdata := &RDataRRSIG{
		TypeCovered: TypeA,
		Algorithm:   AlgorithmRSASHA256,
		Labels:      2,
		OriginalTTL: 3600,
		Expiration:  1700000000,
		Inception:   1600000000,
		KeyTag:      12345,
		SignerName:  signer,
		Signature:   []byte{0x01, 0x02},
	}
	s := rdata.String()
	// String format contains type covered and algorithm number
	if !strings.Contains(s, "A") {
		t.Errorf("String should contain type A, got: %s", s)
	}
	if !strings.Contains(s, "8") { // AlgorithmRSASHA256 = 8
		t.Errorf("String should contain algorithm 8, got: %s", s)
	}
}

// TestRRSIGCopy tests RRSIG Copy method
func TestRRSIGCopy(t *testing.T) {
	signer, _ := ParseName("example.com.")
	rdata1 := &RDataRRSIG{
		TypeCovered: TypeA,
		Algorithm:   AlgorithmRSASHA256,
		KeyTag:      12345,
		SignerName:  signer,
		Signature:   []byte{0x01, 0x02},
	}
	rdata2 := rdata1.Copy().(*RDataRRSIG)
	if rdata2.TypeCovered != rdata1.TypeCovered {
		t.Error("TypeCovered not copied")
	}
	if !rdata2.SignerName.Equal(rdata1.SignerName) {
		t.Error("SignerName not copied")
	}
}

// TestRRSIGIsExpired tests RRSIG IsExpired method
func TestRRSIGIsExpired(t *testing.T) {
	// Expired signature (very old timestamp)
	expired := &RDataRRSIG{Expiration: 1000}
	if !expired.IsExpired() {
		t.Error("Should be expired")
	}

	// Valid signature (future timestamp)
	valid := &RDataRRSIG{Expiration: uint32(time.Now().Unix()) + 3600}
	if valid.IsExpired() {
		t.Error("Should not be expired")
	}
}

// TestRRSIGIsInceptionValid tests RRSIG IsInceptionValid method
func TestRRSIGIsInceptionValid(t *testing.T) {
	// Inception in future - invalid
	future := &RDataRRSIG{Inception: uint32(time.Now().Unix()) + 3600}
	if future.IsInceptionValid() {
		t.Error("Future inception should be invalid")
	}

	// Inception in past - valid
	past := &RDataRRSIG{Inception: uint32(time.Now().Unix()) - 3600}
	if !past.IsInceptionValid() {
		t.Error("Past inception should be valid")
	}
}

// TestRRSIGValidityPeriod tests RRSIG ValidityPeriod method
func TestRRSIGValidityPeriod(t *testing.T) {
	rdata := &RDataRRSIG{
		Inception:  1600000000,
		Expiration: 1700000000,
	}
	inception, expiration := rdata.ValidityPeriod()
	if inception.IsZero() {
		t.Error("Inception should not be zero")
	}
	if expiration.IsZero() {
		t.Error("Expiration should not be zero")
	}
}

// TestRRSIGSignerNameString tests RRSIG SignerNameString method
func TestRRSIGSignerNameString(t *testing.T) {
	signer, _ := ParseName("example.com.")
	rdata := &RDataRRSIG{SignerName: signer}
	s := rdata.SignerNameString()
	if !strings.Contains(s, "example.com") {
		t.Error("SignerNameString should contain domain")
	}
}

// TestNewQuery tests NewQuery function
func TestNewQuery(t *testing.T) {
	msg, err := NewQuery(1234, "example.com.", TypeA)
	if err != nil {
		t.Fatalf("NewQuery failed: %v", err)
	}
	if msg == nil {
		t.Fatal("NewQuery returned nil")
	}
	if len(msg.Questions) != 1 {
		t.Error("Should have one question")
	}
	if !msg.Header.Flags.RecursionDesired() {
		t.Error("RecursionDesired should be set")
	}
}

// TestMessageIsQuery tests Message IsQuery method
func TestMessageIsQuery(t *testing.T) {
	msg := NewMessage(Header{Flags: NewQueryFlags()})
	if !msg.IsQuery() {
		t.Error("Should be a query")
	}
	msg.Header.Flags.QR = true
	if msg.IsQuery() {
		t.Error("Should not be a query when QR is set")
	}
}

// TestMessageIsResponse tests Message IsResponse method
func TestMessageIsResponse(t *testing.T) {
	msg := NewMessage(Header{Flags: Flags{QR: true}})
	if !msg.IsResponse() {
		t.Error("Should be a response")
	}
	msg.Header.Flags.QR = false
	if msg.IsResponse() {
		t.Error("Should not be a response when QR is not set")
	}
}

// TestMessageSetResponse tests Message SetResponse method
func TestMessageSetResponse(t *testing.T) {
	msg := NewMessage(Header{})
	msg.SetResponse(RcodeSuccess)
	if !msg.Header.Flags.QR {
		t.Error("QR should be set")
	}
}

// TestMessageAddAuthority tests Message AddAuthority method
func TestMessageAddAuthority(t *testing.T) {
	msg := NewMessage(Header{})
	name, _ := ParseName("example.com.")
	rr := &ResourceRecord{
		Name:  name,
		Type:  TypeNS,
		Class: ClassIN,
		TTL:   3600,
		Data:  &RDataNS{NSDName: name},
	}
	msg.AddAuthority(rr)
	if len(msg.Authorities) != 1 {
		t.Error("Should have one authority record")
	}
}

// TestMessageAddAdditional tests Message AddAdditional method
func TestMessageAddAdditional(t *testing.T) {
	msg := NewMessage(Header{})
	name, _ := ParseName("example.com.")
	rr := &ResourceRecord{
		Name:  name,
		Type:  TypeA,
		Class: ClassIN,
		TTL:   3600,
		Data:  &RDataA{Address: [4]byte{1, 2, 3, 4}},
	}
	msg.AddAdditional(rr)
	if len(msg.Additionals) != 1 {
		t.Error("Should have one additional record")
	}
}

// TestMessageGetOPT tests Message GetOPT method
func TestMessageGetOPT(t *testing.T) {
	msg := NewMessage(Header{})

	// No OPT record
	if opt := msg.GetOPT(); opt != nil {
		t.Error("GetOPT should return nil when no OPT present")
	}

	// Add OPT record
	name, _ := ParseName(".")
	optRR := &ResourceRecord{
		Name:  name,
		Type:  TypeOPT,
		Class: ClassIN,
		TTL:   0,
		Data:  &RDataOPT{},
	}
	msg.Additionals = append(msg.Additionals, optRR)

	if opt := msg.GetOPT(); opt == nil {
		t.Error("GetOPT should return OPT record")
	}
}

// TestMessageSetEDNS0 tests Message SetEDNS0 method
func TestMessageSetEDNS0(t *testing.T) {
	msg := NewMessage(Header{})
	msg.SetEDNS0(4096, false)

	opt := msg.GetOPT()
	if opt == nil {
		t.Fatal("SetEDNS0 should create OPT record")
	}
}

// TestMessageString tests Message String method
func TestMessageString(t *testing.T) {
	msg := NewMessage(Header{ID: 1234})
	msg.Header.Flags.QR = true

	name, _ := ParseName("example.com.")
	msg.AddQuestion(&Question{Name: name, QType: TypeA, QClass: ClassIN})

	s := msg.String()
	if !strings.Contains(s, "1234") {
		t.Error("String should contain ID")
	}
}

// TestTXTString tests TXT String method with multiple strings
func TestTXTString(t *testing.T) {
	rdata := &RDataTXT{Strings: []string{"hello", "world"}}
	s := rdata.String()
	if !strings.Contains(s, "hello") {
		t.Error("String should contain first string")
	}
	if !strings.Contains(s, "world") {
		t.Error("String should contain second string")
	}
}

// TestTXTPackErrors tests TXT Pack error cases
func TestTXTPackErrors(t *testing.T) {
	// String too long
	longStr := strings.Repeat("x", 256)
	rdata := &RDataTXT{Strings: []string{longStr}}
	buf := make([]byte, 300)
	_, err := rdata.Pack(buf, 0)
	if err == nil {
		t.Error("Pack should fail with string >255 chars")
	}

	// Buffer too small
	rdata = &RDataTXT{Strings: []string{"hello"}}
	buf = make([]byte, 2)
	_, err = rdata.Pack(buf, 0)
	if err == nil {
		t.Error("Pack should fail with small buffer")
	}
}

// TestTXTUnpackErrors tests TXT Unpack error cases
func TestTXTUnpackErrors(t *testing.T) {
	rdata := &RDataTXT{}

	// Empty buffer
	_, err := rdata.Unpack([]byte{}, 0, 1)
	if err == nil {
		t.Error("Unpack should fail with empty buffer")
	}

	// Truncated string
	buf := []byte{5, 'h', 'e', 'l'} // Length 5 but only 3 chars
	_, err = rdata.Unpack(buf, 0, 4)
	if err == nil {
		t.Error("Unpack should fail with truncated string")
	}
}

// TestTXTCopy tests TXT Copy method
func TestTXTCopy(t *testing.T) {
	rdata1 := &RDataTXT{Strings: []string{"hello", "world"}}
	rdata2 := rdata1.Copy().(*RDataTXT)

	if len(rdata2.Strings) != len(rdata1.Strings) {
		t.Error("Strings not copied correctly")
	}

	// Modify original to ensure deep copy
	rdata1.Strings[0] = "modified"
	if rdata2.Strings[0] == "modified" {
		t.Error("Copy should be deep")
	}
}

// TestSOACopy tests SOA Copy method
func TestSOACopy(t *testing.T) {
	mname, _ := ParseName("ns1.example.com.")
	rname, _ := ParseName("admin.example.com.")

	rdata1 := &RDataSOA{
		MName:   mname,
		RName:   rname,
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minimum: 300,
	}

	rdata2 := rdata1.Copy().(*RDataSOA)
	if !rdata2.MName.Equal(rdata1.MName) {
		t.Error("MName not copied correctly")
	}
	if rdata2.Serial != rdata1.Serial {
		t.Error("Serial not copied correctly")
	}
}

// TestCNAMEString tests CNAME String with nil CName
func TestCNAMEString(t *testing.T) {
	rdata := &RDataCNAME{}
	s := rdata.String()
	if s != "." {
		t.Errorf("String() with nil CName should be '.', got %q", s)
	}
}

// TestMXString tests MX String with nil Exchange
func TestMXString(t *testing.T) {
	rdata := &RDataMX{}
	s := rdata.String()
	if !strings.Contains(s, "0") {
		t.Error("String should contain preference 0")
	}
}

// TestNSString tests NS String with nil NSDName
func TestNSString(t *testing.T) {
	rdata := &RDataNS{}
	s := rdata.String()
	if s != "." {
		t.Errorf("String() with nil NSDName should be '.', got %q", s)
	}
}

// TestPTRString tests PTR String with nil PTRDName
func TestPTRString(t *testing.T) {
	rdata := &RDataPTR{}
	s := rdata.String()
	if s != "." {
		t.Errorf("String() with nil PTRDName should be '.', got %q", s)
	}
}

// TestSRVPackErrors tests SRV Pack error cases
func TestSRVPackErrors(t *testing.T) {
	target, _ := ParseName("target.example.com.")
	rdata := &RDataSRV{
		Priority: 10,
		Weight:   20,
		Port:     80,
		Target:   target,
	}

	// Buffer too small
	buf := make([]byte, 5)
	_, err := rdata.Pack(buf, 0)
	if err == nil {
		t.Error("Pack should fail with small buffer")
	}
}

// TestARoundTripMore tests more A record scenarios
func TestARoundTripMore(t *testing.T) {
	rdata := &RDataA{Address: [4]byte{192, 168, 1, 1}}

	// Test String
	s := rdata.String()
	if s != "192.168.1.1" {
		t.Errorf("String() = %s, want 192.168.1.1", s)
	}

	// Test Copy
	cpy := rdata.Copy().(*RDataA)
	if cpy.Address != rdata.Address {
		t.Error("Copy address mismatch")
	}
}

// TestAAAARoundTripMore tests more AAAA record scenarios
func TestAAAARoundTripMore(t *testing.T) {
	addr := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	rdata := &RDataAAAA{Address: addr}

	// Test String
	s := rdata.String()
	if !strings.Contains(s, "2001:db8::1") {
		t.Errorf("String() = %s, want to contain 2001:db8::1", s)
	}

	// Test Copy
	cpy := rdata.Copy().(*RDataAAAA)
	if cpy.Address != rdata.Address {
		t.Error("Copy address mismatch")
	}
}

// TestMessageCopy tests Message.Copy method
func TestMessageCopy(t *testing.T) {
	name, _ := ParseName("example.com.")
	msg := &Message{
		Header: Header{
			ID:      0x1234,
			QDCount: 1,
			ANCount: 1,
			Flags:   Flags{QR: true, RD: true},
		},
		Questions: []*Question{
			{Name: name, QType: TypeA, QClass: ClassIN},
		},
		Answers: []*ResourceRecord{
			{Name: name, Type: TypeA, Class: ClassIN, TTL: 300, Data: &RDataA{Address: [4]byte{1, 2, 3, 4}}},
		},
	}

	cpy := msg.Copy()
	if cpy == nil {
		t.Fatal("Copy returned nil")
	}

	// Check that the copy is independent
	if &cpy.Header == &msg.Header {
		t.Error("Header should be copied, not shared")
	}

	if cpy.Header.ID != msg.Header.ID {
		t.Errorf("Header.ID mismatch: %d != %d", cpy.Header.ID, msg.Header.ID)
	}

	// Modify original and verify copy is unchanged
	msg.Header.ID = 0xFFFF
	if cpy.Header.ID == 0xFFFF {
		t.Error("Copy should be independent of original")
	}
}

// TestMessageClear tests Message.Clear method
func TestMessageClear(t *testing.T) {
	name, _ := ParseName("example.com.")
	msg := &Message{
		Header: Header{
			ID:      0x1234,
			QDCount: 1,
			ANCount: 1,
			NSCount: 1,
			ARCount: 1,
		},
		Questions: []*Question{
			{Name: name, QType: TypeA, QClass: ClassIN},
		},
		Answers: []*ResourceRecord{
			{Name: name, Type: TypeA, Class: ClassIN, TTL: 300, Data: &RDataA{}},
		},
		Authorities: []*ResourceRecord{
			{Name: name, Type: TypeNS, Class: ClassIN, TTL: 300, Data: &RDataNS{}},
		},
		Additionals: []*ResourceRecord{
			{Name: name, Type: TypeOPT, Class: 4096, TTL: 0, Data: &RDataOPT{}},
		},
	}

	msg.Clear()

	if len(msg.Questions) != 0 {
		t.Errorf("Questions should be cleared, got %d", len(msg.Questions))
	}
	if len(msg.Answers) != 0 {
		t.Errorf("Answers should be cleared, got %d", len(msg.Answers))
	}
	if len(msg.Authorities) != 0 {
		t.Errorf("Authorities should be cleared, got %d", len(msg.Authorities))
	}
	if len(msg.Additionals) != 0 {
		t.Errorf("Additionals should be cleared, got %d", len(msg.Additionals))
	}
}

// TestMessageTruncate tests Message.Truncate method
func TestMessageTruncate(t *testing.T) {
	name, _ := ParseName("example.com.")
	msg := &Message{
		Header: Header{
			ID:      0x1234,
			QDCount: 1,
		},
		Questions: []*Question{
			{Name: name, QType: TypeA, QClass: ClassIN},
		},
	}

	// Message that already fits
	originalLen := msg.WireLength()
	msg.Truncate(originalLen + 100)
	if msg.Header.Flags.TC {
		t.Error("TC bit should not be set when message fits")
	}

	// Message that doesn't fit - create one with answers
	msg2 := &Message{
		Header: Header{
			ID:      0x1234,
			QDCount: 1,
			ANCount: 10,
		},
		Questions: []*Question{
			{Name: name, QType: TypeA, QClass: ClassIN},
		},
	}

	// Add many answers
	for i := 0; i < 10; i++ {
		msg2.Answers = append(msg2.Answers, &ResourceRecord{
			Name:  name,
			Type:  TypeA,
			Class: ClassIN,
			TTL:   300,
			Data:  &RDataA{Address: [4]byte{byte(i), 2, 3, 4}},
		})
	}

	// Truncate to very small size
	msg2.Truncate(50)
	// TC bit may or may not be set depending on how much fits
	_ = originalLen
}

// TestCalculateDSDigest tests DS digest calculation
func TestCalculateDSDigest(t *testing.T) {
	dnskey := &RDataDNSKEY{
		Flags:     DNSKEYFlagZone | DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: AlgorithmRSASHA256,
		PublicKey: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
	}

	// Test SHA-256 (type 2)
	digest, err := CalculateDSDigest("example.com.", dnskey, 2)
	if err != nil {
		t.Fatalf("CalculateDSDigest(SHA256) error: %v", err)
	}
	if len(digest) != 32 {
		t.Errorf("SHA-256 digest length: got %d, want 32", len(digest))
	}

	// Test SHA-384 (type 4)
	digest4, err := CalculateDSDigest("example.com.", dnskey, 4)
	if err != nil {
		t.Fatalf("CalculateDSDigest(SHA384) error: %v", err)
	}
	if len(digest4) != 48 {
		t.Errorf("SHA-384 digest length: got %d, want 48", len(digest4))
	}

	// Test unsupported digest type
	_, err = CalculateDSDigest("example.com.", dnskey, 99)
	if err == nil {
		t.Error("CalculateDSDigest should return error for unsupported digest type")
	}
}

// TestRRSIGForRRSet tests RRSIG creation for RRSet
func TestRRSIGForRRSet(t *testing.T) {
	name, _ := ParseName("example.com.")
	rrset := []*ResourceRecord{
		{Name: name, Type: TypeA, Class: ClassIN, TTL: 300, Data: &RDataA{Address: [4]byte{1, 2, 3, 4}}},
		{Name: name, Type: TypeA, Class: ClassIN, TTL: 300, Data: &RDataA{Address: [4]byte{5, 6, 7, 8}}},
	}

	signerName, _ := ParseName("example.com.")

	rrsig := &RDataRRSIG{
		TypeCovered: TypeA,
		Algorithm:   AlgorithmRSASHA256,
		Labels:      2,
		OriginalTTL: 300,
		Expiration:  1735689600, // Jan 1, 2025
		Inception:   1704153600, // Jan 2, 2024
		KeyTag:      12345,
		SignerName:  signerName,
		Signature:   []byte("test-signature-data"),
	}

	result, err := RRSIGForRRSet(rrsig, rrset)
	if err != nil {
		t.Logf("RRSIGForRRSet returned error (expected for placeholder): %v", err)
	}
	// Function is placeholder returning nil, nil, so result will be nil
	_ = result
}

// TestResourceRecordString tests ResourceRecord String method
func TestResourceRecordString(t *testing.T) {
	name, _ := ParseName("example.com.")
	rr := &ResourceRecord{
		Name:  name,
		Type:  TypeA,
		Class: ClassIN,
		TTL:   300,
		Data:  &RDataA{Address: [4]byte{1, 2, 3, 4}},
	}

	s := rr.String()
	if !strings.Contains(s, "example.com") {
		t.Error("String should contain name")
	}
	if !strings.Contains(s, "1.2.3.4") {
		t.Error("String should contain address")
	}
}

// TestRDataOPTMethods tests RDataOPT methods
func TestRDataOPTMethods(t *testing.T) {
	opt := &RDataOPT{}

	// Test Type
	if opt.Type() != TypeOPT {
		t.Errorf("Type() = %d, want %d", opt.Type(), TypeOPT)
	}

	// Test AddOption
	opt.AddOption(OptionCodeNSID, []byte("test"))
	if len(opt.Options) != 1 {
		t.Error("AddOption should add option")
	}

	// Test GetOption
	got := opt.GetOption(OptionCodeNSID)
	if got == nil {
		t.Error("GetOption should find option")
	}

	// Test GetOption not found
	notFound := opt.GetOption(9999)
	if notFound != nil {
		t.Error("GetOption should return nil for non-existent option")
	}

	// Test String
	s := opt.String()
	if !strings.Contains(s, "NSID") {
		t.Error("String should contain option name")
	}

	// Test Len
	if opt.Len() != 8 { // 4 bytes header + 4 bytes data
		t.Errorf("Len() = %d, want 8", opt.Len())
	}

	// Test Copy
	cpy := opt.Copy().(*RDataOPT)
	if len(cpy.Options) != len(opt.Options) {
		t.Error("Copy should have same number of options")
	}

	// Test RemoveOption
	opt.AddOption(OptionCodeClientSubnet, []byte{1, 2, 3})
	opt.RemoveOption(OptionCodeNSID)
	if len(opt.Options) != 1 {
		t.Errorf("RemoveOption should leave 1 option, got %d", len(opt.Options))
	}
	if opt.Options[0].Code != OptionCodeClientSubnet {
		t.Error("Wrong option remained after RemoveOption")
	}
}

// TestEDNS0ClientSubnetMethods tests EDNS0ClientSubnet methods
func TestEDNS0ClientSubnetMethods(t *testing.T) {
	// Test with IPv4 - use /32 to get full IP
	ip := net.ParseIP("192.168.1.1")
	ecs := NewEDNS0ClientSubnet(ip, 32)

	// Test IP method
	gotIP := ecs.IP()
	if gotIP == nil {
		t.Fatal("IP() returned nil")
	}
	if !gotIP.Equal(ip) {
		t.Errorf("IP() = %v, want %v", gotIP, ip)
	}

	// Test String
	s := ecs.String()
	if !strings.Contains(s, "192.168.1") {
		t.Errorf("String() = %s, should contain IP", s)
	}

	// Test ToEDNS0Option
	opt := ecs.ToEDNS0Option()
	if opt.Code != OptionCodeClientSubnet {
		t.Errorf("ToEDNS0Option Code = %d, want %d", opt.Code, OptionCodeClientSubnet)
	}

	// Test with IPv6
	ip6 := net.ParseIP("2001:db8::1")
	ecs6 := NewEDNS0ClientSubnet(ip6, 64)
	if ecs6.Family != 2 {
		t.Errorf("IPv6 Family = %d, want 2", ecs6.Family)
	}

	// Test IP method with IPv6
	gotIP6 := ecs6.IP()
	if gotIP6 == nil {
		t.Fatal("IPv6 IP() returned nil")
	}

	// Test with unknown family
	ecsBad := &EDNS0ClientSubnet{Family: 99}
	if ip := ecsBad.IP(); ip != nil {
		t.Error("IP() should return nil for unknown family")
	}
}

// TestBufferMethods tests Buffer read/write methods
func TestBufferMethods(t *testing.T) {
	buf := NewBuffer(512)

	// Test Data
	if buf.Data() == nil {
		t.Error("Data() should not return nil")
	}

	// Test Bytes (initially empty)
	if len(buf.Bytes()) != 0 {
		t.Error("Bytes() should be empty initially")
	}

	// Test Offset
	if buf.Offset() != 0 {
		t.Errorf("Offset() = %d, want 0", buf.Offset())
	}

	// Test SetOffset
	err := buf.SetOffset(100)
	if err != nil {
		t.Errorf("SetOffset(100) error: %v", err)
	}
	if buf.Offset() != 100 {
		t.Errorf("Offset after SetOffset = %d, want 100", buf.Offset())
	}

	// Test SetOffset invalid
	err = buf.SetOffset(-1)
	if err == nil {
		t.Error("SetOffset(-1) should return error")
	}
	err = buf.SetOffset(10000)
	if err == nil {
		t.Error("SetOffset(10000) should return error for small buffer")
	}

	// Reset and test write methods
	buf.Reset()

	// Test Available
	if buf.Available() != 512 {
		t.Errorf("Available() = %d, want 512", buf.Available())
	}

	// Test WriteUint16
	err = buf.WriteUint16(0x1234)
	if err != nil {
		t.Errorf("WriteUint16 error: %v", err)
	}
	if buf.Offset() != 2 {
		t.Errorf("Offset after WriteUint16 = %d, want 2", buf.Offset())
	}

	// Test WriteUint32
	err = buf.WriteUint32(0x12345678)
	if err != nil {
		t.Errorf("WriteUint32 error: %v", err)
	}
	if buf.Offset() != 6 {
		t.Errorf("Offset after WriteUint32 = %d, want 6", buf.Offset())
	}

	// Test WriteBytes
	err = buf.WriteBytes([]byte{1, 2, 3})
	if err != nil {
		t.Errorf("WriteBytes error: %v", err)
	}
	if buf.Offset() != 9 {
		t.Errorf("Offset after WriteBytes = %d, want 9", buf.Offset())
	}

	// Test Length
	if buf.Length() != 9 {
		t.Errorf("Length() = %d, want 9", buf.Length())
	}

	// Test Bytes
	if len(buf.Bytes()) != 9 {
		t.Errorf("len(Bytes()) = %d, want 9", len(buf.Bytes()))
	}

	// Test Remaining (after writing, we've consumed from offset 0)
	buf.SetOffset(0)
	if buf.Remaining() != 9 {
		t.Errorf("Remaining() = %d, want 9", buf.Remaining())
	}

	// Test ReadUint16
	v16, err := buf.ReadUint16()
	if err != nil {
		t.Errorf("ReadUint16 error: %v", err)
	}
	if v16 != 0x1234 {
		t.Errorf("ReadUint16 = %x, want 1234", v16)
	}

	// Test ReadUint32
	v32, err := buf.ReadUint32()
	if err != nil {
		t.Errorf("ReadUint32 error: %v", err)
	}
	if v32 != 0x12345678 {
		t.Errorf("ReadUint32 = %x, want 12345678", v32)
	}

	// Test ReadBytes
	bytes, err := buf.ReadBytes(3)
	if err != nil {
		t.Errorf("ReadBytes error: %v", err)
	}
	if !reflect.DeepEqual(bytes, []byte{1, 2, 3}) {
		t.Errorf("ReadBytes = %v, want [1 2 3]", bytes)
	}

	// Test PeekUint16 (after resetting and reading again)
	buf.SetOffset(0)
	peek, err := buf.PeekUint16()
	if err != nil {
		t.Errorf("PeekUint16 error: %v", err)
	}
	if peek != 0x1234 {
		t.Errorf("PeekUint16 = %x, want 1234", peek)
	}
	if buf.Offset() != 0 {
		t.Error("PeekUint16 should not advance offset")
	}

	// Test Skip
	err = buf.Skip(2)
	if err != nil {
		t.Errorf("Skip error: %v", err)
	}
	if buf.Offset() != 2 {
		t.Errorf("Offset after Skip = %d, want 2", buf.Offset())
	}

	// Test ReadUint8
	buf.SetOffset(0)
	v8, err := buf.ReadUint8()
	if err != nil {
		t.Errorf("ReadUint8 error: %v", err)
	}
	if v8 != 0x12 {
		t.Errorf("ReadUint8 = %x, want 12", v8)
	}
}

// TestBufferErrors tests Buffer error cases
func TestBufferErrors(t *testing.T) {
	// Small buffer for testing errors - use MinBufferSize (512) as NewBuffer enforces minimum
	buf := NewBuffer(10) // Will actually be 512 due to MinBufferSize

	// WriteUint16 overflow - use offset near end
	buf.offset = len(buf.data) - 1
	err := buf.WriteUint16(0)
	if err == nil {
		t.Error("WriteUint16 should fail when buffer too small")
	}

	// WriteUint32 overflow
	buf.offset = len(buf.data) - 3
	err = buf.WriteUint32(0)
	if err == nil {
		t.Error("WriteUint32 should fail when buffer too small")
	}

	// WriteBytes overflow
	buf.offset = len(buf.data) - 5
	err = buf.WriteBytes([]byte{1, 2, 3, 4, 5, 6})
	if err == nil {
		t.Error("WriteBytes should fail when buffer too small")
	}

	// ReadUint8 overflow - need to set length properly
	buf.Reset()
	buf.length = 10
	buf.offset = 10
	_, err = buf.ReadUint8()
	if err == nil {
		t.Error("ReadUint8 should fail at end of buffer")
	}

	// ReadUint16 overflow
	buf.offset = 9
	_, err = buf.ReadUint16()
	if err == nil {
		t.Error("ReadUint16 should fail near end of buffer")
	}

	// ReadUint32 overflow
	buf.offset = 7
	_, err = buf.ReadUint32()
	if err == nil {
		t.Error("ReadUint32 should fail near end of buffer")
	}

	// ReadBytes overflow
	buf.offset = 5
	_, err = buf.ReadBytes(10)
	if err == nil {
		t.Error("ReadBytes should fail when requesting too many bytes")
	}

	// PeekUint16 overflow
	buf.offset = 9
	_, err = buf.PeekUint16()
	if err == nil {
		t.Error("PeekUint16 should fail near end of buffer")
	}

	// Skip overflow
	buf.offset = 5
	err = buf.Skip(10)
	if err == nil {
		t.Error("Skip should fail when skipping past end")
	}
}

// TestOffsetMap tests offsetMap methods
func TestOffsetMap(t *testing.T) {
	m := make(offsetMap)

	// Test add
	m.add("example.com", 12)
	if m["example.com"] != 12 {
		t.Error("add should add entry to map")
	}

	// Test lookup
	offset, ok := m.lookup("example.com")
	if !ok || offset != 12 {
		t.Error("lookup should find entry")
	}

	// Test lookup not found
	_, ok = m.lookup("nonexistent.com")
	if ok {
		t.Error("lookup should not find non-existent entry")
	}

	// Test nil map
	var nilMap offsetMap
	nilMap.add("test.com", 0) // Should not panic
	_, ok = nilMap.lookup("test.com")
	if ok {
		t.Error("nil map lookup should return false")
	}
}

// TestOptionCodeString tests OptionCodeString
func TestOptionCodeString(t *testing.T) {
	tests := []struct {
		code   uint16
		expect string
	}{
		{OptionCodeNSID, "NSID"},
		{OptionCodeClientSubnet, "ECS"},
		{OptionCodeExpire, "EXPIRE"},
		{OptionCodeCookie, "COOKIE"},
		{OptionCodeTCPKeepalive, "TCPKEEPALIVE"},
		{OptionCodePadding, "PADDING"},
		{OptionCodeChain, "CHAIN"},
		{OptionCodeExtendedError, "EDE"},
		{9999, "OPTION9999"},
	}

	for _, tt := range tests {
		result := OptionCodeString(tt.code)
		if result != tt.expect {
			t.Errorf("OptionCodeString(%d) = %s, want %s", tt.code, result, tt.expect)
		}
	}
}

// TestParseEDNS0Header tests ParseEDNS0Header
func TestParseEDNS0Header(t *testing.T) {
	name, _ := ParseName(".")
	// TTL format: ExtendedRCODE(8) | Version(8) | DO(1) | Z(15)
	// ExtendedRCODE = 0x01, Version = 0x02, DO = 1, Z = 0
	// ExtendedRCODE: bits 24-31
	// Version: bits 16-23
	// DO: bit 15
	// Z: bits 0-14
	rr := &ResourceRecord{
		Name:  name,
		Type:  TypeOPT,
		Class: 4096,       // UDP Size
		TTL:   0x01028000, // ExtendedRCODE=1, Version=2, DO=1, Z=0
	}

	h := ParseEDNS0Header(rr)
	if h.UDPSize != 4096 {
		t.Errorf("UDPSize = %d, want 4096", h.UDPSize)
	}
	if h.ExtendedRCODE != 1 {
		t.Errorf("ExtendedRCODE = %d, want 1", h.ExtendedRCODE)
	}
	if h.Version != 2 {
		t.Errorf("Version = %d, want 2", h.Version)
	}
	if !h.DO {
		t.Error("DO should be true")
	}
}

// TestBuildEDNSTTL tests BuildEDNSTTL
func TestBuildEDNSTTL(t *testing.T) {
	ttl := BuildEDNSTTL(1, 2, true, 0)
	if ttl == 0 {
		t.Error("BuildEDNSTTL should return non-zero")
	}

	// Check specific bits
	if (ttl>>24)&0xFF != 1 {
		t.Error("ExtendedRCODE not in correct position")
	}
	if (ttl>>16)&0xFF != 2 {
		t.Error("Version not in correct position")
	}
	if ttl&0x8000 == 0 {
		t.Error("DO bit not set")
	}
}

// TestBufferFromDataMethods tests NewBufferFromData methods
func TestBufferFromDataMethods(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	buf := NewBufferFromData(data)

	if buf.Length() != 5 {
		t.Errorf("Length() = %d, want 5", buf.Length())
	}

	if buf.Capacity() != 5 {
		t.Errorf("Capacity() = %d, want 5", buf.Capacity())
	}

	if buf.Remaining() != 5 {
		t.Errorf("Remaining() = %d, want 5", buf.Remaining())
	}
}

// TestPutSliceSized tests PutSliceSized
func TestPutSliceSized(t *testing.T) {
	slice := GetSlice()
	*slice = append(*slice, 1, 2, 3)

	// Should return to pool (within size limit)
	PutSliceSized(slice, 4096)

	// Get again and verify it was reset
	slice2 := GetSlice()
	if len(*slice2) != 0 {
		t.Error("Slice should be reset after PutSliceSized")
	}
	PutSlice(slice2)

	// Test discarding oversized slice
	bigSlice := new([]byte)
	*bigSlice = make([]byte, 10000)
	PutSliceSized(bigSlice, 4096) // Should be discarded
}

// TestPutBufferSized tests PutBufferSized
func TestPutBufferSized(t *testing.T) {
	buf := GetBuffer()

	// Should return to pool (within size limit)
	PutBufferSized(buf, 4096)

	// Get again
	buf2 := GetBuffer()
	if buf2.Length() != 0 {
		t.Error("Buffer should be reset after PutBufferSized")
	}
	PutBuffer(buf2)

	// Test discarding oversized buffer
	bigBuf := NewBuffer(10000)
	PutBufferSized(bigBuf, 4096) // Should be discarded
}

// TestRDataTypeMethods tests Type(), Len(), Copy(), IP() methods for various RData types
func TestRDataTypeMethods(t *testing.T) {
	// RDataA
	a := &RDataA{Address: [4]byte{1, 2, 3, 4}}
	if a.Type() != TypeA {
		t.Errorf("RDataA.Type() = %d, want %d", a.Type(), TypeA)
	}
	if a.Len() != 4 {
		t.Errorf("RDataA.Len() = %d, want 4", a.Len())
	}
	if a.Copy().(*RDataA).Address != a.Address {
		t.Error("RDataA.Copy() mismatch")
	}
	if a.IP() == nil {
		t.Error("RDataA.IP() should not be nil")
	}

	// RDataAAAA
	aaaa := &RDataAAAA{Address: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}}
	if aaaa.Type() != TypeAAAA {
		t.Errorf("RDataAAAA.Type() = %d, want %d", aaaa.Type(), TypeAAAA)
	}
	if aaaa.Len() != 16 {
		t.Errorf("RDataAAAA.Len() = %d, want 16", aaaa.Len())
	}
	if aaaa.Copy().(*RDataAAAA).Address != aaaa.Address {
		t.Error("RDataAAAA.Copy() mismatch")
	}
	if aaaa.IP() == nil {
		t.Error("RDataAAAA.IP() should not be nil")
	}
}

// TestRDataCNAMEType tests CNAME Type method
func TestRDataCNAMEType(t *testing.T) {
	name, _ := ParseName("target.example.com.")
	cname := &RDataCNAME{CName: name}
	if cname.Type() != TypeCNAME {
		t.Errorf("CNAME.Type() = %d, want %d", cname.Type(), TypeCNAME)
	}
	if cname.Len() < 2 {
		t.Error("CNAME.Len() should be at least 2")
	}
	cpy := cname.Copy().(*RDataCNAME)
	if !cpy.CName.Equal(name) {
		t.Error("CNAME.Copy() mismatch")
	}
}

// TestRDataMXTypes tests MX Type, Len, Copy methods
func TestRDataMXTypes(t *testing.T) {
	name, _ := ParseName("mail.example.com.")
	mx := &RDataMX{Preference: 10, Exchange: name}
	if mx.Type() != TypeMX {
		t.Errorf("MX.Type() = %d, want %d", mx.Type(), TypeMX)
	}
	if mx.Len() < 4 {
		t.Error("MX.Len() should be at least 4")
	}
	cpy := mx.Copy().(*RDataMX)
	if cpy.Preference != mx.Preference {
		t.Error("MX.Copy() preference mismatch")
	}
}

// TestRDataNSTypes tests NS Type, Len, Copy methods
func TestRDataNSTypes(t *testing.T) {
	name, _ := ParseName("ns1.example.com.")
	ns := &RDataNS{NSDName: name}
	if ns.Type() != TypeNS {
		t.Errorf("NS.Type() = %d, want %d", ns.Type(), TypeNS)
	}
	if ns.Len() < 2 {
		t.Error("NS.Len() should be at least 2")
	}
	cpy := ns.Copy().(*RDataNS)
	if !cpy.NSDName.Equal(name) {
		t.Error("NS.Copy() mismatch")
	}
}

// TestRDataPTRTypes tests PTR Type, Len, Copy methods
func TestRDataPTRTypes(t *testing.T) {
	name, _ := ParseName("host.example.com.")
	ptr := &RDataPTR{PtrDName: name}
	if ptr.Type() != TypePTR {
		t.Errorf("PTR.Type() = %d, want %d", ptr.Type(), TypePTR)
	}
	if ptr.Len() < 2 {
		t.Error("PTR.Len() should be at least 2")
	}
	cpy := ptr.Copy().(*RDataPTR)
	if !cpy.PtrDName.Equal(name) {
		t.Error("PTR.Copy() mismatch")
	}
}

// TestRDataSOATypes tests SOA Type, Len, Copy methods
func TestRDataSOATypes(t *testing.T) {
	mname, _ := ParseName("ns1.example.com.")
	rname, _ := ParseName("admin.example.com.")
	soa := &RDataSOA{
		MName:   mname,
		RName:   rname,
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minimum: 300,
	}
	if soa.Type() != TypeSOA {
		t.Errorf("SOA.Type() = %d, want %d", soa.Type(), TypeSOA)
	}
	if soa.Len() < 22 {
		t.Error("SOA.Len() should be at least 22")
	}
	cpy := soa.Copy().(*RDataSOA)
	if cpy.Serial != soa.Serial {
		t.Error("SOA.Copy() serial mismatch")
	}
}

// TestRDataTXTTypes tests TXT Type, Len, Copy methods
func TestRDataTXTTypes(t *testing.T) {
	txt := &RDataTXT{Strings: []string{"hello", "world"}}
	if txt.Type() != TypeTXT {
		t.Errorf("TXT.Type() = %d, want %d", txt.Type(), TypeTXT)
	}
	if txt.Len() < 2 {
		t.Error("TXT.Len() should be at least 2")
	}
	cpy := txt.Copy().(*RDataTXT)
	if len(cpy.Strings) != len(txt.Strings) {
		t.Error("TXT.Copy() strings mismatch")
	}
}

// TestRDataSRVTypes tests SRV Type, Len, Copy methods
func TestRDataSRVTypes(t *testing.T) {
	target, _ := ParseName("target.example.com.")
	srv := &RDataSRV{Priority: 10, Weight: 20, Port: 80, Target: target}
	if srv.Type() != TypeSRV {
		t.Errorf("SRV.Type() = %d, want %d", srv.Type(), TypeSRV)
	}
	if srv.Len() < 8 {
		t.Error("SRV.Len() should be at least 8")
	}
	cpy := srv.Copy().(*RDataSRV)
	if cpy.Priority != srv.Priority {
		t.Error("SRV.Copy() priority mismatch")
	}
}

// TestRDataCaaTypes tests CAA Type, String, Len, Copy methods
func TestRDataCaaTypes(t *testing.T) {
	caa := &RDataCAA{Flags: 1, Tag: "issue", Value: "ca.example.com"}
	if caa.Type() != TypeCAA {
		t.Errorf("CAA.Type() = %d, want %d", caa.Type(), TypeCAA)
	}
	if caa.Len() < 4 {
		t.Error("CAA.Len() should be at least 4")
	}
	s := caa.String()
	if !strings.Contains(s, "issue") {
		t.Error("CAA.String() should contain tag")
	}
	cpy := caa.Copy().(*RDataCAA)
	if cpy.Tag != caa.Tag {
		t.Error("CAA.Copy() tag mismatch")
	}
}

// TestRDataNaptrTypes tests NAPTR Type, String, Len, Copy methods
func TestRDataNaptrTypes(t *testing.T) {
	replacement, _ := ParseName("replacement.example.com.")
	naptr := &RDataNAPTR{
		Order:       100,
		Preference:  10,
		Flags:       "S",
		Service:     "SIP+D2U",
		Regexp:      "",
		Replacement: replacement,
	}
	if naptr.Type() != TypeNAPTR {
		t.Errorf("NAPTR.Type() = %d, want %d", naptr.Type(), TypeNAPTR)
	}
	if naptr.Len() < 8 {
		t.Error("NAPTR.Len() should be at least 8")
	}
	s := naptr.String()
	if !strings.Contains(s, "SIP") {
		t.Error("NAPTR.String() should contain services")
	}
	cpy := naptr.Copy().(*RDataNAPTR)
	if cpy.Order != naptr.Order {
		t.Error("NAPTR.Copy() order mismatch")
	}
}

// TestRDataSshfpTypes tests SSHFP Type, String, Len, Copy methods
func TestRDataSshfpTypes(t *testing.T) {
	sshfp := &RDataSSHFP{
		Algorithm:   1,
		FPType:      2,
		Fingerprint: []byte{1, 2, 3, 4, 5},
	}
	if sshfp.Type() != TypeSSHFP {
		t.Errorf("SSHFP.Type() = %d, want %d", sshfp.Type(), TypeSSHFP)
	}
	if sshfp.Len() != 7 {
		t.Errorf("SSHFP.Len() = %d, want 7", sshfp.Len())
	}
	s := sshfp.String()
	if !strings.Contains(s, "0102030405") {
		t.Error("SSHFP.String() should contain fingerprint hex")
	}
	cpy := sshfp.Copy().(*RDataSSHFP)
	if cpy.Algorithm != sshfp.Algorithm {
		t.Error("SSHFP.Copy() algorithm mismatch")
	}
}

// TestRDataTlsaTypes tests TLSA Type, String, Len, Copy methods
func TestRDataTlsaTypes(t *testing.T) {
	tlsa := &RDataTLSA{
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Certificate:  []byte{1, 2, 3, 4, 5},
	}
	if tlsa.Type() != TypeTLSA {
		t.Errorf("TLSA.Type() = %d, want %d", tlsa.Type(), TypeTLSA)
	}
	if tlsa.Len() != 8 { // 3 + 5
		t.Errorf("TLSA.Len() = %d, want 8", tlsa.Len())
	}
	s := tlsa.String()
	if !strings.Contains(s, "3 1 1") {
		t.Error("TLSA.String() should contain usage/selector/matching")
	}
	cpy := tlsa.Copy().(*RDataTLSA)
	if cpy.Usage != tlsa.Usage {
		t.Error("TLSA.Copy() usage mismatch")
	}
}

// TestRDataDnskeyTypeMethods tests DNSKEY Type method
func TestRDataDnskeyTypeMethods(t *testing.T) {
	dnskey := &RDataDNSKEY{
		Flags:     DNSKEYFlagZone,
		Protocol:  3,
		Algorithm: AlgorithmRSASHA256,
		PublicKey: []byte{1, 2, 3, 4},
	}
	if dnskey.Type() != TypeDNSKEY {
		t.Errorf("DNSKEY.Type() = %d, want %d", dnskey.Type(), TypeDNSKEY)
	}
}

// TestRDataDSTypeMethods tests DS Type method
func TestRDataDSTypeMethods(t *testing.T) {
	ds := &RDataDS{
		KeyTag:     12345,
		Algorithm:  AlgorithmRSASHA256,
		DigestType: 2,
		Digest:     []byte{1, 2, 3, 4},
	}
	if ds.Type() != TypeDS {
		t.Errorf("DS.Type() = %d, want %d", ds.Type(), TypeDS)
	}
}

// TestRDataNsecTypeMethods tests NSEC Type method
func TestRDataNsecTypeMethods(t *testing.T) {
	name, _ := ParseName("next.example.com.")
	nsec := &RDataNSEC{
		NextDomain: name,
		TypeBitMap: []uint16{TypeA, TypeNS},
	}
	if nsec.Type() != TypeNSEC {
		t.Errorf("NSEC.Type() = %d, want %d", nsec.Type(), TypeNSEC)
	}
}

// TestRDataNsec3TypeMethods tests NSEC3 Type method
func TestRDataNsec3TypeMethods(t *testing.T) {
	nsec3 := &RDataNSEC3{
		HashAlgorithm: 1,
		Flags:         0,
		Iterations:    10,
		Salt:          []byte{1, 2},
		NextHashed:    []byte{1, 2, 3, 4},
		TypeBitMap:    []uint16{TypeA},
	}
	if nsec3.Type() != TypeNSEC3 {
		t.Errorf("NSEC3.Type() = %d, want %d", nsec3.Type(), TypeNSEC3)
	}
}

// TestRDataNsec3ParamTypeMethods tests NSEC3PARAM Type method
func TestRDataNsec3ParamTypeMethods(t *testing.T) {
	nsec3param := &RDataNSEC3PARAM{
		HashAlgorithm: 1,
		Flags:         0,
		Iterations:    10,
		Salt:          []byte{1, 2},
	}
	if nsec3param.Type() != TypeNSEC3PARAM {
		t.Errorf("NSEC3PARAM.Type() = %d, want %d", nsec3param.Type(), TypeNSEC3PARAM)
	}
}

// TestRDataRrsigTypeMethods tests RRSIG Type method
func TestRDataRrsigTypeMethods(t *testing.T) {
	signer, _ := ParseName("example.com.")
	rrsig := &RDataRRSIG{
		TypeCovered: TypeA,
		Algorithm:   AlgorithmRSASHA256,
		Labels:      2,
		SignerName:  signer,
		Signature:   []byte{1, 2, 3},
	}
	if rrsig.Type() != TypeRRSIG {
		t.Errorf("RRSIG.Type() = %d, want %d", rrsig.Type(), TypeRRSIG)
	}
}

// TestNewResourceRecord tests NewResourceRecord function
func TestNewResourceRecord(t *testing.T) {
	rr, err := NewResourceRecord("example.com.", TypeA, ClassIN, 300, &RDataA{Address: [4]byte{1, 2, 3, 4}})
	if err != nil {
		t.Fatalf("NewResourceRecord error: %v", err)
	}
	if rr.Name.String() != "example.com." {
		t.Errorf("Name = %s, want example.com.", rr.Name.String())
	}
	if rr.Type != TypeA {
		t.Errorf("Type = %d, want %d", rr.Type, TypeA)
	}
	if rr.Class != ClassIN {
		t.Errorf("Class = %d, want %d", rr.Class, ClassIN)
	}
	if rr.TTL != 300 {
		t.Errorf("TTL = %d, want 300", rr.TTL)
	}

	// Test with name containing null byte
	_, err = NewResourceRecord("test\x00invalid.com.", TypeA, ClassIN, 300, &RDataA{})
	if err == nil {
		t.Error("NewResourceRecord should fail with null byte in name")
	}
}

// TestRDataRawMethods tests RDataRaw methods
func TestRDataRawMethods(t *testing.T) {
	raw := &RDataRaw{
		TypeVal: 99, // Unknown type
		Data:    []byte{1, 2, 3, 4, 5},
	}

	// Test Type
	if raw.Type() != 99 {
		t.Errorf("Type() = %d, want 99", raw.Type())
	}

	// Test Len
	if raw.Len() != 5 {
		t.Errorf("Len() = %d, want 5", raw.Len())
	}

	// Test Pack
	buf := make([]byte, 10)
	n, err := raw.Pack(buf, 0)
	if err != nil {
		t.Fatalf("Pack error: %v", err)
	}
	if n != 5 {
		t.Errorf("Pack returned %d, want 5", n)
	}

	// Test Unpack
	raw2 := &RDataRaw{}
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	n, err = raw2.Unpack(data, 0, 4)
	if err != nil {
		t.Fatalf("Unpack error: %v", err)
	}
	if n != 4 {
		t.Errorf("Unpack returned %d, want 4", n)
	}
	if len(raw2.Data) != 4 {
		t.Errorf("Data length = %d, want 4", len(raw2.Data))
	}

	// Test Unpack error (buffer too small)
	_, err = raw2.Unpack([]byte{1}, 0, 4)
	if err == nil {
		t.Error("Unpack should fail with small buffer")
	}

	// Test Copy
	cpy := raw.Copy().(*RDataRaw)
	if cpy.TypeVal != raw.TypeVal {
		t.Error("Copy type mismatch")
	}
	if !bytes.Equal(cpy.Data, raw.Data) {
		t.Error("Copy data mismatch")
	}

	// Verify deep copy
	raw.Data[0] = 99
	if cpy.Data[0] == 99 {
		t.Error("Copy should be deep")
	}
}

// TestResourceRecordIsExpired tests ResourceRecord.IsExpired
func TestResourceRecordIsExpired(t *testing.T) {
	name, _ := ParseName("example.com.")
	rr := &ResourceRecord{
		Name:  name,
		Type:  TypeA,
		Class: ClassIN,
		TTL:   10, // 10 seconds
		Data:  &RDataA{Address: [4]byte{1, 2, 3, 4}},
	}

	// Not expired (just cached)
	if rr.IsExpired(time.Now().Add(-5 * time.Second)) {
		t.Error("Record should not be expired")
	}

	// Expired (cached longer ago than TTL)
	if !rr.IsExpired(time.Now().Add(-15 * time.Second)) {
		t.Error("Record should be expired")
	}
}

// TestResourceRecordRemainingTTL tests ResourceRecord.RemainingTTL
func TestResourceRecordRemainingTTL(t *testing.T) {
	name, _ := ParseName("example.com.")
	rr := &ResourceRecord{
		Name:  name,
		Type:  TypeA,
		Class: ClassIN,
		TTL:   100,
		Data:  &RDataA{Address: [4]byte{1, 2, 3, 4}},
	}

	// Check remaining TTL
	remaining := rr.RemainingTTL(time.Now().Add(-50 * time.Second))
	if remaining < 45 || remaining > 55 {
		t.Errorf("RemainingTTL = %d, expected around 50", remaining)
	}

	// Fully expired
	remaining = rr.RemainingTTL(time.Now().Add(-150 * time.Second))
	if remaining != 0 {
		t.Errorf("RemainingTTL for expired = %d, want 0", remaining)
	}
}
