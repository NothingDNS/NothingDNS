package protocol

// coverage_test.go adds tests for improve coverage for low-coverage functions.
// Functions targeted (below 80%):
//   - CalculateKeyTag (DNSKEY method): 0%
//   - RDataRaw.String: 0%
//   - createRData: 19%
//   - Message.String: 50%
//   - opcodeString: 28.6%
//   - AlgorithmToString: 53.3%
//   - Message.Pack: 71%
//   - Message.Truncate: 70.6%
//   - Message.UnpackMessage: 66.7%
//   - SetEDNS0: 57.1%
//   - SignerNameString (nil): 66.7%
//   - RDataSOA.String: 0%
//   - RDataSRV.String/Len: 0%/66.7%
//   - RDataNAPTR.String: 0%/66.7%
//   - Pack errors for various RData types
//   - TypeString/ClassString/RcodeString: 66.7%
//   - CompareNames: 75%
//   - toLower: 66.7%
//   - Name.Equal: 83.3%
//   - WireNameLength: 85%
//   - NewQuestion: 75%
//   - VerifyParams: 71.4%
//   - RDataDNSKEY.Pack: 78.9%
//   - RDataDS.Pack: 78.9%
//   - CalculateDSDigest: 77.3%
//   - RDataRRSIG.Pack: 76.9%
//   - RDataNSEC.Pack: 92.1%
//   - RDataNSEC.Unpack: 85.2%
//   - RDataNSEC3.Pack: 83.8%
//   - RDataNSEC3.Unpack: 85.1%
//   - RDataNSEC3PARAM.Pack: 76%
//   - RDataOPT.Pack: 81.2%
//   - RDataOPT.Unpack: 84.2%
//   - RDataCAA.Pack: 80%
//   - RDataCAA.Unpack: 82.4%
//   - RDataNAPTR.Pack: 78%
//   - RDataNAPTR.Unpack: 76.9%
//   - RDataSSHFP.Pack: 88.9%
//   - RDataTLSA.Pack: 90.9%
//   - ResourceRecord.Pack: 77.8%
//   - ResourceRecord.Copy: 66.7%

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// ============================================================================
// Constants
// ============================================================================

func TestTypeStringUnknown(t *testing.T) {
	// Test unknown type - falls to default case
	s := TypeString(65535)
	if !strings.Contains(s, "TYPE") {
		t.Errorf("TypeString for unknown type should contain TYPE, got %q", s)
	}
	// Test known type
	if TypeString(TypeA) != "A" {
		t.Errorf("TypeString(TypeA) = %q, want A", TypeString(TypeA))
	}
}

func TestClassStringUnknown(t *testing.T) {
	s := ClassString(65535)
	if !strings.Contains(s, "CLASS") {
		t.Errorf("ClassString for unknown class should contain CLASS, got %q", s)
	}
	if ClassString(ClassIN) != "IN" {
		t.Errorf("ClassString(ClassIN) = %q, want IN", ClassString(ClassIN))
	}
}

func TestRcodeStringUnknown(t *testing.T) {
	s := RcodeString(65535)
	if !strings.Contains(s, "RCODE") {
		t.Errorf("RcodeString for unknown rcode should contain RCODE, got %q", s)
	}
	if RcodeString(RcodeSuccess) != "NOERROR" {
		t.Errorf("RcodeString(RcodeSuccess) = %q, want NOERROR", RcodeString(RcodeSuccess))
	}
}

// ============================================================================
// AlgorithmToString
// ============================================================================

func TestAlgorithmToStringAll(t *testing.T) {
	tests := []struct {
		alg      uint8
		expected string
	}{
		{1, "RSAMD5"},
		{2, "DH"},
		{3, "DSA"},
		{5, "RSASHA1"},
		{6, "DSA-NSEC3-SHA1"},
		{7, "RSASHA1-NSEC3-SHA1"},
		{8, "RSASHA256"},
		{10, "RSASHA512"},
		{12, "ECC-GOST"},
		{13, "ECDSAP256SHA256"},
		{14, "ECDSAP384SHA384"},
		{15, "ED25519"},
		{16, "ED448"},
		{99, "ALG99"},
	}
	for _, tt := range tests {
		result := AlgorithmToString(tt.alg)
		if result != tt.expected {
			t.Errorf("AlgorithmToString(%d) = %q, want %q", tt.alg, result, tt.expected)
		}
	}
}

// ============================================================================
// CalculateKeyTag (DNSKEY method)
// ============================================================================

func TestDNSKEYCalculateKeyTag(t *testing.T) {
	rdata := &RDataDNSKEY{
		Flags:     DNSKEYFlagZone,
		Protocol:  3,
		Algorithm: AlgorithmRSASHA256,
		PublicKey: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
	}
	tag := rdata.CalculateKeyTag()
	// Verify the standalone function returns the same value
	tag2 := CalculateKeyTag(rdata.Flags, rdata.Algorithm, rdata.PublicKey)
	if tag != tag2 {
		t.Errorf("CalculateKeyTag method = %d, function = %d, should match", tag, tag2)
	}
}

// ============================================================================
// RDataRaw.String
// ============================================================================

func TestRDataRawString(t *testing.T) {
	raw := &RDataRaw{TypeVal: 99, Data: []byte{0xAB, 0xCD}}
	s := raw.String()
	if !strings.Contains(s, "\\#") {
		t.Errorf("RDataRaw.String() should contain \\# for hex prefix, got %q", s)
	}
	if !strings.Contains(s, "abcd") {
		t.Errorf("RDataRaw.String() should contain hex data, got %q", s)
	}
}

// ============================================================================
// createRData
// ============================================================================

func TestCreateRDataAllTypes(t *testing.T) {
	types := []struct {
		typ      uint16
		expected string
	}{
		{TypeA, "*RDataA"},
		{TypeAAAA, "*RDataAAAA"},
		{TypeCNAME, "*RDataCNAME"},
		{TypeNS, "*RDataNS"},
		{TypePTR, "*RDataPTR"},
		{TypeMX, "*RDataMX"},
		{TypeTXT, "*RDataTXT"},
		{TypeSOA, "*RDataSOA"},
		{TypeSRV, "*RDataSRV"},
		{TypeCAA, "*RDataCAA"},
		{TypeNAPTR, "*RDataNAPTR"},
		{TypeSSHFP, "*RDataSSHFP"},
		{TypeTLSA, "*RDataTLSA"},
		{TypeDS, "*RDataDS"},
		{TypeDNSKEY, "*RDataDNSKEY"},
		{TypeRRSIG, "*RDataRRSIG"},
		{TypeNSEC, "*RDataNSEC"},
		{TypeNSEC3, "*RDataNSEC3"},
		{TypeNSEC3PARAM, "*RDataNSEC3PARAM"},
		{9999, ""}, // Unknown type should return nil
	}
	for _, tt := range types {
		r := createRData(tt.typ)
		if tt.typ == 9999 {
			if r != nil {
				t.Errorf("createRData(%d) should return nil for unknown type", tt.typ)
			}
		} else if r == nil {
			t.Errorf("createRData(%d) returned nil, want non-nil", tt.typ)
		}
	}
}

// ============================================================================
// Message.String full coverage
// ============================================================================

func TestMessageStringFull(t *testing.T) {
	name, _ := ParseName("example.com.")
	msg := NewMessage(Header{ID: 0x1234, Flags: NewResponseFlags(RcodeSuccess)})
	msg.AddQuestion(&Question{Name: name, QType: TypeA, QClass: ClassIN})
	msg.AddAnswer(&ResourceRecord{
		Name: name, Type: TypeA, Class: ClassIN, TTL: 300,
		Data: &RDataA{Address: [4]byte{1, 2, 3, 4}},
	})
	msg.AddAuthority(&ResourceRecord{
		Name: name, Type: TypeNS, Class: ClassIN, TTL: 3600,
		Data: &RDataNS{NSDName: name},
	})
	msg.AddAdditional(&ResourceRecord{
		Name: name, Type: TypeA, Class: ClassIN, TTL: 60,
		Data: &RDataA{Address: [4]byte{5, 6, 7, 8}},
	})
	s := msg.String()
	if !strings.Contains(s, "QUESTION") {
		t.Error("String should contain QUESTION SECTION")
	}
	if !strings.Contains(s, "ANSWER") {
		t.Error("String should contain ANSWER SECTION")
	}
	if !strings.Contains(s, "AUTHORITY") {
		t.Error("String should contain AUTHORITY SECTION")
	}
	if !strings.Contains(s, "ADDITIONAL") {
		t.Error("String should contain ADDITIONAL SECTION")
	}
}

// ============================================================================
// opcodeString - tested indirectly through Flags.String, but let's exercise default
// ============================================================================

func TestOpcodeStringDefault(t *testing.T) {
	// opcodeString is called from Flags.String; we already test known opcodes
	// through comprehensive_test.go. The default case (returning integer) is
	// tested with opcode 15 in TestFlagsString.
	// Let's verify it directly by checking the flags string for unknown opcode
	f := Flags{Opcode: 6}
	s := f.String()
	if !strings.Contains(s, "6") {
		t.Errorf("Unknown opcode should show number, got %q", s)
	}
}

// ============================================================================
// Message.Pack error cases
// ============================================================================

func TestMessagePackBufferTooSmall(t *testing.T) {
	msg := NewMessage(Header{ID: 0x1234, Flags: NewQueryFlags()})
	q, _ := NewQuestion("example.com.", TypeA, ClassIN)
	msg.AddQuestion(q)

	buf := make([]byte, 5) // Way too small
	_, err := msg.Pack(buf)
	if err == nil {
		t.Error("Pack should fail with too small buffer")
	}
}

// ============================================================================
// Message.UnpackMessage error cases
// ============================================================================

func TestUnpackMessageErrors(t *testing.T) {
	// Too short for header
	_, err := UnpackMessage([]byte{1, 2, 3})
	if err == nil {
		t.Error("UnpackMessage should fail with too short buffer")
	}

	// Test unpack with a valid header but truncated question data
	buf := make([]byte, HeaderLen+2)
	h := Header{ID: 0x1234, Flags: NewQueryFlags(), QDCount: 1}
	h.Pack(buf[:HeaderLen])
	// Only 2 extra bytes - not enough for even a short name + type + class

	_, err = UnpackMessage(buf)
	if err == nil {
		t.Error("UnpackMessage should fail with truncated question section")
	}

	// Test unpack with a valid header but truncated answer
	msg := NewMessage(Header{ID: 0x1234, Flags: NewResponseFlags(RcodeSuccess)})
	q, _ := NewQuestion("example.com.", TypeA, ClassIN)
	msg.AddQuestion(q)
	buf2 := make([]byte, 1024)
	n, _ := msg.Pack(buf2)

	// Truncate the buffer in the middle of the data
	if n > HeaderLen+30 {
		_, err = UnpackMessage(buf2[:HeaderLen+30])
		if err == nil {
			t.Error("UnpackMessage should fail with truncated answer data")
		}
	}
}

// ============================================================================
// Message.Truncate full coverage
// ============================================================================

func TestMessageTruncateFull(t *testing.T) {
	name, _ := ParseName("example.com.")

	// Test truncation that removes additionals
	msg := NewMessage(Header{ID: 0x1234})
	msg.AddQuestion(&Question{Name: name, QType: TypeA, QClass: ClassIN})
	for i := 0; i < 3; i++ {
		msg.AddAdditional(&ResourceRecord{
			Name: name, Type: TypeA, Class: ClassIN, TTL: 300,
			Data: &RDataA{Address: [4]byte{byte(i), 2, 3, 4}},
		})
	}
	// Use question-only size to force removal of all additionals
	questionOnlySize := 12 + name.WireLength() + 4 // header + question
	msg.Truncate(questionOnlySize)
	if len(msg.Additionals) != 0 {
		t.Errorf("Truncate should have removed all additionals, got %d", len(msg.Additionals))
	}

	// Test truncation that removes authorities
	msg2 := NewMessage(Header{ID: 0x1234})
	msg2.AddQuestion(&Question{Name: name, QType: TypeA, QClass: ClassIN})
	for i := 0; i < 3; i++ {
		msg2.AddAuthority(&ResourceRecord{
			Name: name, Type: TypeNS, Class: ClassIN, TTL: 300,
			Data: &RDataNS{NSDName: name},
		})
	}
	msg2.Truncate(questionOnlySize)
	if len(msg2.Authorities) != 0 {
		t.Errorf("Truncate should have removed all authorities, got %d", len(msg2.Authorities))
	}

	// Test truncation that removes answers and sets TC bit
	// Use a very small maxSize that can't even fit the question alone
	msg3 := NewMessage(Header{ID: 0x1234})
	msg3.AddQuestion(&Question{Name: name, QType: TypeA, QClass: ClassIN})
	for i := 0; i < 5; i++ {
		msg3.AddAnswer(&ResourceRecord{
			Name: name, Type: TypeA, Class: ClassIN, TTL: 300,
			Data: &RDataA{Address: [4]byte{byte(i), 2, 3, 4}},
		})
	}
	msg3.Truncate(10) // Smaller than header - forces TC even after removing all answers
	if !msg3.Header.Flags.TC {
		t.Error("Truncate should set TC bit when message still doesn't fit")
	}
}

// ============================================================================
// SetEDNS0 replacing existing
// ============================================================================

func TestSetEDNS0ReplaceExisting(t *testing.T) {
	msg := NewMessage(Header{ID: 0x1234})
	msg.SetEDNS0(4096, false)
	opt1 := msg.GetOPT()
	if opt1 == nil {
		t.Fatal("First SetEDNS0 should create OPT")
	}
	// Set again - should replace
	msg.SetEDNS0(1232, true)
	opt2 := msg.GetOPT()
	if opt2 == nil {
		t.Fatal("Second SetEDNS0 should create OPT")
	}
	if opt2.Class != 1232 {
		t.Errorf("Replaced OPT Class = %d, want 1232", opt2.Class)
	}
	// Should still be only 1 additional
	if len(msg.Additionals) != 1 {
		t.Errorf("Should have 1 additional, got %d", len(msg.Additionals))
	}
}

// ============================================================================
// SignerNameString with nil
// ============================================================================

func TestRRSIGSignerNameStringNil(t *testing.T) {
	rdata := &RDataRRSIG{SignerName: nil}
	s := rdata.SignerNameString()
	if s != "." {
		t.Errorf("SignerNameString with nil SignerName = %q, want .", s)
	}
}

// ============================================================================
// RDataSOA.String / RDataSRV.String / RDataNAPTR.String with nil fields
// ============================================================================

func TestRDataSOAStringNil(t *testing.T) {
	rdata := &RDataSOA{MName: nil, RName: nil}
	s := rdata.String()
	if !strings.Contains(s, ".") {
		t.Errorf("SOA String with nil names should contain ., got %q", s)
	}
}

func TestRDataSOALenNil(t *testing.T) {
	rdata := &RDataSOA{MName: nil, RName: nil}
	l := rdata.Len()
	if l != 22 { // 1 + 1 + 20
		t.Errorf("SOA Len with nil names = %d, want 22", l)
	}
}

func TestRDataSRVStringNil(t *testing.T) {
	rdata := &RDataSRV{Priority: 10, Weight: 20, Port: 80, Target: nil}
	s := rdata.String()
	if !strings.Contains(s, "10 20 80 .") {
		t.Errorf("SRV String with nil target should contain '10 20 80 .', got %q", s)
	}
}

func TestRDataSRVLenNil(t *testing.T) {
	rdata := &RDataSRV{Target: nil}
	l := rdata.Len()
	if l != 7 {
		t.Errorf("SRV Len with nil target = %d, want 7", l)
	}
}

func TestRDataNAPTRStringNil(t *testing.T) {
	rdata := &RDataNAPTR{Replacement: nil}
	s := rdata.String()
	if !strings.Contains(s, ".") {
		t.Errorf("NAPTR String with nil replacement should contain ., got %q", s)
	}
}

func TestRDataNAPTRLenNil(t *testing.T) {
	rdata := &RDataNAPTR{Replacement: nil}
	l := rdata.Len()
	// 2 + 2 + 1 + 0 + 1 + 0 + 1 + 0 + 0 = 7
	if l != 7 {
		t.Errorf("NAPTR Len with nil replacement = %d, want 7", l)
	}
}

// ============================================================================
// Pack errors for various RData types
// ============================================================================

func TestRDataAPackBufferTooSmall(t *testing.T) {
	rdata := &RDataA{Address: [4]byte{1, 2, 3, 4}}
	buf := make([]byte, 2)
	_, err := rdata.Pack(buf, 0)
	if err == nil {
		t.Error("RDataA.Pack should fail with too small buffer")
	}
}

func TestRDataAAAAPackBufferTooSmall(t *testing.T) {
	rdata := &RDataAAAA{Address: [16]byte{}}
	buf := make([]byte, 8)
	_, err := rdata.Pack(buf, 0)
	if err == nil {
		t.Error("RDataAAAA.Pack should fail with too small buffer")
	}
}

func TestRDataAUnpackInvalidLength(t *testing.T) {
	rdata := &RDataA{}
	_, err := rdata.Unpack([]byte{1, 2, 3, 4}, 0, 5) // rdlength=5 for A record
	if err == nil {
		t.Error("RDataA.Unpack should fail with invalid rdlength")
	}
	_, err = rdata.Unpack([]byte{1, 2}, 0, 4) // buffer too small
	if err == nil {
		t.Error("RDataA.Unpack should fail with buffer too small")
	}
}

func TestRDataAAAAUnpackInvalidLength(t *testing.T) {
	rdata := &RDataAAAA{}
	_, err := rdata.Unpack([]byte{1, 2, 3}, 0, 15) // rdlength=15 for AAAA record
	if err == nil {
		t.Error("RDataAAAA.Unpack should fail with invalid rdlength")
	}
	_, err = rdata.Unpack([]byte{1, 2, 3}, 0, 16) // buffer too small
	if err == nil {
		t.Error("RDataAAAA.Unpack should fail with buffer too small")
	}
}

func TestRDataSOAPackBufferTooSmall(t *testing.T) {
	mname, _ := ParseName("ns1.example.com.")
	rname, _ := ParseName("admin.example.com.")
	rdata := &RDataSOA{MName: mname, RName: rname, Serial: 1, Refresh: 2, Retry: 3, Expire: 4, Minimum: 5}
	buf := make([]byte, 5)
	_, err := rdata.Pack(buf, 0)
	if err == nil {
		t.Error("RDataSOA.Pack should fail with too small buffer")
	}
}

func TestRDataSOAUnpackBufferTooSmall(t *testing.T) {
	rdata := &RDataSOA{}
	// Create a valid SOA buffer first
	mname, _ := ParseName("ns1.example.com.")
	rname, _ := ParseName("admin.example.com.")
	fullRdata := &RDataSOA{MName: mname, RName: rname, Serial: 1, Refresh: 2, Retry: 3, Expire: 4, Minimum: 5}
	buf := make([]byte, 512)
	n, _ := fullRdata.Pack(buf, 0)

	// Now try to unpack from a truncated buffer
	_, err := rdata.Unpack(buf[:n-5], 0, uint16(n))
	if err == nil {
		t.Error("RDataSOA.Unpack should fail with too small buffer for fixed fields")
	}
}

func TestRDataCNAMEPackBufferTooSmall(t *testing.T) {
	name, _ := ParseName("www.example.com.")
	rdata := &RDataCNAME{CName: name}
	buf := make([]byte, 3)
	_, err := rdata.Pack(buf, 0)
	if err == nil {
		t.Error("RDataCNAME.Pack should fail with too small buffer")
	}
}

func TestRDataNSPackBufferTooSmall(t *testing.T) {
	name, _ := ParseName("ns1.example.com.")
	rdata := &RDataNS{NSDName: name}
	buf := make([]byte, 3)
	_, err := rdata.Pack(buf, 0)
	if err == nil {
		t.Error("RDataNS.Pack should fail with too small buffer")
	}
}

func TestRDataPTRPackBufferTooSmall(t *testing.T) {
	name, _ := ParseName("www.example.com.")
	rdata := &RDataPTR{PtrDName: name}
	buf := make([]byte, 3)
	_, err := rdata.Pack(buf, 0)
	if err == nil {
		t.Error("RDataPTR.Pack should fail with too small buffer")
	}
}

func TestRDataMXUnpackBufferTooSmall(t *testing.T) {
	rdata := &RDataMX{}
	_, err := rdata.Unpack([]byte{1}, 0, 10) // Buffer too small for preference
	if err == nil {
		t.Error("RDataMX.Unpack should fail with too small buffer for preference")
	}
}

func TestRDataCAAPackErrors(t *testing.T) {
	// Tag too long
	rdata := &RDataCAA{Tag: strings.Repeat("x", 256), Value: "test"}
	buf := make([]byte, 600)
	_, err := rdata.Pack(buf, 0)
	if err == nil {
		t.Error("RDataCAA.Pack should fail with tag > 255")
	}

	// Buffer too small for flags
	rdata2 := &RDataCAA{Tag: "issue", Value: "test"}
	buf2 := make([]byte, 0)
	_, err = rdata2.Pack(buf2, 0)
	if err == nil {
		t.Error("RDataCAA.Pack should fail with empty buffer")
	}
}

func TestRDataCAAUnpackErrors(t *testing.T) {
	rdata := &RDataCAA{}
	// Buffer too small for endOffset
	_, err := rdata.Unpack([]byte{1, 2}, 0, 10)
	if err == nil {
		t.Error("RDataCAA.Unpack should fail with buffer too small for endOffset")
	}
	// Buffer too small for header (2 bytes needed)
	_, err = rdata.Unpack([]byte{1}, 0, 1)
	if err == nil {
		t.Error("RDataCAA.Unpack should fail with buffer too small for header")
	}
	// Tag extends past endOffset
	_, err = rdata.Unpack([]byte{0, 5, 'h', 'e', 'l'}, 0, 3) // tagLen=5 but only 3 bytes
	if err == nil {
		t.Error("RDataCAA.Unpack should fail when tag extends past endOffset")
	}
}

func TestRDataNAPTRPackErrors(t *testing.T) {
	target, _ := ParseName("sip.example.com.")
	rdata := &RDataNAPTR{Order: 1, Preference: 2, Flags: strings.Repeat("x", 256), Replacement: target}
	buf := make([]byte, 600)
	_, err := rdata.Pack(buf, 0)
	if err == nil {
		t.Error("RDataNAPTR.Pack should fail with flags > 255")
	}
	rdata2 := &RDataNAPTR{Order: 1, Preference: 2, Flags: "U", Service: strings.Repeat("x", 256), Replacement: target}
	_, err = rdata2.Pack(buf, 0)
	if err == nil {
		t.Error("RDataNAPTR.Pack should fail with service > 255")
	}
	rdata3 := &RDataNAPTR{Order: 1, Preference: 2, Flags: "U", Service: "SIP", Regexp: strings.Repeat("x", 256), Replacement: target}
	_, err = rdata3.Pack(buf, 0)
	if err == nil {
		t.Error("RDataNAPTR.Pack should fail with regexp > 255")
	}
}

func TestRDataNAPTRPackBufferTooSmall(t *testing.T) {
	rdata := &RDataNAPTR{Order: 1, Preference: 2}
	buf := make([]byte, 3)
	_, err := rdata.Pack(buf, 0)
	if err == nil {
		t.Error("RDataNAPTR.Pack should fail with buffer too small for order")
	}
}

func TestRDataSSHFPPackBufferTooSmall(t *testing.T) {
	rdata := &RDataSSHFP{Algorithm: 1, FPType: 2, Fingerprint: []byte{1, 2, 3}}
	buf := make([]byte, 3) // Too small for 2 + 3 = 5 bytes
	_, err := rdata.Pack(buf, 0)
	if err == nil {
		t.Error("RDataSSHFP.Pack should fail with too small buffer")
	}
}

func TestRDataTLSAPackBufferTooSmall(t *testing.T) {
	rdata := &RDataTLSA{Usage: 1, Selector: 2, MatchingType: 3, Certificate: []byte{4, 5}}
	buf := make([]byte, 3) // Too small for 3 + 2 = 5 bytes
	_, err := rdata.Pack(buf, 0)
	if err == nil {
		t.Error("RDataTLSA.Pack should fail with too small buffer")
	}
}

func TestRDataDNSKEYPackRoundTrip(t *testing.T) {
	rdata := &RDataDNSKEY{
		Flags:     DNSKEYFlagZone | DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: AlgorithmRSASHA256,
		PublicKey: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
	}
	buf := make([]byte, 512)
	n, err := rdata.Pack(buf, 0)
	if err != nil {
		t.Fatalf("DNSKEY.Pack error: %v", err)
	}
	unpacked := &RDataDNSKEY{}
	_, err = unpacked.Unpack(buf, 0, uint16(n))
	if err != nil {
		t.Fatalf("DNSKEY.Unpack error: %v", err)
	}
	if unpacked.Flags != rdata.Flags {
		t.Errorf("DNSKEY Flags mismatch: got %d, want %d", unpacked.Flags, rdata.Flags)
	}
	if unpacked.Algorithm != rdata.Algorithm {
		t.Errorf("DNSKEY Algorithm mismatch: got %d, want %d", unpacked.Algorithm, rdata.Algorithm)
	}
	if !bytes.Equal(unpacked.PublicKey, rdata.PublicKey) {
		t.Errorf("DNSKEY PublicKey mismatch")
	}
}

func TestRDataDNSKEYPackBufferTooSmall(t *testing.T) {
	rdata := &RDataDNSKEY{Flags: 257, Protocol: 3, Algorithm: 8, PublicKey: []byte{1, 2, 3}}
	buf := make([]byte, 2)
	_, err := rdata.Pack(buf, 0)
	if err == nil {
		t.Error("RDataDNSKEY.Pack should fail with too small buffer")
	}
}

func TestRDataDSPackRoundTrip(t *testing.T) {
	rdata := &RDataDS{
		KeyTag:     12345,
		Algorithm:  AlgorithmRSASHA256,
		DigestType: 2,
		Digest:     []byte{0xAA, 0xBB, 0xCC, 0xDD},
	}
	buf := make([]byte, 512)
	n, err := rdata.Pack(buf, 0)
	if err != nil {
		t.Fatalf("DS.Pack error: %v", err)
	}
	unpacked := &RDataDS{}
	_, err = unpacked.Unpack(buf, 0, uint16(n))
	if err != nil {
		t.Fatalf("DS.Unpack error: %v", err)
	}
	if unpacked.KeyTag != rdata.KeyTag {
		t.Errorf("DS KeyTag mismatch: got %d, want %d", unpacked.KeyTag, rdata.KeyTag)
	}
}

func TestRDataDSPackBufferTooSmall(t *testing.T) {
	rdata := &RDataDS{KeyTag: 1, Algorithm: 8, DigestType: 2, Digest: []byte{1, 2}}
	buf := make([]byte, 2)
	_, err := rdata.Pack(buf, 0)
	if err == nil {
		t.Error("RDataDS.Pack should fail with too small buffer")
	}
}

func TestRDataRRSIGPackRoundTrip(t *testing.T) {
	signer, _ := ParseName("example.com.")
	rdata := &RDataRRSIG{
		TypeCovered: TypeA,
		Algorithm:   AlgorithmRSASHA256,
		Labels:      2,
		OriginalTTL: 3600,
		Expiration:  1735689600,
		Inception:   1704153600,
		KeyTag:      12345,
		SignerName:  signer,
		Signature:   []byte{0xAA, 0xBB, 0xCC},
	}
	buf := make([]byte, 512)
	n, err := rdata.Pack(buf, 0)
	if err != nil {
		t.Fatalf("RRSIG.Pack error: %v", err)
	}
	unpacked := &RDataRRSIG{}
	_, err = unpacked.Unpack(buf, 0, uint16(n))
	if err != nil {
		t.Fatalf("RRSIG.Unpack error: %v", err)
	}
	if unpacked.TypeCovered != rdata.TypeCovered {
		t.Errorf("RRSIG TypeCovered mismatch")
	}
	if unpacked.KeyTag != rdata.KeyTag {
		t.Errorf("RRSIG KeyTag mismatch")
	}
}

func TestRDataRRSIGPackBufferTooSmall(t *testing.T) {
	signer, _ := ParseName("example.com.")
	rdata := &RDataRRSIG{SignerName: signer, Signature: []byte{1}}
	buf := make([]byte, 5)
	_, err := rdata.Pack(buf, 0)
	if err == nil {
		t.Error("RRSIG.Pack should fail with too small buffer")
	}
}

// ============================================================================
// RDataNSECPack/Unpack round-trip
// ============================================================================

func TestRDataNSECPackRoundTrip(t *testing.T) {
	next, _ := ParseName("next.example.com.")
	rdata := &RDataNSEC{NextDomain: next, TypeBitMap: []uint16{TypeA, TypeNS, TypeMX, TypeAAAA, TypeTXT}}
	buf := make([]byte, 512)
	n, err := rdata.Pack(buf, 0)
	if err != nil {
		t.Fatalf("NSEC.Pack error: %v", err)
	}
	unpacked := &RDataNSEC{}
	_, err = unpacked.Unpack(buf, 0, uint16(n))
	if err != nil {
		t.Fatalf("NSEC.Unpack error: %v", err)
	}
	if !unpacked.NextDomain.Equal(rdata.NextDomain) {
		t.Errorf("NSEC NextDomain mismatch: got %s, want %s", unpacked.NextDomain, rdata.NextDomain)
	}
}

func TestRDataNSECPackBufferTooSmall(t *testing.T) {
	next, _ := ParseName("next.example.com.")
	rdata := &RDataNSEC{NextDomain: next}
	buf := make([]byte, 3)
	_, err := rdata.Pack(buf, 0)
	if err == nil {
		t.Error("NSEC.Pack should fail with too small buffer")
	}
}

func TestRDataNSEC3PackRoundTrip(t *testing.T) {
	rdata := &RDataNSEC3{
		HashAlgorithm: NSEC3HashSHA1,
		Flags:         NSEC3FlagOptOut,
		Iterations:    100,
		Salt:          []byte{0xAA, 0xBB},
		NextHashed:    []byte{0x01, 0x02, 0x03, 0x04},
		TypeBitMap:    []uint16{TypeA, TypeNS},
	}
	buf := make([]byte, 512)
	n, err := rdata.Pack(buf, 0)
	if err != nil {
		t.Fatalf("NSEC3.Pack error: %v", err)
	}
	unpacked := &RDataNSEC3{}
	_, err = unpacked.Unpack(buf, 0, uint16(n))
	if err != nil {
		t.Fatalf("NSEC3.Unpack error: %v", err)
	}
	if unpacked.Iterations != rdata.Iterations {
		t.Errorf("NSEC3 Iterations mismatch: got %d, want %d", unpacked.Iterations, rdata.Iterations)
	}
}

func TestRDataNSEC3PARAMPackRoundTrip(t *testing.T) {
	rdata := &RDataNSEC3PARAM{
		HashAlgorithm: NSEC3HashSHA1,
		Flags:         0,
		Iterations:    100,
		Salt:          []byte{0xAA, 0xBB},
	}
	buf := make([]byte, 512)
	n, err := rdata.Pack(buf, 0)
	if err != nil {
		t.Fatalf("NSEC3PARAM.Pack error: %v", err)
	}
	unpacked := &RDataNSEC3PARAM{}
	_, err = unpacked.Unpack(buf, 0, uint16(n))
	if err != nil {
		t.Fatalf("NSEC3PARAM.Unpack error: %v", err)
	}
	if unpacked.Iterations != rdata.Iterations {
		t.Errorf("NSEC3PARAM Iterations mismatch: got %d, want %d", unpacked.Iterations, rdata.Iterations)
	}
}

func TestRDataNSEC3PARAMPackBufferTooSmall(t *testing.T) {
	rdata := &RDataNSEC3PARAM{HashAlgorithm: 1, Iterations: 100, Salt: []byte{1, 2}}
	buf := make([]byte, 3)
	_, err := rdata.Pack(buf, 0)
	if err == nil {
		t.Error("NSEC3PARAM.Pack should fail with too small buffer")
	}
}

// ============================================================================
// RDataOPT Pack/Unpack edge cases
// ============================================================================

func TestRDataOPTPackBufferTooSmall(t *testing.T) {
	opt := &RDataOPT{Options: []EDNS0Option{{Code: 1, Data: []byte("test")}}}
	buf := make([]byte, 3)
	_, err := opt.Pack(buf, 0)
	if err == nil {
		t.Error("RDataOPT.Pack should fail with too small buffer")
	}
}

func TestRDataOPTUnpackBufferTooSmall(t *testing.T) {
	opt := &RDataOPT{}
	_, err := opt.Unpack([]byte{1, 2}, 0, 10) // rdlength > buffer
	if err == nil {
		t.Error("RDataOPT.Unpack should fail with too small buffer")
	}
}

// ============================================================================
// ResourceRecord.Pack/Unpack error cases
// ============================================================================

func TestResourceRecordPackBufferTooSmall(t *testing.T) {
	name, _ := ParseName("example.com.")
	rr := &ResourceRecord{Name: name, Type: TypeA, Class: ClassIN, TTL: 300, Data: &RDataA{Address: [4]byte{1, 2, 3, 4}}}
	buf := make([]byte, 5)
	_, err := rr.Pack(buf, 0, nil)
	if err == nil {
		t.Error("ResourceRecord.Pack should fail with too small buffer")
	}
}

func TestResourceRecordCopyNil(t *testing.T) {
	var rr *ResourceRecord
	cpy := rr.Copy()
	if cpy != nil {
		t.Error("Copy of nil ResourceRecord should return nil")
	}
}

func TestRDataRawPackBufferTooSmall(t *testing.T) {
	raw := &RDataRaw{TypeVal: 99, Data: []byte{1, 2, 3, 4, 5}}
	buf := make([]byte, 3)
	_, err := raw.Pack(buf, 0)
	if err == nil {
		t.Error("RDataRaw.Pack should fail with too small buffer")
	}
}

// ============================================================================
// CompareNames edge cases
// ============================================================================

func TestCompareNamesEdgeCases(t *testing.T) {
	// Equal names
	a, _ := ParseName("example.com.")
	b, _ := ParseName("example.com.")
	if result := CompareNames(a, b); result != 0 {
		t.Errorf("CompareNames(equal) = %d, want 0", result)
	}

	// Different TLDs
	c, _ := ParseName("example.com.")
	d, _ := ParseName("example.org.")
	result := CompareNames(c, d)
	if result == 0 {
		t.Error("CompareNames for different TLDs should not be 0")
	}
}

// ============================================================================
// WireNameLength edge cases
// ============================================================================

func TestWireNameLengthPointerChain(t *testing.T) {
	// Pointer to root name
	data := []byte{0xC0, 0x02, 0x00}
	length, err := WireNameLength(data, 0)
	if err != nil {
		t.Fatalf("WireNameLength pointer error: %v", err)
	}
	if length != 2 {
		t.Errorf("WireNameLength pointer = %d, want 2", length)
	}
}

// ============================================================================
// NewQuestion error case
// ============================================================================

func TestNewQuestionError(t *testing.T) {
	_, err := NewQuestion("test\x00invalid", TypeA, ClassIN)
	if err == nil {
		t.Error("NewQuestion should fail with null byte in name")
	}
}

// ============================================================================
// VerifyParams edge cases
// ============================================================================

func TestNSEC3PARAMVerifyParamsInvalidAlgorithm(t *testing.T) {
	invalid := &RDataNSEC3PARAM{
		HashAlgorithm: 99,
		Iterations:    100,
		Salt:          []byte{},
	}
	if err := invalid.VerifyParams(); err == nil {
		t.Error("VerifyParams should fail for invalid algorithm")
	}
}

// ============================================================================
// CalculateDSDigest with SHA-1
// ============================================================================

func TestCalculateDSDigestSHA1Unsupported(t *testing.T) {
	dnskey := &RDataDNSKEY{
		Flags:     DNSKEYFlagZone,
		Protocol:  3,
		Algorithm: AlgorithmRSASHA256,
		PublicKey: []byte{0x01, 0x02, 0x03, 0x04},
	}
	_, err := CalculateDSDigest("example.com.", dnskey, 1) // SHA-1 - deprecated, not supported
	if err == nil {
		t.Error("CalculateDSDigest should fail for SHA-1 (deprecated)")
	}
}

func TestCalculateDSDigestGOSTUnsupported(t *testing.T) {
	dnskey := &RDataDNSKEY{
		Flags:     DNSKEYFlagZone,
		Protocol:  3,
		Algorithm: AlgorithmRSASHA256,
		PublicKey: []byte{0x01, 0x02, 0x03, 0x04},
	}
	_, err := CalculateDSDigest("example.com.", dnskey, 3) // GOST - not implemented
	if err == nil {
		t.Error("CalculateDSDigest should fail for GOST (not implemented)")
	}
}

// ============================================================================
// RDataTXT String with special chars
// ============================================================================

func TestRDataTXTStringWithSpecialChars(t *testing.T) {
	rdata := &RDataTXT{Strings: []string{"hello world", `test "quoted"`}}
	s := rdata.String()
	if !strings.Contains(s, "hello") {
		t.Error("String should contain 'hello'")
	}
}

// ============================================================================
// Labels edge cases
// ============================================================================

func TestNameEqualEdgeCase(t *testing.T) {
	// Both nil names
	n1 := &Name{Labels: nil, FQDN: true}
	n2 := &Name{Labels: nil, FQDN: true}
	if !n1.Equal(n2) {
		t.Error("Two nil-label names should be equal")
	}

	// Different number of labels
	n3, _ := ParseName("a.example.com.")
	n4, _ := ParseName("example.com.")
	if n3.Equal(n4) {
		t.Error("Names with different label counts should not be equal")
	}
}

// ============================================================================
// WriteUint8 error case
// ============================================================================

func TestBufferWriteUint8Error(t *testing.T) {
	buf := NewBuffer(512)
	buf.SetOffset(int(buf.Capacity()) - 1)
	buf.length = buf.Capacity()
	// Fill the buffer up to capacity
	for i := 0; i < buf.Capacity()-1; i++ {
		buf.WriteUint8(0)
	}
	// Now writing should fail
	err := buf.WriteUint8(0)
	if err == nil {
		t.Error("WriteUint8 should fail when buffer is full")
	}
}

// ============================================================================
// UnpackMessage with full round-trip
// ============================================================================

func TestUnpackMessageWithAuthorityAndAdditional(t *testing.T) {
	msg := NewMessage(Header{ID: 0x1234, Flags: NewResponseFlags(RcodeSuccess)})
	q, _ := NewQuestion("example.com.", TypeA, ClassIN)
	msg.AddQuestion(q)

	name, _ := ParseName("example.com.")
	msg.AddAnswer(&ResourceRecord{Name: name, Type: TypeA, Class: ClassIN, TTL: 300,
		Data: &RDataA{Address: [4]byte{1, 2, 3, 4}}})
	msg.AddAuthority(&ResourceRecord{Name: name, Type: TypeNS, Class: ClassIN, TTL: 3600,
		Data: &RDataNS{NSDName: name}})
	msg.AddAdditional(&ResourceRecord{Name: name, Type: TypeA, Class: ClassIN, TTL: 60,
		Data: &RDataA{Address: [4]byte{5, 6, 7, 8}}})

	buf := make([]byte, 1024)
	n, err := msg.Pack(buf)
	if err != nil {
		t.Fatalf("Pack error: %v", err)
	}
	unpacked, err := UnpackMessage(buf[:n])
	if err != nil {
		t.Fatalf("UnpackMessage error: %v", err)
	}
	if len(unpacked.Authorities) != 1 {
		t.Errorf("Authorities count = %d, want 1", len(unpacked.Authorities))
	}
	if len(unpacked.Additionals) != 1 {
		t.Errorf("Additionals count = %d, want 1", len(unpacked.Additionals))
	}
}

// ============================================================================
// opcodeString - cover IQUERY, STATUS, NOTIFY, UPDATE cases (28.6%)
// ============================================================================

func TestOpcodeStringAllCases(t *testing.T) {
	// opcodeString() is called from Header.String(), not Flags.String().
	// Flags.String() has its own switch that outputs "OPCODE<n>" for unknown opcodes.
	tests := []struct {
		opcode uint8
		want   string
	}{
		{OpcodeQuery, "QUERY"},
		{OpcodeIQuery, "IQUERY"},
		{OpcodeStatus, "STATUS"},
		{OpcodeNotify, "NOTIFY"},
		{OpcodeUpdate, "UPDATE"},
		{6, "opcode: 6"}, // default case from opcodeString
	}
	for _, tt := range tests {
		h := Header{ID: 1, Flags: Flags{Opcode: tt.opcode}}
		s := h.String()
		if !strings.Contains(s, tt.want) {
			t.Errorf("Header{Opcode:%d}.String() = %q, want to contain %q", tt.opcode, s, tt.want)
		}
	}
}

// ============================================================================
// toLower - cover uppercase and non-uppercase paths via PackName (66.7%)
// ============================================================================

func TestToLowerViaPackName(t *testing.T) {
	// toLower is called from PackName when packing label bytes.
	// Pack uppercase labels to exercise the uppercase branch.
	name, _ := ParseName("EXAMPLE.COM.")
	buf := make([]byte, 512)
	n, err := PackName(name, buf, 0, nil)
	if err != nil {
		t.Fatalf("PackName error: %v", err)
	}
	// Verify the packed bytes are lowercase
	// "example" = 7 bytes prefixed by 7, "com" = 3 bytes prefixed by 3, then 0
	if buf[0] != 7 {
		t.Errorf("First label length = %d, want 7", buf[0])
	}
	// Check that "example" was lowercased
	for i := 1; i <= 7; i++ {
		if buf[i] < 'a' || buf[i] > 'z' {
			t.Errorf("Byte %d = %d, expected lowercase letter", i, buf[i])
		}
	}
	_ = n

	// Also pack lowercase to exercise the non-uppercase branch
	nameLower, _ := ParseName("example.com.")
	buf2 := make([]byte, 512)
	n2, err := PackName(nameLower, buf2, 0, nil)
	if err != nil {
		t.Fatalf("PackName lower error: %v", err)
	}
	_ = n2
}

// ============================================================================
// CompareNames - cover subdomain comparison branches (75%)
// ============================================================================

func TestCompareNamesSubdomainBranches(t *testing.T) {
	// a is shorter (fewer labels) than b -> returns -1 (i < 0)
	a, _ := ParseName("example.com.")
	b, _ := ParseName("www.example.com.")
	if result := CompareNames(a, b); result != -1 {
		t.Errorf("CompareNames(example.com, www.example.com) = %d, want -1", result)
	}

	// a is longer (more labels) than b -> returns 1 (j < 0)
	c, _ := ParseName("www.example.com.")
	d, _ := ParseName("example.com.")
	if result := CompareNames(c, d); result != 1 {
		t.Errorf("CompareNames(www.example.com, example.com) = %d, want 1", result)
	}

	// Equal names with different case
	e, _ := ParseName("Example.Com.")
	f2, _ := ParseName("example.com.")
	if result := CompareNames(e, f2); result != 0 {
		t.Errorf("CompareNames(Example.Com, example.com) = %d, want 0", result)
	}
}

// ============================================================================
// CNAME String/Len with non-nil CName (66.7%)
// ============================================================================

func TestRDataCNAMEStringAndLenNonNil(t *testing.T) {
	name, _ := ParseName("www.example.com.")
	rdata := &RDataCNAME{CName: name}
	s := rdata.String()
	if s != "www.example.com." {
		t.Errorf("CNAME.String() = %q, want %q", s, "www.example.com.")
	}
	l := rdata.Len()
	if l != name.WireLength() {
		t.Errorf("CNAME.Len() = %d, want %d", l, name.WireLength())
	}
}

// ============================================================================
// NS String/Len with non-nil NSDName (66.7%)
// ============================================================================

func TestRDataNSStringAndLenNonNil(t *testing.T) {
	name, _ := ParseName("ns1.example.com.")
	rdata := &RDataNS{NSDName: name}
	s := rdata.String()
	if s != "ns1.example.com." {
		t.Errorf("NS.String() = %q, want %q", s, "ns1.example.com.")
	}
	l := rdata.Len()
	if l != name.WireLength() {
		t.Errorf("NS.Len() = %d, want %d", l, name.WireLength())
	}
}

// ============================================================================
// PTR String/Len with non-nil PtrDName (66.7%)
// ============================================================================

func TestRDataPTRStringAndLenNonNil(t *testing.T) {
	name, _ := ParseName("host.example.com.")
	rdata := &RDataPTR{PtrDName: name}
	s := rdata.String()
	if s != "host.example.com." {
		t.Errorf("PTR.String() = %q, want %q", s, "host.example.com.")
	}
	l := rdata.Len()
	if l != name.WireLength() {
		t.Errorf("PTR.Len() = %d, want %d", l, name.WireLength())
	}
}

// ============================================================================
// MX String/Len with non-nil Exchange (66.7%/75%)
// ============================================================================

func TestRDataMXStringAndLenNonNil(t *testing.T) {
	name, _ := ParseName("mail.example.com.")
	rdata := &RDataMX{Preference: 10, Exchange: name}
	s := rdata.String()
	expected := "10 mail.example.com."
	if s != expected {
		t.Errorf("MX.String() = %q, want %q", s, expected)
	}
	l := rdata.Len()
	if l != 2+name.WireLength() {
		t.Errorf("MX.Len() = %d, want %d", l, 2+name.WireLength())
	}
}

// ============================================================================
// SOA String with non-nil MName/RName (71.4%)
// ============================================================================

func TestRDataSOAStringNonNil(t *testing.T) {
	mname, _ := ParseName("ns1.example.com.")
	rname, _ := ParseName("admin.example.com.")
	rdata := &RDataSOA{
		MName: mname, RName: rname,
		Serial: 2024010101, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 86400,
	}
	s := rdata.String()
	if !strings.Contains(s, "ns1.example.com.") {
		t.Errorf("SOA.String() should contain mname, got %q", s)
	}
	if !strings.Contains(s, "admin.example.com.") {
		t.Errorf("SOA.String() should contain rname, got %q", s)
	}
	if !strings.Contains(s, "2024010101") {
		t.Errorf("SOA.String() should contain serial, got %q", s)
	}
}

// ============================================================================
// SRV String with non-nil Target (75%)
// ============================================================================

func TestRDataSRVStringNonNil(t *testing.T) {
	target, _ := ParseName("sip.example.com.")
	rdata := &RDataSRV{Priority: 10, Weight: 20, Port: 5060, Target: target}
	s := rdata.String()
	expected := "10 20 5060 sip.example.com."
	if s != expected {
		t.Errorf("SRV.String() = %q, want %q", s, expected)
	}
	l := rdata.Len()
	if l != 6+target.WireLength() {
		t.Errorf("SRV.Len() = %d, want %d", l, 6+target.WireLength())
	}
}

// ============================================================================
// RRSIG.Pack - cover each buffer-too-small boundary (79.5%)
// ============================================================================

func TestRDataRRSIGPackBoundaryErrors(t *testing.T) {
	signer, _ := ParseName("example.com.")
	base := &RDataRRSIG{
		TypeCovered: TypeA,
		Algorithm:   AlgorithmRSASHA256,
		Labels:      2,
		OriginalTTL: 3600,
		Expiration:  1735689600,
		Inception:   1704153600,
		KeyTag:      12345,
		SignerName:  signer,
		Signature:   []byte{0xAA, 0xBB, 0xCC},
	}

	// Each boundary: we test buffer sizes that fail at each check point
	// TypeCovered needs 2 bytes
	_, err := base.Pack(make([]byte, 1), 0)
	if err == nil {
		t.Error("RRSIG.Pack should fail at TypeCovered with buf size 1")
	}
	// Algorithm needs 1 more byte (offset 2)
	_, err = base.Pack(make([]byte, 2), 0)
	if err == nil {
		t.Error("RRSIG.Pack should fail at Algorithm with buf size 2")
	}
	// Labels needs 1 more byte (offset 3)
	_, err = base.Pack(make([]byte, 3), 0)
	if err == nil {
		t.Error("RRSIG.Pack should fail at Labels with buf size 3")
	}
	// OriginalTTL needs 4 more bytes (offset 4)
	_, err = base.Pack(make([]byte, 4), 0)
	if err == nil {
		t.Error("RRSIG.Pack should fail at OriginalTTL with buf size 4")
	}
	// Expiration needs 4 more bytes (offset 8)
	_, err = base.Pack(make([]byte, 7), 0)
	if err == nil {
		t.Error("RRSIG.Pack should fail at Expiration with buf size 7")
	}
	// Inception needs 4 more bytes (offset 12)
	_, err = base.Pack(make([]byte, 11), 0)
	if err == nil {
		t.Error("RRSIG.Pack should fail at Inception with buf size 11")
	}
	// KeyTag needs 2 more bytes (offset 16)
	_, err = base.Pack(make([]byte, 15), 0)
	if err == nil {
		t.Error("RRSIG.Pack should fail at KeyTag with buf size 15")
	}
	// Signature doesn't fit
	// Signer name wire length for "example.com." is 13 bytes
	signerWireLen := signer.WireLength()
	sigOffset := 18 + signerWireLen
	_, err = base.Pack(make([]byte, sigOffset+1), 0) // Need 3 bytes for sig, only 1 available
	if err == nil {
		t.Error("RRSIG.Pack should fail at Signature with small buffer")
	}
}

// ============================================================================
// NAPTR Unpack - cover buffer-too-small branches (76.9%)
// ============================================================================

func TestRDataNAPTRUnpackBoundaryErrors(t *testing.T) {
	// Pack a valid NAPTR first
	replacement, _ := ParseName("sip.example.com.")
	full := &RDataNAPTR{
		Order: 1, Preference: 2, Flags: "U", Service: "SIP+D2U",
		Regexp: "", Replacement: replacement,
	}
	buf := make([]byte, 512)
	n, err := full.Pack(buf, 0)
	if err != nil {
		t.Fatalf("Pack error: %v", err)
	}

	// Test truncated buffers at various points
	rdata := &RDataNAPTR{}

	// Order truncated (need 2 bytes, have 1)
	_, err = rdata.Unpack([]byte{0}, 0, 1)
	if err == nil {
		t.Error("NAPTR.Unpack should fail with 1-byte buffer for Order")
	}

	// Preference truncated (need 4 bytes total for order+pref, have 3)
	_, err = rdata.Unpack(buf[:3], 0, 3)
	if err == nil {
		t.Error("NAPTR.Unpack should fail with 3-byte buffer for Preference")
	}

	// Flags length byte missing (need 5 bytes)
	_, err = rdata.Unpack(buf[:4], 0, 4)
	if err == nil {
		t.Error("NAPTR.Unpack should fail with 4-byte buffer for Flags length")
	}

	// Service length byte truncated
	// Pack: 2(order) + 2(pref) + 1(flagsLen) + 1(flagsVal) + 1(serviceLen) = 7 bytes to get to service length
	serviceLenOffset := 2 + 2 + 1 + len(full.Flags) + 1
	if serviceLenOffset > 0 && serviceLenOffset <= n {
		_, err = rdata.Unpack(buf[:serviceLenOffset-1], 0, uint16(serviceLenOffset-1))
		if err == nil {
			t.Error("NAPTR.Unpack should fail when service length byte is missing")
		}
	}

	// Regexp length byte truncated
	regexpLenOffset := 2 + 2 + 1 + len(full.Flags) + 1 + len(full.Service) + 1
	if regexpLenOffset > 0 && regexpLenOffset <= n {
		_, err = rdata.Unpack(buf[:regexpLenOffset-1], 0, uint16(regexpLenOffset-1))
		if err == nil {
			t.Error("NAPTR.Unpack should fail when regexp length byte is missing")
		}
	}
}

// ============================================================================
// UnpackMessage - cover authority/additional unpack error branches (79.5%)
// ============================================================================

func TestUnpackMessageAuthorityError(t *testing.T) {
	// Create a message with an authority record, then truncate at the authority section
	msg := NewMessage(Header{ID: 0x1234, Flags: NewResponseFlags(RcodeSuccess)})
	q, _ := NewQuestion("example.com.", TypeA, ClassIN)
	msg.AddQuestion(q)

	name, _ := ParseName("example.com.")
	msg.AddAuthority(&ResourceRecord{Name: name, Type: TypeNS, Class: ClassIN, TTL: 3600,
		Data: &RDataNS{NSDName: name}})

	buf := make([]byte, 1024)
	n, _ := msg.Pack(buf)

	// Truncate right after the question section to make authority unpack fail
	questionEnd := HeaderLen
	for _, q := range msg.Questions {
		questionEnd += q.Name.WireLength() + 4
	}
	// Add a few bytes to enter the authority section but not enough
	truncatedSize := questionEnd + 3
	if truncatedSize < n {
		_, err := UnpackMessage(buf[:truncatedSize])
		if err == nil {
			t.Error("UnpackMessage should fail with truncated authority data")
		}
	}
}

func TestUnpackMessageAdditionalError(t *testing.T) {
	// Create a message with an additional record, then truncate at the additional section
	msg := NewMessage(Header{ID: 0x1234, Flags: NewResponseFlags(RcodeSuccess)})
	q, _ := NewQuestion("example.com.", TypeA, ClassIN)
	msg.AddQuestion(q)

	name, _ := ParseName("example.com.")
	msg.AddAdditional(&ResourceRecord{Name: name, Type: TypeA, Class: ClassIN, TTL: 60,
		Data: &RDataA{Address: [4]byte{5, 6, 7, 8}}})

	buf := make([]byte, 1024)
	n, _ := msg.Pack(buf)

	// Calculate the offset just after questions
	questionEnd := HeaderLen
	for _, q := range msg.Questions {
		questionEnd += q.Name.WireLength() + 4
	}

	// Find the end of answers (none) + authorities (none) = questionEnd
	// Truncate a few bytes into the additional section
	truncatedSize := questionEnd + 3
	if truncatedSize < n {
		_, err := UnpackMessage(buf[:truncatedSize])
		if err == nil {
			t.Error("UnpackMessage should fail with truncated additional data")
		}
	}
}

// ============================================================================
// UnpackMessage answer error
// ============================================================================

func TestUnpackMessageAnswerError(t *testing.T) {
	// Create a message with answers, truncate in answer section
	msg := NewMessage(Header{ID: 0x1234, Flags: NewResponseFlags(RcodeSuccess)})
	q, _ := NewQuestion("example.com.", TypeA, ClassIN)
	msg.AddQuestion(q)

	name, _ := ParseName("example.com.")
	msg.AddAnswer(&ResourceRecord{Name: name, Type: TypeA, Class: ClassIN, TTL: 300,
		Data: &RDataA{Address: [4]byte{1, 2, 3, 4}}})

	buf := make([]byte, 1024)
	n, _ := msg.Pack(buf)

	// Calculate question end offset
	questionEnd := HeaderLen
	for _, q := range msg.Questions {
		questionEnd += q.Name.WireLength() + 4
	}

	// Truncate a few bytes into the answer section
	truncatedSize := questionEnd + 5
	if truncatedSize < n {
		_, err := UnpackMessage(buf[:truncatedSize])
		if err == nil {
			t.Error("UnpackMessage should fail with truncated answer data")
		}
	}
}

// ============================================================================
// Header.String with various opcodes
// ============================================================================

func TestHeaderStringWithOpcode(t *testing.T) {
	tests := []struct {
		opcode uint8
		want   string
	}{
		{OpcodeQuery, "QUERY"},
		{OpcodeIQuery, "IQUERY"},
		{OpcodeStatus, "STATUS"},
		{OpcodeNotify, "NOTIFY"},
		{OpcodeUpdate, "UPDATE"},
	}
	for _, tt := range tests {
		h := Header{ID: 1, Flags: Flags{Opcode: tt.opcode}}
		s := h.String()
		if !strings.Contains(s, tt.want) {
			t.Errorf("Header.String() with Opcode=%d should contain %q, got %q", tt.opcode, tt.want, s)
		}
	}
}

// ============================================================================
// RDataSOA Len with non-nil names
// ============================================================================

func TestRDataSOALenNonNil(t *testing.T) {
	mname, _ := ParseName("ns1.example.com.")
	rname, _ := ParseName("admin.example.com.")
	rdata := &RDataSOA{
		MName: mname, RName: rname,
		Serial: 1, Refresh: 2, Retry: 3, Expire: 4, Minimum: 5,
	}
	expectedLen := mname.WireLength() + rname.WireLength() + 20
	l := rdata.Len()
	if l != expectedLen {
		t.Errorf("SOA.Len() = %d, want %d", l, expectedLen)
	}
}

// ============================================================================
// CNAME/NS/PTR/MX Len with nil fields (covers nil branches at 66.7%)
// ============================================================================

func TestRDataCNAMELenNil(t *testing.T) {
	rdata := &RDataCNAME{CName: nil}
	l := rdata.Len()
	if l != 1 {
		t.Errorf("CNAME.Len() with nil = %d, want 1", l)
	}
}

func TestRDataNSLenNil(t *testing.T) {
	rdata := &RDataNS{NSDName: nil}
	l := rdata.Len()
	if l != 1 {
		t.Errorf("NS.Len() with nil = %d, want 1", l)
	}
}

func TestRDataPTRLenNil(t *testing.T) {
	rdata := &RDataPTR{PtrDName: nil}
	l := rdata.Len()
	if l != 1 {
		t.Errorf("PTR.Len() with nil = %d, want 1", l)
	}
}

func TestRDataMXLenNil(t *testing.T) {
	rdata := &RDataMX{Exchange: nil}
	l := rdata.Len()
	if l != 3 {
		t.Errorf("MX.Len() with nil Exchange = %d, want 3", l)
	}
}

// ============================================================================
// UnpackMessage offset boundary check for questions
// ============================================================================

func TestUnpackMessageQuestionOffsetCheck(t *testing.T) {
	// Create a header that says QDCount=1 but buffer is just header + 0 bytes
	buf := make([]byte, HeaderLen)
	h := Header{ID: 0x1234, Flags: NewQueryFlags(), QDCount: 1}
	h.Pack(buf[:HeaderLen])

	_, err := UnpackMessage(buf)
	if err == nil {
		t.Error("UnpackMessage should fail when buffer is exactly header size with QDCount=1")
	}
}

// ============================================================================
// fmt import check - ensure we don't have unused imports
// ============================================================================

func TestCoverageImportCheck(t *testing.T) {
	// This ensures the fmt import is used
	_ = fmt.Sprintf("test")
}
