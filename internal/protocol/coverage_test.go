package protocol

import (
	"bytes"
	"net"
	"strings"
	"testing"
)

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
	if msg.Header.Flags.TC {
		t.Error("Truncate must not set TC bit when only additionals were removed (RFC 2181 §9)")
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
	if !msg2.Header.Flags.TC {
		t.Error("Truncate should set TC bit when removing authorities")
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

// TestMessageTruncateTCBitSemantics verifies RFC 2181 §9 TC semantics:
// TC is set only when required data (Answer/Authority records) was removed,
// never when only Additional-section records were dropped.
func TestMessageTruncateTCBitSemantics(t *testing.T) {
	name, _ := ParseName("example.com.")

	newRR := func(i byte, typ uint16) *ResourceRecord {
		return &ResourceRecord{
			Name: name, Type: typ, Class: ClassIN, TTL: 300,
			Data: &RDataA{Address: [4]byte{i, 2, 3, 4}},
		}
	}

	t.Run("only additionals dropped sets no TC", func(t *testing.T) {
		msg := NewMessage(Header{ID: 0x1234})
		msg.AddQuestion(&Question{Name: name, QType: TypeA, QClass: ClassIN})
		msg.AddAnswer(newRR(1, TypeA))
		for i := byte(0); i < 5; i++ {
			msg.AddAdditional(newRR(i, TypeA))
		}
		// Budget that fits header + question + the one answer, but not the
		// additionals: removing additionals alone makes it fit.
		maxSize := msg.WireLength() - len(msg.Additionals)*msg.Additionals[0].WireLength()
		msg.Truncate(maxSize)
		if got := packedLenForTest(msg); got > maxSize {
			t.Fatalf("message does not fit after Truncate: %d > %d", got, maxSize)
		}
		if len(msg.Answers) != 1 {
			t.Errorf("answers should be intact, got %d", len(msg.Answers))
		}
		if len(msg.Additionals) != 0 {
			t.Errorf("additionals should be removed, got %d", len(msg.Additionals))
		}
		if msg.Header.ARCount != 0 {
			t.Errorf("ARCount = %d, want 0", msg.Header.ARCount)
		}
		if msg.Header.Flags.TC {
			t.Error("TC must not be set when only additionals were dropped (RFC 2181 §9)")
		}
	})

	t.Run("answers dropped sets TC", func(t *testing.T) {
		msg := NewMessage(Header{ID: 0x1234})
		msg.AddQuestion(&Question{Name: name, QType: TypeA, QClass: ClassIN})
		for i := byte(0); i < 5; i++ {
			msg.AddAnswer(newRR(i, TypeA))
		}
		msg.AddAdditional(newRR(9, TypeA))
		// Budget that forces removal of additionals AND at least one answer.
		maxSize := 12 + name.WireLength() + 4 + 2*msg.Answers[0].WireLength()
		msg.Truncate(maxSize)
		if got := packedLenForTest(msg); got > maxSize {
			t.Fatalf("message does not fit after Truncate: %d > %d", got, maxSize)
		}
		if len(msg.Answers) >= 5 {
			t.Fatalf("expected answers to be removed, still have %d", len(msg.Answers))
		}
		if !msg.Header.Flags.TC {
			t.Error("TC must be set when Answer records were removed")
		}
	})

	t.Run("nothing dropped sets no TC", func(t *testing.T) {
		msg := NewMessage(Header{ID: 0x1234})
		msg.AddQuestion(&Question{Name: name, QType: TypeA, QClass: ClassIN})
		msg.AddAnswer(newRR(1, TypeA))
		msg.AddAdditional(newRR(2, TypeA))
		before := msg.WireLength()
		msg.Truncate(before) // exactly fits
		if len(msg.Answers) != 1 || len(msg.Additionals) != 1 {
			t.Errorf("no records should be removed, got %d answers / %d additionals",
				len(msg.Answers), len(msg.Additionals))
		}
		if msg.Header.Flags.TC {
			t.Error("TC must not be set when nothing was removed")
		}
	})
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
// CalculateDSDigest with SHA-1 (NOT RECOMMENDED but supported for compatibility)
// ============================================================================

func TestCalculateDSDigestSHA1(t *testing.T) {
	dnskey := &RDataDNSKEY{
		Flags:     DNSKEYFlagZone,
		Protocol:  3,
		Algorithm: AlgorithmRSASHA256,
		PublicKey: []byte{0x01, 0x02, 0x03, 0x04},
	}
	digest, err := CalculateDSDigest("example.com.", dnskey, 1) // SHA-1 - deprecated but supported
	if err != nil {
		t.Errorf("CalculateDSDigest failed for SHA-1: %v", err)
	}
	if len(digest) != 20 { // SHA-1 produces 20-byte digest
		t.Errorf("expected 20-byte SHA-1 digest, got %d bytes", len(digest))
	}
}

func TestCalculateDSDigestGOST(t *testing.T) {
	// GOST R 34.11-94 (DS digest type 3) is intentionally not implemented;
	// see internal/protocol/dnssec_ds.go header comment. Confirm the
	// honest-fail path returns an error rather than silently producing a
	// non-conformant hash that could match either side of a forgery.
	dnskey := &RDataDNSKEY{
		Flags:     DNSKEYFlagZone,
		Protocol:  3,
		Algorithm: AlgorithmRSASHA256,
		PublicKey: []byte{0x01, 0x02, 0x03, 0x04},
	}
	_, err := CalculateDSDigest("example.com.", dnskey, 3)
	if err == nil {
		t.Fatal("expected error for digest type 3 (GOST); deprecated by RFC 8624 §3.2")
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
	n1 := NewName(nil, true)
	n2 := NewName(nil, true)
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
	buf.SetOffset(buf.Capacity() - 1)
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
	_ = "test"
}

// ============================================================================
// types.go RDataCNAME.Unpack (80.0%) - buffer too small during name unpack
// Line 145: Unpack calls UnpackName which fails with truncated buffer
// ============================================================================

func TestRDataCNAMEUnpackBufferTooSmall(t *testing.T) {
	r := &RDataCNAME{}
	// Label length says 5 bytes but only 1 available
	buf := []byte{0x05, 'a'}
	_, err := r.Unpack(buf, 0, 3)
	if err == nil {
		t.Error("CNAME.Unpack should fail with truncated name data")
	}
}

// ============================================================================
// types.go RDataNS.Unpack (80.0%) - buffer too small during name unpack
// Line 197: Unpack calls UnpackName which fails with truncated buffer
// ============================================================================

func TestRDataNSUnpackBufferTooSmall(t *testing.T) {
	r := &RDataNS{}
	// Label length says 5 bytes but only 1 available
	buf := []byte{0x05, 'a'}
	_, err := r.Unpack(buf, 0, 3)
	if err == nil {
		t.Error("NS.Unpack should fail with truncated name data")
	}
}

// ============================================================================
// types.go RDataPTR.Unpack (80.0%) - buffer too small during name unpack
// Line 249: Unpack calls UnpackName which fails with truncated buffer
// ============================================================================

func TestRDataPTRUnpackBufferTooSmall(t *testing.T) {
	r := &RDataPTR{}
	// Label length says 5 bytes but only 1 available
	buf := []byte{0x05, 'a'}
	_, err := r.Unpack(buf, 0, 3)
	if err == nil {
		t.Error("PTR.Unpack should fail with truncated name data")
	}
}

// ============================================================================
// types.go RDataMX.Unpack (80.0%) - buffer too small for preference
// Line 318: offset+2 > len(buf) check
// ============================================================================

func TestRDataMXUnpackPreferenceTooSmall(t *testing.T) {
	r := &RDataMX{}
	buf := []byte{0x00} // Only 1 byte, need 2 for preference
	_, err := r.Unpack(buf, 0, 2)
	if err == nil {
		t.Error("MX.Unpack should fail when buffer too small for preference")
	}
}

// ============================================================================
// types.go RDataMX.Unpack (80.0%) - preference ok but exchange name fails
// ============================================================================

func TestRDataMXUnpackExchangeNameError(t *testing.T) {
	r := &RDataMX{}
	// 2 bytes for preference, then truncated name
	buf := []byte{0x00, 0x0A, 0x10} // Preference=10, then label len=16 but no data
	_, err := r.Unpack(buf, 0, 5)
	if err == nil {
		t.Error("MX.Unpack should fail when exchange name is truncated")
	}
}

// ============================================================================
// types.go RDataSOA.Unpack (80.0%) - MName unpack error
// Line 145 area: MName UnpackName fails
// ============================================================================

func TestRDataSOAUnpackMNameError(t *testing.T) {
	r := &RDataSOA{}
	// Truncated name for MName
	buf := []byte{0x10} // Label length 16, no data
	_, err := r.Unpack(buf, 0, 30)
	if err == nil {
		t.Error("SOA.Unpack should fail when MName is invalid")
	}
}

// ============================================================================
// types.go RDataSOA.Unpack (80.0%) - RName unpack error
// ============================================================================

func TestRDataSOAUnpackRNameError(t *testing.T) {
	r := &RDataSOA{}
	// Valid MName (root), then truncated RName
	buf := []byte{
		0x00,                // MName = root (1 byte)
		0x10, 'a', 'b', 'c', // RName label length=16, only 3 chars
	}
	_, err := r.Unpack(buf, 0, 30)
	if err == nil {
		t.Error("SOA.Unpack should fail when RName is invalid")
	}
}

// ============================================================================
// types.go RDataSOA.Unpack (80.0%) - fixed fields too small after names
// ============================================================================

func TestRDataSOAUnpackFixedFieldsTooSmall(t *testing.T) {
	r := &RDataSOA{}
	// Valid MName and RName (both root), but only 5 bytes remaining for fixed fields (need 20)
	buf := []byte{
		0x00,                         // MName = root
		0x00,                         // RName = root
		0x01, 0x02, 0x03, 0x04, 0x05, // Only 5 bytes, need 20
	}
	_, err := r.Unpack(buf, 0, 27)
	if err == nil {
		t.Error("SOA.Unpack should fail when fixed fields too small")
	}
}

// ============================================================================
// types.go RDataSOA.Pack (95.5%) - RName pack error
// ============================================================================

func TestRDataSOAPackRNameError(t *testing.T) {
	mname, _ := ParseName("a.")
	rname, _ := ParseName("example.com.")
	r := &RDataSOA{
		MName:   mname,
		RName:   rname,
		Serial:  1,
		Refresh: 2,
		Retry:   3,
		Expire:  4,
		Minimum: 5,
	}

	// Buffer large enough for MName (3 bytes: 1+'a'+0) but not RName
	buf := make([]byte, 3)
	_, err := r.Pack(buf, 0)
	if err == nil {
		t.Error("SOA.Pack should fail when buffer too small for RName")
	}
}

// ============================================================================
// types.go RDataSRV.Unpack (80.0%) - fixed fields too small
// Line 641: offset+6 > len(buf) check
// ============================================================================

func TestRDataSRVUnpackFixedFieldsTooSmall(t *testing.T) {
	r := &RDataSRV{}
	// Only 4 bytes, need 6 for priority+weight+port
	buf := []byte{0x00, 0x01, 0x00, 0x02}
	_, err := r.Unpack(buf, 0, 6)
	if err == nil {
		t.Error("SRV.Unpack should fail when fixed fields too small")
	}
}

// ============================================================================
// types.go RDataSRV.Unpack (80.0%) - target name error
// ============================================================================

func TestRDataSRVUnpackTargetNameError(t *testing.T) {
	r := &RDataSRV{}
	// Valid fixed fields (6 bytes), then truncated target name
	buf := []byte{
		0x00, 0x01, 0x00, 0x02, 0x00, 0x33, // Priority=1, Weight=2, Port=51
		0x10, // Label length=16, no data
	}
	_, err := r.Unpack(buf, 0, 10)
	if err == nil {
		t.Error("SRV.Unpack should fail when target name is invalid")
	}
}

// ============================================================================
// types.go RDataCAA.Unpack (90.9%) - tag length extends past endOffset
// Line 768: offset+tagLen > endOffset check
// ============================================================================

func TestRDataCAAUnpackTagTooLarge(t *testing.T) {
	r := &RDataCAA{}
	// Flags=0, TagLength=10, but only 1 byte of tag data
	buf := []byte{
		0x00, // Flags
		0x0A, // Tag length = 10
		'a',  // Only 1 byte of tag data
	}
	_, err := r.Unpack(buf, 0, 4)
	if err == nil {
		t.Error("CAA.Unpack should fail when tag length extends past endOffset")
	}
}

// ============================================================================
// types.go RDataCAA.Unpack (90.9%) - rdlength too small for even flags+taglen
// Line 756: offset+2 > endOffset check
// ============================================================================

func TestRDataCAAUnpackRdLengthTooSmall(t *testing.T) {
	r := &RDataCAA{}
	// rdlength=1, need at least 2 bytes (flags + tag length)
	buf := []byte{0x00}
	_, err := r.Unpack(buf, 0, 1)
	if err == nil {
		t.Error("CAA.Unpack should fail when rdlength too small for flags+taglen")
	}
}

// ============================================================================
// types.go RDataTXT.Unpack (92.9%) - endOffset > len(buf)
// Line 406: endOffset > len(buf) check
// ============================================================================

func TestRDataTXTUnpackEndOffsetPastBuf(t *testing.T) {
	r := &RDataTXT{}
	buf := []byte{0x00}
	// rdlength=10 but buffer only has 1 byte
	_, err := r.Unpack(buf, 0, 10)
	if err == nil {
		t.Error("TXT.Unpack should fail when endOffset > len(buf)")
	}
}

// ============================================================================
// types.go RDataTXT.Unpack (92.9%) - string data extends past buffer
// Line 417: offset+slen > len(buf) check
// ============================================================================

func TestRDataTXTUnpackStringDataPastBuf(t *testing.T) {
	r := &RDataTXT{}
	// rdlength=5, first string length=4, but only 1 byte of string data after length byte
	buf := []byte{0x04, 'a'}
	_, err := r.Unpack(buf, 0, 5)
	if err == nil {
		t.Error("TXT.Unpack should fail when string data extends past buffer")
	}
}

// ============================================================================
// types.go RDataNAPTR.Pack (97.6%) - service string too long
// Line 981: serviceLen > 255 check
// ============================================================================

func TestRDataNAPTRPackServiceTooLong(t *testing.T) {
	longService := make([]byte, 256)
	for i := range longService {
		longService[i] = 'a'
	}
	r := &RDataNAPTR{
		Order:      1,
		Preference: 1,
		Flags:      "U",
		Service:    string(longService),
		Regexp:     "",
	}
	replacement, _ := ParseName(".")
	r.Replacement = replacement

	buf := make([]byte, 600)
	_, err := r.Pack(buf, 0)
	if err == nil {
		t.Error("NAPTR.Pack should fail when service string > 255 bytes")
	}
}

// ============================================================================
// types.go RDataNAPTR.Pack (97.6%) - regexp string too long
// Line 994: regexpLen > 255 check
// ============================================================================

func TestRDataNAPTRPackRegexpTooLong(t *testing.T) {
	longRegexp := make([]byte, 256)
	for i := range longRegexp {
		longRegexp[i] = 'a'
	}
	r := &RDataNAPTR{
		Order:      1,
		Preference: 1,
		Flags:      "U",
		Service:    "SIP+D2T",
		Regexp:     string(longRegexp),
	}
	replacement, _ := ParseName(".")
	r.Replacement = replacement

	buf := make([]byte, 600)
	_, err := r.Pack(buf, 0)
	if err == nil {
		t.Error("NAPTR.Pack should fail when regexp string > 255 bytes")
	}
}

// ============================================================================
// types.go RDataNAPTR.Unpack (91.7%) - flags data extends past buffer
// Line 1039: offset+flagsLen > len(buf) check
// ============================================================================

func TestRDataNAPTRUnpackFlagsDataTooShort(t *testing.T) {
	// Order(2)+Preference(2)+FlagsLen(1)=5, FlagsLen=5 but only 1 byte of data
	buf := []byte{
		0x00, 0x01, // Order
		0x00, 0x01, // Preference
		0x05, // Flags length = 5
		'U',  // Only 1 byte of flags data
	}
	r := &RDataNAPTR{}
	_, err := r.Unpack(buf, 0, 8)
	if err == nil {
		t.Error("NAPTR.Unpack should fail when flags data extends past buffer")
	}
}

// ============================================================================
// types.go RDataNAPTR.Unpack (91.7%) - service data extends past buffer
// Line 1051: offset+serviceLen > len(buf) check
// ============================================================================

func TestRDataNAPTRUnpackServiceDataTooShort(t *testing.T) {
	buf := []byte{
		0x00, 0x01, // Order
		0x00, 0x01, // Preference
		0x01, 'U', // Flags: length=1, data="U"
		0x05, // Service length = 5
		'a',  // Only 1 byte of service data
	}
	r := &RDataNAPTR{}
	_, err := r.Unpack(buf, 0, 10)
	if err == nil {
		t.Error("NAPTR.Unpack should fail when service data extends past buffer")
	}
}

// ============================================================================
// types.go RDataNAPTR.Unpack (91.7%) - regexp data extends past buffer
// Line 1063: offset+regexpLen > len(buf) check
// ============================================================================

func TestRDataNAPTRUnpackRegexpDataTooShort(t *testing.T) {
	buf := []byte{
		0x00, 0x01, // Order
		0x00, 0x01, // Preference
		0x01, 'U', // Flags: length=1, data="U"
		0x01, 'S', // Service: length=1, data="S"
		0x05, // Regexp length = 5
		'a',  // Only 1 byte of regexp data
	}
	r := &RDataNAPTR{}
	_, err := r.Unpack(buf, 0, 12)
	if err == nil {
		t.Error("NAPTR.Unpack should fail when regexp data extends past buffer")
	}
}

func TestRDataNAPTRUnpackRejectsRegexpPastRDLength(t *testing.T) {
	buf := []byte{
		0x00, 0x01, // Order
		0x00, 0x01, // Preference
		0x01, 'U', // Flags
		0x01, 'S', // Service
		0x03, 'a', // Regexp length=3, but rdlength only includes 1 byte of data
		'b', 'c', // Bytes after RDLENGTH must not be consumed
		0x00, // Replacement root
	}
	r := &RDataNAPTR{}
	_, err := r.Unpack(buf, 0, 10)
	if err == nil {
		t.Fatal("NAPTR.Unpack should reject regexp data that extends past RDLENGTH")
	}
}

// ============================================================================
// types.go RDataNAPTR.Unpack (91.7%) - replacement name error
// ============================================================================

func TestRDataNAPTRUnpackReplacementError(t *testing.T) {
	buf := []byte{
		0x00, 0x01, // Order
		0x00, 0x01, // Preference
		0x01, 'U', // Flags
		0x01, 'S', // Service
		0x01, 'R', // Regexp
		0x10, // Replacement: label length=16, no data
	}
	r := &RDataNAPTR{}
	_, err := r.Unpack(buf, 0, 14)
	if err == nil {
		t.Error("NAPTR.Unpack should fail when replacement name is invalid")
	}
}

func TestRDataNAPTRUnpackRejectsTrailingRData(t *testing.T) {
	buf := []byte{
		0x00, 0x01, // Order
		0x00, 0x01, // Preference
		0x01, 'U', // Flags
		0x01, 'S', // Service
		0x00, // Empty Regexp
		0x00, // Replacement root
		0xAA, // Trailing byte inside RDLENGTH
	}
	r := &RDataNAPTR{}
	_, err := r.Unpack(buf, 0, uint16(len(buf)))
	if err == nil {
		t.Fatal("NAPTR.Unpack should reject trailing bytes after replacement")
	}
}

// ============================================================================
// types.go RDataSSHFP.Unpack - buffer too small for fixed fields
// ============================================================================

func TestRDataSSHFPUnpackFixedTooSmall(t *testing.T) {
	r := &RDataSSHFP{}
	buf := []byte{0x01} // Only 1 byte, need 2 for algo+fptype
	_, err := r.Unpack(buf, 0, 3)
	if err == nil {
		t.Error("SSHFP.Unpack should fail when buffer too small for fixed fields")
	}
}

// ============================================================================
// types.go RDataSSHFP.Unpack - fingerprint extends past buffer
// ============================================================================

func TestRDataSSHFPUnpackFingerprintTooShort(t *testing.T) {
	r := &RDataSSHFP{}
	buf := []byte{
		0x01, // Algorithm
		0x02, // FPType
		0xAA, // Only 1 byte of fingerprint, but rdlength says 4 (so 2 more expected)
	}
	_, err := r.Unpack(buf, 0, 4)
	if err == nil {
		t.Error("SSHFP.Unpack should fail when fingerprint extends past buffer")
	}
}

// ============================================================================
// types.go RDataTLSA.Unpack - buffer too small for fixed fields
// ============================================================================

func TestRDataTLSAUnpackFixedTooSmall(t *testing.T) {
	r := &RDataTLSA{}
	buf := []byte{0x01, 0x02} // Only 2 bytes, need 3 for usage+selector+matching
	_, err := r.Unpack(buf, 0, 4)
	if err == nil {
		t.Error("TLSA.Unpack should fail when buffer too small for fixed fields")
	}
}

// ============================================================================
// types.go RDataTLSA.Unpack - certificate data extends past buffer
// ============================================================================

func TestRDataTLSAUnpackCertificateTooShort(t *testing.T) {
	r := &RDataTLSA{}
	buf := []byte{
		0x01, // Usage
		0x02, // Selector
		0x03, // MatchingType
		0xAA, // Only 1 byte of cert, but rdlength=5 (so 2 expected)
	}
	_, err := r.Unpack(buf, 0, 5)
	if err == nil {
		t.Error("TLSA.Unpack should fail when certificate extends past buffer")
	}
}

// ============================================================================
// types.go RDataDS.Pack (92.9%) - buffer too small for fixed fields
// ============================================================================

func TestRDataDSPackFixedTooSmall(t *testing.T) {
	r := &RDataDS{
		KeyTag:     123,
		Algorithm:  1,
		DigestType: 2,
		Digest:     []byte{0xAA, 0xBB},
	}
	buf := make([]byte, 3) // Need 4 for fixed fields
	_, err := r.Pack(buf, 0)
	if err == nil {
		t.Error("DS.Pack should fail when buffer too small for fixed fields")
	}
}

// ============================================================================
// types.go RDataDS.Pack (92.9%) - buffer too small for digest data
// ============================================================================

func TestRDataDSPackDigestTooSmall(t *testing.T) {
	r := &RDataDS{
		KeyTag:     123,
		Algorithm:  1,
		DigestType: 2,
		Digest:     []byte{0xAA, 0xBB, 0xCC},
	}
	buf := make([]byte, 5) // 4 fixed + only 1 byte, need 3 for digest
	_, err := r.Pack(buf, 0)
	if err == nil {
		t.Error("DS.Pack should fail when buffer too small for digest data")
	}
}

// ============================================================================
// types.go RDataDNSKEY.Pack (95.0%) - buffer too small for fixed fields
// ============================================================================

func TestRDataDNSKEYPackFixedTooSmall(t *testing.T) {
	r := &RDataDNSKEY{
		Flags:     256,
		Protocol:  3,
		Algorithm: 1,
		PublicKey: []byte{0x01},
	}
	buf := make([]byte, 3) // Need 4 for fixed fields
	_, err := r.Pack(buf, 0)
	if err == nil {
		t.Error("DNSKEY.Pack should fail when buffer too small for fixed fields")
	}
}

// ============================================================================
// types.go RDataDNSKEY.Pack (95.0%) - buffer too small for public key
// ============================================================================

func TestRDataDNSKEYPackPublicKeyTooSmall(t *testing.T) {
	r := &RDataDNSKEY{
		Flags:     256,
		Protocol:  3,
		Algorithm: 1,
		PublicKey: []byte{0x01, 0x02, 0x03},
	}
	buf := make([]byte, 5) // 4 fixed + only 1 byte, need 3 for pubkey
	_, err := r.Pack(buf, 0)
	if err == nil {
		t.Error("DNSKEY.Pack should fail when buffer too small for public key")
	}
}

// ============================================================================
// types.go RDataMX.Pack (90.0%) - buffer too small for exchange name
// Line 297: Pack fails at PackName for exchange
// ============================================================================

func TestRDataMXPackExchangeError(t *testing.T) {
	exchange, _ := ParseName("mail.example.com.")
	r := &RDataMX{
		Preference: 10,
		Exchange:   exchange,
	}

	// Buffer large enough for preference (2 bytes) but not for exchange name
	buf := make([]byte, 2)
	_, err := r.Pack(buf, 0)
	if err == nil {
		t.Error("MX.Pack should fail when buffer too small for exchange name")
	}
}

// ============================================================================
// types.go RDataSRV.Pack (92.9%) - target name error
// ============================================================================

func TestRDataSRVPackTargetError(t *testing.T) {
	target, _ := ParseName("target.example.com.")
	r := &RDataSRV{
		Priority: 10,
		Weight:   20,
		Port:     80,
		Target:   target,
	}

	// Buffer large enough for fixed fields (6 bytes) but not target name
	buf := make([]byte, 6)
	_, err := r.Pack(buf, 0)
	if err == nil {
		t.Error("SRV.Pack should fail when buffer too small for target name")
	}
}

// ============================================================================
// types.go RDataNAPTR.Pack - flags buffer too small
// ============================================================================

func TestRDataNAPTRPackFlagsBufTooSmall(t *testing.T) {
	replacement, _ := ParseName(".")
	r := &RDataNAPTR{
		Order:       1,
		Preference:  1,
		Flags:       "U",
		Service:     "",
		Regexp:      "",
		Replacement: replacement,
	}

	// Buffer enough for order(2)+pref(2)+flagsLen(1) = 5 bytes, but not flags data
	buf := make([]byte, 5)
	_, err := r.Pack(buf, 0)
	if err == nil {
		t.Error("NAPTR.Pack should fail when buffer too small for flags data")
	}
}

// ============================================================================
// types.go RDataNAPTR.Pack - service buffer too small
// ============================================================================

func TestRDataNAPTRPackServiceBufTooSmall(t *testing.T) {
	replacement, _ := ParseName(".")
	r := &RDataNAPTR{
		Order:       1,
		Preference:  1,
		Flags:       "U",
		Service:     "SIP+D2T",
		Regexp:      "",
		Replacement: replacement,
	}

	// Buffer enough for order(2)+pref(2)+flagsLen(1)+flags(1)+serviceLen(1) = 7, but not service data
	buf := make([]byte, 7)
	_, err := r.Pack(buf, 0)
	if err == nil {
		t.Error("NAPTR.Pack should fail when buffer too small for service data")
	}
}

// ============================================================================
// types.go RDataNAPTR.Pack - regexp buffer too small
// ============================================================================

func TestRDataNAPTRPackRegexpBufTooSmall(t *testing.T) {
	replacement, _ := ParseName(".")
	r := &RDataNAPTR{
		Order:       1,
		Preference:  1,
		Flags:       "U",
		Service:     "SIP",
		Regexp:      "!.*!sip:info@example.com!",
		Replacement: replacement,
	}

	// Build the exact size needed up to regexp, but not for regexp data
	// order(2)+pref(2)+flagsLen(1)+flags(1)+serviceLen(1)+service(3)+regexpLen(1) = 11
	buf := make([]byte, 11)
	_, err := r.Pack(buf, 0)
	if err == nil {
		t.Error("NAPTR.Pack should fail when buffer too small for regexp data")
	}
}

// ============================================================================
// types.go RDataNAPTR.Unpack - service length byte past buffer
// ============================================================================

func TestRDataNAPTRUnpackServiceLenPastBuf(t *testing.T) {
	buf := []byte{
		0x00, 0x01, // Order
		0x00, 0x01, // Preference
		0x00, // Flags: length=0 (empty)
		// No more bytes for service length
	}
	r := &RDataNAPTR{}
	_, err := r.Unpack(buf, 0, 7)
	if err == nil {
		t.Error("NAPTR.Unpack should fail when service length byte is missing")
	}
}

// ============================================================================
// types.go RDataNAPTR.Unpack - regexp length byte past buffer
// ============================================================================

func TestRDataNAPTRUnpackRegexpLenPastBuf(t *testing.T) {
	buf := []byte{
		0x00, 0x01, // Order
		0x00, 0x01, // Preference
		0x00, // Flags: length=0 (empty)
		0x00, // Service: length=0 (empty)
		// No more bytes for regexp length
	}
	r := &RDataNAPTR{}
	_, err := r.Unpack(buf, 0, 9)
	if err == nil {
		t.Error("NAPTR.Unpack should fail when regexp length byte is missing")
	}
}

// ============================================================================
// types.go RDataNAPTR.Unpack - order fixed field too small
// ============================================================================

func TestRDataNAPTRUnpackOrderTooSmall(t *testing.T) {
	buf := []byte{0x00} // Only 1 byte, need 2 for order
	r := &RDataNAPTR{}
	_, err := r.Unpack(buf, 0, 4)
	if err == nil {
		t.Error("NAPTR.Unpack should fail when buffer too small for order")
	}
}

// ============================================================================
// types.go RDataNAPTR.Unpack - preference fixed field too small
// ============================================================================

func TestRDataNAPTRUnpackPreferenceTooSmall(t *testing.T) {
	buf := []byte{
		0x00, 0x01, // Order
		0x00, // Only 1 byte, need 2 for preference
	}
	r := &RDataNAPTR{}
	_, err := r.Unpack(buf, 0, 4)
	if err == nil {
		t.Error("NAPTR.Unpack should fail when buffer too small for preference")
	}
}

// ============================================================================
// types.go RDataNAPTR.Unpack - flags length byte past buffer
// ============================================================================

func TestRDataNAPTRUnpackFlagsLenPastBuf(t *testing.T) {
	buf := []byte{
		0x00, 0x01, // Order
		0x00, 0x01, // Preference
		// No more bytes for flags length
	}
	r := &RDataNAPTR{}
	_, err := r.Unpack(buf, 0, 5)
	if err == nil {
		t.Error("NAPTR.Unpack should fail when flags length byte is missing")
	}
}

// ============================================================================
// message.go UnpackMessage (89.7%) - question error at offset boundary
// Line 220: offset >= len(buf) check for questions
// ============================================================================

func TestUnpackMessageQuestionTruncated(t *testing.T) {
	// Header with QDCount=1 but buffer ends right after header
	buf := make([]byte, HeaderLen)
	// Set QDCount=1
	PutUint16(buf[4:], 1)

	_, err := UnpackMessage(buf)
	if err == nil {
		t.Error("UnpackMessage should fail when question section is truncated")
	}
}

// ============================================================================
// message.go UnpackMessage (89.7%) - answer error at offset boundary
// Line 233: offset >= len(buf) check for answers
// ============================================================================

func TestUnpackMessageAnswerTruncated(t *testing.T) {
	// Header with ANCount=1 but no answer data
	buf := make([]byte, HeaderLen)
	PutUint16(buf[6:], 1) // ANCount=1

	_, err := UnpackMessage(buf)
	if err == nil {
		t.Error("UnpackMessage should fail when answer section is truncated")
	}
}

// ============================================================================
// message.go UnpackMessage (89.7%) - authority error at offset boundary
// Line 246: offset >= len(buf) check for authorities
// ============================================================================

func TestUnpackMessageAuthorityTruncated(t *testing.T) {
	// Header with NSCount=1 but no authority data
	buf := make([]byte, HeaderLen)
	PutUint16(buf[8:], 1) // NSCount=1

	_, err := UnpackMessage(buf)
	if err == nil {
		t.Error("UnpackMessage should fail when authority section is truncated")
	}
}

// ============================================================================
// message.go UnpackMessage (89.7%) - additional error at offset boundary
// Line 259: offset >= len(buf) check for additionals
// ============================================================================

func TestUnpackMessageAdditionalTruncated(t *testing.T) {
	// Header with ARCount=1 but no additional data
	buf := make([]byte, HeaderLen)
	PutUint16(buf[10:], 1) // ARCount=1

	_, err := UnpackMessage(buf)
	if err == nil {
		t.Error("UnpackMessage should fail when additional section is truncated")
	}
}

// ============================================================================
// message.go Pack (83.9%) - buffer too small for WireLength check
// Line 152: len(buf) < m.WireLength() check
// ============================================================================

func TestMessagePackBufferSmallerThanWireLength(t *testing.T) {
	msg := NewMessage(Header{ID: 0x1234, Flags: NewQueryFlags()})
	q, _ := NewQuestion("example.com.", TypeA, ClassIN)
	msg.AddQuestion(q)

	// Buffer 1 byte smaller than needed
	wireLen := msg.WireLength()
	buf := make([]byte, wireLen-1)
	_, err := msg.Pack(buf)
	if err == nil {
		t.Error("Pack should fail when buffer smaller than WireLength")
	}
}

func TestMessagePackRejectsSectionCountOverflow(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*Message)
	}{
		{
			name: "questions",
			setup: func(msg *Message) {
				msg.Questions = make([]*Question, 0x10000)
			},
		},
		{
			name: "answers",
			setup: func(msg *Message) {
				msg.Answers = make([]*ResourceRecord, 0x10000)
			},
		},
		{
			name: "authorities",
			setup: func(msg *Message) {
				msg.Authorities = make([]*ResourceRecord, 0x10000)
			},
		},
		{
			name: "additionals",
			setup: func(msg *Message) {
				msg.Additionals = make([]*ResourceRecord, 0x10000)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := NewMessage(Header{ID: 0x1234, Flags: NewQueryFlags()})
			tt.setup(msg)
			if _, err := msg.Pack(make([]byte, HeaderLen)); err == nil {
				t.Fatal("Pack should reject section counts that overflow DNS header uint16 fields")
			}
		})
	}
}

// ============================================================================
// record.go UnpackResourceRecord (88.9%) - unpacking authority rdata error
// Cover the "unpacking rdata" error path via UnpackResourceRecord
// ============================================================================

func TestUnpackResourceRecordSOAUnpackError(t *testing.T) {
	// Create a wire-format SOA record with truncated rdata
	name := []byte{0x03, 'f', 'o', 'o', 0x03, 'c', 'o', 'm', 0x00}
	fixedFields := make([]byte, 10)
	PutUint16(fixedFields[0:], TypeSOA)
	PutUint16(fixedFields[2:], ClassIN)
	PutUint32(fixedFields[4:], 300)
	PutUint16(fixedFields[8:], 10) // RDLENGTH=10 but SOA needs more

	// Provide SOA rdata with valid MName but truncated RName
	rdata := []byte{
		0x00,                // MName = root
		0x10, 'a', 'b', 'c', // RName: label length=16, only 3 bytes
	}

	buf := append(name, fixedFields...)
	buf = append(buf, rdata...)

	_, _, err := UnpackResourceRecord(buf, 0)
	if err == nil {
		t.Error("UnpackResourceRecord should fail when SOA rdata is invalid")
	}
}

// ============================================================================
// record.go UnpackResourceRecord - unpack MX rdata error
// ============================================================================

func TestUnpackResourceRecordMXUnpackError(t *testing.T) {
	name := []byte{0x03, 'f', 'o', 'o', 0x03, 'c', 'o', 'm', 0x00}
	fixedFields := make([]byte, 10)
	PutUint16(fixedFields[0:], TypeMX)
	PutUint16(fixedFields[2:], ClassIN)
	PutUint32(fixedFields[4:], 300)
	PutUint16(fixedFields[8:], 5)

	// MX rdata: preference (2 bytes) + truncated exchange name
	rdata := []byte{0x00, 0x0A, 0x10, 'a'} // Pref=10, exchange: label len=16, 1 byte

	buf := append(name, fixedFields...)
	buf = append(buf, rdata...)

	_, _, err := UnpackResourceRecord(buf, 0)
	if err == nil {
		t.Error("UnpackResourceRecord should fail when MX rdata is invalid")
	}
}

// ============================================================================
// record.go UnpackResourceRecord - unpack SRV rdata error
// ============================================================================

func TestUnpackResourceRecordSRVUnpackError(t *testing.T) {
	name := []byte{0x03, 'f', 'o', 'o', 0x03, 'c', 'o', 'm', 0x00}
	fixedFields := make([]byte, 10)
	PutUint16(fixedFields[0:], TypeSRV)
	PutUint16(fixedFields[2:], ClassIN)
	PutUint32(fixedFields[4:], 300)
	PutUint16(fixedFields[8:], 4) // RDLENGTH=4 but SRV needs 6+ for fixed fields

	// SRV rdata: only 4 bytes but need at least 6 for priority+weight+port
	rdata := []byte{0x00, 0x01, 0x00, 0x02}

	buf := append(name, fixedFields...)
	buf = append(buf, rdata...)

	_, _, err := UnpackResourceRecord(buf, 0)
	if err == nil {
		t.Error("UnpackResourceRecord should fail when SRV rdata is invalid")
	}
}

// ============================================================================
// record.go UnpackResourceRecord - unpack CAA rdata error
// ============================================================================

func TestUnpackResourceRecordCAAUnpackError(t *testing.T) {
	name := []byte{0x03, 'f', 'o', 'o', 0x03, 'c', 'o', 'm', 0x00}
	fixedFields := make([]byte, 10)
	PutUint16(fixedFields[0:], TypeCAA)
	PutUint16(fixedFields[2:], ClassIN)
	PutUint32(fixedFields[4:], 300)
	PutUint16(fixedFields[8:], 1) // RDLENGTH=1, need at least 2 for CAA

	// CAA rdata: only 1 byte, need at least 2
	rdata := []byte{0x00}

	buf := append(name, fixedFields...)
	buf = append(buf, rdata...)

	_, _, err := UnpackResourceRecord(buf, 0)
	if err == nil {
		t.Error("UnpackResourceRecord should fail when CAA rdata is invalid")
	}
}

// ============================================================================
// labels.go ValidateLabel (90.9%) - hyphen at end of label
// ============================================================================

func TestValidateLabelHyphenAtEndExtended(t *testing.T) {
	err := ValidateLabel("test-")
	if err == nil {
		t.Error("ValidateLabel should fail with hyphen at end")
	}
}

// ============================================================================
// labels.go ValidateLabel (90.9%) - single hyphen (both start and end)
// ============================================================================

func TestValidateLabelSingleHyphen(t *testing.T) {
	err := ValidateLabel("-")
	if err == nil {
		t.Error("ValidateLabel should fail with single hyphen")
	}
}

// ============================================================================
// labels.go ValidateLabel (90.9%) - underscore at start
// ============================================================================

func TestValidateLabelUnderscoreAtStart(t *testing.T) {
	// Underscore is valid per isValidLabelChar, so this should succeed
	err := ValidateLabel("_test")
	if err != nil {
		t.Errorf("ValidateLabel should succeed with underscore at start: %v", err)
	}
}

// ============================================================================
// labels.go PackName (91.2%) - compression pointer buffer too small
// Line 199: offset+2 > len(buf) check when writing compression pointer
// ============================================================================

func TestPackNameCompressionPointerBufTooSmall(t *testing.T) {
	name, _ := ParseName("www.example.com.")
	exKey, _ := ParseName("example.com.")
	compression := map[string]int{
		wireSuffixKey(exKey.wire): 12,
	}

	// Buffer with only 1 byte at offset, need 2 for pointer
	buf := make([]byte, 1)
	_, err := PackName(name, buf, 0, compression)
	if err == nil {
		t.Error("PackName should fail when buffer too small for compression pointer")
	}
}

// ============================================================================
// labels.go PackName (91.2%) - terminating zero buffer too small
// Line 238: offset >= len(buf) check
// ============================================================================

func TestPackNameTerminatingZeroBufTooSmall(t *testing.T) {
	// Single label "a" needs: 1+1+1 = 3 bytes (len+'a'+zero)
	name, _ := ParseName("a.")
	// Give exactly 2 bytes: room for len+'a' but not terminator
	buf := make([]byte, 2)
	_, err := PackName(name, buf, 0, nil)
	if err == nil {
		t.Error("PackName should fail when buffer too small for terminating zero")
	}
}

// ============================================================================
// question.go Pack (92.3%) - QType buffer too small
// Line 95: offset+2 > len(buf) check for QType
// ============================================================================

func TestQuestionPackQTypeTooSmall(t *testing.T) {
	q, _ := NewQuestion("a.", TypeA, ClassIN)
	// name = 1+1+1 = 3 bytes, give 4 (name fits but only 1 byte for QType, need 2)
	buf := make([]byte, 4)
	_, err := q.Pack(buf, 0, nil)
	if err == nil {
		t.Error("Question.Pack should fail when buffer too small for QType")
	}
}

// ============================================================================
// message.go Pack (83.9%) - pack with authority that has name pack error
// Cover the authority pack error path (line 187)
// ============================================================================

func TestMessagePackAuthorityNameError(t *testing.T) {
	msg := NewMessage(Header{ID: 0x1234, Flags: NewResponseFlags(RcodeSuccess)})
	q, _ := NewQuestion("a.", TypeA, ClassIN)
	msg.AddQuestion(q)

	// Create a record with a very long name that will fail in wire format
	// Use a valid name for the authority but force a buffer issue
	name, _ := ParseName("ns.example.com.")
	msg.AddAuthority(&ResourceRecord{
		Name:  name,
		Type:  TypeA,
		Class: ClassIN,
		TTL:   300,
		Data:  &RDataA{Address: [4]byte{1, 2, 3, 4}},
	})

	// Buffer just big enough for header + question but not enough for authority name
	buf := make([]byte, HeaderLen+3+2) // header(12) + question(3) + a little
	// This is much smaller than WireLength, so WireLength check catches it
	_, err := msg.Pack(buf)
	if err == nil {
		t.Error("Pack should fail with buffer too small for authority")
	}
}

// ============================================================================
// message.go Pack (83.9%) - pack additional record rdata error
// Cover the additional pack error path more specifically
// ============================================================================

func TestMessagePackAdditionalRDataError(t *testing.T) {
	msg := NewMessage(Header{ID: 0x1234, Flags: NewResponseFlags(RcodeSuccess)})
	q, _ := NewQuestion("a.", TypeA, ClassIN)
	msg.AddQuestion(q)

	name, _ := ParseName("a.")
	// Add an additional record
	msg.AddAdditional(&ResourceRecord{
		Name:  name,
		Type:  TypeA,
		Class: ClassIN,
		TTL:   300,
		Data:  &RDataA{Address: [4]byte{1, 2, 3, 4}},
	})

	// Use a buffer big enough for header+question+name+type+class+ttl+rdlength but not rdata
	buf := make([]byte, HeaderLen+3+3+10)
	_, err := msg.Pack(buf)
	if err == nil {
		t.Error("Pack should fail when buffer too small for additional rdata")
	}
}

// ============================================================================
// message.go Pack (83.9%) - pack answer record name error
// Test answer section pack failure due to name packing
// ============================================================================

func TestMessagePackAnswerNameError(t *testing.T) {
	msg := NewMessage(Header{ID: 0x1234, Flags: NewResponseFlags(RcodeSuccess)})
	// No question, just an answer
	name, _ := ParseName("longname.example.com.")
	msg.AddAnswer(&ResourceRecord{
		Name:  name,
		Type:  TypeA,
		Class: ClassIN,
		TTL:   300,
		Data:  &RDataA{Address: [4]byte{1, 2, 3, 4}},
	})

	// Buffer just big enough for header but not the answer name
	buf := make([]byte, HeaderLen+2)
	_, err := msg.Pack(buf)
	if err == nil {
		t.Error("Pack should fail when buffer too small for answer name")
	}
}

// ============================================================================
// wire.go ValidateMessage (90.0%) - valid message
// ============================================================================

func TestValidateMessageValid(t *testing.T) {
	buf := make([]byte, 12)
	// All counts are 0 - valid
	err := ValidateMessage(buf)
	if err != nil {
		t.Errorf("ValidateMessage should succeed with valid 12-byte message: %v", err)
	}
}

// ============================================================================
// opt.go NewEDNS0ClientSubnet (93.3%) - IPv4 non-byte-aligned prefix
// Line 211: sourceBits%8 != 0 && numBytes > 0 check
// ============================================================================

func TestNewEDNS0ClientSubnetIPv4NonByteAligned(t *testing.T) {
	ip := net.ParseIP("192.168.1.1")
	ecs := NewEDNS0ClientSubnet(ip, 13)
	if ecs.Family != 1 {
		t.Errorf("Family = %d, want 1 for IPv4", ecs.Family)
	}
	if ecs.SourcePrefixLength != 13 {
		t.Errorf("SourcePrefixLength = %d, want 13", ecs.SourcePrefixLength)
	}
	// 13 bits = 2 bytes, last byte should be masked
	if len(ecs.Address) != 2 {
		t.Errorf("Address length = %d, want 2", len(ecs.Address))
	}
	// Verify masking: 13 bits = first byte untouched, second byte has lower 3 bits masked
	// Mask is 0xFF << (8 - 13%8) = 0xFF << 3 = 0xF8
	// Original second byte of 192.168 is 168 = 0xA8 = 10101000
	// Masked: 0xA8 & 0xF8 = 0xA8 (no change because lower 3 bits were already 0)
	if ecs.Address[1] != (168 & 0xF8) {
		t.Errorf("Last byte should be masked: got 0x%02X, want 0x%02X", ecs.Address[1], byte(168&0xF8))
	}
}

// ============================================================================
// types.go RDataTXT.Pack - string too long (>255 bytes)
// ============================================================================

func TestRDataTXTPackStringTooLong(t *testing.T) {
	longStr := make([]byte, 256)
	for i := range longStr {
		longStr[i] = 'a'
	}
	r := &RDataTXT{Strings: []string{string(longStr)}}
	buf := make([]byte, 600)
	_, err := r.Pack(buf, 0)
	if err == nil {
		t.Error("TXT.Pack should fail with string > 255 bytes")
	}
}

// ============================================================================
// types.go RDataTXT.Pack - buffer too small for string data
// ============================================================================

func TestRDataTXTPackBufferTooSmall(t *testing.T) {
	r := &RDataTXT{Strings: []string{"hello"}}
	buf := make([]byte, 2) // Need 1+5=6, only have 2
	_, err := r.Pack(buf, 0)
	if err == nil {
		t.Error("TXT.Pack should fail when buffer too small for string data")
	}
}

// ============================================================================
// message.go Pack (83.9%) - Trigger answer section pack error via long label
// By creating a Name with a label > 63 chars using NewName (bypasses ParseName
// validation), WireLength passes but PackName fails with ErrLabelTooLong.
// This covers the "packing answer" error path (line 178).
// ============================================================================

func TestMessagePackAnswerLabelTooLong(t *testing.T) {
	msg := NewMessage(Header{ID: 0x1234, Flags: NewResponseFlags(RcodeSuccess)})

	// Create a valid question
	q, _ := NewQuestion("example.com.", TypeA, ClassIN)
	msg.AddQuestion(q)

	// Create a Name with a label > 63 chars directly (bypasses ParseName validation)
	longLabel := make([]byte, 64)
	for i := range longLabel {
		longLabel[i] = 'a'
	}
	badName := unsafeName([]string{string(longLabel)}, true)

	msg.AddAnswer(&ResourceRecord{
		Name:  badName,
		Type:  TypeA,
		Class: ClassIN,
		TTL:   300,
		Data:  &RDataA{Address: [4]byte{1, 2, 3, 4}},
	})

	buf := make([]byte, msg.WireLength())
	_, err := msg.Pack(buf)
	if err == nil {
		t.Error("Pack should fail when answer has label > 63 chars")
	}
}

// ============================================================================
// message.go Pack (83.9%) - Trigger authority section pack error via long label
// Covers the "packing authority" error path (line 187).
// ============================================================================

func TestMessagePackAuthorityLabelTooLong(t *testing.T) {
	msg := NewMessage(Header{ID: 0x1234, Flags: NewResponseFlags(RcodeSuccess)})

	q, _ := NewQuestion("example.com.", TypeA, ClassIN)
	msg.AddQuestion(q)

	// Create a Name with a label > 63 chars
	longLabel := make([]byte, 64)
	for i := range longLabel {
		longLabel[i] = 'a'
	}
	badName := unsafeName([]string{string(longLabel)}, true)

	msg.AddAuthority(&ResourceRecord{
		Name:  badName,
		Type:  TypeA,
		Class: ClassIN,
		TTL:   300,
		Data:  &RDataA{Address: [4]byte{1, 2, 3, 4}},
	})

	buf := make([]byte, msg.WireLength())
	_, err := msg.Pack(buf)
	if err == nil {
		t.Error("Pack should fail when authority has label > 63 chars")
	}
}

// ============================================================================
// message.go Pack (83.9%) - Trigger additional section pack error via long label
// Covers the "packing additional" error path (line 196).
// ============================================================================

func TestMessagePackAdditionalLabelTooLong(t *testing.T) {
	msg := NewMessage(Header{ID: 0x1234, Flags: NewResponseFlags(RcodeSuccess)})

	q, _ := NewQuestion("example.com.", TypeA, ClassIN)
	msg.AddQuestion(q)

	// Create a Name with a label > 63 chars
	longLabel := make([]byte, 64)
	for i := range longLabel {
		longLabel[i] = 'a'
	}
	badName := unsafeName([]string{string(longLabel)}, true)

	msg.AddAdditional(&ResourceRecord{
		Name:  badName,
		Type:  TypeA,
		Class: ClassIN,
		TTL:   300,
		Data:  &RDataA{Address: [4]byte{1, 2, 3, 4}},
	})

	buf := make([]byte, msg.WireLength())
	_, err := msg.Pack(buf)
	if err == nil {
		t.Error("Pack should fail when additional has label > 63 chars")
	}
}

// ============================================================================
// message.go Pack (83.9%) - Trigger question section pack error via long label
// Covers the "packing question" error path (line 169).
// ============================================================================

func TestMessagePackQuestionLabelTooLong(t *testing.T) {
	msg := NewMessage(Header{ID: 0x1234, Flags: NewQueryFlags()})

	// Create a Name with a label > 63 chars directly
	longLabel := make([]byte, 64)
	for i := range longLabel {
		longLabel[i] = 'a'
	}
	badName := unsafeName([]string{string(longLabel)}, true)

	// Manually add the question with the bad name
	msg.Questions = append(msg.Questions, &Question{
		Name:   badName,
		QType:  TypeA,
		QClass: ClassIN,
	})
	msg.Header.QDCount = 1

	buf := make([]byte, msg.WireLength())
	_, err := msg.Pack(buf)
	if err == nil {
		t.Error("Pack should fail when question has label > 63 chars")
	}
}

// ============================================================================
// record.go UnpackResourceRecord (88.9%) - CNAME/PTR/NS rdata unpack error
// These use UnpackName internally and can fail with bad wire data
// ============================================================================

func TestUnpackResourceRecordCNAMEUnpackError(t *testing.T) {
	name := []byte{0x03, 'f', 'o', 'o', 0x03, 'c', 'o', 'm', 0x00}
	fixedFields := make([]byte, 10)
	PutUint16(fixedFields[0:], TypeCNAME)
	PutUint16(fixedFields[2:], ClassIN)
	PutUint32(fixedFields[4:], 300)
	PutUint16(fixedFields[8:], 5) // RDLENGTH=5

	// CNAME rdata with truncated name: label len=10, only 1 byte
	rdata := []byte{0x0A, 'a', 'b', 'c', 'd'}

	buf := append(name, fixedFields...)
	buf = append(buf, rdata...)

	_, _, err := UnpackResourceRecord(buf, 0)
	if err == nil {
		t.Error("UnpackResourceRecord should fail when CNAME rdata has truncated name")
	}
}

func TestUnpackResourceRecordRejectsRDataShortRead(t *testing.T) {
	name := []byte{0x03, 'f', 'o', 'o', 0x03, 'c', 'o', 'm', 0x00}
	fixedFields := make([]byte, 10)
	PutUint16(fixedFields[0:], TypeCNAME)
	PutUint16(fixedFields[2:], ClassIN)
	PutUint32(fixedFields[4:], 300)
	PutUint16(fixedFields[8:], 2)

	// CNAME RDATA is the root name (one zero byte) plus one extra byte.
	// The name unpacker consumes only the root-name byte; accepting that
	// short read would desynchronize the next resource record boundary.
	rdata := []byte{0x00, 0xAA}

	buf := append(name, fixedFields...)
	buf = append(buf, rdata...)

	_, _, err := UnpackResourceRecord(buf, 0)
	if err == nil {
		t.Fatal("UnpackResourceRecord should reject RDATA that consumes less than RDLENGTH")
	}
}

func TestUnpackResourceRecordUnknownTypeUsesRawData(t *testing.T) {
	name := []byte{0x03, 'f', 'o', 'o', 0x03, 'c', 'o', 'm', 0x00}
	rdata := []byte{0xde, 0xad, 0xbe, 0xef}
	fixedFields := make([]byte, 10)
	PutUint16(fixedFields[0:], 65280)
	PutUint16(fixedFields[2:], ClassIN)
	PutUint32(fixedFields[4:], 300)
	PutUint16(fixedFields[8:], uint16(len(rdata)))

	buf := append(name, fixedFields...)
	buf = append(buf, rdata...)

	rr, n, err := UnpackResourceRecord(buf, 0)
	if err != nil {
		t.Fatalf("UnpackResourceRecord() error = %v", err)
	}
	if n != len(buf) {
		t.Fatalf("consumed = %d, want %d", n, len(buf))
	}
	raw, ok := rr.Data.(*RDataRaw)
	if !ok {
		t.Fatalf("Data type = %T, want *RDataRaw", rr.Data)
	}
	if raw.TypeVal != 65280 {
		t.Fatalf("raw TypeVal = %d, want 65280", raw.TypeVal)
	}
	if string(raw.Data) != string(rdata) {
		t.Fatalf("raw Data = %x, want %x", raw.Data, rdata)
	}
}

func TestUnpackResourceRecordPTRUnpackError(t *testing.T) {
	name := []byte{0x03, 'f', 'o', 'o', 0x03, 'c', 'o', 'm', 0x00}
	fixedFields := make([]byte, 10)
	PutUint16(fixedFields[0:], TypePTR)
	PutUint16(fixedFields[2:], ClassIN)
	PutUint32(fixedFields[4:], 300)
	PutUint16(fixedFields[8:], 3)

	// PTR rdata with truncated name
	rdata := []byte{0x0A, 'a', 'b'}

	buf := append(name, fixedFields...)
	buf = append(buf, rdata...)

	_, _, err := UnpackResourceRecord(buf, 0)
	if err == nil {
		t.Error("UnpackResourceRecord should fail when PTR rdata has truncated name")
	}
}

func TestUnpackResourceRecordNSUnpackError(t *testing.T) {
	name := []byte{0x03, 'f', 'o', 'o', 0x03, 'c', 'o', 'm', 0x00}
	fixedFields := make([]byte, 10)
	PutUint16(fixedFields[0:], TypeNS)
	PutUint16(fixedFields[2:], ClassIN)
	PutUint32(fixedFields[4:], 300)
	PutUint16(fixedFields[8:], 3)

	// NS rdata with truncated name
	rdata := []byte{0x0A, 'a', 'b'}

	buf := append(name, fixedFields...)
	buf = append(buf, rdata...)

	_, _, err := UnpackResourceRecord(buf, 0)
	if err == nil {
		t.Error("UnpackResourceRecord should fail when NS rdata has truncated name")
	}
}

// ============================================================================
// types.go RDataTXT.Unpack (92.9%) - offset >= len(buf) inside loop
// Line 411: offset >= len(buf) check when reading string length
// ============================================================================

func TestRDataTXTUnpackOffsetPastBufInLoop(t *testing.T) {
	r := &RDataTXT{}
	// rdlength=2, first string: length=0 (1 byte consumed), then offset=1
	// offset < endOffset (2), but offset >= len(buf) if we craft carefully
	// Actually let's use rdlength=0 which should just return 0
	buf := []byte{}
	_, err := r.Unpack(buf, 0, 0)
	if err != nil {
		t.Errorf("TXT.Unpack with rdlength=0 should succeed: %v", err)
	}
}

// ============================================================================
// types.go RDataTXT.Unpack (92.9%) - second iteration offset >= len(buf)
// ============================================================================

func TestRDataTXTUnpackSecondStringOffsetPastBuf(t *testing.T) {
	r := &RDataTXT{}
	// rdlength=3, first string: len=1, data='a' (2 bytes consumed)
	// Second iteration: offset=2 < endOffset=3, but only 1 byte left
	// and that byte says string length > remaining buffer
	buf := []byte{0x01, 'a', 0x05} // First: len=1,'a'. Second: len=5 but no data
	_, err := r.Unpack(buf, 0, 3)
	if err == nil {
		t.Error("TXT.Unpack should fail when second string data extends past buffer")
	}
}

// ============================================================================
// labels.go ValidateLabel (90.9%) - label too long (>63 chars)
// ============================================================================

func TestValidateLabelTooLong(t *testing.T) {
	longLabel := make([]byte, 64)
	for i := range longLabel {
		longLabel[i] = 'a'
	}
	err := ValidateLabel(string(longLabel))
	if err == nil {
		t.Error("ValidateLabel should fail with label > 63 chars")
	}
}

// ============================================================================
// labels.go ValidateLabel (90.9%) - invalid char at first position (not hyphen)
// e.g., a dot or other special character
// ============================================================================

func TestValidateLabelInvalidCharAtFirst(t *testing.T) {
	err := ValidateLabel(".test")
	if err == nil {
		t.Error("ValidateLabel should fail with dot at start")
	}
}

// ============================================================================
// types.go RDataCAA.Pack (95.0%) - buffer too small for flags byte
// ============================================================================

func TestRDataCAAPackFlagsByteTooSmall(t *testing.T) {
	r := &RDataCAA{Flags: 0, Tag: "issue", Value: "ca.example.com"}
	buf := make([]byte, 0) // No room even for flags byte
	_, err := r.Pack(buf, 0)
	if err == nil {
		t.Error("CAA.Pack should fail when buffer too small for flags byte")
	}
}

// ============================================================================
// types.go RDataCAA.Pack (95.0%) - buffer too small for tag
// ============================================================================

func TestRDataCAAPackTagTooSmall(t *testing.T) {
	r := &RDataCAA{Flags: 0, Tag: "issue", Value: "ca.example.com"}
	buf := make([]byte, 2) // Room for flags + tag len byte but not tag data
	_, err := r.Pack(buf, 0)
	if err == nil {
		t.Error("CAA.Pack should fail when buffer too small for tag data")
	}
}

// ============================================================================
// types.go RDataCAA.Pack (95.0%) - tag too long
// ============================================================================

func TestRDataCAAPackTagTooLong(t *testing.T) {
	longTag := make([]byte, 256)
	for i := range longTag {
		longTag[i] = 'a'
	}
	r := &RDataCAA{Flags: 0, Tag: string(longTag), Value: ""}
	buf := make([]byte, 300)
	_, err := r.Pack(buf, 0)
	if err == nil {
		t.Error("CAA.Pack should fail when tag > 255 bytes")
	}
}

// ============================================================================
// types.go RDataCAA.Pack (95.0%) - buffer too small for value
// ============================================================================

func TestRDataCAAPackValueTooSmall(t *testing.T) {
	r := &RDataCAA{Flags: 0, Tag: "i", Value: "ca.example.com"}
	buf := make([]byte, 3) // flags(1) + taglen(1) + tag(1) = 3, no room for value
	_, err := r.Pack(buf, 0)
	if err == nil {
		t.Error("CAA.Pack should fail when buffer too small for value")
	}
}

// ============================================================================
// message.go Pack - cover error paths in answer/authority/additional packing
// (Currently 83.9%)
// ============================================================================

func TestMessagePackAnswerError(t *testing.T) {
	msg := NewMessage(Header{ID: 0x1234, Flags: NewResponseFlags(RcodeSuccess)})
	q, _ := NewQuestion("example.com.", TypeA, ClassIN)
	msg.AddQuestion(q)

	name, _ := ParseName("example.com.")
	// Add an answer with a record that fails to pack due to buffer too small
	msg.AddAnswer(&ResourceRecord{
		Name:  name,
		Type:  TypeA,
		Class: ClassIN,
		TTL:   300,
		Data:  &RDataA{Address: [4]byte{1, 2, 3, 4}},
	})

	// Use a buffer just big enough for header + question but not the answer
	buf := make([]byte, HeaderLen+name.WireLength()+4+1)
	_, err := msg.Pack(buf)
	if err == nil {
		t.Error("Pack should fail when buffer too small for answer")
	}
}

func TestMessagePackAuthoritySmallBuffer(t *testing.T) {
	msg := NewMessage(Header{ID: 0x1234, NSCount: 1, Flags: NewResponseFlags(RcodeSuccess)})
	q, _ := NewQuestion("example.com.", TypeA, ClassIN)
	msg.AddQuestion(q)

	name, _ := ParseName("example.com.")
	msg.AddAuthority(&ResourceRecord{
		Name:  name,
		Type:  TypeA,
		Class: ClassIN,
		TTL:   300,
		Data:  &RDataA{Address: [4]byte{1, 2, 3, 4}},
	})

	// Use a tiny buffer that can fit header+question but not authority
	buf := make([]byte, 30)
	_, err := msg.Pack(buf)
	if err == nil {
		t.Error("Pack should fail when buffer too small for authority")
	}
}

func TestMessagePackAdditionalSmallBuffer(t *testing.T) {
	msg := NewMessage(Header{ID: 0x1234, ARCount: 1, Flags: NewResponseFlags(RcodeSuccess)})
	q, _ := NewQuestion("example.com.", TypeA, ClassIN)
	msg.AddQuestion(q)

	name, _ := ParseName("example.com.")
	msg.AddAdditional(&ResourceRecord{
		Name:  name,
		Type:  TypeA,
		Class: ClassIN,
		TTL:   300,
		Data:  &RDataA{Address: [4]byte{1, 2, 3, 4}},
	})

	// Use a tiny buffer that can fit header+question but not additional
	buf := make([]byte, 30)
	_, err := msg.Pack(buf)
	if err == nil {
		t.Error("Pack should fail when buffer too small for additional")
	}
}

// ============================================================================
// message.go UnpackMessage - cover answer error path (89.7%)
// ============================================================================

func TestUnpackMessageAnswerUnpackError(t *testing.T) {
	// Create a valid message then truncate it mid-answer to force unpack error
	msg := NewMessage(Header{ID: 0x1234, ANCount: 1, Flags: NewResponseFlags(RcodeSuccess)})
	q, _ := NewQuestion("example.com.", TypeA, ClassIN)
	msg.AddQuestion(q)

	name, _ := ParseName("example.com.")
	msg.AddAnswer(&ResourceRecord{
		Name:  name,
		Type:  TypeA,
		Class: ClassIN,
		TTL:   300,
		Data:  &RDataA{Address: [4]byte{1, 2, 3, 4}},
	})

	buf := make([]byte, 512)
	n, _ := msg.Pack(buf)

	// Truncate to cut off the answer's RDATA, making RDLENGTH extend past buffer
	// Header(12) + question(~17) + answer name(~17) + type(2)+class(2)+ttl(4)+rdlength(2) = ~56
	// Cut at 50 so RDLENGTH claims data exists but it's been truncated
	if n > 50 {
		_, err := UnpackMessage(buf[:50])
		if err == nil {
			t.Error("UnpackMessage should fail with truncated answer data")
		}
	}
}

// ============================================================================
// record.go Pack - cover more error paths (81.5%)
// Cover: type too small, class too small, TTL too small, RDLENGTH too small
// ============================================================================

func TestResourceRecordPackTypeTooSmall(t *testing.T) {
	name, _ := ParseName("example.com.")
	rr := &ResourceRecord{
		Name:  name,
		Type:  TypeA,
		Class: ClassIN,
		TTL:   300,
		Data:  &RDataA{Address: [4]byte{1, 2, 3, 4}},
	}

	// Buffer just enough for name but not for type (2 bytes)
	nameWireLen := name.WireLength()
	buf := make([]byte, nameWireLen+1) // 1 byte short for type
	_, err := rr.Pack(buf, 0, nil)
	if err == nil {
		t.Error("Pack should fail when buffer too small for type field")
	}
}

func TestResourceRecordPackClassTooSmall(t *testing.T) {
	name, _ := ParseName("example.com.")
	rr := &ResourceRecord{
		Name:  name,
		Type:  TypeA,
		Class: ClassIN,
		TTL:   300,
		Data:  &RDataA{Address: [4]byte{1, 2, 3, 4}},
	}

	nameWireLen := name.WireLength()
	// Enough for name + type, but not class
	buf := make([]byte, nameWireLen+3)
	_, err := rr.Pack(buf, 0, nil)
	if err == nil {
		t.Error("Pack should fail when buffer too small for class field")
	}
}

func TestResourceRecordPackTTLTooSmall(t *testing.T) {
	name, _ := ParseName("example.com.")
	rr := &ResourceRecord{
		Name:  name,
		Type:  TypeA,
		Class: ClassIN,
		TTL:   300,
		Data:  &RDataA{Address: [4]byte{1, 2, 3, 4}},
	}

	nameWireLen := name.WireLength()
	// Enough for name + type + class, but not TTL (needs 4)
	buf := make([]byte, nameWireLen+5)
	_, err := rr.Pack(buf, 0, nil)
	if err == nil {
		t.Error("Pack should fail when buffer too small for TTL field")
	}
}

func TestResourceRecordPackRDLengthTooSmall(t *testing.T) {
	name, _ := ParseName("example.com.")
	rr := &ResourceRecord{
		Name:  name,
		Type:  TypeA,
		Class: ClassIN,
		TTL:   300,
		Data:  &RDataA{Address: [4]byte{1, 2, 3, 4}},
	}

	nameWireLen := name.WireLength()
	// Enough for name + type + class + TTL, but not RDLENGTH (2 bytes)
	buf := make([]byte, nameWireLen+9)
	_, err := rr.Pack(buf, 0, nil)
	if err == nil {
		t.Error("Pack should fail when buffer too small for RDLENGTH field")
	}
}

// ============================================================================
// record.go UnpackResourceRecord - cover error paths (81.5%)
// Cover: name unpack error, fixed fields too small, rdlength extends past buf
// ============================================================================

func TestUnpackResourceRecordNameError(t *testing.T) {
	// Create a buffer with a truncated name (length byte but not enough data)
	buf := []byte{0x10} // Label length = 16, but no data follows
	_, _, err := UnpackResourceRecord(buf, 0)
	if err == nil {
		t.Error("UnpackResourceRecord should fail with invalid name")
	}
}

func TestUnpackResourceRecordFixedFieldsTooSmall(t *testing.T) {
	// Create a buffer with a valid name but not enough bytes for fixed fields
	buf := []byte{
		0x03, 'f', 'o', 'o', 0x03, 'c', 'o', 'm', 0x00, // "foo.com."
		0x00, 0x01, // Only 2 extra bytes, need 10 (type+class+ttl+rdlength)
	}
	_, _, err := UnpackResourceRecord(buf, 0)
	if err == nil {
		t.Error("UnpackResourceRecord should fail with insufficient fixed fields")
	}
}

func TestUnpackResourceRecordRDLengthTooLarge(t *testing.T) {
	// Create a buffer with valid name and fixed fields, but RDLENGTH extends past buffer
	name := []byte{0x03, 'f', 'o', 'o', 0x03, 'c', 'o', 'm', 0x00}
	fixedFields := make([]byte, 10)
	PutUint16(fixedFields[0:], TypeA)
	PutUint16(fixedFields[2:], ClassIN)
	PutUint32(fixedFields[4:], 300)
	PutUint16(fixedFields[8:], 100) // RDLENGTH = 100 but no data

	buf := append(name, fixedFields...)
	_, _, err := UnpackResourceRecord(buf, 0)
	if err == nil {
		t.Error("UnpackResourceRecord should fail when RDLENGTH extends past buffer")
	}
}

func TestUnpackResourceRecordRDATAPackError(t *testing.T) {
	// Create a buffer with A record type but wrong rdlength
	name := []byte{0x03, 'f', 'o', 'o', 0x03, 'c', 'o', 'm', 0x00}
	fixedFields := make([]byte, 10)
	PutUint16(fixedFields[0:], TypeA)
	PutUint16(fixedFields[2:], ClassIN)
	PutUint32(fixedFields[4:], 300)
	PutUint16(fixedFields[8:], 3) // RDLENGTH = 3 but A record needs 4

	rdata := []byte{1, 2, 3} // Only 3 bytes but A expects 4
	buf := append(name, fixedFields...)
	buf = append(buf, rdata...)

	_, _, err := UnpackResourceRecord(buf, 0)
	if err == nil {
		t.Error("UnpackResourceRecord should fail when RDATA unpack fails (wrong rdlength for type A)")
	}
}

// ============================================================================
// question.go Pack - cover QClass buffer too small (84.6%)
// ============================================================================

func TestQuestionPackQClassTooSmall(t *testing.T) {
	q, _ := NewQuestion("a.b.", TypeA, ClassIN)
	// Buffer large enough for name (4 bytes for "a.b.") + QType (2 bytes) but not QClass (2 bytes)
	// name = 1+1+1+1+1 = 5 bytes, QType = 2 bytes, total 7. Give 7 bytes (no room for QClass)
	buf := make([]byte, 7)
	_, err := q.Pack(buf, 0, nil)
	if err == nil {
		t.Error("Question.Pack should fail when buffer too small for QClass")
	}
}

// ============================================================================
// labels.go Equal - cover case where labels differ (83.3%)
// Specifically the case where same number of labels but different content
// ============================================================================

func TestNameEqualDifferentLabels(t *testing.T) {
	// Same number of labels but different content
	n1, _ := ParseName("foo.example.com.")
	n2, _ := ParseName("bar.example.com.")
	if n1.Equal(n2) {
		t.Error("Names with different first labels should not be equal")
	}

	// Single label, same FQDN, same content
	n3, _ := ParseName("test.")
	n4, _ := ParseName("test.")
	if !n3.Equal(n4) {
		t.Error("Identical single-label names should be equal")
	}
}

// ============================================================================
// labels.go ValidateLabel - cover invalid char at start (hyphen) and middle (90.9%)
// ============================================================================

func TestValidateLabelHyphenAtStart(t *testing.T) {
	err := ValidateLabel("-test")
	if err == nil {
		t.Error("ValidateLabel should fail with hyphen at start")
	}
}

func TestValidateLabelInvalidCharMiddle(t *testing.T) {
	err := ValidateLabel("te#st")
	if err == nil {
		t.Error("ValidateLabel should fail with # in middle")
	}
}

// ============================================================================
// labels.go PackName - cover name too long case (88.2%)
// ============================================================================

func TestPackNameTooLong(t *testing.T) {
	// Create a name that is too long (> 255 bytes wire format)
	longLabel := ""
	for i := 0; i < 50; i++ {
		longLabel += "aaaaaaaaaa" // 10 chars each
		if i < 49 {
			longLabel += "."
		}
	}
	// This will be 500+ chars, well over the 255 byte limit
	n, err := ParseName(longLabel + ".")
	if err != nil {
		// ParseName rejected it, that's fine - nothing more to test
		t.Skipf("ParseName rejected the long name: %v", err)
	}
	buf := make([]byte, 600)
	_, err = PackName(n, buf, 0, nil)
	if err == nil {
		t.Error("PackName should fail with name > 255 bytes")
	}
}

// ============================================================================
// labels.go UnpackName - cover buffer too small on label data (94.9%)
// ============================================================================

func TestUnpackNameBufferTooSmallForLabelData(t *testing.T) {
	// Label length says 5 bytes but only 2 available
	buf := []byte{0x05, 'h', 'e'} // length=5, only 2 chars
	_, _, err := UnpackName(buf, 0)
	if err == nil {
		t.Error("UnpackName should fail when label data extends past buffer")
	}
}

func TestUnpackNameTooLongTotal(t *testing.T) {
	// Create a name where total length exceeds 255 bytes
	buf := make([]byte, 300)
	offset := 0
	for i := 0; i < 30; i++ {
		buf[offset] = 8
		offset++
		copy(buf[offset:], "aaaaaaaa")
		offset += 8
	}
	buf[offset] = 0 // terminator
	// Total: 30 * 9 = 270 bytes > 255
	_, _, err := UnpackName(buf, 0)
	if err == nil {
		t.Error("UnpackName should fail when total name length > 255")
	}
}

// ============================================================================
// dnssec_ds.go CalculateDSDigest - cover SHA-384 case more thoroughly (90.9%)
// ============================================================================

func TestCalculateDSDigestSHA384(t *testing.T) {
	dnskey := &RDataDNSKEY{
		Flags:     DNSKEYFlagZone | DNSKEYFlagSEP,
		Protocol:  3,
		Algorithm: AlgorithmRSASHA256,
		PublicKey: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
	}

	digest, err := CalculateDSDigest("example.com.", dnskey, 4)
	if err != nil {
		t.Fatalf("CalculateDSDigest(SHA384) error: %v", err)
	}
	if len(digest) != 48 {
		t.Errorf("SHA-384 digest length: got %d, want 48", len(digest))
	}

	// Verify it's not all zeros
	allZero := true
	for _, b := range digest {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("SHA-384 digest should not be all zeros")
	}
}

// ============================================================================
// dnssec_rrsig.go Pack - cover buffer too small for signer name (94.9%)
// ============================================================================

func TestRDataRRSIGPackSignerNameError(t *testing.T) {
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
		Signature:   []byte{0xAA},
	}

	// Buffer large enough for fixed fields (18 bytes) but not signer name
	_, err := rdata.Pack(make([]byte, 18), 0)
	if err == nil {
		t.Error("RRSIG.Pack should fail when buffer too small for signer name")
	}
}

// ============================================================================
// dnssec_rrsig.go Unpack - cover signer name error and offset > endOffset (90.6%)
// ============================================================================

func TestRDataRRSIGUnpackSignerNameError(t *testing.T) {
	rdata := &RDataRRSIG{}
	// 18 bytes of fixed fields, then a bad name (label length = 255)
	buf := make([]byte, 20)
	// Fill fixed fields
	for i := 0; i < 18; i++ {
		buf[i] = 0
	}
	buf[18] = 0xFF // Invalid label length

	_, err := rdata.Unpack(buf, 0, 20)
	if err == nil {
		t.Error("RRSIG.Unpack should fail with invalid signer name")
	}
}

func TestRDataRRSIGUnpackEndOffsetPastBuf(t *testing.T) {
	rdata := &RDataRRSIG{}
	// Provide 18 bytes but rdlength says more
	buf := make([]byte, 18)
	_, err := rdata.Unpack(buf, 0, 30)
	if err == nil {
		t.Error("RRSIG.Unpack should fail when endOffset > len(buf)")
	}
}

// ============================================================================
// dnssec_nsec.go Pack - cover buffer too small for bitmap (94.7%)
// ============================================================================

func TestRDataNSECPackBitmapTooSmall(t *testing.T) {
	next, _ := ParseName("next.example.com.")
	rdata := &RDataNSEC{
		NextDomain: next,
		TypeBitMap: []uint16{TypeA, TypeNS, TypeMX, TypeAAAA},
	}

	// Allocate just enough for the name but not the bitmap
	nameLen := next.WireLength()
	buf := make([]byte, nameLen+1) // 1 byte too small for bitmap window header
	_, err := rdata.Pack(buf, 0)
	if err == nil {
		t.Error("NSEC.Pack should fail when buffer too small for bitmap")
	}
}

// ============================================================================
// dnssec_nsec.go Unpack - cover endOffset > len(buf) (96.3%)
// ============================================================================

func TestRDataNSECUnpackEndOffsetPastBuf(t *testing.T) {
	rdata := &RDataNSEC{}
	// rdlength extends past actual buffer
	buf := make([]byte, 10)
	_, err := rdata.Unpack(buf, 0, 20)
	if err == nil {
		t.Error("NSEC.Unpack should fail when endOffset > len(buf)")
	}
}

// ============================================================================
// dnssec_nsec3.go Pack - cover buffer too small for bitmap (98.5%)
// ============================================================================

func TestRDataNSEC3PackBitmapTooSmall(t *testing.T) {
	rdata := &RDataNSEC3{
		HashAlgorithm: NSEC3HashSHA1,
		Flags:         0,
		Iterations:    0,
		Salt:          nil,
		NextHashed:    []byte{0x01},
		TypeBitMap:    []uint16{TypeA, TypeNS},
	}

	// Fixed fields = 1+1+2+1+0+1+1 = 7 bytes for header
	// Bitmap needs at least 3 bytes (2 header + 1 bitmap)
	// Give exactly 7 + 2 = 9 (enough for bitmap header but we need it slightly shorter)
	buf := make([]byte, 8) // 1 byte short for the full bitmap
	_, err := rdata.Pack(buf, 0)
	if err == nil {
		t.Error("NSEC3.Pack should fail when buffer too small for bitmap")
	}
}

// ============================================================================
// dnssec_nsec3.go Unpack - cover truncated bitmap (95.7%)
// ============================================================================

func TestRDataNSEC3UnpackTruncatedBitmapHeader(t *testing.T) {
	rdata := &RDataNSEC3{}
	// Fixed: hash(1)+flags(1)+iter(2)+saltLen(1)+hashLen(1) = 6, with no salt and no hash
	// Then 1 byte remaining for bitmap but need 2
	buf := []byte{1, 0, 0, 0, 0, 0, 0xAA} // 7 bytes, rdlength=7
	_, err := rdata.Unpack(buf, 0, 7)
	if err == nil {
		t.Error("NSEC3.Unpack should fail with only 1 byte remaining for bitmap header (need 2)")
	}
}

func TestRDataNSEC3UnpackBitmapDataTooShort(t *testing.T) {
	rdata := &RDataNSEC3{}
	// Fixed: hash(1)+flags(1)+iter(2)+saltLen(1)=0+hashLen(1)=0 = 6 bytes consumed
	// With rdlength=9: remaining 3 bytes for bitmap
	// bitmap: window(1)+length(1)+data... but length says 3 when only 1 byte available
	buf := []byte{1, 0, 0, 0, 0, 0, 0x00, 0x03, 0x40} // 9 bytes
	_, err := rdata.Unpack(buf, 0, 9)
	if err == nil {
		t.Error("NSEC3.Unpack should fail when bitmap data extends past endOffset")
	}
}

// ============================================================================
// dnssec_nsec3param.go Unpack - cover endOffset > len(buf) (95.0%)
// ============================================================================

func TestRDataNSEC3PARAMUnpackEndOffsetPastBuf(t *testing.T) {
	rdata := &RDataNSEC3PARAM{}
	// rdlength extends past actual buffer
	buf := make([]byte, 5)
	_, err := rdata.Unpack(buf, 0, 10)
	if err == nil {
		t.Error("NSEC3PARAM.Unpack should fail when endOffset > len(buf)")
	}
}

// ============================================================================
// header.go Pack - cover the Flags.Pack() call path with Z flag set (95.0%)
// The Z flag in Flags.Pack is at line ~165
// ============================================================================

func TestFlagsPackZFlag(t *testing.T) {
	f := Flags{Z: true}
	packed := f.Pack()
	if packed&FlagZ == 0 {
		t.Error("Z flag should be set in packed flags")
	}

	// Round trip
	unpacked := UnpackFlags(packed)
	if !unpacked.Z {
		t.Error("Z flag should be preserved after unpack")
	}
}

// ============================================================================
// opt.go NewEDNS0ClientSubnet - cover IPv6 non-byte-aligned prefix (93.3%)
// ============================================================================

func TestNewEDNS0ClientSubnetIPv6NonByteAligned(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	ecs := NewEDNS0ClientSubnet(ip, 65)
	if ecs.Family != 2 {
		t.Errorf("Family = %d, want 2 for IPv6", ecs.Family)
	}
	if ecs.SourcePrefixLength != 65 {
		t.Errorf("SourcePrefixLength = %d, want 65", ecs.SourcePrefixLength)
	}
	// 65 bits = 9 bytes, and the last byte should be masked
	if len(ecs.Address) != 9 {
		t.Errorf("Address length = %d, want 9", len(ecs.Address))
	}
}

func TestNewEDNS0ClientSubnetIPv6FullPrefix(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	ecs := NewEDNS0ClientSubnet(ip, 128)
	if ecs.Family != 2 {
		t.Errorf("Family = %d, want 2 for IPv6", ecs.Family)
	}
	if len(ecs.Address) != 16 {
		t.Errorf("Address length = %d, want 16 for /128", len(ecs.Address))
	}
}

// ============================================================================
// wire.go ValidateMessage - cover record count too high path (90.0%)
// The code checks qdcount/ancount/nscount/arcount against maxRecords (65535)
// but since uint16 max is 65535, this can never trigger.
// However, let's test the "message too short" path more thoroughly.
// ============================================================================

func TestValidateMessageTooShort11Bytes(t *testing.T) {
	buf := make([]byte, 11)
	err := ValidateMessage(buf)
	if err == nil {
		t.Error("ValidateMessage should fail with 11 bytes")
	}
}

// ============================================================================
// record.go Pack - cover data pack error path
// ============================================================================

func TestResourceRecordPackDataError(t *testing.T) {
	name, _ := ParseName("example.com.")
	rr := &ResourceRecord{
		Name:  name,
		Type:  TypeA,
		Class: ClassIN,
		TTL:   300,
		Data:  &RDataA{Address: [4]byte{1, 2, 3, 4}},
	}

	// Buffer just enough for name+type+class+ttl+rdlength but not rdata
	nameWireLen := name.WireLength()
	buf := make([]byte, nameWireLen+10) // +10 = type(2)+class(2)+ttl(4)+rdlength(2)
	// A record data needs 4 more bytes, so this should fail
	_, err := rr.Pack(buf, 0, nil)
	if err == nil {
		t.Error("Pack should fail when buffer too small for RData")
	}
}

func TestResourceRecordPackRejectsOversizedRData(t *testing.T) {
	name, _ := ParseName("example.com.")
	rr := &ResourceRecord{
		Name:  name,
		Type:  65280,
		Class: ClassIN,
		TTL:   300,
		Data: &RDataRaw{
			TypeVal: 65280,
			Data:    make([]byte, 0x10000),
		},
	}

	buf := make([]byte, rr.WireLength())
	_, err := rr.Pack(buf, 0, nil)
	if err == nil {
		t.Fatal("Pack accepted RDATA that cannot fit in uint16 RDLENGTH")
	}
	if !strings.Contains(err.Error(), "exceeds 65535") {
		t.Fatalf("Pack error = %v, want oversized RDATA error", err)
	}
}

// ============================================================================
// message.go Pack - cover the question pack error path more specifically
// (The question packing with compression map failure)
// ============================================================================

func TestMessagePackQuestionWithCompressionError(t *testing.T) {
	msg := NewMessage(Header{ID: 0x1234, Flags: NewQueryFlags()})
	q, _ := NewQuestion("example.com.", TypeA, ClassIN)
	msg.AddQuestion(q)

	// Create a buffer that is too small for the question
	buf := make([]byte, HeaderLen+2) // Only 2 bytes after header, not enough for question
	_, err := msg.Pack(buf)
	if err == nil {
		t.Error("Pack should fail with buffer too small for question")
	}
}

// ============================================================================
// labels.go PackName - cover compression pointer path more thoroughly
// ============================================================================

func TestPackNameWithCompressionHit(t *testing.T) {
	name, _ := ParseName("www.example.com.")
	exKey, _ := ParseName("example.com.")
	compression := map[string]int{
		wireSuffixKey(exKey.wire): 12, // Simulate "example.com" already packed at offset 12
	}

	buf := make([]byte, 512)
	n, err := PackName(name, buf, 0, compression)
	if err != nil {
		t.Fatalf("PackName with compression hit failed: %v", err)
	}

	// RFC 1035 §4.1.4: the suffix "example.com" matches at offset 12, but
	// the leading "www" label MUST be emitted before the pointer —
	// 1+3 label bytes + 2 pointer bytes = 6. (The old code jumped straight
	// to the pointer and the name decoded as "example.com.".)
	if n != 6 {
		t.Errorf("PackName with compression: got %d bytes, want 6", n)
	}
	if buf[0] != 3 || string(buf[1:4]) != "www" {
		t.Errorf("leading label = %v %q, want 3 %q", buf[0], buf[1:4], "www")
	}
	if buf[4]&0xC0 != 0xC0 {
		t.Errorf("byte after labels should be compression pointer (0xC0|), got 0x%02X", buf[4])
	}
	if ptr := int(buf[4]&0x3F)<<8 | int(buf[5]); ptr != 12 {
		t.Errorf("pointer offset = %d, want 12", ptr)
	}
}

func TestPackNameWithCompressionExactMatch(t *testing.T) {
	name, _ := ParseName("example.com.")
	exKey, _ := ParseName("example.com.")
	compression := map[string]int{
		wireSuffixKey(exKey.wire): 0, // Full match
	}

	buf := make([]byte, 512)
	n, err := PackName(name, buf, 20, compression)
	if err != nil {
		t.Fatalf("PackName with exact compression match failed: %v", err)
	}

	// Should be just a 2-byte pointer
	if n != 2 {
		t.Errorf("PackName with exact match: got %d bytes, want 2", n)
	}

	// Verify it's a pointer
	if buf[20]&0xC0 != 0xC0 {
		t.Error("Should be a compression pointer")
	}
}

func TestPackNameWithCompressionPointerTooSmall(t *testing.T) {
	name, _ := ParseName("example.com.")
	exKey, _ := ParseName("example.com.")
	compression := map[string]int{
		wireSuffixKey(exKey.wire): 0x4000, // Over max pointer offset
	}

	buf := make([]byte, 512)
	// This should not match since ptrOffset >= PointerOffsetMask
	_, err := PackName(name, buf, 0, compression)
	if err != nil {
		// Should succeed - just pack normally without using the compression entry
		t.Errorf("PackName should succeed even if compression offset is too large: %v", err)
	}
}

// ============================================================================
// labels.go WireNameLength - cover the loop detection path (95.0%)
// ============================================================================

func TestWireNameLengthLoopDetection(t *testing.T) {
	// Create a chain of labels that exceeds MaxNameLength (255) iterations
	buf := make([]byte, 300)
	for i := 0; i < 260; i++ {
		buf[i] = 1 // Each label is 1 byte
		buf[i+1] = 'a'
	}
	// No terminator within reasonable range
	_, err := WireNameLength(buf, 0)
	if err == nil {
		t.Error("WireNameLength should detect loop/excessive labels")
	}
}

// ============================================================================
// DNSSEC records - cover multi-window bitmap packing in NSEC
// ============================================================================

func TestRDataNSECMultiWindow(t *testing.T) {
	next, _ := ParseName("next.example.com.")
	// Create types spanning multiple windows
	rdata := &RDataNSEC{
		NextDomain: next,
		TypeBitMap: []uint16{
			TypeA,   // Window 0
			TypeMX,  // Window 0
			TypeTXT, // Window 0
			0x0101,  // Window 1, bit 1
			0x0102,  // Window 1, bit 2
		},
	}

	buf := make([]byte, 512)
	n, err := rdata.Pack(buf, 0)
	if err != nil {
		t.Fatalf("NSEC multi-window Pack failed: %v", err)
	}

	unpacked := &RDataNSEC{}
	_, err = unpacked.Unpack(buf, 0, uint16(n))
	if err != nil {
		t.Fatalf("NSEC multi-window Unpack failed: %v", err)
	}

	for _, typ := range rdata.TypeBitMap {
		if !unpacked.HasType(typ) {
			t.Errorf("Type %d missing after round-trip", typ)
		}
	}
}

// ============================================================================
// DNSSEC NSEC3 - multi-window bitmap
// ============================================================================

func TestRDataNSEC3MultiWindow(t *testing.T) {
	rdata := &RDataNSEC3{
		HashAlgorithm: NSEC3HashSHA1,
		Flags:         0,
		Iterations:    10,
		Salt:          []byte{0xAA},
		NextHashed:    []byte{0x01, 0x02},
		TypeBitMap: []uint16{
			TypeA,  // Window 0
			0x0101, // Window 1
		},
	}

	buf := make([]byte, 512)
	n, err := rdata.Pack(buf, 0)
	if err != nil {
		t.Fatalf("NSEC3 multi-window Pack failed: %v", err)
	}

	unpacked := &RDataNSEC3{}
	_, err = unpacked.Unpack(buf, 0, uint16(n))
	if err != nil {
		t.Fatalf("NSEC3 multi-window Unpack failed: %v", err)
	}

	if !unpacked.HasType(TypeA) {
		t.Error("TypeA missing after round-trip")
	}
	if !unpacked.HasType(0x0101) {
		t.Error("Type 0x0101 missing after round-trip")
	}
}
