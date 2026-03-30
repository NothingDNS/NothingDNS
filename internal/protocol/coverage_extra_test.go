package protocol

import (
	"net"
	"testing"
)

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
		Data: &RDataA{Address: [4]byte{1, 2, 3, 4}},
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
		Data: &RDataA{Address: [4]byte{1, 2, 3, 4}},
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
		Data: &RDataA{Address: [4]byte{1, 2, 3, 4}},
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
		Data: &RDataA{Address: [4]byte{1, 2, 3, 4}},
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
	compression := map[string]int{
		"example.com": 12, // Simulate "example.com" already packed at offset 12
	}

	buf := make([]byte, 512)
	n, err := PackName(name, buf, 0, compression)
	if err != nil {
		t.Fatalf("PackName with compression hit failed: %v", err)
	}

	// PackName checks suffixes: i=1 matches "example.com", so it only writes
	// a 2-byte compression pointer (no labels are written before the match)
	if n != 2 {
		t.Errorf("PackName with compression: got %d bytes, want 2", n)
	}

	// Verify pointer bytes (compression pointer has top 2 bits set)
	if buf[0]&0xC0 != 0xC0 {
		t.Errorf("First byte should be compression pointer (0xC0|), got 0x%02X", buf[0])
	}
}

func TestPackNameWithCompressionExactMatch(t *testing.T) {
	name, _ := ParseName("example.com.")
	compression := map[string]int{
		"example.com": 0, // Full match
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
	compression := map[string]int{
		"example.com": 0x4000, // Over max pointer offset
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
			TypeA,   // Window 0
			0x0101,  // Window 1
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
