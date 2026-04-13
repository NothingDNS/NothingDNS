package protocol

// coverage2_test.go adds tests to improve coverage for low-coverage functions.
// Targets remaining uncovered branches in:
//   - DNSSEC Pack/Unpack error paths (buffer too small at each checkpoint)
//   - types.go: SRV/CAA/SSHFP/TLSA/NAPTR Pack/Unpack buffer-too-small branches
//   - NSEC/NSEC3/NSEC3PARAM Unpack truncated data paths
//   - OPT Unpack truncated option data
//   - Message.Copy with all sections populated
//   - RDataOPT.String with multiple options
//   - NewQuery with invalid name
//   - base64Encode edge cases (1 byte, 2 bytes)
//   - EDNS0ClientSubnet edge cases (non-byte-aligned prefix)
//   - WireNameLength with buffer overflow
//   - ValidateMessage edge cases

import (
	"bytes"
	"net"
	"strings"
	"testing"
)

// ============================================================================
// DNSKEY Pack boundary error tests (84.2% -> higher)
// ============================================================================

func TestRDataDNSKEYPackBoundaryErrors(t *testing.T) {
	rdata := &RDataDNSKEY{
		Flags:     257,
		Protocol:  3,
		Algorithm: 8,
		PublicKey: []byte{0x01, 0x02, 0x03},
	}

	// Flags needs 2 bytes
	_, err := rdata.Pack(make([]byte, 1), 0)
	if err == nil {
		t.Error("DNSKEY.Pack should fail at Flags with buf size 1")
	}

	// Protocol needs 1 more byte (offset 2)
	_, err = rdata.Pack(make([]byte, 2), 0)
	if err == nil {
		t.Error("DNSKEY.Pack should fail at Protocol with buf size 2")
	}

	// Algorithm needs 1 more byte (offset 3)
	_, err = rdata.Pack(make([]byte, 3), 0)
	if err == nil {
		t.Error("DNSKEY.Pack should fail at Algorithm with buf size 3")
	}

	// PublicKey doesn't fit (need 4+3=7, only have 4)
	_, err = rdata.Pack(make([]byte, 4), 0)
	if err == nil {
		t.Error("DNSKEY.Pack should fail at PublicKey with buf size 4")
	}
}

// DNSKEY Unpack truncated rdlength (88.2%)
func TestRDataDNSKEYUnpackTruncated(t *testing.T) {
	rdata := &RDataDNSKEY{}
	// Need at least 4 bytes for fixed fields; give only 3
	_, err := rdata.Unpack([]byte{0, 0, 0}, 0, 3)
	if err == nil {
		t.Error("DNSKEY.Unpack should fail with rdlength < 4")
	}
}

// ============================================================================
// DS Pack boundary error tests (84.2% -> higher)
// ============================================================================

func TestRDataDSPackBoundaryErrors(t *testing.T) {
	rdata := &RDataDS{
		KeyTag:     12345,
		Algorithm:  8,
		DigestType: 2,
		Digest:     []byte{0xAA, 0xBB},
	}

	// KeyTag needs 2 bytes
	_, err := rdata.Pack(make([]byte, 1), 0)
	if err == nil {
		t.Error("DS.Pack should fail at KeyTag with buf size 1")
	}

	// Algorithm needs 1 more byte (offset 2)
	_, err = rdata.Pack(make([]byte, 2), 0)
	if err == nil {
		t.Error("DS.Pack should fail at Algorithm with buf size 2")
	}

	// DigestType needs 1 more byte (offset 3)
	_, err = rdata.Pack(make([]byte, 3), 0)
	if err == nil {
		t.Error("DS.Pack should fail at DigestType with buf size 3")
	}

	// Digest doesn't fit (need 4+2=6, only have 4)
	_, err = rdata.Pack(make([]byte, 4), 0)
	if err == nil {
		t.Error("DS.Pack should fail at Digest with buf size 4")
	}
}

// DS Unpack truncated rdlength (88.2%)
func TestRDataDSUnpackTruncated(t *testing.T) {
	rdata := &RDataDS{}
	// Need at least 4 bytes for fixed fields; give only 3
	_, err := rdata.Unpack([]byte{0, 0, 0}, 0, 3)
	if err == nil {
		t.Error("DS.Unpack should fail with rdlength < 4")
	}
}

// ============================================================================
// NSEC Unpack truncated paths (85.2%)
// ============================================================================

func TestRDataNSECUnpackTruncated(t *testing.T) {
	// Pack a valid NSEC first
	next, _ := ParseName("next.example.com.")
	full := &RDataNSEC{NextDomain: next, TypeBitMap: []uint16{TypeA, TypeNS}}
	buf := make([]byte, 512)
	n, _ := full.Pack(buf, 0)

	// Test: endOffset > len(buf)
	rdata := &RDataNSEC{}
	_, err := rdata.Unpack(buf[:5], 0, uint16(n))
	if err == nil {
		t.Error("NSEC.Unpack should fail when endOffset > buffer length")
	}

	// Test: truncated bitmap (need at least 2 bytes for window header)
	// Pack the name portion only, then add 1 byte for incomplete bitmap
	nameBuf := make([]byte, 512)
	nameN, _ := PackName(next, nameBuf, 0, nil)
	truncBuf := make([]byte, nameN+1)
	copy(truncBuf, nameBuf[:nameN])
	truncBuf[nameN] = 0x00 // window number byte, but no length byte

	_, err = rdata.Unpack(truncBuf, 0, uint16(len(truncBuf)))
	if err == nil {
		t.Error("NSEC.Unpack should fail with truncated bitmap header")
	}

	// Test: bitmap data extends past endOffset
	truncBuf2 := make([]byte, nameN+3)
	copy(truncBuf2, nameBuf[:nameN])
	truncBuf2[nameN] = 0x00   // window number
	truncBuf2[nameN+1] = 0x05 // bitmap length = 5, but we only have 1 byte
	truncBuf2[nameN+2] = 0x40

	_, err = rdata.Unpack(truncBuf2, 0, uint16(len(truncBuf2)))
	if err == nil {
		t.Error("NSEC.Unpack should fail when bitmap data extends past endOffset")
	}
}

// ============================================================================
// NSEC3 Pack boundary errors (83.8%)
// ============================================================================

func TestRDataNSEC3PackBoundaryErrors(t *testing.T) {
	rdata := &RDataNSEC3{
		HashAlgorithm: 1,
		Flags:         0,
		Iterations:    10,
		Salt:          []byte{0xAA, 0xBB},
		NextHashed:    []byte{0x01, 0x02},
	}

	// Hash Algorithm needs 1 byte
	_, err := rdata.Pack(make([]byte, 0), 0)
	if err == nil {
		t.Error("NSEC3.Pack should fail at HashAlgorithm with empty buf")
	}

	// Flags needs 1 more byte (offset 1)
	_, err = rdata.Pack(make([]byte, 1), 0)
	if err == nil {
		t.Error("NSEC3.Pack should fail at Flags with buf size 1")
	}

	// Iterations needs 2 more bytes (offset 2)
	_, err = rdata.Pack(make([]byte, 2), 0)
	if err == nil {
		t.Error("NSEC3.Pack should fail at Iterations with buf size 2")
	}

	// Salt Length needs 1 more byte (offset 4)
	_, err = rdata.Pack(make([]byte, 4), 0)
	if err == nil {
		t.Error("NSEC3.Pack should fail at SaltLength with buf size 4")
	}

	// Salt doesn't fit
	_, err = rdata.Pack(make([]byte, 5), 0)
	if err == nil {
		t.Error("NSEC3.Pack should fail at Salt with buf size 5")
	}

	// Hash Length needs 1 more byte
	_, err = rdata.Pack(make([]byte, 7), 0) // 5 + 2 salt = 7
	if err == nil {
		t.Error("NSEC3.Pack should fail at HashLength with buf size 7")
	}

	// NextHashed doesn't fit
	_, err = rdata.Pack(make([]byte, 8), 0) // 7 + 1 hashLen = 8
	if err == nil {
		t.Error("NSEC3.Pack should fail at NextHashed with buf size 8")
	}

	// Test salt too long
	rdata2 := &RDataNSEC3{Salt: make([]byte, 256)}
	_, err = rdata2.Pack(make([]byte, 600), 0)
	if err == nil {
		t.Error("NSEC3.Pack should fail with salt > 255")
	}

	// Test NextHashed too long
	rdata3 := &RDataNSEC3{Salt: nil, NextHashed: make([]byte, 256)}
	_, err = rdata3.Pack(make([]byte, 600), 0)
	if err == nil {
		t.Error("NSEC3.Pack should fail with NextHashed > 255")
	}

	// Test bitmap buffer too small
	rdata4 := &RDataNSEC3{
		HashAlgorithm: 1,
		Flags:         0,
		Iterations:    0,
		Salt:          nil,
		NextHashed:    nil,
		TypeBitMap:    []uint16{TypeA},
	}
	// 1+1+2+1+0+1+0 = 6 bytes for header, then bitmap needs 2+1 = 3 bytes
	// Total 9 bytes, give 8
	_, err = rdata4.Pack(make([]byte, 8), 0)
	if err == nil {
		t.Error("NSEC3.Pack should fail with bitmap buffer too small")
	}
}

// NSEC3 Unpack truncated paths (85.1%)
func TestRDataNSEC3UnpackTruncated(t *testing.T) {
	rdata := &RDataNSEC3{}

	// Need at least 6 bytes for fixed fields before salt
	_, err := rdata.Unpack([]byte{1, 0, 0, 10, 2}, 0, 5)
	if err == nil {
		t.Error("NSEC3.Unpack should fail with < 6 bytes")
	}

	// Salt extends past end
	buf := make([]byte, 10)
	buf[4] = 0xFF // salt length = 255 but buffer only has a few bytes
	_, err = rdata.Unpack(buf, 0, 10)
	if err == nil {
		t.Error("NSEC3.Unpack should fail when salt extends past endOffset")
	}

	// Hash length byte missing
	buf2 := []byte{1, 0, 0, 10, 0} // 5 bytes: hashAlg+flags+iterations+saltLen+no_salt
	_, err = rdata.Unpack(buf2, 0, 5)
	if err == nil {
		t.Error("NSEC3.Unpack should fail when hash length byte is missing")
	}

	// NextHashed extends past end
	buf3 := []byte{1, 0, 0, 10, 0, 0x0A} // hashLen = 10 but no data
	_, err = rdata.Unpack(buf3, 0, 6)
	if err == nil {
		t.Error("NSEC3.Unpack should fail when NextHashed extends past endOffset")
	}

	// Truncated bitmap header - only 1 byte remaining for bitmap when we need 2 (window + length)
	// Fixed fields (hashAlg+flags+iterations+saltLen) = 5 bytes, then saltLen=0, then hashLen byte at offset 5
	// With rdlength=6, endOffset=6. After reading hashLen (offset=6), offset == endOffset, loop exits.
	// So we need rdlength=7 to have 1 extra byte. After reading hashLen at offset 5 with hashLen=0,
	// offset becomes 6. Loop: offset(6) < endOffset(7) -> need offset+2=8 > endOffset(7) -> fail!
	buf4b := []byte{1, 0, 0, 10, 0, 0} // 6 bytes data, rdlength will be 7
	_, err = rdata.Unpack(buf4b, 0, 7) // endOffset=7 but only 6 bytes in buf; endOffset > len(buf)
	if err == nil {
		t.Error("NSEC3.Unpack should fail when endOffset exceeds buffer and partial bitmap remains")
	}

	// Bitmap data extends past endOffset - valid window header but not enough bitmap bytes
	// Fixed fields = 5 bytes (offset 0-4), saltLen=0 at offset 4, hashLen=0 at offset 5
	// After reading all fixed + hash: offset=6. endOffset=9. Loop enters.
	// Read window=0x00 at offset 6, bitmapLen=3 at offset 7. offset becomes 8.
	// Check: offset+bitmapLen=11 > endOffset=9 -> fail
	buf5 := []byte{1, 0, 0, 10, 0, 0, 0x00, 0x03, 0x40} // 9 bytes, rdlength=9
	_, err = rdata.Unpack(buf5, 0, 9)
	if err == nil {
		t.Error("NSEC3.Unpack should fail when bitmap data extends past endOffset")
	}
}

// ============================================================================
// NSEC3PARAM Pack boundary errors (80.0%)
// ============================================================================

func TestRDataNSEC3PARAMPackBoundaryErrors(t *testing.T) {
	rdata := &RDataNSEC3PARAM{
		HashAlgorithm: 1,
		Flags:         0,
		Iterations:    10,
		Salt:          []byte{0xAA},
	}

	// Hash Algorithm needs 1 byte
	_, err := rdata.Pack(make([]byte, 0), 0)
	if err == nil {
		t.Error("NSEC3PARAM.Pack should fail at HashAlgorithm with empty buf")
	}

	// Flags needs 1 more byte (offset 1)
	_, err = rdata.Pack(make([]byte, 1), 0)
	if err == nil {
		t.Error("NSEC3PARAM.Pack should fail at Flags with buf size 1")
	}

	// Iterations needs 2 more bytes (offset 2)
	_, err = rdata.Pack(make([]byte, 2), 0)
	if err == nil {
		t.Error("NSEC3PARAM.Pack should fail at Iterations with buf size 2")
	}

	// Salt Length needs 1 more byte (offset 4)
	_, err = rdata.Pack(make([]byte, 4), 0)
	if err == nil {
		t.Error("NSEC3PARAM.Pack should fail at SaltLength with buf size 4")
	}

	// Salt doesn't fit (need 5+1=6, only have 5)
	_, err = rdata.Pack(make([]byte, 5), 0)
	if err == nil {
		t.Error("NSEC3PARAM.Pack should fail at Salt with buf size 5")
	}

	// Salt too long
	rdata2 := &RDataNSEC3PARAM{Salt: make([]byte, 256)}
	_, err = rdata2.Pack(make([]byte, 600), 0)
	if err == nil {
		t.Error("NSEC3PARAM.Pack should fail with salt > 255")
	}
}

// NSEC3PARAM Unpack truncated paths (85.0%)
func TestRDataNSEC3PARAMUnpackTruncated(t *testing.T) {
	rdata := &RDataNSEC3PARAM{}

	// Need at least 5 bytes for fixed fields before salt
	_, err := rdata.Unpack([]byte{1, 0, 0, 10}, 0, 4)
	if err == nil {
		t.Error("NSEC3PARAM.Unpack should fail with < 5 bytes")
	}

	// Salt extends past end
	buf := make([]byte, 10)
	buf[4] = 0xFF // salt length = 255 but only a few bytes
	_, err = rdata.Unpack(buf, 0, 10)
	if err == nil {
		t.Error("NSEC3PARAM.Unpack should fail when salt extends past endOffset")
	}
}

// NSEC3PARAM VerifyParams - cover the salt too long branch (85.7%)
func TestNSEC3PARAMVerifyParamsSaltTooLong(t *testing.T) {
	rdata := &RDataNSEC3PARAM{
		HashAlgorithm: NSEC3HashSHA1,
		Iterations:    10,
		Salt:          make([]byte, 256),
	}
	if err := rdata.VerifyParams(); err == nil {
		t.Error("VerifyParams should fail with salt > 255 bytes")
	}
}

// ============================================================================
// RDataOPT Pack/Unpack edge cases
// ============================================================================

func TestRDataOPTPackBufferTooSmallOptionData(t *testing.T) {
	opt := &RDataOPT{Options: []EDNS0Option{{Code: 1, Data: []byte("test")}}}
	// 2 bytes for code, but only 1 byte available
	buf := make([]byte, 1)
	_, err := opt.Pack(buf, 0)
	if err == nil {
		t.Error("RDataOPT.Pack should fail with buffer too small for option code")
	}

	// Code fits but length doesn't
	buf = make([]byte, 2)
	_, err = opt.Pack(buf, 0)
	if err == nil {
		t.Error("RDataOPT.Pack should fail with buffer too small for option length")
	}

	// Code+length fit but data doesn't
	buf = make([]byte, 4)
	_, err = opt.Pack(buf, 0)
	if err == nil {
		t.Error("RDataOPT.Pack should fail with buffer too small for option data")
	}
}

func TestRDataOPTUnpackTruncatedOption(t *testing.T) {
	opt := &RDataOPT{}
	// Truncated option (need 4 bytes for header but rdlength says there's more)
	data := []byte{0, 1, 0, 2, 0xAA, 0xBB}
	_, err := opt.Unpack(data, 0, 2) // rdlength=2 but need 4 bytes for code+length
	if err == nil {
		t.Error("RDataOPT.Unpack should fail with truncated option header")
	}

	// Option data extends past rdlength
	_, err = opt.Unpack(data, 0, 5) // rdlength=5, code+length=4, data says 2 bytes but only 1 available
	if err == nil {
		t.Error("RDataOPT.Unpack should fail with truncated option data")
	}
}

// RDataOPT String with multiple options (cover i > 0 branch)
func TestRDataOPTStringMultipleOptions(t *testing.T) {
	opt := &RDataOPT{
		Options: []EDNS0Option{
			{Code: OptionCodeNSID, Data: []byte("ns1")},
			{Code: OptionCodePadding, Data: []byte{0, 0, 0}},
		},
	}
	s := opt.String()
	if !strings.Contains(s, "NSID") || !strings.Contains(s, "PADDING") {
		t.Errorf("String should contain both option names, got %q", s)
	}
	// Verify there's a space separator between options
	if !strings.Contains(s, " ") {
		t.Error("String should contain space separator between options")
	}
}

// ============================================================================
// EDNS0ClientSubnet edge cases (80.0%)
// ============================================================================

func TestNewEDNS0ClientSubnetNonByteAligned(t *testing.T) {
	// Test with non-byte-aligned prefix (e.g., /23 for IPv4)
	ip := net.ParseIP("192.168.1.100")
	ecs := NewEDNS0ClientSubnet(ip, 23)

	if ecs.Family != 1 {
		t.Errorf("Family = %d, want 1 for IPv4", ecs.Family)
	}
	if ecs.SourcePrefixLength != 23 {
		t.Errorf("SourcePrefixLength = %d, want 23", ecs.SourcePrefixLength)
	}
	// 23 bits = 3 bytes, and the last byte should be masked
	if len(ecs.Address) != 3 {
		t.Errorf("Address length = %d, want 3", len(ecs.Address))
	}
	// Verify masking: 192.168.1 is the first 3 bytes, last byte (0x01) should be masked
	// 23 % 8 = 7, mask = 0xFF << (8-7) = 0xFE, so 0x01 & 0xFE = 0x00
	if ecs.Address[2] != 0x00 {
		t.Errorf("Address[2] = %d, want 0 (masked)", ecs.Address[2])
	}
}

func TestUnpackEDNS0ClientSubnetTooShort(t *testing.T) {
	_, err := UnpackEDNS0ClientSubnet([]byte{0, 1, 0})
	if err == nil {
		t.Error("UnpackEDNS0ClientSubnet should fail with < 4 bytes")
	}
}

func TestUnpackEDNS0ClientSubnetWithAddress(t *testing.T) {
	data := []byte{0x00, 0x01, 0x18, 0x00, 0xC0, 0xA8, 0x01}
	ecs, err := UnpackEDNS0ClientSubnet(data)
	if err != nil {
		t.Fatalf("UnpackEDNS0ClientSubnet error: %v", err)
	}
	if ecs.Family != 1 {
		t.Errorf("Family = %d, want 1", ecs.Family)
	}
	if ecs.SourcePrefixLength != 24 {
		t.Errorf("SourcePrefixLength = %d, want 24", ecs.SourcePrefixLength)
	}
	if !bytes.Equal(ecs.Address, []byte{0xC0, 0xA8, 0x01}) {
		t.Errorf("Address = %x, want C0A801", ecs.Address)
	}
}

// ============================================================================
// base64Encode edge cases (95.2%)
// ============================================================================

func TestBase64EncodeEdgeCases(t *testing.T) {
	// 1 byte -> should produce 2 chars + 2 padding
	s := base64Encode([]byte{0x01})
	if len(s) != 4 {
		t.Errorf("base64Encode(1 byte) length = %d, want 4", len(s))
	}
	if s[2] != '=' || s[3] != '=' {
		t.Errorf("base64Encode(1 byte) should have 2 padding chars, got %q", s)
	}

	// 2 bytes -> should produce 3 chars + 1 padding
	s = base64Encode([]byte{0x01, 0x02})
	if len(s) != 4 {
		t.Errorf("base64Encode(2 bytes) length = %d, want 4", len(s))
	}
	if s[3] != '=' {
		t.Errorf("base64Encode(2 bytes) should have 1 padding char, got %q", s)
	}

	// 3 bytes -> no padding
	s = base64Encode([]byte{0x01, 0x02, 0x03})
	if len(s) != 4 {
		t.Errorf("base64Encode(3 bytes) length = %d, want 4", len(s))
	}
	if strings.Contains(s, "=") {
		t.Errorf("base64Encode(3 bytes) should have no padding, got %q", s)
	}

	// empty -> empty
	s = base64Encode([]byte{})
	if s != "" {
		t.Errorf("base64Encode(empty) = %q, want empty", s)
	}
}

// ============================================================================
// RDataSRV Unpack buffer too small (86.7%)
// ============================================================================

func TestRDataSRVUnpackBufferTooSmall(t *testing.T) {
	rdata := &RDataSRV{}
	// Need at least 6 bytes for fixed fields
	_, err := rdata.Unpack([]byte{0, 0, 0, 0, 0}, 0, 5)
	if err == nil {
		t.Error("SRV.Unpack should fail with < 6 bytes for fixed fields")
	}
}

// ============================================================================
// RDataMX Pack buffer too small (81.5% via types.go MX)
// ============================================================================

func TestRDataMXPackBufferTooSmallPreference(t *testing.T) {
	rdata := &RDataMX{Preference: 10, Exchange: must(ParseName("mail.example.com."))}
	buf := make([]byte, 1)
	_, err := rdata.Pack(buf, 0)
	if err == nil {
		t.Error("MX.Pack should fail with buffer too small for preference")
	}
}

// ============================================================================
// RDataTXT Unpack - cover offset >= len(buf) branch (92.9%)
// ============================================================================

func TestRDataTXTUnpackOffsetPastBuf(t *testing.T) {
	rdata := &RDataTXT{}
	// rdlength points past the buffer
	_, err := rdata.Unpack([]byte{0}, 0, 10)
	if err == nil {
		t.Error("TXT.Unpack should fail when rdlength extends past buffer")
	}
}

// ============================================================================
// RDataCAA Pack - cover value too large branch (90.0%)
// ============================================================================

func TestRDataCAAPackValueTooLarge(t *testing.T) {
	rdata := &RDataCAA{
		Flags: 0,
		Tag:   "issue",
		Value: "test",
	}
	// 1 byte flags + 1 byte tagLen + 5 bytes tag + value
	// Total = 12 bytes. Give just enough for flags + tag but not value
	buf := make([]byte, 7)
	_, err := rdata.Pack(buf, 0)
	if err == nil {
		t.Error("CAA.Pack should fail with buffer too small for value")
	}
}

// ============================================================================
// RDataSSHFP Unpack buffer too small (84.6%)
// ============================================================================

func TestRDataSSHFPUnpackBufferTooSmall(t *testing.T) {
	rdata := &RDataSSHFP{}
	// Need at least 2 bytes for fixed fields
	_, err := rdata.Unpack([]byte{0}, 0, 5)
	if err == nil {
		t.Error("SSHFP.Unpack should fail with < 2 bytes")
	}

	// Fingerprint extends past buffer
	_, err = rdata.Unpack([]byte{1, 2, 0xAA}, 0, 5) // rdlength=5, but only 3 bytes available
	if err == nil {
		t.Error("SSHFP.Unpack should fail when fingerprint extends past buffer")
	}
}

// ============================================================================
// RDataTLSA Unpack buffer too small (86.7%)
// ============================================================================

func TestRDataTLSAUnpackBufferTooSmall(t *testing.T) {
	rdata := &RDataTLSA{}
	// Need at least 3 bytes for fixed fields
	_, err := rdata.Unpack([]byte{0, 0}, 0, 5)
	if err == nil {
		t.Error("TLSA.Unpack should fail with < 3 bytes")
	}

	// Certificate extends past buffer
	_, err = rdata.Unpack([]byte{1, 2, 3, 0xAA}, 0, 5) // rdlength=5, but only 4 bytes available
	if err == nil {
		t.Error("TLSA.Unpack should fail when certificate extends past buffer")
	}
}

// ============================================================================
// RDataNAPTR Unpack - cover more truncated scenarios (89.7%)
// ============================================================================

func TestRDataNAPTRUnpackTruncatedFlagsData(t *testing.T) {
	rdata := &RDataNAPTR{}
	// flagsLen = 5 but only 1 byte available
	data := []byte{0, 1, 0, 2, 5, 'h'}
	_, err := rdata.Unpack(data, 0, 6)
	if err == nil {
		t.Error("NAPTR.Unpack should fail when flags data extends past buffer")
	}

	// Service data extends past buffer
	data2 := []byte{0, 1, 0, 2, 1, 'U', 5, 'S'}
	_, err = rdata.Unpack(data2, 0, 8)
	if err == nil {
		t.Error("NAPTR.Unpack should fail when service data extends past buffer")
	}

	// Regexp data extends past buffer
	data3 := []byte{0, 1, 0, 2, 1, 'U', 1, 'S', 5, 'R'}
	_, err = rdata.Unpack(data3, 0, 10)
	if err == nil {
		t.Error("NAPTR.Unpack should fail when regexp data extends past buffer")
	}
}

// ============================================================================
// RDataNAPTR Pack buffer too small at preference (87.8%)
// ============================================================================

func TestRDataNAPTRPackBufferTooSmallPreference(t *testing.T) {
	target, _ := ParseName("sip.example.com.")
	rdata := &RDataNAPTR{Order: 1, Preference: 2, Replacement: target}
	buf := make([]byte, 1) // Only 1 byte, need 2 for Order
	_, err := rdata.Pack(buf, 0)
	if err == nil {
		t.Error("NAPTR.Pack should fail at Order with buf size 1")
	}

	// Preference needs 2 more bytes (offset 2)
	_, err = rdata.Pack(make([]byte, 2), 0)
	if err == nil {
		t.Error("NAPTR.Pack should fail at Preference with buf size 2")
	}

	// Flags length needs 1 more byte (offset 4)
	_, err = rdata.Pack(make([]byte, 3), 0)
	if err == nil {
		t.Error("NAPTR.Pack should fail at Preference with buf size 3")
	}

	// Flags data doesn't fit
	rdata2 := &RDataNAPTR{Order: 1, Preference: 2, Flags: "UUUU", Replacement: target}
	_, err = rdata2.Pack(make([]byte, 6), 0)
	if err == nil {
		t.Error("NAPTR.Pack should fail when flags data doesn't fit")
	}

	// Service data doesn't fit
	rdata3 := &RDataNAPTR{Order: 1, Preference: 2, Flags: "U", Service: "SSSS", Replacement: target}
	_, err = rdata3.Pack(make([]byte, 10), 0)
	if err == nil {
		t.Error("NAPTR.Pack should fail when service data doesn't fit")
	}

	// Regexp data doesn't fit
	rdata4 := &RDataNAPTR{Order: 1, Preference: 2, Flags: "U", Service: "SIP", Regexp: "RRRR", Replacement: target}
	_, err = rdata4.Pack(make([]byte, 15), 0)
	if err == nil {
		t.Error("NAPTR.Pack should fail when regexp data doesn't fit")
	}
}

// ============================================================================
// RDataSOA Pack - cover the offset+20 > len(buf) branch (90.9%)
// ============================================================================

func TestRDataSOAPackFixedFieldsTooSmall(t *testing.T) {
	mname, _ := ParseName("ns1.example.com.")
	rname, _ := ParseName("admin.example.com.")
	rdata := &RDataSOA{
		MName:  mname,
		RName:  rname,
		Serial: 1, Refresh: 2, Retry: 3, Expire: 4, Minimum: 5,
	}
	// Pack the names first to find where fixed fields start
	buf := make([]byte, 512)
	n, _ := rdata.Pack(buf, 0)
	// Now create a buffer that fits the names but not the fixed fields
	truncBuf := make([]byte, n-10) // Remove 10 bytes so fixed fields don't fit
	_, err := rdata.Pack(truncBuf, 0)
	if err == nil {
		t.Error("SOA.Pack should fail when buffer too small for fixed fields")
	}
}

// ============================================================================
// WireNameLength with buffer overflow (85.0%)
// ============================================================================

func TestWireNameLengthBufferOverflow(t *testing.T) {
	// Label that would extend past the buffer
	data := []byte{5, 'h', 'e', 'l', 'l', 'o'} // length=5 but no terminator
	_, err := WireNameLength(data, 0)
	if err == nil {
		t.Error("WireNameLength should fail when label extends past buffer")
	}

	// Pointer extends past buffer (only 1 byte)
	data2 := []byte{0xC0}
	_, err = WireNameLength(data2, 0)
	if err == nil {
		t.Error("WireNameLength should fail when pointer extends past buffer")
	}
}

// ============================================================================
// ValidateMessage - cover the "record count too high" branch (90.0%)
// ============================================================================

// Note: the maxRecords check uses 65535 which is the uint16 max,
// so it can never actually trigger. But let's verify the happy path
// works with max counts.
func TestValidateMessageMaxCounts(t *testing.T) {
	header := make([]byte, 12)
	// Set all counts to max uint16 values — should be rejected by new stricter limits
	header[4] = 0xFF
	header[5] = 0xFF
	header[6] = 0xFF
	header[7] = 0xFF
	header[8] = 0xFF
	header[9] = 0xFF
	header[10] = 0xFF
	header[11] = 0xFF
	if err := ValidateMessage(header); err == nil {
		t.Error("ValidateMessage should reject max uint16 counts")
	}
}

// ValidateMessage should pass with reasonable counts.
func TestValidateMessageReasonableCounts(t *testing.T) {
	header := make([]byte, 12)
	// Set reasonable counts: 1 question, 2 answers, 1 authority, 3 additionals
	header[4] = 0x00
	header[5] = 0x01
	header[6] = 0x00
	header[7] = 0x02
	header[8] = 0x00
	header[9] = 0x01
	header[10] = 0x00
	header[11] = 0x03
	if err := ValidateMessage(header); err != nil {
		t.Errorf("ValidateMessage should pass with reasonable counts: %v", err)
	}
}

// ============================================================================
// RDataOPT Unpack - cover endOffset > len(buf) branch (89.5%)
// ============================================================================

func TestRDataOPTUnpackEndOffsetPastBuf(t *testing.T) {
	opt := &RDataOPT{}
	// rdlength > actual buffer - should hit endOffset > len(buf)
	_, err := opt.Unpack([]byte{0}, 0, 10)
	if err == nil {
		t.Error("RDataOPT.Unpack should fail when endOffset > len(buf)")
	}
}

// ============================================================================
// RDataCNAME Copy with nil (cover nil branch)
// ============================================================================

func TestRDataCNAMECopyNil(t *testing.T) {
	rdata := &RDataCNAME{CName: nil}
	cpy := rdata.Copy().(*RDataCNAME)
	if cpy.CName != nil {
		t.Error("CNAME.Copy with nil CName should produce nil CName")
	}
}

// ============================================================================
// RDataNS Copy with nil
// ============================================================================

func TestRDataNSCopyNil(t *testing.T) {
	rdata := &RDataNS{NSDName: nil}
	cpy := rdata.Copy().(*RDataNS)
	if cpy.NSDName != nil {
		t.Error("NS.Copy with nil NSDName should produce nil NSDName")
	}
}

// ============================================================================
// RDataPTR Copy with nil
// ============================================================================

func TestRDataPTRCopyNil(t *testing.T) {
	rdata := &RDataPTR{PtrDName: nil}
	cpy := rdata.Copy().(*RDataPTR)
	if cpy.PtrDName != nil {
		t.Error("PTR.Copy with nil PtrDName should produce nil PtrDName")
	}
}

// ============================================================================
// RDataMX Copy with nil Exchange
// ============================================================================

func TestRDataMXCopyNilExchange(t *testing.T) {
	rdata := &RDataMX{Preference: 10, Exchange: nil}
	cpy := rdata.Copy().(*RDataMX)
	if cpy.Exchange != nil {
		t.Error("MX.Copy with nil Exchange should produce nil Exchange")
	}
	if cpy.Preference != 10 {
		t.Errorf("MX.Copy preference = %d, want 10", cpy.Preference)
	}
}

// ============================================================================
// RDataSOA Copy with nil names
// ============================================================================

func TestRDataSOACopyNilNames(t *testing.T) {
	rdata := &RDataSOA{
		MName:   nil,
		RName:   nil,
		Serial:  1,
		Refresh: 2,
		Retry:   3,
		Expire:  4,
		Minimum: 5,
	}
	cpy := rdata.Copy().(*RDataSOA)
	if cpy.MName != nil || cpy.RName != nil {
		t.Error("SOA.Copy with nil names should produce nil names")
	}
	if cpy.Serial != 1 {
		t.Errorf("SOA.Copy serial = %d, want 1", cpy.Serial)
	}
}

// ============================================================================
// RDataSRV Copy with nil Target
// ============================================================================

func TestRDataSRVCopyNilTarget(t *testing.T) {
	rdata := &RDataSRV{Priority: 10, Weight: 20, Port: 80, Target: nil}
	cpy := rdata.Copy().(*RDataSRV)
	if cpy.Target != nil {
		t.Error("SRV.Copy with nil Target should produce nil Target")
	}
}

// ============================================================================
// RDataNAPTR Copy with nil Replacement
// ============================================================================

func TestRDataNAPTRCopyNilReplacement(t *testing.T) {
	rdata := &RDataNAPTR{Order: 1, Preference: 2, Replacement: nil}
	cpy := rdata.Copy().(*RDataNAPTR)
	if cpy.Replacement != nil {
		t.Error("NAPTR.Copy with nil Replacement should produce nil Replacement")
	}
}

// ============================================================================
// Message.Copy with all sections (80.0%)
// ============================================================================

func TestMessageCopyAllSections(t *testing.T) {
	name, _ := ParseName("example.com.")
	msg := NewMessage(Header{ID: 0x1234, Flags: NewResponseFlags(RcodeSuccess)})
	msg.AddQuestion(&Question{Name: name, QType: TypeA, QClass: ClassIN})
	msg.AddAnswer(&ResourceRecord{Name: name, Type: TypeA, Class: ClassIN, TTL: 300,
		Data: &RDataA{Address: [4]byte{1, 2, 3, 4}}})
	msg.AddAuthority(&ResourceRecord{Name: name, Type: TypeNS, Class: ClassIN, TTL: 3600,
		Data: &RDataNS{NSDName: name}})
	msg.AddAdditional(&ResourceRecord{Name: name, Type: TypeA, Class: ClassIN, TTL: 60,
		Data: &RDataA{Address: [4]byte{5, 6, 7, 8}}})

	cpy := msg.Copy()

	// Verify copy is independent
	if len(cpy.Questions) != 1 {
		t.Errorf("Copy Questions = %d, want 1", len(cpy.Questions))
	}
	if len(cpy.Answers) != 1 {
		t.Errorf("Copy Answers = %d, want 1", len(cpy.Answers))
	}
	if len(cpy.Authorities) != 1 {
		t.Errorf("Copy Authorities = %d, want 1", len(cpy.Authorities))
	}
	if len(cpy.Additionals) != 1 {
		t.Errorf("Copy Additionals = %d, want 1", len(cpy.Additionals))
	}

	// Modify original and verify copy is unchanged
	msg.Answers[0].TTL = 999
	if cpy.Answers[0].TTL == 999 {
		t.Error("Copy should be independent of original")
	}
}

// ============================================================================
// NewQuery with invalid name (83.3%)
// ============================================================================

func TestNewQueryInvalidName(t *testing.T) {
	_, err := NewQuery(1234, "test\x00invalid", TypeA)
	if err == nil {
		t.Error("NewQuery should fail with invalid name")
	}
}

// ============================================================================
// RDataRRSIG Unpack - cover buffer too small for fixed fields (87.5%)
// ============================================================================

func TestRDataRRSIGUnpackBufferTooSmall(t *testing.T) {
	rdata := &RDataRRSIG{}
	// Need at least 18 bytes for fixed fields
	_, err := rdata.Unpack(make([]byte, 17), 0, 17)
	if err == nil {
		t.Error("RRSIG.Unpack should fail with < 18 bytes for fixed fields")
	}
}

// ============================================================================
// RDataDNSKEY Unpack - endOffset > len(buf) (88.2%)
// ============================================================================

func TestRDataDNSKEYUnpackEndOffsetPastBuf(t *testing.T) {
	rdata := &RDataDNSKEY{}
	// Provide 4 bytes of header but rdlength says there's more
	_, err := rdata.Unpack([]byte{0, 1, 3, 8}, 0, 10)
	if err == nil {
		t.Error("DNSKEY.Unpack should fail when endOffset > len(buf)")
	}
}

// ============================================================================
// RDataDS Unpack - endOffset > len(buf) (88.2%)
// ============================================================================

func TestRDataDSUnpackEndOffsetPastBuf(t *testing.T) {
	rdata := &RDataDS{}
	// Provide 4 bytes of header but rdlength says there's more
	_, err := rdata.Unpack([]byte{0, 1, 8, 2}, 0, 10)
	if err == nil {
		t.Error("DS.Unpack should fail when endOffset > len(buf)")
	}
}

// ============================================================================
// CalculateDSDigest - cover the "parsing owner name" error path (86.4%)
// ============================================================================

func TestCalculateDSDigestInvalidOwnerName(t *testing.T) {
	dnskey := &RDataDNSKEY{
		Flags:     DNSKEYFlagZone,
		Protocol:  3,
		Algorithm: AlgorithmRSASHA256,
		PublicKey: []byte{0x01, 0x02, 0x03, 0x04},
	}
	_, err := CalculateDSDigest("invalid\x00name", dnskey, 2)
	if err == nil {
		t.Error("CalculateDSDigest should fail with invalid owner name")
	}
}

// ============================================================================
// RDataRRSIG Len with nil SignerName
// ============================================================================

func TestRDataRRSIGLenNilSignerName(t *testing.T) {
	rdata := &RDataRRSIG{
		SignerName: nil,
		Signature:  []byte{1, 2, 3},
	}
	expected := 18 + 1 + 3 // 18 fixed + 1 for nil signer + 3 for signature
	if l := rdata.Len(); l != expected {
		t.Errorf("RRSIG.Len with nil SignerName = %d, want %d", l, expected)
	}
}

// ============================================================================
// Header Pack with buffer exactly HeaderLen (95.0% -> higher)
// ============================================================================

func TestHeaderPackExactSize(t *testing.T) {
	h := Header{
		ID:      0xABCD,
		Flags:   NewQueryFlags(),
		QDCount: 1,
		ANCount: 2,
		NSCount: 3,
		ARCount: 4,
	}
	buf := make([]byte, HeaderLen)
	err := h.Pack(buf)
	if err != nil {
		t.Fatalf("Header.Pack with exact size should succeed: %v", err)
	}
}

// ============================================================================
// NSEC String with nil NextDomain
// ============================================================================

func TestRDataNSECStringNilNextDomain(t *testing.T) {
	rdata := &RDataNSEC{NextDomain: nil, TypeBitMap: []uint16{TypeA}}
	s := rdata.String()
	if !strings.Contains(s, ".") {
		t.Errorf("NSEC.String with nil NextDomain should contain '.', got %q", s)
	}
}

// ============================================================================
// NSEC3 String with empty salt
// ============================================================================

func TestRDataNSEC3StringEmptySalt(t *testing.T) {
	rdata := &RDataNSEC3{
		HashAlgorithm: NSEC3HashSHA1,
		Flags:         0,
		Iterations:    0,
		Salt:          []byte{},
		NextHashed:    []byte{0x01},
		TypeBitMap:    nil,
	}
	s := rdata.String()
	if !strings.Contains(s, "-") {
		t.Errorf("NSEC3.String with empty salt should contain '-', got %q", s)
	}
}

// ============================================================================
// NSEC3PARAM String with empty salt
// ============================================================================

func TestRDataNSEC3PARAMStringEmptySalt(t *testing.T) {
	rdata := &RDataNSEC3PARAM{
		HashAlgorithm: NSEC3HashSHA1,
		Flags:         0,
		Iterations:    10,
		Salt:          []byte{},
	}
	s := rdata.String()
	if !strings.Contains(s, "-") {
		t.Errorf("NSEC3PARAM.String with empty salt should contain '-', got %q", s)
	}
}

// ============================================================================
// RDataSRV Pack buffer too small for fixed fields
// ============================================================================

func TestRDataSRVPackFixedFieldsTooSmall(t *testing.T) {
	target, _ := ParseName("target.example.com.")
	rdata := &RDataSRV{Priority: 10, Weight: 20, Port: 80, Target: target}

	// Only 5 bytes, need 6 for Priority+Weight+Port
	_, err := rdata.Pack(make([]byte, 5), 0)
	if err == nil {
		t.Error("SRV.Pack should fail with buffer too small for fixed fields")
	}
}

// ============================================================================
// Labels ValidateLabel - cover hyphen at end case
// ============================================================================

func TestValidateLabelHyphenAtEnd(t *testing.T) {
	err := ValidateLabel("test-")
	if err == nil {
		t.Error("ValidateLabel should fail with hyphen at end")
	}
}

// ============================================================================
// EDNS0ClientSubnet with sourceBits = 0
// ============================================================================

func TestNewEDNS0ClientSubnetZeroBits(t *testing.T) {
	ip := net.ParseIP("192.168.1.1")
	ecs := NewEDNS0ClientSubnet(ip, 0)
	if ecs.Family != 1 {
		t.Errorf("Family = %d, want 1", ecs.Family)
	}
	if len(ecs.Address) != 0 {
		t.Errorf("Address length = %d, want 0 for 0-bit prefix", len(ecs.Address))
	}
}
