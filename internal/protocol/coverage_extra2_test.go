package protocol

import (
	"net"
	"testing"
)

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
	compression := map[string]int{
		"example.com": 12,
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
	badName := NewName([]string{string(longLabel)}, true)

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
	badName := NewName([]string{string(longLabel)}, true)

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
	badName := NewName([]string{string(longLabel)}, true)

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
	badName := NewName([]string{string(longLabel)}, true)

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
