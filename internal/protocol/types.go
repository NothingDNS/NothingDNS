package protocol

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ============================================================================
// A Record (IPv4 Address) - RFC 1035
// ============================================================================

// RDataA represents an IPv4 address record.
type RDataA struct {
	Address [4]byte
}

// Type returns TypeA.
func (r *RDataA) Type() uint16 { return TypeA }

// Pack serializes the A record.
func (r *RDataA) Pack(buf []byte, offset int) (int, error) {
	if offset+4 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	copy(buf[offset:], r.Address[:])
	return 4, nil
}

// Unpack deserializes the A record.
func (r *RDataA) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if rdlength != 4 {
		return 0, fmt.Errorf("invalid A record length: %d", rdlength)
	}
	if offset+4 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	copy(r.Address[:], buf[offset:offset+4])
	return 4, nil
}

// String returns the IPv4 address as a string.
func (r *RDataA) String() string {
	return net.IP(r.Address[:]).String()
}

// Len returns 4.
func (r *RDataA) Len() int { return 4 }

// Copy creates a copy.
func (r *RDataA) Copy() RData {
	return &RDataA{Address: r.Address}
}

// IP returns the address as net.IP.
func (r *RDataA) IP() net.IP {
	return net.IP(r.Address[:])
}

// SetIP sets the address from net.IP.
func (r *RDataA) SetIP(ip net.IP) {
	if v4 := ip.To4(); v4 != nil {
		copy(r.Address[:], v4)
	}
}

// ============================================================================
// AAAA Record (IPv6 Address) - RFC 3596
// ============================================================================

// RDataAAAA represents an IPv6 address record.
type RDataAAAA struct {
	Address [16]byte
}

// Type returns TypeAAAA.
func (r *RDataAAAA) Type() uint16 { return TypeAAAA }

// Pack serializes the AAAA record.
func (r *RDataAAAA) Pack(buf []byte, offset int) (int, error) {
	if offset+16 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	copy(buf[offset:], r.Address[:])
	return 16, nil
}

// Unpack deserializes the AAAA record.
func (r *RDataAAAA) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if rdlength != 16 {
		return 0, fmt.Errorf("invalid AAAA record length: %d", rdlength)
	}
	if offset+16 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	copy(r.Address[:], buf[offset:offset+16])
	return 16, nil
}

// String returns the IPv6 address as a string.
func (r *RDataAAAA) String() string {
	return net.IP(r.Address[:]).String()
}

// Len returns 16.
func (r *RDataAAAA) Len() int { return 16 }

// Copy creates a copy.
func (r *RDataAAAA) Copy() RData {
	return &RDataAAAA{Address: r.Address}
}

// IP returns the address as net.IP.
func (r *RDataAAAA) IP() net.IP {
	return net.IP(r.Address[:])
}

// SetIP sets the address from net.IP.
func (r *RDataAAAA) SetIP(ip net.IP) {
	if v6 := ip.To16(); v6 != nil {
		copy(r.Address[:], v6)
	}
}

// ============================================================================
// CNAME Record (Canonical Name) - RFC 1035
// ============================================================================

// RDataCNAME represents a CNAME record.
type RDataCNAME struct {
	CName *Name
}

// Type returns TypeCNAME.
func (r *RDataCNAME) Type() uint16 { return TypeCNAME }

// Pack serializes the CNAME record.
func (r *RDataCNAME) Pack(buf []byte, offset int) (int, error) {
	return PackName(r.CName, buf, offset, nil)
}

// Unpack deserializes the CNAME record.
func (r *RDataCNAME) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	name, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, err
	}
	r.CName = name
	return n, nil
}

// String returns the canonical name.
func (r *RDataCNAME) String() string {
	if r.CName == nil {
		return "."
	}
	return r.CName.String()
}

// Len returns the wire length.
func (r *RDataCNAME) Len() int {
	if r.CName == nil {
		return 1
	}
	return r.CName.WireLength()
}

// Copy creates a copy.
func (r *RDataCNAME) Copy() RData {
	var cname *Name
	if r.CName != nil {
		cname = NewName(r.CName.Labels, r.CName.FQDN)
	}
	return &RDataCNAME{CName: cname}
}

// ============================================================================
// NS Record (Name Server) - RFC 1035
// ============================================================================

// RDataNS represents an NS record.
type RDataNS struct {
	NSDName *Name
}

// Type returns TypeNS.
func (r *RDataNS) Type() uint16 { return TypeNS }

// Pack serializes the NS record.
func (r *RDataNS) Pack(buf []byte, offset int) (int, error) {
	return PackName(r.NSDName, buf, offset, nil)
}

// Unpack deserializes the NS record.
func (r *RDataNS) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	name, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, err
	}
	r.NSDName = name
	return n, nil
}

// String returns the NS domain name.
func (r *RDataNS) String() string {
	if r.NSDName == nil {
		return "."
	}
	return r.NSDName.String()
}

// Len returns the wire length.
func (r *RDataNS) Len() int {
	if r.NSDName == nil {
		return 1
	}
	return r.NSDName.WireLength()
}

// Copy creates a copy.
func (r *RDataNS) Copy() RData {
	var nsdname *Name
	if r.NSDName != nil {
		nsdname = NewName(r.NSDName.Labels, r.NSDName.FQDN)
	}
	return &RDataNS{NSDName: nsdname}
}

// ============================================================================
// PTR Record (Pointer) - RFC 1035
// ============================================================================

// RDataPTR represents a PTR record.
type RDataPTR struct {
	PtrDName *Name
}

// Type returns TypePTR.
func (r *RDataPTR) Type() uint16 { return TypePTR }

// Pack serializes the PTR record.
func (r *RDataPTR) Pack(buf []byte, offset int) (int, error) {
	return PackName(r.PtrDName, buf, offset, nil)
}

// Unpack deserializes the PTR record.
func (r *RDataPTR) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	name, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, err
	}
	r.PtrDName = name
	return n, nil
}

// String returns the PTR domain name.
func (r *RDataPTR) String() string {
	if r.PtrDName == nil {
		return "."
	}
	return r.PtrDName.String()
}

// Len returns the wire length.
func (r *RDataPTR) Len() int {
	if r.PtrDName == nil {
		return 1
	}
	return r.PtrDName.WireLength()
}

// Copy creates a copy.
func (r *RDataPTR) Copy() RData {
	var ptrdname *Name
	if r.PtrDName != nil {
		ptrdname = NewName(r.PtrDName.Labels, r.PtrDName.FQDN)
	}
	return &RDataPTR{PtrDName: ptrdname}
}

// ============================================================================
// MX Record (Mail Exchange) - RFC 1035
// ============================================================================

// RDataMX represents an MX record.
type RDataMX struct {
	Preference uint16
	Exchange   *Name
}

// Type returns TypeMX.
func (r *RDataMX) Type() uint16 { return TypeMX }

// Pack serializes the MX record.
func (r *RDataMX) Pack(buf []byte, offset int) (int, error) {
	startOffset := offset

	// Preference (2 bytes)
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	PutUint16(buf[offset:], r.Preference)
	offset += 2

	// Exchange name
	n, err := PackName(r.Exchange, buf, offset, nil)
	if err != nil {
		return 0, err
	}
	offset += n

	return offset - startOffset, nil
}

// Unpack deserializes the MX record.
func (r *RDataMX) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	startOffset := offset

	// Preference
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	r.Preference = Uint16(buf[offset:])
	offset += 2

	// Exchange name
	name, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, err
	}
	r.Exchange = name
	offset += n

	return offset - startOffset, nil
}

// String returns the MX record data.
func (r *RDataMX) String() string {
	exchange := "."
	if r.Exchange != nil {
		exchange = r.Exchange.String()
	}
	return fmt.Sprintf("%d %s", r.Preference, exchange)
}

// Len returns the wire length.
func (r *RDataMX) Len() int {
	if r.Exchange == nil {
		return 3
	}
	return 2 + r.Exchange.WireLength()
}

// Copy creates a copy.
func (r *RDataMX) Copy() RData {
	var exchange *Name
	if r.Exchange != nil {
		exchange = NewName(r.Exchange.Labels, r.Exchange.FQDN)
	}
	return &RDataMX{
		Preference: r.Preference,
		Exchange:   exchange,
	}
}

// ============================================================================
// TXT Record (Text) - RFC 1035
// ============================================================================

// RDataTXT represents a TXT record.
type RDataTXT struct {
	Strings []string
}

// Type returns TypeTXT.
func (r *RDataTXT) Type() uint16 { return TypeTXT }

// Pack serializes the TXT record.
func (r *RDataTXT) Pack(buf []byte, offset int) (int, error) {
	startOffset := offset

	for _, s := range r.Strings {
		slen := len(s)
		if slen > 255 {
			return 0, ErrLabelTooLong
		}
		if offset+1+slen > len(buf) {
			return 0, ErrBufferTooSmall
		}
		buf[offset] = byte(slen)
		offset++
		copy(buf[offset:], s)
		offset += slen
	}

	return offset - startOffset, nil
}

// Unpack deserializes the TXT record.
func (r *RDataTXT) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	startOffset := offset
	endOffset := offset + int(rdlength)

	if endOffset > len(buf) {
		return 0, ErrBufferTooSmall
	}

	for offset < endOffset {
		if offset >= len(buf) {
			return 0, ErrBufferTooSmall
		}
		slen := int(buf[offset])
		offset++

		if offset+slen > len(buf) {
			return 0, ErrBufferTooSmall
		}
		r.Strings = append(r.Strings, string(buf[offset:offset+slen]))
		offset += slen
	}

	return offset - startOffset, nil
}

// String returns the TXT record data.
func (r *RDataTXT) String() string {
	var parts []string
	for _, s := range r.Strings {
		// Quote strings that contain spaces or special chars
		if strings.ContainsAny(s, " \t\n\r\"") {
			s = strconv.Quote(s)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}

// Len returns the wire length.
func (r *RDataTXT) Len() int {
	length := 0
	for _, s := range r.Strings {
		length += 1 + len(s)
	}
	return length
}

// Copy creates a copy.
func (r *RDataTXT) Copy() RData {
	strings := make([]string, len(r.Strings))
	copy(strings, r.Strings)
	return &RDataTXT{Strings: strings}
}

// ============================================================================
// SOA Record (Start of Authority) - RFC 1035
// ============================================================================

// RDataSOA represents an SOA record.
type RDataSOA struct {
	MName   *Name  // Primary master name server
	RName   *Name  // Responsible authority's mailbox
	Serial  uint32 // Serial number
	Refresh uint32 // Refresh interval
	Retry   uint32 // Retry interval
	Expire  uint32 // Expire limit
	Minimum uint32 // Minimum TTL
}

// Type returns TypeSOA.
func (r *RDataSOA) Type() uint16 { return TypeSOA }

// Pack serializes the SOA record.
func (r *RDataSOA) Pack(buf []byte, offset int) (int, error) {
	startOffset := offset

	// MName
	n, err := PackName(r.MName, buf, offset, nil)
	if err != nil {
		return 0, err
	}
	offset += n

	// RName
	n, err = PackName(r.RName, buf, offset, nil)
	if err != nil {
		return 0, err
	}
	offset += n

	// Check space for fixed fields
	if offset+20 > len(buf) {
		return 0, ErrBufferTooSmall
	}

	// Serial, Refresh, Retry, Expire, Minimum (5 x 4 bytes = 20 bytes)
	PutUint32(buf[offset:], r.Serial)
	offset += 4
	PutUint32(buf[offset:], r.Refresh)
	offset += 4
	PutUint32(buf[offset:], r.Retry)
	offset += 4
	PutUint32(buf[offset:], r.Expire)
	offset += 4
	PutUint32(buf[offset:], r.Minimum)
	offset += 4

	return offset - startOffset, nil
}

// Unpack deserializes the SOA record.
func (r *RDataSOA) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	startOffset := offset

	// MName
	mname, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, err
	}
	r.MName = mname
	offset += n

	// RName
	rname, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, err
	}
	r.RName = rname
	offset += n

	// Check space for fixed fields
	if offset+20 > len(buf) {
		return 0, ErrBufferTooSmall
	}

	// Serial, Refresh, Retry, Expire, Minimum
	r.Serial = Uint32(buf[offset:])
	offset += 4
	r.Refresh = Uint32(buf[offset:])
	offset += 4
	r.Retry = Uint32(buf[offset:])
	offset += 4
	r.Expire = Uint32(buf[offset:])
	offset += 4
	r.Minimum = Uint32(buf[offset:])
	offset += 4

	return offset - startOffset, nil
}

// String returns the SOA record data.
func (r *RDataSOA) String() string {
	mname := "."
	rname := "."
	if r.MName != nil {
		mname = r.MName.String()
	}
	if r.RName != nil {
		rname = r.RName.String()
	}
	return fmt.Sprintf("%s %s %d %d %d %d %d",
		mname, rname, r.Serial, r.Refresh, r.Retry, r.Expire, r.Minimum,
	)
}

// Len returns the wire length.
func (r *RDataSOA) Len() int {
	mnameLen := 1
	rnameLen := 1
	if r.MName != nil {
		mnameLen = r.MName.WireLength()
	}
	if r.RName != nil {
		rnameLen = r.RName.WireLength()
	}
	return mnameLen + rnameLen + 20
}

// Copy creates a copy.
func (r *RDataSOA) Copy() RData {
	var mname, rname *Name
	if r.MName != nil {
		mname = NewName(r.MName.Labels, r.MName.FQDN)
	}
	if r.RName != nil {
		rname = NewName(r.RName.Labels, r.RName.FQDN)
	}
	return &RDataSOA{
		MName:   mname,
		RName:   rname,
		Serial:  r.Serial,
		Refresh: r.Refresh,
		Retry:   r.Retry,
		Expire:  r.Expire,
		Minimum: r.Minimum,
	}
}

// ============================================================================
// SRV Record (Service Locator) - RFC 2782
// ============================================================================

// RDataSRV represents an SRV record.
type RDataSRV struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   *Name
}

// Type returns TypeSRV.
func (r *RDataSRV) Type() uint16 { return TypeSRV }

// Pack serializes the SRV record.
func (r *RDataSRV) Pack(buf []byte, offset int) (int, error) {
	startOffset := offset

	// Priority, Weight, Port
	if offset+6 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	PutUint16(buf[offset:], r.Priority)
	offset += 2
	PutUint16(buf[offset:], r.Weight)
	offset += 2
	PutUint16(buf[offset:], r.Port)
	offset += 2

	// Target
	n, err := PackName(r.Target, buf, offset, nil)
	if err != nil {
		return 0, err
	}
	offset += n

	return offset - startOffset, nil
}

// Unpack deserializes the SRV record.
func (r *RDataSRV) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	startOffset := offset

	// Priority, Weight, Port
	if offset+6 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	r.Priority = Uint16(buf[offset:])
	offset += 2
	r.Weight = Uint16(buf[offset:])
	offset += 2
	r.Port = Uint16(buf[offset:])
	offset += 2

	// Target
	target, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, err
	}
	r.Target = target
	offset += n

	return offset - startOffset, nil
}

// String returns the SRV record data.
func (r *RDataSRV) String() string {
	target := "."
	if r.Target != nil {
		target = r.Target.String()
	}
	return fmt.Sprintf("%d %d %d %s", r.Priority, r.Weight, r.Port, target)
}

// Len returns the wire length.
func (r *RDataSRV) Len() int {
	if r.Target == nil {
		return 7
	}
	return 6 + r.Target.WireLength()
}

// Copy creates a copy.
func (r *RDataSRV) Copy() RData {
	var target *Name
	if r.Target != nil {
		target = NewName(r.Target.Labels, r.Target.FQDN)
	}
	return &RDataSRV{
		Priority: r.Priority,
		Weight:   r.Weight,
		Port:     r.Port,
		Target:   target,
	}
}

// ============================================================================
// CAA Record (Certification Authority Authorization) - RFC 8659
// ============================================================================

// RDataCAA represents a CAA record.
type RDataCAA struct {
	Flags uint8
	Tag   string
	Value string
}

// Type returns TypeCAA.
func (r *RDataCAA) Type() uint16 { return TypeCAA }

// Pack serializes the CAA record.
func (r *RDataCAA) Pack(buf []byte, offset int) (int, error) {
	startOffset := offset

	// Flags (1 byte)
	if offset+1 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = r.Flags
	offset++

	// Tag length and Tag
	tagLen := len(r.Tag)
	if tagLen > 255 {
		return 0, ErrLabelTooLong
	}
	if offset+1+tagLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = byte(tagLen)
	offset++
	copy(buf[offset:], r.Tag)
	offset += tagLen

	// Value
	valueLen := len(r.Value)
	if offset+valueLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	copy(buf[offset:], r.Value)
	offset += valueLen

	return offset - startOffset, nil
}

// Unpack deserializes the CAA record.
func (r *RDataCAA) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	startOffset := offset
	endOffset := offset + int(rdlength)

	if endOffset > len(buf) {
		return 0, ErrBufferTooSmall
	}

	// Need at least 2 bytes: flags + tag length
	if offset+2 > endOffset {
		return 0, ErrBufferTooSmall
	}

	// Flags
	r.Flags = buf[offset]
	offset++

	// Tag length and Tag
	tagLen := int(buf[offset])
	offset++

	if offset+tagLen > endOffset {
		return 0, ErrBufferTooSmall
	}
	r.Tag = string(buf[offset : offset+tagLen])
	offset += tagLen

	// Value (remaining bytes)
	r.Value = string(buf[offset:endOffset])
	offset = endOffset

	return offset - startOffset, nil
}

// String returns the CAA record data.
func (r *RDataCAA) String() string {
	return fmt.Sprintf("%d %s \"%s\"", r.Flags, r.Tag, r.Value)
}

// Len returns the wire length.
func (r *RDataCAA) Len() int { return 1 + 1 + len(r.Tag) + len(r.Value) }

// Copy creates a copy.
func (r *RDataCAA) Copy() RData {
	return &RDataCAA{Flags: r.Flags, Tag: r.Tag, Value: r.Value}
}

// ============================================================================
// SSHFP Record (SSH Key Fingerprint) - RFC 4255
// ============================================================================

// RDataSSHFP represents an SSHFP record.
type RDataSSHFP struct {
	Algorithm   uint8
	FPType      uint8
	Fingerprint []byte
}

// Type returns TypeSSHFP.
func (r *RDataSSHFP) Type() uint16 { return TypeSSHFP }

// Pack serializes the SSHFP record.
func (r *RDataSSHFP) Pack(buf []byte, offset int) (int, error) {
	length := 2 + len(r.Fingerprint)
	if offset+length > len(buf) {
		return 0, ErrBufferTooSmall
	}

	buf[offset] = r.Algorithm
	offset++
	buf[offset] = r.FPType
	offset++
	copy(buf[offset:], r.Fingerprint)

	return length, nil
}

// Unpack deserializes the SSHFP record.
func (r *RDataSSHFP) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	r.Algorithm = buf[offset]
	offset++
	r.FPType = buf[offset]
	offset++

	fpLen := int(rdlength) - 2
	if offset+fpLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	r.Fingerprint = make([]byte, fpLen)
	copy(r.Fingerprint, buf[offset:offset+fpLen])
	offset += fpLen

	return offset - (offset - int(rdlength)), nil
}

// String returns the SSHFP record data.
func (r *RDataSSHFP) String() string {
	return fmt.Sprintf("%d %d %s", r.Algorithm, r.FPType, hex.EncodeToString(r.Fingerprint))
}

// Len returns the wire length.
func (r *RDataSSHFP) Len() int { return 2 + len(r.Fingerprint) }

// Copy creates a copy.
func (r *RDataSSHFP) Copy() RData {
	fpCopy := make([]byte, len(r.Fingerprint))
	copy(fpCopy, r.Fingerprint)
	return &RDataSSHFP{Algorithm: r.Algorithm, FPType: r.FPType, Fingerprint: fpCopy}
}

// ============================================================================
// TLSA Record (TLS Authentication) - RFC 6698
// ============================================================================

// RDataTLSA represents a TLSA record.
type RDataTLSA struct {
	Usage        uint8
	Selector     uint8
	MatchingType uint8
	Certificate  []byte
}

// Type returns TypeTLSA.
func (r *RDataTLSA) Type() uint16 { return TypeTLSA }

// Pack serializes the TLSA record.
func (r *RDataTLSA) Pack(buf []byte, offset int) (int, error) {
	length := 3 + len(r.Certificate)
	if offset+length > len(buf) {
		return 0, ErrBufferTooSmall
	}

	buf[offset] = r.Usage
	offset++
	buf[offset] = r.Selector
	offset++
	buf[offset] = r.MatchingType
	offset++
	copy(buf[offset:], r.Certificate)

	return length, nil
}

// Unpack deserializes the TLSA record.
func (r *RDataTLSA) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if offset+3 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	r.Usage = buf[offset]
	offset++
	r.Selector = buf[offset]
	offset++
	r.MatchingType = buf[offset]
	offset++

	certLen := int(rdlength) - 3
	if offset+certLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	r.Certificate = make([]byte, certLen)
	copy(r.Certificate, buf[offset:offset+certLen])
	offset += certLen

	return offset - (offset - int(rdlength)), nil
}

// String returns the TLSA record data.
func (r *RDataTLSA) String() string {
	return fmt.Sprintf("%d %d %d %s", r.Usage, r.Selector, r.MatchingType, hex.EncodeToString(r.Certificate))
}

// Len returns the wire length.
func (r *RDataTLSA) Len() int { return 3 + len(r.Certificate) }

// Copy creates a copy.
func (r *RDataTLSA) Copy() RData {
	certCopy := make([]byte, len(r.Certificate))
	copy(certCopy, r.Certificate)
	return &RDataTLSA{Usage: r.Usage, Selector: r.Selector, MatchingType: r.MatchingType, Certificate: certCopy}
}

// ============================================================================
// NAPTR Record (Naming Authority Pointer) - RFC 3403
// ============================================================================

// RDataNAPTR represents a NAPTR record.
type RDataNAPTR struct {
	Order       uint16
	Preference  uint16
	Flags       string
	Service     string
	Regexp      string
	Replacement *Name
}

// Type returns TypeNAPTR.
func (r *RDataNAPTR) Type() uint16 { return TypeNAPTR }

// Pack serializes the NAPTR record.
func (r *RDataNAPTR) Pack(buf []byte, offset int) (int, error) {
	startOffset := offset

	// Order (2 bytes)
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	PutUint16(buf[offset:], r.Order)
	offset += 2

	// Preference (2 bytes)
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	PutUint16(buf[offset:], r.Preference)
	offset += 2

	// Flags length and Flags
	flagsLen := len(r.Flags)
	if flagsLen > 255 {
		return 0, ErrLabelTooLong
	}
	if offset+1+flagsLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = byte(flagsLen)
	offset++
	copy(buf[offset:], r.Flags)
	offset += flagsLen

	// Service length and Service
	serviceLen := len(r.Service)
	if serviceLen > 255 {
		return 0, ErrLabelTooLong
	}
	if offset+1+serviceLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = byte(serviceLen)
	offset++
	copy(buf[offset:], r.Service)
	offset += serviceLen

	// Regexp length and Regexp
	regexpLen := len(r.Regexp)
	if regexpLen > 255 {
		return 0, ErrLabelTooLong
	}
	if offset+1+regexpLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = byte(regexpLen)
	offset++
	copy(buf[offset:], r.Regexp)
	offset += regexpLen

	// Replacement domain name
	n, err := PackName(r.Replacement, buf, offset, nil)
	if err != nil {
		return 0, err
	}
	offset += n

	return offset - startOffset, nil
}

// Unpack deserializes the NAPTR record.
func (r *RDataNAPTR) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	startOffset := offset

	// Order
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	r.Order = Uint16(buf[offset:])
	offset += 2

	// Preference
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	r.Preference = Uint16(buf[offset:])
	offset += 2

	// Flags
	if offset >= len(buf) {
		return 0, ErrBufferTooSmall
	}
	flagsLen := int(buf[offset])
	offset++
	if offset+flagsLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	r.Flags = string(buf[offset : offset+flagsLen])
	offset += flagsLen

	// Service
	if offset >= len(buf) {
		return 0, ErrBufferTooSmall
	}
	serviceLen := int(buf[offset])
	offset++
	if offset+serviceLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	r.Service = string(buf[offset : offset+serviceLen])
	offset += serviceLen

	// Regexp
	if offset >= len(buf) {
		return 0, ErrBufferTooSmall
	}
	regexpLen := int(buf[offset])
	offset++
	if offset+regexpLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	r.Regexp = string(buf[offset : offset+regexpLen])
	offset += regexpLen

	// Replacement
	replacement, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, err
	}
	r.Replacement = replacement
	offset += n

	return offset - startOffset, nil
}

// String returns the NAPTR record data.
func (r *RDataNAPTR) String() string {
	replacement := "."
	if r.Replacement != nil {
		replacement = r.Replacement.String()
	}
	return fmt.Sprintf("%d %d \"%s\" \"%s\" \"%s\" %s",
		r.Order, r.Preference, r.Flags, r.Service, r.Regexp, replacement)
}

// Len returns the wire length.
func (r *RDataNAPTR) Len() int {
	replacementLen := 0
	if r.Replacement != nil {
		replacementLen = r.Replacement.WireLength()
	}
	return 2 + 2 + 1 + len(r.Flags) + 1 + len(r.Service) + 1 + len(r.Regexp) + replacementLen
}

// Copy creates a copy.
func (r *RDataNAPTR) Copy() RData {
	var replacement *Name
	if r.Replacement != nil {
		replacement = NewName(r.Replacement.Labels, r.Replacement.FQDN)
	}
	return &RDataNAPTR{
		Order:       r.Order,
		Preference:  r.Preference,
		Flags:       r.Flags,
		Service:     r.Service,
		Regexp:      r.Regexp,
		Replacement: replacement,
	}
}
