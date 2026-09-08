// Package protocol provides DNS protocol types for NothingDNS.
//
// Naming authority types: HINFO, URI, NAPTR, SVCB params.

package protocol

import (
	"fmt"
)

// ============================================================================

// RDataHINFO represents an HINFO record (RFC 1035).
type RDataHINFO struct {
	CPU string
	OS  string
}

// Type returns TypeHINFO.
func (r *RDataHINFO) Type() uint16 { return TypeHINFO }

// Pack serializes the HINFO record.
func (r *RDataHINFO) Pack(buf []byte, offset int) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil HINFO record")
	}
	startOffset := offset
	n, err := packCharacterString(buf, offset, r.CPU)
	if err != nil {
		return 0, err
	}
	offset += n
	n, err = packCharacterString(buf, offset, r.OS)
	if err != nil {
		return 0, err
	}
	offset += n
	return offset - startOffset, nil
}

// Unpack deserializes the HINFO record.
func (r *RDataHINFO) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil HINFO record")
	}
	startOffset := offset
	endOffset := offset + int(rdlength)
	if endOffset > len(buf) {
		return 0, ErrBufferTooSmall
	}

	cpu, n, err := unpackCharacterString(buf, offset, endOffset)
	if err != nil {
		return 0, err
	}
	offset += n
	os, n, err := unpackCharacterString(buf, offset, endOffset)
	if err != nil {
		return 0, err
	}
	offset += n
	if offset != endOffset {
		return 0, fmt.Errorf("HINFO RDATA length mismatch: consumed %d bytes, rdlength %d", offset-startOffset, rdlength)
	}
	r.CPU = cpu
	r.OS = os
	return offset - startOffset, nil
}

// String returns the HINFO record data.
func (r *RDataHINFO) String() string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("%q %q", r.CPU, r.OS)
}

// Len returns the wire length.
func (r *RDataHINFO) Len() int {
	if r == nil {
		return 0
	}
	return 1 + len(r.CPU) + 1 + len(r.OS)
}

// Copy creates a copy.
func (r *RDataHINFO) Copy() RData {
	if r == nil {
		return nil
	}
	return &RDataHINFO{CPU: r.CPU, OS: r.OS}
}

func packCharacterString(buf []byte, offset int, value string) (int, error) {
	valueLen := len(value)
	if valueLen > 255 {
		return 0, ErrLabelTooLong
	}
	if offset+1+valueLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = byte(valueLen)
	copy(buf[offset+1:], value)
	return 1 + valueLen, nil
}

func unpackCharacterString(buf []byte, offset, endOffset int) (string, int, error) {
	if offset >= endOffset {
		return "", 0, ErrBufferTooSmall
	}
	valueLen := int(buf[offset])
	offset++
	if offset+valueLen > endOffset {
		return "", 0, ErrBufferTooSmall
	}
	return string(buf[offset : offset+valueLen]), 1 + valueLen, nil
}

// ============================================================================

// RDataRP represents an RP record (RFC 1183).
type RDataRP struct {
	MBox *Name
	Txt  *Name
}

// Type returns TypeRP.
func (r *RDataRP) Type() uint16 { return TypeRP }

// Pack serializes the RP record.
func (r *RDataRP) Pack(buf []byte, offset int) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil RP record")
	}

	startOffset := offset
	n, err := PackName(r.MBox, buf, offset, nil)
	if err != nil {
		return 0, err
	}
	offset += n
	n, err = PackName(r.Txt, buf, offset, nil)
	if err != nil {
		return 0, err
	}
	offset += n

	return offset - startOffset, nil
}

// Unpack deserializes the RP record.
func (r *RDataRP) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil RP record")
	}

	startOffset := offset
	endOffset := offset + int(rdlength)
	if endOffset > len(buf) {
		return 0, ErrBufferTooSmall
	}

	mbox, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, err
	}
	r.MBox = mbox
	offset += n

	txt, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, err
	}
	r.Txt = txt
	offset += n
	if offset != endOffset {
		txt.Release()
		return 0, fmt.Errorf("RP RDATA length mismatch: consumed %d bytes, rdlength %d", offset-startOffset, rdlength)
	}

	return offset - startOffset, nil
}

// String returns the RP record data.
func (r *RDataRP) String() string {
	if r == nil {
		return ""
	}
	mbox := "."
	if r.MBox != nil {
		mbox = r.MBox.String()
	}
	txt := "."
	if r.Txt != nil {
		txt = r.Txt.String()
	}
	return fmt.Sprintf("%s %s", mbox, txt)
}

// Len returns the wire length.
func (r *RDataRP) Len() int {
	if r == nil {
		return 0
	}
	return r.MBox.WireLength() + r.Txt.WireLength()
}

// Copy creates a copy.
func (r *RDataRP) Copy() RData {
	if r == nil {
		return nil
	}
	var mbox *Name
	if r.MBox != nil {
		mbox = r.MBox.Copy()
	}
	var txt *Name
	if r.Txt != nil {
		txt = r.Txt.Copy()
	}
	return &RDataRP{MBox: mbox, Txt: txt}
}

// ============================================================================

// RDataAFSDB represents an AFSDB record (RFC 1183).
type RDataAFSDB struct {
	Subtype  uint16
	Hostname *Name
}

// Type returns TypeAFSDB.
func (r *RDataAFSDB) Type() uint16 { return TypeAFSDB }

// Pack serializes the AFSDB record.
func (r *RDataAFSDB) Pack(buf []byte, offset int) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil AFSDB record")
	}

	startOffset := offset
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	PutUint16(buf[offset:], r.Subtype)
	offset += 2

	n, err := PackName(r.Hostname, buf, offset, nil)
	if err != nil {
		return 0, err
	}
	offset += n

	return offset - startOffset, nil
}

// Unpack deserializes the AFSDB record.
func (r *RDataAFSDB) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil AFSDB record")
	}

	startOffset := offset
	endOffset := offset + int(rdlength)
	if endOffset > len(buf) {
		return 0, ErrBufferTooSmall
	}
	if offset+2 > endOffset {
		return 0, ErrBufferTooSmall
	}

	r.Subtype = Uint16(buf[offset:])
	offset += 2

	hostname, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, err
	}
	r.Hostname = hostname
	offset += n
	if offset != endOffset {
		hostname.Release()
		return 0, fmt.Errorf("AFSDB RDATA length mismatch: consumed %d bytes, rdlength %d", offset-startOffset, rdlength)
	}

	return offset - startOffset, nil
}

// String returns the AFSDB record data.
func (r *RDataAFSDB) String() string {
	if r == nil {
		return ""
	}
	hostname := "."
	if r.Hostname != nil {
		hostname = r.Hostname.String()
	}
	return fmt.Sprintf("%d %s", r.Subtype, hostname)
}

// Len returns the wire length.
func (r *RDataAFSDB) Len() int {
	if r == nil {
		return 0
	}
	return 2 + r.Hostname.WireLength()
}

// Copy creates a copy.
func (r *RDataAFSDB) Copy() RData {
	if r == nil {
		return nil
	}
	var hostname *Name
	if r.Hostname != nil {
		hostname = r.Hostname.Copy()
	}
	return &RDataAFSDB{Subtype: r.Subtype, Hostname: hostname}
}

// ============================================================================

// RDataKX represents a KX record (RFC 2230).
type RDataKX struct {
	Preference uint16
	Exchanger  *Name
}

// Type returns TypeKX.
func (r *RDataKX) Type() uint16 { return TypeKX }

// Pack serializes the KX record.
func (r *RDataKX) Pack(buf []byte, offset int) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil KX record")
	}

	startOffset := offset
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	PutUint16(buf[offset:], r.Preference)
	offset += 2

	n, err := PackName(r.Exchanger, buf, offset, nil)
	if err != nil {
		return 0, err
	}
	offset += n

	return offset - startOffset, nil
}

// Unpack deserializes the KX record.
func (r *RDataKX) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil KX record")
	}

	startOffset := offset
	endOffset := offset + int(rdlength)
	if endOffset > len(buf) {
		return 0, ErrBufferTooSmall
	}
	if offset+2 > endOffset {
		return 0, ErrBufferTooSmall
	}

	r.Preference = Uint16(buf[offset:])
	offset += 2

	exchanger, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, err
	}
	r.Exchanger = exchanger
	offset += n
	if offset != endOffset {
		exchanger.Release()
		return 0, fmt.Errorf("KX RDATA length mismatch: consumed %d bytes, rdlength %d", offset-startOffset, rdlength)
	}

	return offset - startOffset, nil
}

// String returns the KX record data.
func (r *RDataKX) String() string {
	if r == nil {
		return ""
	}
	exchanger := "."
	if r.Exchanger != nil {
		exchanger = r.Exchanger.String()
	}
	return fmt.Sprintf("%d %s", r.Preference, exchanger)
}

// Len returns the wire length.
func (r *RDataKX) Len() int {
	if r == nil {
		return 0
	}
	return 2 + r.Exchanger.WireLength()
}

// Copy creates a copy.
func (r *RDataKX) Copy() RData {
	if r == nil {
		return nil
	}
	var exchanger *Name
	if r.Exchanger != nil {
		exchanger = r.Exchanger.Copy()
	}
	return &RDataKX{Preference: r.Preference, Exchanger: exchanger}
}

// ============================================================================

// RDataURI represents a URI record (RFC 7553).
type RDataURI struct {
	Priority uint16
	Weight   uint16
	Target   string
}

// Type returns TypeURI.
func (r *RDataURI) Type() uint16 { return TypeURI }

// Pack serializes the URI record.
func (r *RDataURI) Pack(buf []byte, offset int) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil URI record")
	}

	startOffset := offset
	if offset+4 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	PutUint16(buf[offset:], r.Priority)
	offset += 2
	PutUint16(buf[offset:], r.Weight)
	offset += 2

	targetLen := len(r.Target)
	if targetLen > 255 {
		return 0, ErrLabelTooLong
	}
	if offset+1+targetLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = byte(targetLen)
	offset++
	copy(buf[offset:], r.Target)
	offset += targetLen

	return offset - startOffset, nil
}

// Unpack deserializes the URI record.
func (r *RDataURI) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil URI record")
	}

	startOffset := offset
	endOffset := offset + int(rdlength)
	if endOffset > len(buf) {
		return 0, ErrBufferTooSmall
	}
	if offset+5 > endOffset {
		return 0, ErrBufferTooSmall
	}

	r.Priority = Uint16(buf[offset:])
	offset += 2
	r.Weight = Uint16(buf[offset:])
	offset += 2

	targetLen := int(buf[offset])
	offset++
	if offset+targetLen > endOffset {
		return 0, ErrBufferTooSmall
	}
	r.Target = string(buf[offset : offset+targetLen])
	offset += targetLen
	if offset != endOffset {
		return 0, fmt.Errorf("URI RDATA length mismatch: consumed %d bytes, rdlength %d", offset-startOffset, rdlength)
	}

	return offset - startOffset, nil
}

// String returns the URI record data.
func (r *RDataURI) String() string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("%d %d %q", r.Priority, r.Weight, r.Target)
}

// Len returns the wire length.
func (r *RDataURI) Len() int {
	if r == nil {
		return 0
	}
	return 2 + 2 + 1 + len(r.Target)
}

// Copy creates a copy.
func (r *RDataURI) Copy() RData {
	if r == nil {
		return nil
	}
	return &RDataURI{
		Priority: r.Priority,
		Weight:   r.Weight,
		Target:   r.Target,
	}
}

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
	if r == nil {
		return 0, fmt.Errorf("nil NAPTR record")
	}

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
	if r == nil {
		return 0, fmt.Errorf("nil NAPTR record")
	}

	startOffset := offset
	endOffset := offset + int(rdlength)
	if endOffset > len(buf) {
		return 0, ErrBufferTooSmall
	}

	// Order
	if offset+2 > endOffset {
		return 0, ErrBufferTooSmall
	}
	r.Order = Uint16(buf[offset:])
	offset += 2

	// Preference
	if offset+2 > endOffset {
		return 0, ErrBufferTooSmall
	}
	r.Preference = Uint16(buf[offset:])
	offset += 2

	// Flags
	if offset >= endOffset {
		return 0, ErrBufferTooSmall
	}
	flagsLen := int(buf[offset])
	offset++
	if offset+flagsLen > endOffset {
		return 0, ErrBufferTooSmall
	}
	r.Flags = string(buf[offset : offset+flagsLen])
	offset += flagsLen

	// Service
	if offset >= endOffset {
		return 0, ErrBufferTooSmall
	}
	serviceLen := int(buf[offset])
	offset++
	if offset+serviceLen > endOffset {
		return 0, ErrBufferTooSmall
	}
	r.Service = string(buf[offset : offset+serviceLen])
	offset += serviceLen

	// Regexp
	if offset >= endOffset {
		return 0, ErrBufferTooSmall
	}
	regexpLen := int(buf[offset])
	offset++
	if offset+regexpLen > endOffset {
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
	if offset != endOffset {
		replacement.Release()
		return 0, fmt.Errorf("NAPTR RDATA length mismatch: consumed %d bytes, rdlength %d", offset-startOffset, rdlength)
	}

	return offset - startOffset, nil
}

// String returns the NAPTR record data.
func (r *RDataNAPTR) String() string {
	if r == nil {
		return ""
	}

	replacement := "."
	if r.Replacement != nil {
		replacement = r.Replacement.String()
	}
	return fmt.Sprintf("%d %d \"%s\" \"%s\" \"%s\" %s",
		r.Order, r.Preference, r.Flags, r.Service, r.Regexp, replacement)
}

// Len returns the wire length.
func (r *RDataNAPTR) Len() int {
	if r == nil {
		return 0
	}

	replacementLen := 0
	if r.Replacement != nil {
		replacementLen = r.Replacement.WireLength()
	}
	return 2 + 2 + 1 + len(r.Flags) + 1 + len(r.Service) + 1 + len(r.Regexp) + replacementLen
}

// Copy creates a copy.
func (r *RDataNAPTR) Copy() RData {
	if r == nil {
		return nil
	}

	var replacement *Name
	if r.Replacement != nil {
		replacement = r.Replacement.Copy()
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

// ============================================================================
// SVCB / HTTPS Records (Service Binding) - RFC 9460
