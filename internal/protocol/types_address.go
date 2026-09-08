// Package protocol provides DNS protocol types for NothingDNS.
//
// Address record types: A, AAAA, APL, CNAME, DNAME, LOC, NS, PTR.

package protocol

import (
	"fmt"
	"net"
	"strings"
)

// ============================================================================

// RDataA represents an IPv4 address record.
type RDataA struct {
	Address [4]byte
}

// Type returns TypeA.
func (r *RDataA) Type() uint16 { return TypeA }

// Pack serializes the A record.
func (r *RDataA) Pack(buf []byte, offset int) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil A record")
	}
	if offset+4 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	copy(buf[offset:], r.Address[:])
	return 4, nil
}

// Unpack deserializes the A record.
func (r *RDataA) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil A record")
	}
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
	if r == nil {
		return ""
	}
	return net.IP(r.Address[:]).String()
}

// Len returns 4.
func (r *RDataA) Len() int {
	if r == nil {
		return 0
	}
	return 4
}

// Copy creates a copy.
func (r *RDataA) Copy() RData {
	if r == nil {
		return nil
	}
	copyR := rdataAPool.Get().(*RDataA)
	copyR.Address = r.Address
	return copyR
}

// IP returns the address as net.IP.
func (r *RDataA) IP() net.IP {
	if r == nil {
		return nil
	}
	return net.IP(r.Address[:])
}

// SetIP sets the address from net.IP.
func (r *RDataA) SetIP(ip net.IP) {
	if r == nil {
		return
	}
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
	if r == nil {
		return 0, fmt.Errorf("nil AAAA record")
	}
	if offset+16 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	copy(buf[offset:], r.Address[:])
	return 16, nil
}

// Unpack deserializes the AAAA record.
func (r *RDataAAAA) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil AAAA record")
	}
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
	if r == nil {
		return ""
	}
	return net.IP(r.Address[:]).String()
}

// Len returns 16.
func (r *RDataAAAA) Len() int {
	if r == nil {
		return 0
	}
	return 16
}

// Copy creates a copy.
func (r *RDataAAAA) Copy() RData {
	if r == nil {
		return nil
	}
	copyR := rdataAAAAPool.Get().(*RDataAAAA)
	copyR.Address = r.Address
	return copyR
}

// IP returns the address as net.IP.
func (r *RDataAAAA) IP() net.IP {
	if r == nil {
		return nil
	}
	return net.IP(r.Address[:])
}

// SetIP sets the address from net.IP.
func (r *RDataAAAA) SetIP(ip net.IP) {
	if r == nil {
		return
	}
	if v6 := ip.To16(); v6 != nil {
		copy(r.Address[:], v6)
	}
}

// ============================================================================
// LOC Record (Location Information) - RFC 1876
// ============================================================================

// RDataLOC represents a LOC record.
type RDataLOC struct {
	Version        uint8
	Size           uint8
	HorizPrecision uint8
	VertPrecision  uint8
	Latitude       uint32
	Longitude      uint32
	Altitude       uint32
}

// Type returns TypeLOC.
func (r *RDataLOC) Type() uint16 { return TypeLOC }

// Pack serializes the LOC record.
func (r *RDataLOC) Pack(buf []byte, offset int) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil LOC record")
	}
	if r.Version != 0 {
		return 0, fmt.Errorf("unsupported LOC version %d", r.Version)
	}
	if offset+16 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = r.Version
	buf[offset+1] = r.Size
	buf[offset+2] = r.HorizPrecision
	buf[offset+3] = r.VertPrecision
	PutUint32(buf[offset+4:], r.Latitude)
	PutUint32(buf[offset+8:], r.Longitude)
	PutUint32(buf[offset+12:], r.Altitude)
	return 16, nil
}

// Unpack deserializes the LOC record.
func (r *RDataLOC) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil LOC record")
	}
	if rdlength != 16 {
		return 0, fmt.Errorf("invalid LOC record length: %d", rdlength)
	}
	if offset+16 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	r.Version = buf[offset]
	if r.Version != 0 {
		return 0, fmt.Errorf("unsupported LOC version %d", r.Version)
	}
	r.Size = buf[offset+1]
	r.HorizPrecision = buf[offset+2]
	r.VertPrecision = buf[offset+3]
	r.Latitude = Uint32(buf[offset+4:])
	r.Longitude = Uint32(buf[offset+8:])
	r.Altitude = Uint32(buf[offset+12:])
	return 16, nil
}

// String returns the LOC record data.
func (r *RDataLOC) String() string {
	if r == nil {
		return ""
	}
	latValue := int64(r.Latitude) - locCoordinateBase
	latHemisphere := "N"
	if latValue < 0 {
		latHemisphere = "S"
		latValue = -latValue
	}
	longValue := int64(r.Longitude) - locCoordinateBase
	longHemisphere := "E"
	if longValue < 0 {
		longHemisphere = "W"
		longValue = -longValue
	}
	altitudeCM := int64(r.Altitude) - locAltitudeBaseCM
	return fmt.Sprintf("%s %s %s %s %s %s %s %s",
		formatLOCPosition(latValue), latHemisphere,
		formatLOCPosition(longValue), longHemisphere,
		formatLOCMeters(altitudeCM),
		formatLOCMeters(locPrecisionToCentimeters(r.Size)),
		formatLOCMeters(locPrecisionToCentimeters(r.HorizPrecision)),
		formatLOCMeters(locPrecisionToCentimeters(r.VertPrecision)))
}

// Len returns the wire length.
func (r *RDataLOC) Len() int {
	if r == nil {
		return 0
	}
	return 16
}

// Copy creates a copy.
func (r *RDataLOC) Copy() RData {
	if r == nil {
		return nil
	}
	return &RDataLOC{
		Version:        r.Version,
		Size:           r.Size,
		HorizPrecision: r.HorizPrecision,
		VertPrecision:  r.VertPrecision,
		Latitude:       r.Latitude,
		Longitude:      r.Longitude,
		Altitude:       r.Altitude,
	}
}

const (
	locCoordinateBase = int64(1 << 31)
	locAltitudeBaseCM = int64(10000000)
)

func formatLOCPosition(milliseconds int64) string {
	totalSeconds := milliseconds / 1000
	ms := milliseconds % 1000
	degrees := totalSeconds / 3600
	minutes := (totalSeconds % 3600) / 60
	seconds := totalSeconds % 60
	if ms == 0 {
		return fmt.Sprintf("%d %d %d", degrees, minutes, seconds)
	}
	return fmt.Sprintf("%d %d %d.%03d", degrees, minutes, seconds, ms)
}

func formatLOCMeters(centimeters int64) string {
	sign := ""
	if centimeters < 0 {
		sign = "-"
		centimeters = -centimeters
	}
	meters := centimeters / 100
	cm := centimeters % 100
	if cm == 0 {
		return fmt.Sprintf("%s%dm", sign, meters)
	}
	return fmt.Sprintf("%s%d.%02dm", sign, meters, cm)
}

func locPrecisionToCentimeters(precision uint8) int64 {
	mantissa := int64(precision >> 4)
	exponent := int(precision & 0x0f)
	if mantissa > 9 {
		return 0
	}
	value := mantissa
	for i := 0; i < exponent; i++ {
		value *= 10
	}
	return value
}

// ============================================================================
// APL Record (Address Prefix List) - RFC 3123
// ============================================================================

// APLItem represents one address prefix item in an APL record.
type APLItem struct {
	Negation      bool
	AddressFamily uint16
	Prefix        uint8
	Address       []byte
}

// RDataAPL represents an APL record.
type RDataAPL struct {
	Items []APLItem
}

// Type returns TypeAPL.
func (r *RDataAPL) Type() uint16 { return TypeAPL }

// Pack serializes the APL record.
func (r *RDataAPL) Pack(buf []byte, offset int) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil APL record")
	}
	startOffset := offset
	for _, item := range r.Items {
		if len(item.Address) > 127 {
			return 0, fmt.Errorf("APL address length %d exceeds 127", len(item.Address))
		}
		if offset+4+len(item.Address) > len(buf) {
			return 0, ErrBufferTooSmall
		}
		PutUint16(buf[offset:], item.AddressFamily)
		offset += 2
		buf[offset] = item.Prefix
		offset++
		length := byte(len(item.Address))
		if item.Negation {
			length |= 0x80
		}
		buf[offset] = length
		offset++
		copy(buf[offset:], item.Address)
		offset += len(item.Address)
	}
	return offset - startOffset, nil
}

// Unpack deserializes the APL record.
func (r *RDataAPL) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil APL record")
	}
	startOffset := offset
	endOffset := offset + int(rdlength)
	if endOffset > len(buf) {
		return 0, ErrBufferTooSmall
	}

	r.Items = nil
	for offset < endOffset {
		if offset+4 > endOffset {
			return 0, ErrBufferTooSmall
		}
		item := APLItem{
			AddressFamily: Uint16(buf[offset:]),
			Prefix:        buf[offset+2],
			Negation:      buf[offset+3]&0x80 != 0,
		}
		addrLen := int(buf[offset+3] & 0x7f)
		offset += 4
		if offset+addrLen > endOffset {
			return 0, ErrBufferTooSmall
		}
		item.Address = make([]byte, addrLen)
		copy(item.Address, buf[offset:offset+addrLen])
		offset += addrLen
		r.Items = append(r.Items, item)
	}

	return offset - startOffset, nil
}

// String returns the APL record data.
func (r *RDataAPL) String() string {
	if r == nil {
		return ""
	}
	parts := make([]string, 0, len(r.Items))
	for _, item := range r.Items {
		prefix := ""
		if item.Negation {
			prefix = "!"
		}
		parts = append(parts, fmt.Sprintf("%s%d:%s/%d", prefix, item.AddressFamily, aplAddressString(item), item.Prefix))
	}
	return strings.Join(parts, " ")
}

func aplAddressString(item APLItem) string {
	switch item.AddressFamily {
	case 1:
		var addr [4]byte
		copy(addr[:], item.Address)
		return net.IP(addr[:]).String()
	case 2:
		var addr [16]byte
		copy(addr[:], item.Address)
		return net.IP(addr[:]).String()
	default:
		return fmt.Sprintf("%x", item.Address)
	}
}

// Len returns the wire length.
func (r *RDataAPL) Len() int {
	if r == nil {
		return 0
	}
	length := 0
	for _, item := range r.Items {
		length += 4 + len(item.Address)
	}
	return length
}

// Copy creates a copy.
func (r *RDataAPL) Copy() RData {
	if r == nil {
		return nil
	}
	items := make([]APLItem, len(r.Items))
	for i, item := range r.Items {
		items[i] = item
		if item.Address != nil {
			items[i].Address = make([]byte, len(item.Address))
			copy(items[i].Address, item.Address)
		}
	}
	return &RDataAPL{Items: items}
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
	if r == nil {
		return 0, fmt.Errorf("nil CNAME record")
	}
	return PackName(r.CName, buf, offset, nil)
}

// Unpack deserializes the CNAME record.
//
// Verifies the consumed bytes don't exceed rdlength so a malformed
// or attacker-crafted RDLENGTH can't desync UnpackResourceRecord's
// offset cursor for the rest of the message. See the TXT/SOA
// rdlength-bypass fixes for the broader class.
func (r *RDataCNAME) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil CNAME record")
	}
	name, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, err
	}
	if n > int(rdlength) {
		name.Release()
		return 0, fmt.Errorf("CNAME overflows rdlength (%d > %d)", n, rdlength)
	}
	r.CName = name
	return n, nil
}

// String returns the canonical name.
func (r *RDataCNAME) String() string {
	if r == nil {
		return ""
	}
	if r.CName == nil {
		return "."
	}
	return r.CName.String()
}

// Len returns the wire length.
func (r *RDataCNAME) Len() int {
	if r == nil {
		return 0
	}
	if r.CName == nil {
		return 1
	}
	return r.CName.WireLength()
}

// Copy creates a copy.
func (r *RDataCNAME) Copy() RData {
	if r == nil {
		return nil
	}
	var cname *Name
	if r.CName != nil {
		cname = r.CName.Copy()
	}
	copyR := rdataCNAMEPool.Get().(*RDataCNAME)
	copyR.CName = cname
	return copyR
}

// ============================================================================
// DNAME Record (Delegation Name) - RFC 6672
// ============================================================================

// RDataDNAME represents a DNAME record.
type RDataDNAME struct {
	DName *Name
}

// Type returns TypeDNAME.
func (r *RDataDNAME) Type() uint16 { return TypeDNAME }

// Pack serializes the DNAME record.
func (r *RDataDNAME) Pack(buf []byte, offset int) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil DNAME record")
	}
	return PackName(r.DName, buf, offset, nil)
}

// Unpack deserializes the DNAME record. See RDataCNAME.Unpack for the
// rdlength-bypass rationale.
func (r *RDataDNAME) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil DNAME record")
	}
	name, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, err
	}
	if n > int(rdlength) {
		name.Release()
		return 0, fmt.Errorf("DNAME overflows rdlength (%d > %d)", n, rdlength)
	}
	r.DName = name
	return n, nil
}

// String returns the delegation target name.
func (r *RDataDNAME) String() string {
	if r == nil {
		return ""
	}
	if r.DName == nil {
		return "."
	}
	return r.DName.String()
}

// Len returns the wire length.
func (r *RDataDNAME) Len() int {
	if r == nil {
		return 0
	}
	if r.DName == nil {
		return 1
	}
	return r.DName.WireLength()
}

// Copy creates a copy.
func (r *RDataDNAME) Copy() RData {
	if r == nil {
		return nil
	}
	var dname *Name
	if r.DName != nil {
		dname = r.DName.Copy()
	}
	copyR := rdataDNAMEPool.Get().(*RDataDNAME)
	copyR.DName = dname
	return copyR
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
	if r == nil {
		return 0, fmt.Errorf("nil NS record")
	}
	return PackName(r.NSDName, buf, offset, nil)
}

// Unpack deserializes the NS record. See RDataCNAME.Unpack for the
// rdlength-bypass rationale.
func (r *RDataNS) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil NS record")
	}
	name, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, err
	}
	if n > int(rdlength) {
		name.Release()
		return 0, fmt.Errorf("NS overflows rdlength (%d > %d)", n, rdlength)
	}
	r.NSDName = name
	return n, nil
}

// String returns the NS domain name.
func (r *RDataNS) String() string {
	if r == nil {
		return ""
	}
	if r.NSDName == nil {
		return "."
	}
	return r.NSDName.String()
}

// Len returns the wire length.
func (r *RDataNS) Len() int {
	if r == nil {
		return 0
	}
	if r.NSDName == nil {
		return 1
	}
	return r.NSDName.WireLength()
}

// Copy creates a copy.
func (r *RDataNS) Copy() RData {
	if r == nil {
		return nil
	}
	var nsdname *Name
	if r.NSDName != nil {
		nsdname = r.NSDName.Copy()
	}
	copyR := rdataNSPool.Get().(*RDataNS)
	copyR.NSDName = nsdname
	return copyR
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
	if r == nil {
		return 0, fmt.Errorf("nil PTR record")
	}
	return PackName(r.PtrDName, buf, offset, nil)
}

// Unpack deserializes the PTR record. See RDataCNAME.Unpack for the
// rdlength-bypass rationale.
func (r *RDataPTR) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil PTR record")
	}
	name, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, err
	}
	if n > int(rdlength) {
		name.Release()
		return 0, fmt.Errorf("PTR overflows rdlength (%d > %d)", n, rdlength)
	}
	r.PtrDName = name
	return n, nil
}

// String returns the PTR domain name.
func (r *RDataPTR) String() string {
	if r == nil {
		return ""
	}
	if r.PtrDName == nil {
		return "."
	}
	return r.PtrDName.String()
}

// Len returns the wire length.
func (r *RDataPTR) Len() int {
	if r == nil {
		return 0
	}
	if r.PtrDName == nil {
		return 1
	}
	return r.PtrDName.WireLength()
}

// Copy creates a copy.
func (r *RDataPTR) Copy() RData {
	if r == nil {
		return nil
	}
	var ptrdname *Name
	if r.PtrDName != nil {
		ptrdname = r.PtrDName.Copy()
	}
	copyR := rdataPTRPool.Get().(*RDataPTR)
	copyR.PtrDName = ptrdname
	return copyR
}
