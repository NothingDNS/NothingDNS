// Package protocol provides DNS protocol types for NothingDNS.
//
// Security record types: CAA, CERT, HIP, IPSECKEY, OPENPGPKEY, SSHFP, TLSA.

package protocol

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

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
	if r == nil {
		return 0, fmt.Errorf("nil CAA record")
	}
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
	if r == nil {
		return 0, fmt.Errorf("nil CAA record")
	}
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
	if r == nil {
		return ""
	}
	return fmt.Sprintf("%d %s \"%s\"", r.Flags, r.Tag, r.Value)
}

// Len returns the wire length.
func (r *RDataCAA) Len() int {
	if r == nil {
		return 0
	}
	return 1 + 1 + len(r.Tag) + len(r.Value)
}

// Copy creates a copy.
func (r *RDataCAA) Copy() RData {
	if r == nil {
		return nil
	}
	return &RDataCAA{Flags: r.Flags, Tag: r.Tag, Value: r.Value}
}

// ============================================================================
// IPSECKEY Record - RFC 4025
// ============================================================================

// RDataIPSECKEY represents an IPSECKEY record.
type RDataIPSECKEY struct {
	Precedence  uint8
	GatewayType uint8
	Algorithm   uint8
	Gateway     []byte
	GatewayName *Name
	PublicKey   []byte
}

// Type returns TypeIPSECKEY.
func (r *RDataIPSECKEY) Type() uint16 { return TypeIPSECKEY }

// Pack serializes the IPSECKEY record.
func (r *RDataIPSECKEY) Pack(buf []byte, offset int) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil IPSECKEY record")
	}
	startOffset := offset
	if offset+3 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = r.Precedence
	offset++
	buf[offset] = r.GatewayType
	offset++
	buf[offset] = r.Algorithm
	offset++

	switch r.GatewayType {
	case 0:
		// No gateway data.
	case 1:
		if len(r.Gateway) != 4 {
			return 0, fmt.Errorf("IPSECKEY IPv4 gateway length = %d, want 4", len(r.Gateway))
		}
		if offset+4 > len(buf) {
			return 0, ErrBufferTooSmall
		}
		copy(buf[offset:], r.Gateway)
		offset += 4
	case 2:
		if len(r.Gateway) != 16 {
			return 0, fmt.Errorf("IPSECKEY IPv6 gateway length = %d, want 16", len(r.Gateway))
		}
		if offset+16 > len(buf) {
			return 0, ErrBufferTooSmall
		}
		copy(buf[offset:], r.Gateway)
		offset += 16
	case 3:
		n, err := PackName(r.GatewayName, buf, offset, nil)
		if err != nil {
			return 0, err
		}
		offset += n
	default:
		return 0, fmt.Errorf("unsupported IPSECKEY gateway type %d", r.GatewayType)
	}

	if offset+len(r.PublicKey) > len(buf) {
		return 0, ErrBufferTooSmall
	}
	copy(buf[offset:], r.PublicKey)
	offset += len(r.PublicKey)

	return offset - startOffset, nil
}

// Unpack deserializes the IPSECKEY record.
func (r *RDataIPSECKEY) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil IPSECKEY record")
	}
	startOffset := offset
	endOffset := offset + int(rdlength)
	if endOffset > len(buf) {
		return 0, ErrBufferTooSmall
	}
	if offset+3 > endOffset {
		return 0, ErrBufferTooSmall
	}

	r.Precedence = buf[offset]
	offset++
	r.GatewayType = buf[offset]
	offset++
	r.Algorithm = buf[offset]
	offset++
	r.Gateway = nil
	r.GatewayName = nil

	switch r.GatewayType {
	case 0:
		// No gateway data.
	case 1:
		if offset+4 > endOffset {
			return 0, ErrBufferTooSmall
		}
		r.Gateway = make([]byte, 4)
		copy(r.Gateway, buf[offset:offset+4])
		offset += 4
	case 2:
		if offset+16 > endOffset {
			return 0, ErrBufferTooSmall
		}
		r.Gateway = make([]byte, 16)
		copy(r.Gateway, buf[offset:offset+16])
		offset += 16
	case 3:
		name, n, err := UnpackName(buf, offset)
		if err != nil {
			return 0, err
		}
		if offset+n > endOffset {
			name.Release()
			return 0, ErrBufferTooSmall
		}
		r.GatewayName = name
		offset += n
	default:
		return 0, fmt.Errorf("unsupported IPSECKEY gateway type %d", r.GatewayType)
	}

	if offset > endOffset {
		return 0, ErrBufferTooSmall
	}
	r.PublicKey = make([]byte, endOffset-offset)
	copy(r.PublicKey, buf[offset:endOffset])
	offset = endOffset

	return offset - startOffset, nil
}

// String returns the IPSECKEY record data.
func (r *RDataIPSECKEY) String() string {
	if r == nil {
		return ""
	}
	gateway := "."
	switch r.GatewayType {
	case 1, 2:
		gateway = net.IP(r.Gateway).String()
	case 3:
		if r.GatewayName != nil {
			gateway = r.GatewayName.String()
		}
	}
	return fmt.Sprintf("%d %d %d %s %s", r.Precedence, r.GatewayType, r.Algorithm, gateway, base64.StdEncoding.EncodeToString(r.PublicKey))
}

// Len returns the wire length.
func (r *RDataIPSECKEY) Len() int {
	if r == nil {
		return 0
	}
	length := 3 + len(r.PublicKey)
	switch r.GatewayType {
	case 1:
		length += 4
	case 2:
		length += 16
	case 3:
		length += r.GatewayName.WireLength()
	}
	return length
}

// Copy creates a copy.
func (r *RDataIPSECKEY) Copy() RData {
	if r == nil {
		return nil
	}
	gateway := make([]byte, len(r.Gateway))
	copy(gateway, r.Gateway)
	var gatewayName *Name
	if r.GatewayName != nil {
		gatewayName = r.GatewayName.Copy()
	}
	publicKey := make([]byte, len(r.PublicKey))
	copy(publicKey, r.PublicKey)
	return &RDataIPSECKEY{
		Precedence:  r.Precedence,
		GatewayType: r.GatewayType,
		Algorithm:   r.Algorithm,
		Gateway:     gateway,
		GatewayName: gatewayName,
		PublicKey:   publicKey,
	}
}

// ============================================================================
// HIP Record - RFC 8005
// ============================================================================

// RDataHIP represents a HIP record.
type RDataHIP struct {
	HIT                []byte
	PublicKeyAlgorithm uint8
	PublicKey          []byte
	RendezvousServers  []*Name
}

// Type returns TypeHIP.
func (r *RDataHIP) Type() uint16 { return TypeHIP }

// Pack serializes the HIP record.
func (r *RDataHIP) Pack(buf []byte, offset int) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil HIP record")
	}
	if len(r.HIT) > 255 {
		return 0, fmt.Errorf("HIP HIT length = %d, want <= 255", len(r.HIT))
	}
	if len(r.PublicKey) > 65535 {
		return 0, fmt.Errorf("HIP public key length = %d, want <= 65535", len(r.PublicKey))
	}
	startOffset := offset
	if offset+4 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = byte(len(r.HIT))
	offset++
	buf[offset] = r.PublicKeyAlgorithm
	offset++
	PutUint16(buf[offset:], uint16(len(r.PublicKey)))
	offset += 2

	if offset+len(r.HIT)+len(r.PublicKey) > len(buf) {
		return 0, ErrBufferTooSmall
	}
	copy(buf[offset:], r.HIT)
	offset += len(r.HIT)
	copy(buf[offset:], r.PublicKey)
	offset += len(r.PublicKey)

	for _, server := range r.RendezvousServers {
		if server == nil {
			continue
		}
		n, err := PackName(server, buf, offset, nil)
		if err != nil {
			return 0, err
		}
		offset += n
	}

	return offset - startOffset, nil
}

// Unpack deserializes the HIP record.
func (r *RDataHIP) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil HIP record")
	}
	startOffset := offset
	endOffset := offset + int(rdlength)
	if endOffset > len(buf) {
		return 0, ErrBufferTooSmall
	}
	if offset+4 > endOffset {
		return 0, ErrBufferTooSmall
	}

	hitLen := int(buf[offset])
	offset++
	r.PublicKeyAlgorithm = buf[offset]
	offset++
	publicKeyLen := int(Uint16(buf[offset:]))
	offset += 2

	if offset+hitLen+publicKeyLen > endOffset {
		return 0, ErrBufferTooSmall
	}
	r.HIT = make([]byte, hitLen)
	copy(r.HIT, buf[offset:offset+hitLen])
	offset += hitLen
	r.PublicKey = make([]byte, publicKeyLen)
	copy(r.PublicKey, buf[offset:offset+publicKeyLen])
	offset += publicKeyLen

	r.RendezvousServers = nil
	for offset < endOffset {
		name, n, err := UnpackName(buf, offset)
		if err != nil {
			return 0, err
		}
		offset += n
		if offset > endOffset {
			name.Release()
			return 0, ErrBufferTooSmall
		}
		r.RendezvousServers = append(r.RendezvousServers, name)
	}
	if offset != endOffset {
		return 0, ErrBufferTooSmall
	}

	return offset - startOffset, nil
}

// String returns the HIP record data.
func (r *RDataHIP) String() string {
	if r == nil {
		return ""
	}
	parts := []string{
		fmt.Sprintf("%d", r.PublicKeyAlgorithm),
		hex.EncodeToString(r.HIT),
		base64.StdEncoding.EncodeToString(r.PublicKey),
	}
	for _, server := range r.RendezvousServers {
		if server != nil {
			parts = append(parts, server.String())
		}
	}
	return strings.Join(parts, " ")
}

// Len returns the wire length.
func (r *RDataHIP) Len() int {
	if r == nil {
		return 0
	}
	length := 4 + len(r.HIT) + len(r.PublicKey)
	for _, server := range r.RendezvousServers {
		if server != nil {
			length += server.WireLength()
		}
	}
	return length
}

// Copy creates a copy.
func (r *RDataHIP) Copy() RData {
	if r == nil {
		return nil
	}
	hit := make([]byte, len(r.HIT))
	copy(hit, r.HIT)
	publicKey := make([]byte, len(r.PublicKey))
	copy(publicKey, r.PublicKey)
	servers := make([]*Name, len(r.RendezvousServers))
	for i, server := range r.RendezvousServers {
		if server != nil {
			servers[i] = server.Copy()
		}
	}
	return &RDataHIP{
		HIT:                hit,
		PublicKeyAlgorithm: r.PublicKeyAlgorithm,
		PublicKey:          publicKey,
		RendezvousServers:  servers,
	}
}

// ============================================================================
// CERT Record - RFC 4398
// ============================================================================

// RDataCERT represents a CERT record.
type RDataCERT struct {
	CertType    uint16
	KeyTag      uint16
	Algorithm   uint8
	Certificate []byte
}

// Type returns TypeCERT.
func (r *RDataCERT) Type() uint16 { return TypeCERT }

// Pack serializes the CERT record.
func (r *RDataCERT) Pack(buf []byte, offset int) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil CERT record")
	}
	length := 5 + len(r.Certificate)
	if offset+length > len(buf) {
		return 0, ErrBufferTooSmall
	}

	PutUint16(buf[offset:], r.CertType)
	offset += 2
	PutUint16(buf[offset:], r.KeyTag)
	offset += 2
	buf[offset] = r.Algorithm
	offset++
	copy(buf[offset:], r.Certificate)

	return length, nil
}

// Unpack deserializes the CERT record.
func (r *RDataCERT) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil CERT record")
	}
	startOffset := offset
	if rdlength < 5 {
		return 0, ErrBufferTooSmall
	}
	if offset+int(rdlength) > len(buf) {
		return 0, ErrBufferTooSmall
	}

	r.CertType = Uint16(buf[offset:])
	offset += 2
	r.KeyTag = Uint16(buf[offset:])
	offset += 2
	r.Algorithm = buf[offset]
	offset++

	certLen := int(rdlength) - 5
	r.Certificate = make([]byte, certLen)
	copy(r.Certificate, buf[offset:offset+certLen])
	offset += certLen

	return offset - startOffset, nil
}

// String returns the CERT record data.
func (r *RDataCERT) String() string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("%d %d %d %s", r.CertType, r.KeyTag, r.Algorithm, base64.StdEncoding.EncodeToString(r.Certificate))
}

// Len returns the wire length.
func (r *RDataCERT) Len() int {
	if r == nil {
		return 0
	}
	return 5 + len(r.Certificate)
}

// Copy creates a copy.
func (r *RDataCERT) Copy() RData {
	if r == nil {
		return nil
	}
	certCopy := make([]byte, len(r.Certificate))
	copy(certCopy, r.Certificate)
	return &RDataCERT{
		CertType:    r.CertType,
		KeyTag:      r.KeyTag,
		Algorithm:   r.Algorithm,
		Certificate: certCopy,
	}
}

// ============================================================================
// OPENPGPKEY Record - RFC 7929
// ============================================================================

// RDataOPENPGPKEY represents an OPENPGPKEY record.
type RDataOPENPGPKEY struct {
	PublicKey []byte
}

// Type returns TypeOPENPGPKEY.
func (r *RDataOPENPGPKEY) Type() uint16 { return TypeOPENPGPKEY }

// Pack serializes the OPENPGPKEY record.
func (r *RDataOPENPGPKEY) Pack(buf []byte, offset int) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil OPENPGPKEY record")
	}
	if offset+len(r.PublicKey) > len(buf) {
		return 0, ErrBufferTooSmall
	}
	copy(buf[offset:], r.PublicKey)
	return len(r.PublicKey), nil
}

// Unpack deserializes the OPENPGPKEY record.
func (r *RDataOPENPGPKEY) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil OPENPGPKEY record")
	}
	if offset+int(rdlength) > len(buf) {
		return 0, ErrBufferTooSmall
	}
	r.PublicKey = make([]byte, rdlength)
	copy(r.PublicKey, buf[offset:offset+int(rdlength)])
	return int(rdlength), nil
}

// String returns the OPENPGPKEY record data.
func (r *RDataOPENPGPKEY) String() string {
	if r == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(r.PublicKey)
}

// Len returns the wire length.
func (r *RDataOPENPGPKEY) Len() int {
	if r == nil {
		return 0
	}
	return len(r.PublicKey)
}

// Copy creates a copy.
func (r *RDataOPENPGPKEY) Copy() RData {
	if r == nil {
		return nil
	}
	publicKey := make([]byte, len(r.PublicKey))
	copy(publicKey, r.PublicKey)
	return &RDataOPENPGPKEY{PublicKey: publicKey}
}

// ============================================================================
// DHCID Record (DHCP Identifier) - RFC 4701
// ============================================================================

// RDataDHCID represents a DHCID record.
type RDataDHCID struct {
	Data []byte
}

// Type returns TypeDHCID.
func (r *RDataDHCID) Type() uint16 { return TypeDHCID }

// Pack serializes the DHCID record.
func (r *RDataDHCID) Pack(buf []byte, offset int) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil DHCID record")
	}
	if offset+len(r.Data) > len(buf) {
		return 0, ErrBufferTooSmall
	}
	copy(buf[offset:], r.Data)
	return len(r.Data), nil
}

// Unpack deserializes the DHCID record.
func (r *RDataDHCID) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil DHCID record")
	}
	if offset+int(rdlength) > len(buf) {
		return 0, ErrBufferTooSmall
	}
	r.Data = make([]byte, rdlength)
	copy(r.Data, buf[offset:offset+int(rdlength)])
	return int(rdlength), nil
}

// String returns the DHCID record data.
func (r *RDataDHCID) String() string {
	if r == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(r.Data)
}

// Len returns the wire length.
func (r *RDataDHCID) Len() int {
	if r == nil {
		return 0
	}
	return len(r.Data)
}

// Copy creates a copy.
func (r *RDataDHCID) Copy() RData {
	if r == nil {
		return nil
	}
	data := make([]byte, len(r.Data))
	copy(data, r.Data)
	return &RDataDHCID{Data: data}
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
	if r == nil {
		return 0, fmt.Errorf("nil SSHFP record")
	}
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
	if r == nil {
		return 0, fmt.Errorf("nil SSHFP record")
	}
	startOffset := offset
	if rdlength < 2 {
		return 0, ErrBufferTooSmall
	}
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

	return offset - startOffset, nil
}

// String returns the SSHFP record data.
func (r *RDataSSHFP) String() string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("%d %d %s", r.Algorithm, r.FPType, hex.EncodeToString(r.Fingerprint))
}

// Len returns the wire length.
func (r *RDataSSHFP) Len() int {
	if r == nil {
		return 0
	}
	return 2 + len(r.Fingerprint)
}

// Copy creates a copy.
func (r *RDataSSHFP) Copy() RData {
	if r == nil {
		return nil
	}
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
	if r == nil {
		return 0, fmt.Errorf("nil TLSA record")
	}
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
	if r == nil {
		return 0, fmt.Errorf("nil TLSA record")
	}
	startOffset := offset
	if rdlength < 3 {
		return 0, ErrBufferTooSmall
	}
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

	return offset - startOffset, nil
}

// String returns the TLSA record data.
func (r *RDataTLSA) String() string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("%d %d %d %s", r.Usage, r.Selector, r.MatchingType, hex.EncodeToString(r.Certificate))
}

// Len returns the wire length.
func (r *RDataTLSA) Len() int {
	if r == nil {
		return 0
	}
	return 3 + len(r.Certificate)
}

// Copy creates a copy.
func (r *RDataTLSA) Copy() RData {
	if r == nil {
		return nil
	}
	certCopy := make([]byte, len(r.Certificate))
	copy(certCopy, r.Certificate)
	return &RDataTLSA{Usage: r.Usage, Selector: r.Selector, MatchingType: r.MatchingType, Certificate: certCopy}
}
