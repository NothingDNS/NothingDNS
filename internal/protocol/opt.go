package protocol

import (
	"fmt"
	"net"
)

// EDNS0Header contains the fixed fields from the OPT pseudo-record RData.
// The OPT record stores this information in the "class" and "TTL" fields.
type EDNS0Header struct {
	// UDPSize is the requestor's UDP payload size (stored in CLASS field)
	UDPSize uint16
	// ExtendedRCODE is the upper 8 bits of the extended RCODE (stored in TTL)
	ExtendedRCODE uint8
	// Version is the EDNS version (stored in TTL)
	Version uint8
	// DO bit indicates DNSSEC OK (stored in TTL)
	DO bool
	// Z is the reserved field (stored in TTL)
	Z uint16
}

// RDataOPT represents an EDNS(0) OPT pseudo-record (RFC 6891).
// OPT records have a variable-length options section.
type RDataOPT struct {
	// Options contains the EDNS(0) options
	Options []EDNS0Option
}

// EDNS0Option represents a single EDNS(0) option.
type EDNS0Option struct {
	Code uint16
	Data []byte
}

// Type returns TypeOPT.
func (r *RDataOPT) Type() uint16 { return TypeOPT }

// Pack serializes the OPT record options.
// Note: The OPT record header fields (UDPSize, ExtendedRCODE, Version, DO, Z)
// are stored in the ResourceRecord Class and TTL fields, not in RData.
func (r *RDataOPT) Pack(buf []byte, offset int) (int, error) {
	startOffset := offset

	for _, opt := range r.Options {
		// Option code (2 bytes)
		if offset+2 > len(buf) {
			return 0, ErrBufferTooSmall
		}
		PutUint16(buf[offset:], opt.Code)
		offset += 2

		// Option length (2 bytes)
		optLen := len(opt.Data)
		if offset+2 > len(buf) {
			return 0, ErrBufferTooSmall
		}
		PutUint16(buf[offset:], uint16(optLen))
		offset += 2

		// Option data
		if offset+optLen > len(buf) {
			return 0, ErrBufferTooSmall
		}
		copy(buf[offset:], opt.Data)
		offset += optLen
	}

	return offset - startOffset, nil
}

// Unpack deserializes the OPT record options.
func (r *RDataOPT) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	startOffset := offset
	endOffset := offset + int(rdlength)

	if endOffset > len(buf) {
		return 0, ErrBufferTooSmall
	}

	for offset < endOffset {
		// Need at least 4 bytes for code + length
		if offset+4 > endOffset {
			return 0, fmt.Errorf("truncated EDNS0 option")
		}

		opt := EDNS0Option{}
		opt.Code = Uint16(buf[offset:])
		offset += 2

		optLen := Uint16(buf[offset:])
		offset += 2

		if offset+int(optLen) > endOffset {
			return 0, fmt.Errorf("truncated EDNS0 option data")
		}

		opt.Data = make([]byte, optLen)
		copy(opt.Data, buf[offset:offset+int(optLen)])
		offset += int(optLen)

		r.Options = append(r.Options, opt)
	}

	return offset - startOffset, nil
}

// String returns a human-readable representation.
func (r *RDataOPT) String() string {
	var result string
	for i, opt := range r.Options {
		if i > 0 {
			result += " "
		}
		result += fmt.Sprintf("%s:%x", OptionCodeString(opt.Code), opt.Data)
	}
	return result
}

// Len returns the wire length.
func (r *RDataOPT) Len() int {
	length := 0
	for _, opt := range r.Options {
		length += 4 + len(opt.Data)
	}
	return length
}

// Copy creates a copy.
func (r *RDataOPT) Copy() RData {
	options := make([]EDNS0Option, len(r.Options))
	for i, opt := range r.Options {
		options[i] = EDNS0Option{
			Code: opt.Code,
			Data: append([]byte(nil), opt.Data...),
		}
	}
	return &RDataOPT{Options: options}
}

// AddOption adds an option to the OPT record.
func (r *RDataOPT) AddOption(code uint16, data []byte) {
	r.Options = append(r.Options, EDNS0Option{
		Code: code,
		Data: append([]byte(nil), data...),
	})
}

// GetOption returns the first option with the given code, or nil if not found.
func (r *RDataOPT) GetOption(code uint16) *EDNS0Option {
	for i := range r.Options {
		if r.Options[i].Code == code {
			return &r.Options[i]
		}
	}
	return nil
}

// RemoveOption removes all options with the given code.
func (r *RDataOPT) RemoveOption(code uint16) {
	filtered := r.Options[:0]
	for _, opt := range r.Options {
		if opt.Code != code {
			filtered = append(filtered, opt)
		}
	}
	r.Options = filtered
}

// ============================================================================
// Client Subnet (ECS) Support - RFC 7871
// ============================================================================

// EDNS0ClientSubnet represents the Client Subnet option (RFC 7871).
type EDNS0ClientSubnet struct {
	// Family is the address family (1 for IPv4, 2 for IPv6)
	Family uint16
	// SourcePrefixLength is the length of the source prefix
	SourcePrefixLength uint8
	// ScopePrefixLength is the length of the scope prefix (set by server)
	ScopePrefixLength uint8
	// Address is the client address (truncated to SourcePrefixLength)
	Address []byte
}

// NewEDNS0ClientSubnet creates a new Client Subnet option from an IP address.
func NewEDNS0ClientSubnet(ip net.IP, sourceBits uint8) *EDNS0ClientSubnet {
	// Determine family
	family := uint16(1) // IPv4
	if ip.To4() == nil {
		family = 2 // IPv6
	}

	// Get the address bytes
	addr := ip.To4()
	if addr == nil {
		addr = ip.To16()
	}

	// Calculate how many bytes we need for the prefix
	numBytes := int((sourceBits + 7) / 8)
	if numBytes > len(addr) {
		numBytes = len(addr)
	}

	// Copy the prefix bytes
	address := make([]byte, numBytes)
	copy(address, addr[:numBytes])

	// Mask the last byte if prefix doesn't end on a byte boundary
	if sourceBits%8 != 0 && numBytes > 0 {
		mask := byte(0xFF << (8 - sourceBits%8))
		address[numBytes-1] &= mask
	}

	return &EDNS0ClientSubnet{
		Family:             family,
		SourcePrefixLength: sourceBits,
		ScopePrefixLength:  0,
		Address:            address,
	}
}

// Pack serializes the Client Subnet option data.
func (e *EDNS0ClientSubnet) Pack() []byte {
	data := make([]byte, 4+len(e.Address))
	PutUint16(data[0:], e.Family)
	data[2] = e.SourcePrefixLength
	data[3] = e.ScopePrefixLength
	copy(data[4:], e.Address)
	return data
}

// UnpackEDNS0ClientSubnet deserializes the Client Subnet option data.
func UnpackEDNS0ClientSubnet(data []byte) (*EDNS0ClientSubnet, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("truncated ECS option")
	}

	e := &EDNS0ClientSubnet{}
	e.Family = Uint16(data[0:])
	e.SourcePrefixLength = data[2]
	e.ScopePrefixLength = data[3]

	if len(data) > 4 {
		e.Address = make([]byte, len(data)-4)
		copy(e.Address, data[4:])
	}

	return e, nil
}

// IP returns the address as a net.IP (with zero padding).
func (e *EDNS0ClientSubnet) IP() net.IP {
	var fullAddr []byte
	switch e.Family {
	case 1: // IPv4
		fullAddr = make([]byte, 4)
	case 2: // IPv6
		fullAddr = make([]byte, 16)
	default:
		return nil
	}
	copy(fullAddr, e.Address)
	return net.IP(fullAddr)
}

// String returns a human-readable representation.
func (e *EDNS0ClientSubnet) String() string {
	return fmt.Sprintf("%s/%d scope/%d", e.IP().String(), e.SourcePrefixLength, e.ScopePrefixLength)
}

// ToEDNS0Option converts the Client Subnet to an EDNS0Option.
func (e *EDNS0ClientSubnet) ToEDNS0Option() EDNS0Option {
	return EDNS0Option{
		Code: OptionCodeClientSubnet,
		Data: e.Pack(),
	}
}

// ============================================================================
// Extended DNS Error (EDE) Support - RFC 8914
// ============================================================================

// EDNS0ExtendedError represents an Extended DNS Error (RFC 8914).
// EDE provides additional error information beyond the RCODE via EDNS0 option code 15.
type EDNS0ExtendedError struct {
	// InfoCode is the EDE info code (0-65535) identifying the error type.
	InfoCode uint16
	// ExtraText is optional human-readable UTF-8 text providing additional context.
	ExtraText string
}

// NewEDNS0ExtendedError creates a new Extended DNS Error with the given info code and text.
func NewEDNS0ExtendedError(infoCode uint16, extraText string) *EDNS0ExtendedError {
	return &EDNS0ExtendedError{
		InfoCode:  infoCode,
		ExtraText: extraText,
	}
}

// Pack serializes the Extended DNS Error to wire format.
// Wire format: 2-byte info code (big-endian) followed by optional UTF-8 extra text.
func (e *EDNS0ExtendedError) Pack() []byte {
	data := make([]byte, 2+len(e.ExtraText))
	PutUint16(data[0:], e.InfoCode)
	if len(e.ExtraText) > 0 {
		copy(data[2:], e.ExtraText)
	}
	return data
}

// UnpackEDNS0ExtendedError deserializes an Extended DNS Error from wire format data.
func UnpackEDNS0ExtendedError(data []byte) (*EDNS0ExtendedError, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("truncated EDE option: need at least 2 bytes, got %d", len(data))
	}

	e := &EDNS0ExtendedError{}
	e.InfoCode = Uint16(data[0:])

	if len(data) > 2 {
		e.ExtraText = string(data[2:])
	}

	return e, nil
}

// ToEDNS0Option converts the Extended DNS Error to an EDNS0Option.
func (e *EDNS0ExtendedError) ToEDNS0Option() EDNS0Option {
	return EDNS0Option{
		Code: OptionCodeExtendedError,
		Data: e.Pack(),
	}
}

// String returns a human-readable representation of the Extended DNS Error.
func (e *EDNS0ExtendedError) String() string {
	name := EDEInfoCodeString(e.InfoCode)
	if e.ExtraText != "" {
		return fmt.Sprintf("%s (%d): %s", name, e.InfoCode, e.ExtraText)
	}
	return fmt.Sprintf("%s (%d)", name, e.InfoCode)
}

// EDEInfoCodeString returns the human-readable name for an EDE info code.
func EDEInfoCodeString(code uint16) string {
	switch code {
	case EDEOtherError:
		return "Other Error"
	case EDEUnsupportedDNSKEYAlgo:
		return "Unsupported DNSKEY Algorithm"
	case EDEUnsupportedDSDigest:
		return "Unsupported DS Digest Type"
	case EDEStaleAnswer:
		return "Stale Answer"
	case EDEForgedAnswer:
		return "Forged Answer"
	case EDEDNSSECIndeterminate:
		return "DNSSEC Indeterminate"
	case EDEDNSSECBogus:
		return "DNSSEC Bogus"
	case EDENSECMissing:
		return "Signature Expired"
	case EDECachedError:
		return "Cached Error"
	case EDENotReady:
		return "Not Ready"
	case EDEBlocked:
		return "Blocked"
	case EDECensored:
		return "Censored"
	case EDEFiltered:
		return "Filtered"
	case EDEProhibited:
		return "Prohibited"
	case EDEStaleNXDOMAIN:
		return "Stale NXDOMAIN Answer"
	case EDENotAuthoritative:
		return "Not Authoritative"
	case EDENotSupported:
		return "Not Supported"
	case EDENoReachableAuthority:
		return "No Reachable Authority"
	case EDENetworkError:
		return "Network Error"
	case EDEInvalidData:
		return "Invalid Data"
	case EDESignatureExpiredBefore:
		return "Signature Expired Before Valid Period"
	case EDESignatureNotYetValid:
		return "Signature Not Yet Valid"
	case EDETooEarly:
		return "DNSKEY Missing"
	case EDEUnsupportedNSEC3Iter:
		return "Unsupported NSEC3 Iterations Value"
	case EDENoNSECRecords:
		return "Unable to Conform to Policy"
	case EDENoZoneKeyBitSet:
		return "Synthesized"
	case EDENSECMissingCoverage:
		return "NSEC Missing Coverage"
	default:
		return fmt.Sprintf("EDE%d", code)
	}
}

// AddExtendedError adds an Extended DNS Error option to a message.
// If the message already has an OPT record, the EDE option is appended to it.
// If no OPT record exists, one is created with a default UDP payload size of 4096.
func AddExtendedError(msg *Message, infoCode uint16, extraText string) {
	ede := NewEDNS0ExtendedError(infoCode, extraText)
	opt := msg.GetOPT()

	if opt == nil {
		// Create a new OPT record with sensible defaults
		msg.SetEDNS0(4096, false)
		opt = msg.GetOPT()
	}

	if optData, ok := opt.Data.(*RDataOPT); ok {
		edeOption := ede.ToEDNS0Option()
		optData.AddOption(edeOption.Code, edeOption.Data)
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

// OptionCodeString returns a human-readable name for an option code.
func OptionCodeString(code uint16) string {
	switch code {
	case OptionCodeNSID:
		return "NSID"
	case OptionCodeClientSubnet:
		return "ECS"
	case OptionCodeExpire:
		return "EXPIRE"
	case OptionCodeCookie:
		return "COOKIE"
	case OptionCodeTCPKeepalive:
		return "TCPKEEPALIVE"
	case OptionCodePadding:
		return "PADDING"
	case OptionCodeChain:
		return "CHAIN"
	case OptionCodeExtendedError:
		return "EDE"
	default:
		return fmt.Sprintf("OPTION%d", code)
	}
}

// ParseEDNS0Header extracts EDNS0 information from a ResourceRecord.
// The OPT record uses the CLASS field for UDP payload size and TTL for extended info.
func ParseEDNS0Header(rr *ResourceRecord) *EDNS0Header {
	h := &EDNS0Header{}

	// UDP payload size is stored in the Class field
	h.UDPSize = rr.Class

	// Extended fields are stored in the TTL field
	ttl := rr.TTL
	h.ExtendedRCODE = uint8(ttl >> 24)
	h.Version = uint8((ttl >> 16) & 0xFF)
	h.DO = (ttl & 0x8000) != 0
	h.Z = uint16(ttl & 0x7FFF)

	return h
}

// BuildEDNSTTL builds the TTL field for an OPT record from EDNS0 header info.
func BuildEDNSTTL(extendedRCode, version uint8, do bool, z uint16) uint32 {
	ttl := uint32(extendedRCode) << 24
	ttl |= uint32(version) << 16
	if do {
		ttl |= 0x8000
	}
	ttl |= uint32(z & 0x7FFF)
	return ttl
}
