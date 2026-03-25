package protocol

import (
	"encoding/binary"
	"fmt"
)

// HeaderLen is the fixed length of a DNS header (12 bytes).
const HeaderLen = 12

// Header represents a DNS message header (RFC 1035 §4.1.1).
type Header struct {
	// ID is a 16-bit identifier assigned by the program that generates the query.
	ID uint16

	// Flags contains various bit fields.
	Flags Flags

	// QDCount is the number of entries in the question section.
	QDCount uint16

	// ANCount is the number of resource records in the answer section.
	ANCount uint16

	// NSCount is the number of name server resource records in the authority section.
	NSCount uint16

	// ARCount is the number of resource records in the additional records section.
	ARCount uint16
}

// Flags represents the flag bits in the DNS header.
type Flags struct {
	// QR indicates whether this message is a query (false) or a response (true).
	QR bool

	// Opcode is a four-bit field that specifies the kind of query.
	Opcode uint8

	// AA indicates that the responding name server is an authority for the domain name.
	AA bool

	// TC indicates that this message was truncated due to length > permitted on the transmission channel.
	TC bool

	// RD indicates that recursion is desired.
	RD bool

	// RA indicates whether recursive query support is available in the name server.
	RA bool

	// Z is reserved for future use. Must be zero in all queries and responses.
	Z bool

	// AD indicates in a response that all the data included in the answer and authority
	// sections of the response have been authenticated by the server according to the
	// policies of that server (RFC 2535).
	AD bool

	// CD indicates in a query that non-authenticated data is acceptable to the resolver.
	CD bool

	// RCODE is the response code (4 bits).
	RCODE uint8
}

// NewHeader creates a new Header with default values for a query.
func NewHeader() *Header {
	return &Header{
		ID:      0,
		Flags:   NewQueryFlags(),
		QDCount: 0,
		ANCount: 0,
		NSCount: 0,
		ARCount: 0,
	}
}

// NewQueryFlags returns Flags appropriate for a standard query.
func NewQueryFlags() Flags {
	return Flags{
		QR:     false,
		Opcode: OpcodeQuery,
		RD:     true, // Most resolvers set RD by default
	}
}

// NewResponseFlags returns Flags appropriate for a response.
func NewResponseFlags(rcode uint8) Flags {
	return Flags{
		QR:     true,
		Opcode: OpcodeQuery,
		AA:     true,
		RA:     true,
		RCODE:  rcode,
	}
}

// Pack serializes the header to wire format.
func (h *Header) Pack(buf []byte) error {
	if len(buf) < HeaderLen {
		return ErrBufferTooSmall
	}

	// Pack ID
	binary.BigEndian.PutUint16(buf[0:2], h.ID)

	// Pack flags
	binary.BigEndian.PutUint16(buf[2:4], h.Flags.Pack())

	// Pack counts
	binary.BigEndian.PutUint16(buf[4:6], h.QDCount)
	binary.BigEndian.PutUint16(buf[6:8], h.ANCount)
	binary.BigEndian.PutUint16(buf[8:10], h.NSCount)
	binary.BigEndian.PutUint16(buf[10:12], h.ARCount)

	return nil
}

// Unpack deserializes the header from wire format.
func (h *Header) Unpack(buf []byte) error {
	if len(buf) < HeaderLen {
		return ErrBufferTooSmall
	}

	// Unpack ID
	h.ID = binary.BigEndian.Uint16(buf[0:2])

	// Unpack flags
	h.Flags = UnpackFlags(binary.BigEndian.Uint16(buf[2:4]))

	// Unpack counts
	h.QDCount = binary.BigEndian.Uint16(buf[4:6])
	h.ANCount = binary.BigEndian.Uint16(buf[6:8])
	h.NSCount = binary.BigEndian.Uint16(buf[8:10])
	h.ARCount = binary.BigEndian.Uint16(buf[10:12])

	return nil
}

// Pack serializes Flags to a 16-bit value.
func (f Flags) Pack() uint16 {
	var result uint16

	if f.QR {
		result |= FlagQR
	}

	// Opcode (bits 1-4)
	result |= uint16(f.Opcode&0x0F) << 11

	if f.AA {
		result |= FlagAA
	}
	if f.TC {
		result |= FlagTC
	}
	if f.RD {
		result |= FlagRD
	}
	if f.RA {
		result |= FlagRA
	}
	if f.Z {
		result |= FlagZ
	}
	if f.AD {
		result |= FlagAD
	}
	if f.CD {
		result |= FlagCD
	}

	// RCODE (bits 12-15)
	result |= uint16(f.RCODE & 0x0F)

	return result
}

// UnpackFlags deserializes Flags from a 16-bit value.
func UnpackFlags(v uint16) Flags {
	return Flags{
		QR:     v&FlagQR != 0,
		Opcode: uint8((v >> 11) & 0x0F),
		AA:     v&FlagAA != 0,
		TC:     v&FlagTC != 0,
		RD:     v&FlagRD != 0,
		RA:     v&FlagRA != 0,
		Z:      v&FlagZ != 0,
		AD:     v&FlagAD != 0,
		CD:     v&FlagCD != 0,
		RCODE:  uint8(v & 0x0F),
	}
}

// IsQuery returns true if this is a query message.
func (f Flags) IsQuery() bool {
	return !f.QR
}

// IsResponse returns true if this is a response message.
func (f Flags) IsResponse() bool {
	return f.QR
}

// IsAuthoritative returns true if this is an authoritative response.
func (f Flags) IsAuthoritative() bool {
	return f.AA
}

// IsTruncated returns true if the message was truncated.
func (f Flags) IsTruncated() bool {
	return f.TC
}

// RecursionDesired returns true if recursion was requested.
func (f Flags) RecursionDesired() bool {
	return f.RD
}

// RecursionAvailable returns true if recursion is available.
func (f Flags) RecursionAvailable() bool {
	return f.RA
}

// AuthenticData returns true if all data is authenticated.
func (f Flags) AuthenticData() bool {
	return f.AD
}

// CheckingDisabled returns true if checking was disabled.
func (f Flags) CheckingDisabled() bool {
	return f.CD
}

// String returns a human-readable representation of Flags.
func (f Flags) String() string {
	var parts []string

	if f.QR {
		parts = append(parts, "qr")
	}

	opcodeStr := "QUERY"
	switch f.Opcode {
	case OpcodeIQuery:
		opcodeStr = "IQUERY"
	case OpcodeStatus:
		opcodeStr = "STATUS"
	case OpcodeNotify:
		opcodeStr = "NOTIFY"
	case OpcodeUpdate:
		opcodeStr = "UPDATE"
	default:
		opcodeStr = fmt.Sprintf("OPCODE%d", f.Opcode)
	}
	parts = append(parts, opcodeStr)

	if f.AA {
		parts = append(parts, "aa")
	}
	if f.TC {
		parts = append(parts, "tc")
	}
	if f.RD {
		parts = append(parts, "rd")
	}
	if f.RA {
		parts = append(parts, "ra")
	}
	if f.AD {
		parts = append(parts, "ad")
	}
	if f.CD {
		parts = append(parts, "cd")
	}

	parts = append(parts, RcodeString(int(f.RCODE)))

	result := ""
	for i, part := range parts {
		if i > 0 {
			result += " "
		}
		result += part
	}
	return result
}

// String returns a human-readable representation of the header.
func (h *Header) String() string {
	return fmt.Sprintf(
		";; ->>HEADER<<- opcode: %s, status: %s, id: %d\n"+
		";; flags: %s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d",
		opcodeString(h.Flags.Opcode),
		RcodeString(int(h.Flags.RCODE)),
		h.ID,
		h.Flags.String(),
		h.QDCount,
		h.ANCount,
		h.NSCount,
		h.ARCount,
	)
}

// opcodeString returns a string representation of an opcode.
func opcodeString(opcode uint8) string {
	switch opcode {
	case OpcodeQuery:
		return "QUERY"
	case OpcodeIQuery:
		return "IQUERY"
	case OpcodeStatus:
		return "STATUS"
	case OpcodeNotify:
		return "NOTIFY"
	case OpcodeUpdate:
		return "UPDATE"
	default:
		return fmt.Sprintf("%d", opcode)
	}
}

// SetResponse sets the header for a response with the given RCODE.
func (h *Header) SetResponse(rcode uint8) {
	h.Flags.QR = true
	h.Flags.RCODE = rcode
}

// SetTruncated sets the TC bit.
func (h *Header) SetTruncated(truncated bool) {
	h.Flags.TC = truncated
}

// SetAuthoritative sets the AA bit.
func (h *Header) SetAuthoritative(auth bool) {
	h.Flags.AA = auth
}

// ClearCounts sets all section counts to zero.
func (h *Header) ClearCounts() {
	h.QDCount = 0
	h.ANCount = 0
	h.NSCount = 0
	h.ARCount = 0
}

// IsSuccess returns true if the response code indicates success.
func (h *Header) IsSuccess() bool {
	return h.Flags.RCODE == RcodeSuccess
}

// Copy creates a copy of the header.
func (h *Header) Copy() *Header {
	return &Header{
		ID:      h.ID,
		Flags:   h.Flags,
		QDCount: h.QDCount,
		ANCount: h.ANCount,
		NSCount: h.NSCount,
		ARCount: h.ARCount,
	}
}
