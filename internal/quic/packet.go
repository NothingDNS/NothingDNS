package quic

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Wire protocol constants (RFC 9000).
const (
	// Header forms
	HeaderFormLong  = true
	HeaderFormShort = false

	// Fixed bit patterns
	longHeaderFixedBit = 0x80
	shortHeaderFixedBit = 0x40

	// Packet types
	PacketTypeInitial     = 0x0
	PacketType0RTT        = 0x1
	PacketTypeHandshake   = 0x2
	PacketTypeRetry       = 0x3

	// Version
	Version1 = 0x00000001

	// Connection ID limits
	MaxConnIDLen = 20
	MinInitialConnIDLen = 8

	// Packet number limits
	MaxPacketNumberLen = 4

	// Frame types
	FrameTypePadding        = 0x00
	FrameTypePing           = 0x01
	FrameTypeAck            = 0x02
	FrameTypeAckECN         = 0x03
	FrameTypeResetStream    = 0x04
	FrameTypeStopSending    = 0x05
	FrameTypeCrypto         = 0x06
	FrameTypeNewToken       = 0x07
	FrameTypeStream         = 0x08
	FrameTypeMaxData        = 0x10
	FrameTypeMaxStreamData  = 0x11
	FrameTypeMaxStreamsBidir  = 0x12
	FrameTypeMaxStreamsUnidir = 0x13
	FrameTypeDataBlocked          = 0x14
	FrameTypeStreamDataBlocked    = 0x15
	FrameTypeStreamsBlockedBidir  = 0x16
	FrameTypeStreamsBlockedUnidir = 0x17
	FrameTypeNewConnectionID   = 0x18
	FrameTypeRetireConnectionID = 0x19
	FrameTypePathChallenge     = 0x1a
	FrameTypePathResponse      = 0x1b
	FrameTypeConnectionClose   = 0x1c
	FrameTypeConnectionCloseApp = 0x1d
	FrameTypeHandshakeDone     = 0x1e

	// Stream types
	StreamTypeBidirectional = 0x00
	StreamTypeUnidirectional = 0x01

	// DoQ stream type for DNS queries (RFC 9250 §4.2)
	DoQStreamTypeDNS = 0x00

	// Maximum UDP payload for QUIC
	MaxUDPPayloadSize = 65527

	// Minimum Initial packet size
	MinInitialPacketSize = 1200
)

var (
	ErrInvalidPacket       = errors.New("quic: invalid packet")
	ErrPacketTooShort      = errors.New("quic: packet too short")
	ErrUnknownVersion      = errors.New("quic: unknown version")
	ErrInvalidConnID       = errors.New("quic: invalid connection id")
	ErrUnsupportedFrame    = errors.New("quic: unsupported frame type")
)

// ConnectionID represents a QUIC Connection ID.
type ConnectionID []byte

// String returns a hex representation of the Connection ID.
func (c ConnectionID) String() string {
	return fmt.Sprintf("%x", []byte(c))
}

// Equal returns true if the connection IDs are equal.
func (c ConnectionID) Equal(other ConnectionID) bool {
	if len(c) != len(other) {
		return false
	}
	for i := range c {
		if c[i] != other[i] {
			return false
		}
	}
	return true
}

// LongHeader represents a QUIC long header packet.
type LongHeader struct {
	Type    uint8 // Packet type (0-3)
	Version uint32
	// DestConnID is the destination connection ID.
	DestConnID ConnectionID
	// SrcConnID is the source connection ID.
	SrcConnID ConnectionID
	// Token is the retry token (only for Initial packets).
	Token []byte
	// Payload contains the encrypted payload after the header.
	Payload []byte
}

// ShortHeader represents a QUIC short header packet.
type ShortHeader struct {
	// DestConnID is the destination connection ID.
	DestConnID ConnectionID
	// Payload contains the encrypted payload after the header.
	Payload []byte
}

// ParsePacketType extracts the packet type from a long header first byte.
func ParsePacketType(firstByte byte) uint8 {
	return (firstByte & 0x30) >> 4
}

// IsLongHeader returns true if the first byte indicates a long header.
func IsLongHeader(firstByte byte) bool {
	return firstByte&longHeaderFixedBit != 0
}

// ParseLongHeader parses a QUIC long header from the beginning of data.
// Returns the header and the number of bytes consumed.
func ParseLongHeader(data []byte) (*LongHeader, int, error) {
	if len(data) < 6 {
		return nil, 0, ErrPacketTooShort
	}

	firstByte := data[0]
	if !IsLongHeader(firstByte) {
		return nil, 0, ErrInvalidPacket
	}

	pktType := ParsePacketType(firstByte)

	offset := 1

	// Version (4 bytes)
	version := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	if version == 0 {
		return nil, 0, ErrUnknownVersion
	}

	// Destination Connection ID
	dcIDLen := int(data[offset])
	offset++
	if dcIDLen > MaxConnIDLen {
		return nil, 0, ErrInvalidConnID
	}
	if offset+dcIDLen > len(data) {
		return nil, 0, ErrPacketTooShort
	}
	destConnID := make(ConnectionID, dcIDLen)
	copy(destConnID, data[offset:offset+dcIDLen])
	offset += dcIDLen

	// Source Connection ID
	scIDLen := int(data[offset])
	offset++
	if scIDLen > MaxConnIDLen {
		return nil, 0, ErrInvalidConnID
	}
	if offset+scIDLen > len(data) {
		return nil, 0, ErrPacketTooShort
	}
	srcConnID := make(ConnectionID, scIDLen)
	copy(srcConnID, data[offset:offset+scIDLen])
	offset += scIDLen

	// Token (only for Initial packets)
	var token []byte
	if pktType == PacketTypeInitial {
		tokenLen, n := DecodeVarint(data[offset:])
		if n == 0 {
			return nil, 0, ErrPacketTooShort
		}
		offset += n
		if tokenLen > uint64(len(data)-offset) {
			return nil, 0, ErrPacketTooShort
		}
		token = make([]byte, tokenLen)
		copy(token, data[offset:offset+int(tokenLen)])
		offset += int(tokenLen)
	}

	// Remaining data is the encrypted payload
	var payload []byte
	if offset < len(data) {
		payload = data[offset:]
	}

	return &LongHeader{
		Type:       pktType,
		Version:    version,
		DestConnID: destConnID,
		SrcConnID:  srcConnID,
		Token:      token,
		Payload:    payload,
	}, offset, nil
}

// BuildLongHeader builds a QUIC long header packet.
func BuildLongHeader(h *LongHeader, pktNum uint64, pktNumLen int) ([]byte, error) {
	if pktNumLen < 1 || pktNumLen > 4 {
		return nil, errors.New("quic: packet number length must be 1-4")
	}

	// Estimate size
	size := 1 + 4 + 1 + len(h.DestConnID) + 1 + len(h.SrcConnID)
	if h.Type == PacketTypeInitial {
		tokenLen := EncodeVarintLen(uint64(len(h.Token)))
		size += tokenLen + len(h.Token)
	}
	// Length field (varint) + packet number + payload
	size += 8 + pktNumLen + len(h.Payload)

	buf := make([]byte, 0, size)

	// First byte: form bit (1) | fixed bit (1) | long packet type (2) | reserved (2) | packet number length (2)
	var firstByte byte = longHeaderFixedBit | 0x40 // fixed bit
	firstByte |= byte(h.Type&0x03) << 4
	firstByte |= byte(pktNumLen-1) & 0x03
	buf = append(buf, firstByte)

	// Version
	buf = binary.BigEndian.AppendUint32(buf, h.Version)

	// Destination Connection ID
	buf = append(buf, byte(len(h.DestConnID)))
	buf = append(buf, h.DestConnID...)

	// Source Connection ID
	buf = append(buf, byte(len(h.SrcConnID)))
	buf = append(buf, h.SrcConnID...)

	// Token (Initial only)
	if h.Type == PacketTypeInitial {
		buf = AppendVarint(buf, uint64(len(h.Token)))
		buf = append(buf, h.Token...)
	}

	// Length field: covers packet number + payload
	length := uint64(pktNumLen + len(h.Payload))
	buf = AppendVarint(buf, length)

	// Packet number
	for i := pktNumLen - 1; i >= 0; i-- {
		buf = append(buf, byte(pktNum>>(i*8)))
	}

	// Payload
	buf = append(buf, h.Payload...)

	return buf, nil
}

// ParseShortHeader parses a QUIC short header (1-RTT).
func ParseShortHeader(data []byte, connIDLen int) (*ShortHeader, int, error) {
	if len(data) < 1 {
		return nil, 0, ErrPacketTooShort
	}

	firstByte := data[0]
	if IsLongHeader(firstByte) {
		return nil, 0, ErrInvalidPacket
	}

	offset := 1

	// Destination Connection ID
	if connIDLen > 0 {
		if offset+connIDLen > len(data) {
			return nil, 0, ErrPacketTooShort
		}
		destConnID := make(ConnectionID, connIDLen)
		copy(destConnID, data[offset:offset+connIDLen])
		offset += connIDLen

		return &ShortHeader{
			DestConnID: destConnID,
			Payload:    data[offset:],
		}, offset, nil
	}

	return &ShortHeader{
		DestConnID: nil,
		Payload:    data[offset:],
	}, offset, nil
}

// Varint encoding/decoding (RFC 9000 Section 16)

// DecodeVarint decodes a QUIC variable-length integer.
// Returns the value and the number of bytes consumed.
func DecodeVarint(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}

	first := data[0]
	prefix := first >> 6

	switch prefix {
	case 0: // 1 byte (values 0-63)
		return uint64(first & 0x3f), 1
	case 1: // 2 bytes
		if len(data) < 2 {
			return 0, 0
		}
		return uint64(first&0x3f)<<8 | uint64(data[1]), 2
	case 2: // 4 bytes
		if len(data) < 4 {
			return 0, 0
		}
		return uint64(first&0x3f)<<24 |
			uint64(data[1])<<16 |
			uint64(data[2])<<8 |
			uint64(data[3]), 4
	default: // 8 bytes (prefix 11)
		if len(data) < 8 {
			return 0, 0
		}
		val := uint64(first&0x3f) << 56
		val |= uint64(data[1]) << 48
		val |= uint64(data[2]) << 40
		val |= uint64(data[3]) << 32
		val |= uint64(data[4]) << 24
		val |= uint64(data[5]) << 16
		val |= uint64(data[6]) << 8
		val |= uint64(data[7])
		return val, 8
	}
}

// AppendVarint encodes a QUIC variable-length integer.
func AppendVarint(buf []byte, v uint64) []byte {
	switch {
	case v <= 63:
		return append(buf, byte(v))
	case v <= 16383:
		return append(buf,
			byte(0x40|(v>>8)),
			byte(v))
	case v <= 1073741823:
		return append(buf,
			byte(0x80|(v>>24)),
			byte(v>>16),
			byte(v>>8),
			byte(v))
	default:
		return append(buf,
			byte(0xc0|(v>>56)),
			byte(v>>48),
			byte(v>>40),
			byte(v>>32),
			byte(v>>24),
			byte(v>>16),
			byte(v>>8),
			byte(v))
	}
}

// EncodeVarintLen returns the encoded length of a varint value.
func EncodeVarintLen(v uint64) int {
	switch {
	case v <= 63:
		return 1
	case v <= 16383:
		return 2
	case v <= 1073741823:
		return 4
	default:
		return 8
	}
}

// PacketNumberLen returns the minimum number of bytes needed to encode
// a packet number.
func PacketNumberLen(pn uint64) int {
	switch {
	case pn <= 0xff:
		return 1
	case pn <= 0xffff:
		return 2
	case pn <= 0xffffff:
		return 3
	default:
		return 4
	}
}

// StreamFrame represents a QUIC STREAM frame (RFC 9000 Section 19.8).
type StreamFrame struct {
	StreamID uint64
	Offset   uint64
	Length   uint64
	Data     []byte
	Fin      bool
}

// ParseStreamFrame parses a STREAM frame from data.
// The frame type byte has already been consumed.
func ParseStreamFrame(frameType byte, data []byte) (*StreamFrame, int, error) {
	offset := 0

	// Stream ID (varint)
	streamID, n := DecodeVarint(data[offset:])
	if n == 0 {
		return nil, 0, ErrPacketTooShort
	}
	offset += n

	sf := &StreamFrame{StreamID: streamID}

	// Offset (if O bit set)
	if frameType&0x04 != 0 {
		off, n := DecodeVarint(data[offset:])
		if n == 0 {
			return nil, 0, ErrPacketTooShort
		}
		offset += n
		sf.Offset = off
	}

	// Length (if L bit set)
	if frameType&0x02 != 0 {
		length, n := DecodeVarint(data[offset:])
		if n == 0 {
			return nil, 0, ErrPacketTooShort
		}
		offset += n
		sf.Length = length
	} else {
		// Length is remainder of data
		sf.Length = uint64(len(data) - offset)
	}

	// Data
	if sf.Length > uint64(len(data)-offset) {
		return nil, 0, ErrPacketTooShort
	}
	sf.Data = data[offset : offset+int(sf.Length)]
	offset += int(sf.Length)

	// FIN bit
	sf.Fin = frameType&0x01 != 0

	return sf, offset, nil
}

// BuildStreamFrame builds a STREAM frame.
func BuildStreamFrame(sf *StreamFrame, withOffset, withLength bool) []byte {
	// Frame type: 0x08 | (O<<2) | (L<<1) | FIN
	var frameType byte = FrameTypeStream
	if withOffset {
		frameType |= 0x04
	}
	if withLength {
		frameType |= 0x02
	}
	if sf.Fin {
		frameType |= 0x01
	}

	buf := []byte{frameType}
	buf = AppendVarint(buf, sf.StreamID)

	if withOffset && sf.Offset > 0 {
		buf = AppendVarint(buf, sf.Offset)
	}

	if withLength {
		buf = AppendVarint(buf, uint64(len(sf.Data)))
	}

	buf = append(buf, sf.Data...)
	return buf
}

// CryptoFrame represents a CRYPTO frame (RFC 9000 Section 19.6).
type CryptoFrame struct {
	Offset uint64
	Data   []byte
}

// ParseCryptoFrame parses a CRYPTO frame.
func ParseCryptoFrame(data []byte) (*CryptoFrame, int, error) {
	offset := 0

	off, n := DecodeVarint(data[offset:])
	if n == 0 {
		return nil, 0, ErrPacketTooShort
	}
	offset += n

	length, n := DecodeVarint(data[offset:])
	if n == 0 {
		return nil, 0, ErrPacketTooShort
	}
	offset += n

	if uint64(len(data)-offset) < length {
		return nil, 0, ErrPacketTooShort
	}

	return &CryptoFrame{
		Offset: off,
		Data:   data[offset : offset+int(length)],
	}, offset + int(length), nil
}

// BuildCryptoFrame builds a CRYPTO frame.
func BuildCryptoFrame(cf *CryptoFrame) []byte {
	buf := []byte{FrameTypeCrypto}
	buf = AppendVarint(buf, cf.Offset)
	buf = AppendVarint(buf, uint64(len(cf.Data)))
	buf = append(buf, cf.Data...)
	return buf
}

// ConnectionCloseFrame represents a CONNECTION_CLOSE frame (RFC 9000 Section 19.19).
type ConnectionCloseFrame struct {
	IsApplicationError bool
	ErrorCode          uint64
	FrameType          uint64 // Only for transport close
	ReasonPhrase       string
}

// ParseConnectionCloseFrame parses a CONNECTION_CLOSE frame.
func ParseConnectionCloseFrame(frameType byte, data []byte) (*ConnectionCloseFrame, int, error) {
	offset := 0

	isApp := frameType == FrameTypeConnectionCloseApp

	// Error code
	errorCode, n := DecodeVarint(data[offset:])
	if n == 0 {
		return nil, 0, ErrPacketTooShort
	}
	offset += n

	cf := &ConnectionCloseFrame{
		IsApplicationError: isApp,
		ErrorCode:          errorCode,
	}

	// Frame type (only for transport close)
	if !isApp {
		ft, n := DecodeVarint(data[offset:])
		if n == 0 {
			return nil, 0, ErrPacketTooShort
		}
		offset += n
		cf.FrameType = ft
	}

	// Reason length
	reasonLen, n := DecodeVarint(data[offset:])
	if n == 0 {
		return nil, 0, ErrPacketTooShort
	}
	offset += n

	if uint64(len(data)-offset) < reasonLen {
		return nil, 0, ErrPacketTooShort
	}
	cf.ReasonPhrase = string(data[offset : offset+int(reasonLen)])
	offset += int(reasonLen)

	return cf, offset, nil
}
