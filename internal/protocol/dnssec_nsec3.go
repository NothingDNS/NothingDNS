package protocol

import (
	"encoding/hex"
	"fmt"
	"sort"
)

// NSEC3 flags (RFC 5155).
const (
	// NSEC3FlagOptOut indicates opt-out delegation (RFC 5155 Section 6).
	// When set, the NSEC3 record may cover unsigned delegations.
	NSEC3FlagOptOut = 0x01
)

// NSEC3 hash algorithms (RFC 5155).
const (
	// NSEC3HashSHA1 is the only defined hash algorithm.
	NSEC3HashSHA1 = 1
)

// RDataNSEC3 represents an NSEC3 record (RFC 5155).
// NSEC3 provides authenticated denial of existence with hashed owner names,
// preventing zone walking attacks that are possible with plain NSEC.
type RDataNSEC3 struct {
	HashAlgorithm uint8
	Flags         uint8
	Iterations    uint16
	Salt          []byte
	HashLength    uint8
	NextHashed    []byte // Next hashed owner name
	TypeBitMap    []uint16
}

// Type returns TypeNSEC3.
func (r *RDataNSEC3) Type() uint16 { return TypeNSEC3 }

// Pack serializes the NSEC3 record to wire format.
func (r *RDataNSEC3) Pack(buf []byte, offset int) (int, error) {
	startOffset := offset

	// Hash Algorithm (1 byte)
	if offset+1 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = r.HashAlgorithm
	offset++

	// Flags (1 byte)
	if offset+1 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = r.Flags
	offset++

	// Iterations (2 bytes)
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	PutUint16(buf[offset:], r.Iterations)
	offset += 2

	// Salt Length (1 byte)
	saltLen := len(r.Salt)
	if saltLen > 255 {
		return 0, ErrLabelTooLong
	}
	if offset+1 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = uint8(saltLen)
	offset++

	// Salt
	if offset+saltLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	copy(buf[offset:], r.Salt)
	offset += saltLen

	// Hash Length (1 byte)
	hashLen := len(r.NextHashed)
	if hashLen > 255 {
		return 0, ErrLabelTooLong
	}
	if offset+1 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = uint8(hashLen)
	offset++

	// Next Hashed Owner Name
	if offset+hashLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	copy(buf[offset:], r.NextHashed)
	offset += hashLen

	// Type Bit Map (same windowed format as NSEC)
	if len(r.TypeBitMap) > 0 {
		// Sort the type bitmap
		sortedTypes := make([]uint16, len(r.TypeBitMap))
		copy(sortedTypes, r.TypeBitMap)
		sort.Slice(sortedTypes, func(i, j int) bool {
			return sortedTypes[i] < sortedTypes[j]
		})

		// Group by window
		windows := make(map[uint8][]uint8)
		for _, t := range sortedTypes {
			window := uint8(t >> 8)
			bit := uint8(t & 0xFF)
			windows[window] = append(windows[window], bit)
		}

		// Get sorted window numbers
		var windowNums []uint8
		for w := range windows {
			windowNums = append(windowNums, w)
		}
		sort.Slice(windowNums, func(i, j int) bool {
			return windowNums[i] < windowNums[j]
		})

		// Pack each window
		for _, windowNum := range windowNums {
			bits := windows[windowNum]

			// Find the highest bit to determine bitmap length
			maxBit := bits[len(bits)-1]
			bitmapLen := int(maxBit/8) + 1

			// Check buffer space
			if offset+2+bitmapLen > len(buf) {
				return 0, ErrBufferTooSmall
			}

			// Window number
			buf[offset] = windowNum
			offset++

			// Bitmap length
			buf[offset] = uint8(bitmapLen)
			offset++

			// Create bitmap
			bitmap := make([]byte, bitmapLen)
			for _, bit := range bits {
				byteIndex := bit / 8
				bitIndex := 7 - (bit % 8)
				bitmap[byteIndex] |= 1 << bitIndex
			}

			// Copy bitmap
			copy(buf[offset:], bitmap)
			offset += bitmapLen
		}
	}

	return offset - startOffset, nil
}

// Unpack deserializes the NSEC3 record from wire format.
func (r *RDataNSEC3) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	startOffset := offset
	endOffset := offset + int(rdlength)

	if endOffset > len(buf) {
		return 0, ErrBufferTooSmall
	}

	// Need at least 6 bytes for fixed fields before salt
	if offset+6 > endOffset {
		return 0, ErrBufferTooSmall
	}

	// Hash Algorithm
	r.HashAlgorithm = buf[offset]
	offset++

	// Flags
	r.Flags = buf[offset]
	offset++

	// Iterations
	r.Iterations = Uint16(buf[offset:])
	offset += 2

	// Salt Length
	saltLen := int(buf[offset])
	offset++

	// Salt
	if offset+saltLen > endOffset {
		return 0, ErrBufferTooSmall
	}
	r.Salt = make([]byte, saltLen)
	copy(r.Salt, buf[offset:offset+saltLen])
	offset += saltLen

	// Hash Length
	if offset >= endOffset {
		return 0, ErrBufferTooSmall
	}
	hashLen := int(buf[offset])
	offset++

	// Next Hashed Owner Name
	if offset+hashLen > endOffset {
		return 0, ErrBufferTooSmall
	}
	r.HashLength = uint8(hashLen)
	r.NextHashed = make([]byte, hashLen)
	copy(r.NextHashed, buf[offset:offset+hashLen])
	offset += hashLen

	// Type Bit Map (windowed format)
	r.TypeBitMap = nil

	for offset < endOffset {
		if offset+2 > endOffset {
			return 0, ErrBufferTooSmall
		}

		// Window number
		windowNum := buf[offset]
		offset++

		// Bitmap length
		bitmapLen := int(buf[offset])
		offset++

		if offset+bitmapLen > endOffset {
			return 0, ErrBufferTooSmall
		}

		// Parse bitmap
		for i := 0; i < bitmapLen; i++ {
			b := buf[offset+i]
			for j := 0; j < 8; j++ {
				if b&(1<<(7-j)) != 0 {
					typeNum := uint16(windowNum)<<8 | uint16(i*8+j)
					r.TypeBitMap = append(r.TypeBitMap, typeNum)
				}
			}
		}
		offset += bitmapLen
	}

	return offset - startOffset, nil
}

// String returns the NSEC3 record in presentation format.
func (r *RDataNSEC3) String() string {
	saltStr := "-"
	if len(r.Salt) > 0 {
		saltStr = hex.EncodeToString(r.Salt)
	}

	nextHashStr := Base32Encode(r.NextHashed)

	result := fmt.Sprintf("%d %d %d %s %s",
		r.HashAlgorithm,
		r.Flags,
		r.Iterations,
		saltStr,
		nextHashStr,
	)

	// Add type bitmap
	sortedTypes := make([]uint16, len(r.TypeBitMap))
	copy(sortedTypes, r.TypeBitMap)
	sort.Slice(sortedTypes, func(i, j int) bool {
		return sortedTypes[i] < sortedTypes[j]
	})

	for _, t := range sortedTypes {
		result += " " + TypeString(t)
	}

	return result
}

// Len returns the wire length of the NSEC3 record.
func (r *RDataNSEC3) Len() int {
	length := 1 + 1 + 2 + 1 + len(r.Salt) + 1 + len(r.NextHashed)

	// Type Bit Map length
	if len(r.TypeBitMap) > 0 {
		windows := make(map[uint8]int)
		for _, t := range r.TypeBitMap {
			window := uint8(t >> 8)
			bit := uint8(t & 0xFF)
			byteIndex := int(bit / 8)
			if currentMax, ok := windows[window]; !ok || byteIndex > currentMax {
				windows[window] = byteIndex
			}
		}

		for _, maxByte := range windows {
			length += 2 + maxByte + 1
		}
	}

	return length
}

// Copy creates a deep copy of the NSEC3 record.
func (r *RDataNSEC3) Copy() RData {
	saltCopy := make([]byte, len(r.Salt))
	copy(saltCopy, r.Salt)

	nextHashCopy := make([]byte, len(r.NextHashed))
	copy(nextHashCopy, r.NextHashed)

	typeMapCopy := make([]uint16, len(r.TypeBitMap))
	copy(typeMapCopy, r.TypeBitMap)

	return &RDataNSEC3{
		HashAlgorithm: r.HashAlgorithm,
		Flags:         r.Flags,
		Iterations:    r.Iterations,
		Salt:          saltCopy,
		HashLength:    r.HashLength,
		NextHashed:    nextHashCopy,
		TypeBitMap:    typeMapCopy,
	}
}

// IsOptOut returns true if the opt-out flag is set.
func (r *RDataNSEC3) IsOptOut() bool {
	return r.Flags&NSEC3FlagOptOut != 0
}

// HasType returns true if the given type is in the type bitmap.
func (r *RDataNSEC3) HasType(rrtype uint16) bool {
	for _, t := range r.TypeBitMap {
		if t == rrtype {
			return true
		}
	}
	return false
}

// AddType adds a type to the type bitmap.
func (r *RDataNSEC3) AddType(rrtype uint16) {
	if !r.HasType(rrtype) {
		r.TypeBitMap = append(r.TypeBitMap, rrtype)
	}
}

// RemoveType removes a type from the type bitmap.
func (r *RDataNSEC3) RemoveType(rrtype uint16) {
	for i, t := range r.TypeBitMap {
		if t == rrtype {
			r.TypeBitMap = append(r.TypeBitMap[:i], r.TypeBitMap[i+1:]...)
			return
		}
	}
}

// Base32Encode encodes bytes using base32hex (RFC 4648) without padding.
// This is the encoding used for NSEC3 hashed owner names.
func Base32Encode(data []byte) string {
	const base32Chars = "0123456789abcdefghijklmnopqrstuv"
	if len(data) == 0 {
		return ""
	}

	result := make([]byte, 0, (len(data)*8+4)/5)
	var bits uint32
	var bitsLen int

	for _, b := range data {
		bits = (bits << 8) | uint32(b)
		bitsLen += 8

		for bitsLen >= 5 {
			result = append(result, base32Chars[(bits>>(bitsLen-5))&0x1F])
			bitsLen -= 5
		}
	}

	if bitsLen > 0 {
		result = append(result, base32Chars[(bits<<(5-bitsLen))&0x1F])
	}

	return string(result)
}
