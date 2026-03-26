package protocol

import (
	"fmt"
	"sort"
)

// RDataNSEC represents a Next Secure (NSEC) record (RFC 4034).
// NSEC records are used for authenticated denial of existence.
// They form a circular linked list of all names in a zone and
// indicate which record types exist at each name.
// Note: NSEC3 (RFC 5155) is preferred over NSEC as it prevents zone walking.
type RDataNSEC struct {
	NextDomain *Name
	TypeBitMap []uint16
}

// Type returns TypeNSEC.
func (r *RDataNSEC) Type() uint16 { return TypeNSEC }

// Pack serializes the NSEC record to wire format.
func (r *RDataNSEC) Pack(buf []byte, offset int) (int, error) {
	startOffset := offset

	// Next Domain Name
	n, err := PackName(r.NextDomain, buf, offset, nil)
	if err != nil {
		return 0, fmt.Errorf("packing next domain: %w", err)
	}
	offset += n

	// Type Bit Map (windowed format per RFC 4034)
	if len(r.TypeBitMap) > 0 {
		// Sort the type bitmap
		sortedTypes := make([]uint16, len(r.TypeBitMap))
		copy(sortedTypes, r.TypeBitMap)
		sort.Slice(sortedTypes, func(i, j int) bool {
			return sortedTypes[i] < sortedTypes[j]
		})

		// Group by window (high 8 bits of type)
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

// Unpack deserializes the NSEC record from wire format.
func (r *RDataNSEC) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	startOffset := offset
	endOffset := offset + int(rdlength)

	if endOffset > len(buf) {
		return 0, ErrBufferTooSmall
	}

	// Next Domain Name
	nextDomain, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, fmt.Errorf("unpacking next domain: %w", err)
	}
	r.NextDomain = nextDomain
	offset += n

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
					// Type number = (windowNum << 8) | (i*8 + j)
					typeNum := uint16(windowNum)<<8 | uint16(i*8+j)
					r.TypeBitMap = append(r.TypeBitMap, typeNum)
				}
			}
		}
		offset += bitmapLen
	}

	return offset - startOffset, nil
}

// String returns the NSEC record in presentation format.
func (r *RDataNSEC) String() string {
	nextStr := "."
	if r.NextDomain != nil {
		nextStr = r.NextDomain.String()
	}

	// Sort and format type bitmap
	sortedTypes := make([]uint16, len(r.TypeBitMap))
	copy(sortedTypes, r.TypeBitMap)
	sort.Slice(sortedTypes, func(i, j int) bool {
		return sortedTypes[i] < sortedTypes[j]
	})

	result := nextStr
	for _, t := range sortedTypes {
		result += " " + TypeString(t)
	}

	return result
}

// Len returns the wire length of the NSEC record.
func (r *RDataNSEC) Len() int {
	nextLen := 1
	if r.NextDomain != nil {
		nextLen = r.NextDomain.WireLength()
	}

	// Calculate bitmap length
	bitmapLen := 0
	if len(r.TypeBitMap) > 0 {
		// Group by window
		windows := make(map[uint8]int)
		for _, t := range r.TypeBitMap {
			window := uint8(t >> 8)
			bit := uint8(t & 0xFF)
			byteIndex := int(bit / 8)
			if currentMax, ok := windows[window]; !ok || byteIndex > currentMax {
				windows[window] = byteIndex
			}
		}

		// Each window has 2 bytes header + bitmap
		for _, maxByte := range windows {
			bitmapLen += 2 + maxByte + 1
		}
	}

	return nextLen + bitmapLen
}

// Copy creates a deep copy of the NSEC record.
func (r *RDataNSEC) Copy() RData {
	var nextDomain *Name
	if r.NextDomain != nil {
		nextDomain = NewName(r.NextDomain.Labels, r.NextDomain.FQDN)
	}

	typeMapCopy := make([]uint16, len(r.TypeBitMap))
	copy(typeMapCopy, r.TypeBitMap)

	return &RDataNSEC{
		NextDomain: nextDomain,
		TypeBitMap: typeMapCopy,
	}
}

// HasType returns true if the given type is in the type bitmap.
func (r *RDataNSEC) HasType(rrtype uint16) bool {
	for _, t := range r.TypeBitMap {
		if t == rrtype {
			return true
		}
	}
	return false
}

// AddType adds a type to the type bitmap.
func (r *RDataNSEC) AddType(rrtype uint16) {
	if !r.HasType(rrtype) {
		r.TypeBitMap = append(r.TypeBitMap, rrtype)
	}
}

// RemoveType removes a type from the type bitmap.
func (r *RDataNSEC) RemoveType(rrtype uint16) {
	for i, t := range r.TypeBitMap {
		if t == rrtype {
			r.TypeBitMap = append(r.TypeBitMap[:i], r.TypeBitMap[i+1:]...)
			return
		}
	}
}

// TypeList returns the list of types as strings.
func (r *RDataNSEC) TypeList() []string {
	var result []string
	for _, t := range r.TypeBitMap {
		result = append(result, TypeString(t))
	}
	return result
}
