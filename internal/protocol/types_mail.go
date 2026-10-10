// Package protocol provides DNS protocol types for NothingDNS.
//
// Mail/text record types: MX, TXT.

package protocol

import (
	"fmt"
	"strings"
)

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
	if r == nil {
		return 0, fmt.Errorf("nil MX record")
	}
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

// Unpack deserializes the MX record. See RDataCNAME.Unpack for the
// rdlength-bypass rationale; enforce that the 2-byte preference plus
// the encoded Exchange name fit strictly within rdlength.
func (r *RDataMX) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil MX record")
	}
	startOffset := offset
	if offset < 0 || offset > len(buf) || int(rdlength) > len(buf)-offset {
		return 0, ErrBufferTooSmall
	}
	endOffset := offset + int(rdlength)
	if endOffset > len(buf) {
		return 0, ErrBufferTooSmall
	}

	// Preference
	if offset+2 > endOffset {
		return 0, fmt.Errorf("MX preference overflows rdlength")
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
	if offset > endOffset {
		return 0, fmt.Errorf("MX Exchange overflows rdlength")
	}

	return offset - startOffset, nil
}

// String returns the MX record data.
func (r *RDataMX) String() string {
	if r == nil {
		return ""
	}
	exchange := "."
	if r.Exchange != nil {
		exchange = r.Exchange.String()
	}
	return fmt.Sprintf("%d %s", r.Preference, exchange)
}

// Len returns the wire length.
func (r *RDataMX) Len() int {
	if r == nil {
		return 0
	}
	if r.Exchange == nil {
		return 3
	}
	return 2 + r.Exchange.WireLength()
}

// Copy creates a copy.
func (r *RDataMX) Copy() RData {
	if r == nil {
		return nil
	}
	var exchange *Name
	if r.Exchange != nil {
		exchange = r.Exchange.Copy()
	}
	copyR := rdataMXPool.Get().(*RDataMX)
	copyR.Preference = r.Preference
	copyR.Exchange = exchange
	return copyR
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
	if r == nil {
		return 0, fmt.Errorf("nil TXT record")
	}
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
	if r == nil {
		return 0, fmt.Errorf("nil TXT record")
	}
	startOffset := offset
	if offset < 0 || offset > len(buf) || int(rdlength) > len(buf)-offset {
		return 0, ErrBufferTooSmall
	}
	endOffset := offset + int(rdlength)

	if endOffset > len(buf) {
		return 0, ErrBufferTooSmall
	}

	r.Strings = nil
	for offset < endOffset {
		if offset >= len(buf) {
			return 0, ErrBufferTooSmall
		}
		slen := int(buf[offset])
		offset++

		// SECURITY: enforce the rdlength boundary, not just the
		// overall buffer. A malicious peer that claims string
		// length N at the tail of a TXT RDATA whose true rdlength
		// only contains N-K bytes would read K bytes from the
		// FOLLOWING resource record into this TXT's data. Worse,
		// we'd then return n = offset-startOffset > rdlength to
		// UnpackResourceRecord, which would advance its own offset
		// past the next RR's bytes — corrupting every subsequent
		// record parse in the message.
		if offset+slen > endOffset {
			return 0, fmt.Errorf("TXT string length %d exceeds rdlength boundary", slen)
		}
		r.Strings = append(r.Strings, string(buf[offset:offset+slen]))
		offset += slen
	}

	return offset - startOffset, nil
}

// String returns the TXT record data.
func (r *RDataTXT) String() string {
	if r == nil {
		return ""
	}
	var parts []string
	for _, s := range r.Strings {
		// Quote strings that contain spaces or special chars
		if strings.ContainsAny(s, " \t\n\r\"") {
			s = presentationQuote(s)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}

// Len returns the wire length.
func (r *RDataTXT) Len() int {
	if r == nil {
		return 0
	}
	length := 0
	for _, s := range r.Strings {
		length += 1 + len(s)
	}
	return length
}

// Copy creates a copy.
func (r *RDataTXT) Copy() RData {
	if r == nil {
		return nil
	}
	stringsCopy := make([]string, len(r.Strings))
	copy(stringsCopy, r.Strings)
	copyR := rdataTXTPool.Get().(*RDataTXT)
	copyR.Strings = stringsCopy
	return copyR
}
