// Package dso implements DNS Stateful Operations (DSO) as specified in RFC 8490.
// DSO provides mechanisms for maintaining state between a DNS client and server
// over a long-lived connection.
package dso

import (
	"encoding/binary"
	"fmt"
)

// DSO Message Types
const (
	DSOMessageTypeAcknowledgement = 0x0001
	DSOMessageTypeKeepalive       = 0x0002
	DSOMessageTypePadding         = 0x0003
	DSOMessageTypeAlignment       = 0x0004
)

// DSO Option Codes
const (
	DSOOptionCodePadding   = 2
	DSOOptionCodeAlignment = 3
)

// DSO Errors
var (
	ErrInvalidDSOMessage   = fmt.Errorf("invalid DSO message")
	ErrInvalidDSOLength    = fmt.Errorf("invalid DSO message length")
	ErrUnimplementedDSOType = fmt.Errorf("unimplemented DSO message type")
)

// DSOHeader represents the fixed header of a DSO message.
type DSOHeader struct {
	TransactionID uint16
	MessageType   uint16
	DSOLength     uint16 // Length of DSO-specific portion (everything after the header)
}

// DSOMessage represents a complete DSO message.
type DSOMessage struct {
	Header  DSOHeader
	Options []DSOOption
}

// DSOOption represents a DSO option.
type DSOOption struct {
	OptionCode   uint16
	OptionLength uint16
	OptionData   []byte
}

// DSOPadding represents a padding option.
type DSOPadding struct {
	Length uint16
}

// DSOAlignment represents an alignment option.
type DSOAlignment struct {
	Granularity uint16
}

// NewDSOMessage creates a new DSO message with the given transaction ID and message type.
func NewDSOMessage(transactionID uint16, messageType uint16) *DSOMessage {
	return &DSOMessage{
		Header: DSOHeader{
			TransactionID: transactionID,
			MessageType:   messageType,
		},
		Options: make([]DSOOption, 0),
	}
}

// AddPadding adds a padding option to the DSO message.
func (m *DSOMessage) AddPadding(length uint16) {
	m.Options = append(m.Options, DSOOption{
		OptionCode:   DSOOptionCodePadding,
		OptionLength: length,
		OptionData:   make([]byte, length),
	})
}

// AddAlignment adds an alignment option to the DSO message.
func (m *DSOMessage) AddAlignment(granularity uint16) {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, granularity)
	m.Options = append(m.Options, DSOOption{
		OptionCode:   DSOOptionCodeAlignment,
		OptionLength: 2,
		OptionData:   data,
	})
}

// Pack serializes the DSO message to wire format.
func (m *DSOMessage) Pack() ([]byte, error) {
	// Calculate total size
	// Header: 2 + 2 + 2 = 6 bytes
	// Options: for each option: 2 + 2 + OptionLength = 4 + OptionLength
	optionLen := 0
	for _, opt := range m.Options {
		optionLen += 4 + int(opt.OptionLength)
	}

	totalLen := 6 + optionLen
	if totalLen > 65535 {
		return nil, fmt.Errorf("DSO message too large: %d bytes", totalLen)
	}

	buf := make([]byte, totalLen)
	offset := 0

	// Transaction ID
	binary.BigEndian.PutUint16(buf[offset:], m.Header.TransactionID)
	offset += 2

	// Message type
	binary.BigEndian.PutUint16(buf[offset:], m.Header.MessageType)
	offset += 2

	// DSO length
	binary.BigEndian.PutUint16(buf[offset:], uint16(optionLen))
	offset += 2

	// Options
	for _, opt := range m.Options {
		binary.BigEndian.PutUint16(buf[offset:], opt.OptionCode)
		offset += 2

		binary.BigEndian.PutUint16(buf[offset:], opt.OptionLength)
		offset += 2

		copy(buf[offset:], opt.OptionData)
		offset += int(opt.OptionLength)
	}

	return buf, nil
}

// UnpackDSOMessage deserializes a DSO message from wire format.
func UnpackDSOMessage(buf []byte) (*DSOMessage, error) {
	if len(buf) < 6 {
		return nil, ErrInvalidDSOLength
	}

	m := &DSOMessage{}

	offset := 0

	// Transaction ID
	m.Header.TransactionID = binary.BigEndian.Uint16(buf[offset:])
	offset += 2

	// Message type
	m.Header.MessageType = binary.BigEndian.Uint16(buf[offset:])
	offset += 2

	// DSO length
	m.Header.DSOLength = binary.BigEndian.Uint16(buf[offset:])
	offset += 2

	if len(buf)-6 < int(m.Header.DSOLength) {
		return nil, ErrInvalidDSOLength
	}

	// Parse options
	endOffset := 6 + int(m.Header.DSOLength)
	for offset < endOffset {
		if offset+4 > endOffset {
			return nil, ErrInvalidDSOMessage
		}

		opt := DSOOption{}
		opt.OptionCode = binary.BigEndian.Uint16(buf[offset:])
		offset += 2

		opt.OptionLength = binary.BigEndian.Uint16(buf[offset:])
		offset += 2

		if offset+int(opt.OptionLength) > endOffset {
			return nil, ErrInvalidDSOMessage
		}

		opt.OptionData = make([]byte, opt.OptionLength)
		copy(opt.OptionData, buf[offset:offset+int(opt.OptionLength)])
		offset += int(opt.OptionLength)

		m.Options = append(m.Options, opt)
	}

	return m, nil
}

// IsAcknowledgement returns true if the message is a DSO acknowledgement.
func (m *DSOMessage) IsAcknowledgement() bool {
	return m.Header.MessageType == DSOMessageTypeAcknowledgement
}

// IsKeepalive returns true if the message is a keepalive message.
func (m *DSOMessage) IsKeepalive() bool {
	return m.Header.MessageType == DSOMessageTypeKeepalive
}

// GetPadding returns the padding option if present.
func (m *DSOMessage) GetPadding() *DSOPadding {
	for _, opt := range m.Options {
		if opt.OptionCode == DSOOptionCodePadding {
			return &DSOPadding{
				Length: opt.OptionLength,
			}
		}
	}
	return nil
}

// GetAlignment returns the alignment option if present.
func (m *DSOMessage) GetAlignment() *DSOAlignment {
	for _, opt := range m.Options {
		if opt.OptionCode == DSOOptionCodeAlignment {
			if len(opt.OptionData) >= 2 {
				return &DSOAlignment{
					Granularity: binary.BigEndian.Uint16(opt.OptionData),
				}
			}
		}
	}
	return nil
}

// String returns a human-readable representation of the DSO message.
func (m *DSOMessage) String() string {
	msgType := "Unknown"
	switch m.Header.MessageType {
	case DSOMessageTypeAcknowledgement:
		msgType = "Acknowledgement"
	case DSOMessageTypeKeepalive:
		msgType = "Keepalive"
	case DSOMessageTypePadding:
		msgType = "Padding"
	case DSOMessageTypeAlignment:
		msgType = "Alignment"
	}

	return fmt.Sprintf("DSO[type=%s txid=%d len=%d opts=%d]",
		msgType, m.Header.TransactionID, m.Header.DSOLength, len(m.Options))
}
