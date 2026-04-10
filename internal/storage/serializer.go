// Package storage provides persistent storage capabilities for NothingDNS.
// It implements a WAL (Write-Ahead Log) and a B+tree based key-value store.
package storage

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// TLV (Type-Length-Value) encoding for binary serialization.
// Format: [1 byte type][4 bytes length][N bytes value]
// This provides a simple, efficient way to serialize structured data.

// TLV type constants
const (
	TypeRecord   byte = 0x01
	TypeIndex    byte = 0x02
	TypeZone     byte = 0x03
	TypeConfig   byte = 0x04
	TypeKeyMeta  byte = 0x05
	TypeSOA      byte = 0x06
	TypeNS       byte = 0x07
	TypeA        byte = 0x08
	TypeAAAA     byte = 0x09
	TypeCNAME    byte = 0x0A
	TypeMX       byte = 0x0B
	TypeTXT      byte = 0x0C
	TypePTR      byte = 0x0D
	TypeSRV      byte = 0x0E
	TypeCAA      byte = 0x0F
	TypeDeletion byte = 0xFF // Tombstone marker
)

// TLVHeaderSize is the size of the TLV header (type + length)
const TLVHeaderSize = 5

// MaxValueSize is the maximum size of a TLV value (16MB)
const MaxValueSize = 16 * 1024 * 1024

// Common errors
var (
	ErrValueTooLarge   = errors.New("value exceeds maximum size")
	ErrInvalidTLV      = errors.New("invalid TLV format")
	ErrUnexpectedEOF   = errors.New("unexpected end of data")
	ErrTypeMismatch    = errors.New("type mismatch")
	ErrCorruptedData   = errors.New("corrupted data")
	ErrUnsupportedType = errors.New("unsupported type")
)

// TLV represents a Type-Length-Value structure
type TLV struct {
	Type  byte
	Value []byte
}

// TLVEncoder encodes TLV structures to a writer
type TLVEncoder struct {
	w io.Writer
}

// NewTLVEncoder creates a new TLV encoder
func NewTLVEncoder(w io.Writer) *TLVEncoder {
	return &TLVEncoder{w: w}
}

// Encode writes a TLV structure to the underlying writer
func (e *TLVEncoder) Encode(tlv *TLV) error {
	if len(tlv.Value) > MaxValueSize {
		return ErrValueTooLarge
	}

	// Write type (1 byte)
	if _, err := e.w.Write([]byte{tlv.Type}); err != nil {
		return fmt.Errorf("write type: %w", err)
	}

	// Write length (4 bytes, big-endian)
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(tlv.Value)))
	if _, err := e.w.Write(lenBuf); err != nil {
		return fmt.Errorf("write length: %w", err)
	}

	// Write value
	if len(tlv.Value) > 0 {
		if _, err := e.w.Write(tlv.Value); err != nil {
			return fmt.Errorf("write value: %w", err)
		}
	}

	return nil
}

// EncodeWithType encodes a value with a specific type
func (e *TLVEncoder) EncodeWithType(typ byte, value []byte) error {
	return e.Encode(&TLV{Type: typ, Value: value})
}

// TLVDecoder decodes TLV structures from a reader
type TLVDecoder struct {
	r io.Reader
}

// NewTLVDecoder creates a new TLV decoder
func NewTLVDecoder(r io.Reader) *TLVDecoder {
	return &TLVDecoder{r: r}
}

// Decode reads a TLV structure from the underlying reader
func (d *TLVDecoder) Decode() (*TLV, error) {
	// Read type (1 byte)
	typeBuf := make([]byte, 1)
	if _, err := io.ReadFull(d.r, typeBuf); err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("read type: %w", err)
	}

	// Read length (4 bytes)
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(d.r, lenBuf); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}

	length := binary.BigEndian.Uint32(lenBuf)
	if length > MaxValueSize {
		return nil, ErrValueTooLarge
	}

	// Read value
	value := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(d.r, value); err != nil {
			return nil, fmt.Errorf("read value: %w", err)
		}
	}

	return &TLV{
		Type:  typeBuf[0],
		Value: value,
	}, nil
}

// DecodeType reads only the type of the next TLV without reading the value
func (d *TLVDecoder) DecodeType() (byte, error) {
	typeBuf := make([]byte, 1)
	if _, err := io.ReadFull(d.r, typeBuf); err != nil {
		return 0, err
	}
	return typeBuf[0], nil
}

// EncodeTLV is a convenience function to encode a single TLV to bytes
func EncodeTLV(typ byte, value []byte) ([]byte, error) {
	if len(value) > MaxValueSize {
		return nil, ErrValueTooLarge
	}

	buf := make([]byte, TLVHeaderSize+len(value))
	buf[0] = typ
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(value)))
	copy(buf[TLVHeaderSize:], value)

	return buf, nil
}

// DecodeTLV is a convenience function to decode a single TLV from bytes
func DecodeTLV(data []byte) (*TLV, int, error) {
	if len(data) < TLVHeaderSize {
		return nil, 0, ErrUnexpectedEOF
	}

	typ := data[0]
	length := binary.BigEndian.Uint32(data[1:5])

	if length > MaxValueSize {
		return nil, 0, ErrValueTooLarge
	}

	totalSize := TLVHeaderSize + int(length)
	if len(data) < totalSize {
		return nil, 0, ErrUnexpectedEOF
	}

	value := make([]byte, length)
	copy(value, data[TLVHeaderSize:totalSize])

	return &TLV{
		Type:  typ,
		Value: value,
	}, totalSize, nil
}

// BatchEncoder encodes multiple TLV structures efficiently
type BatchEncoder struct {
	buf []byte
}

// NewBatchEncoder creates a new batch encoder with preallocated buffer
func NewBatchEncoder(initialSize int) *BatchEncoder {
	return &BatchEncoder{
		buf: make([]byte, 0, initialSize),
	}
}

// Add adds a TLV to the batch
func (e *BatchEncoder) Add(typ byte, value []byte) error {
	if len(value) > MaxValueSize {
		return ErrValueTooLarge
	}

	offset := len(e.buf)
	newLen := offset + TLVHeaderSize + len(value)

	// Grow buffer if needed
	if cap(e.buf) < newLen {
		newCap := cap(e.buf) * 2
		if newCap < newLen {
			newCap = newLen
		}
		newBuf := make([]byte, len(e.buf), newCap)
		copy(newBuf, e.buf)
		e.buf = newBuf
	}

	e.buf = e.buf[:newLen]
	e.buf[offset] = typ
	binary.BigEndian.PutUint32(e.buf[offset+1:offset+5], uint32(len(value)))
	copy(e.buf[offset+TLVHeaderSize:], value)

	return nil
}

// Bytes returns the encoded bytes
func (e *BatchEncoder) Bytes() []byte {
	return e.buf
}

// Reset clears the batch
func (e *BatchEncoder) Reset() {
	e.buf = e.buf[:0]
}

// Len returns the current length of the batch
func (e *BatchEncoder) Len() int {
	return len(e.buf)
}

// BatchDecoder decodes multiple TLV structures
type BatchDecoder struct {
	data []byte
	pos  int
}

// NewBatchDecoder creates a new batch decoder
func NewBatchDecoder(data []byte) *BatchDecoder {
	return &BatchDecoder{
		data: data,
		pos:  0,
	}
}

// Next returns the next TLV in the batch
func (d *BatchDecoder) Next() (*TLV, error) {
	if d.pos >= len(d.data) {
		return nil, io.EOF
	}

	tlv, size, err := DecodeTLV(d.data[d.pos:])
	if err != nil {
		return nil, err
	}

	d.pos += size
	return tlv, nil
}

// HasNext returns true if there are more TLVs to decode
func (d *BatchDecoder) HasNext() bool {
	return d.pos < len(d.data)
}

// Reset resets the decoder with new data
func (d *BatchDecoder) Reset(data []byte) {
	d.data = data
	d.pos = 0
}

// Pos returns the current position in the data
func (d *BatchDecoder) Pos() int {
	return d.pos
}
