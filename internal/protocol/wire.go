package protocol

import (
	"encoding/binary"
	"errors"
	"sync"
)

// Buffer size constants.
const (
	// MinBufferSize is the minimum size for a buffer.
	MinBufferSize = 512
	// MaxUDPSize is the maximum UDP payload size without EDNS.
	MaxUDPSize = 512
	// MaxEDNSSize is the maximum UDP payload size with EDNS.
	MaxEDNSSize = 4096
	// MaxTCPSize is the maximum TCP payload size.
	MaxTCPSize = 65535
)

// Common errors.
var (
	ErrBufferTooSmall = errors.New("buffer too small")
	ErrInvalidOffset  = errors.New("invalid buffer offset")
)

// Buffer is a wrapper around a byte slice for DNS wire format operations.
type Buffer struct {
	data   []byte
	offset int
	length int // Length of valid data in buffer
}

// NewBuffer creates a new Buffer with the given size.
func NewBuffer(size int) *Buffer {
	if size < MinBufferSize {
		size = MinBufferSize
	}
	return &Buffer{
		data:   make([]byte, size),
		offset: 0,
		length: 0,
	}
}

// NewBufferFromData creates a Buffer from existing data.
func NewBufferFromData(data []byte) *Buffer {
	return &Buffer{
		data:   data,
		offset: 0,
		length: len(data),
	}
}

// Reset resets the buffer for reuse.
func (b *Buffer) Reset() {
	b.offset = 0
	b.length = 0
}

// Data returns the underlying byte slice.
func (b *Buffer) Data() []byte {
	return b.data
}

// Bytes returns a slice of the valid data in the buffer.
func (b *Buffer) Bytes() []byte {
	return b.data[:b.length]
}

// Length returns the length of valid data.
func (b *Buffer) Length() int {
	return b.length
}

// Capacity returns the capacity of the buffer.
func (b *Buffer) Capacity() int {
	return len(b.data)
}

// Offset returns the current read/write offset.
func (b *Buffer) Offset() int {
	return b.offset
}

// SetOffset sets the current offset.
func (b *Buffer) SetOffset(offset int) error {
	if offset < 0 || offset > len(b.data) {
		return ErrInvalidOffset
	}
	b.offset = offset
	return nil
}

// Remaining returns the number of bytes remaining from current offset.
func (b *Buffer) Remaining() int {
	return b.length - b.offset
}

// Available returns the number of bytes available for writing.
func (b *Buffer) Available() int {
	return len(b.data) - b.offset
}

// WriteUint8 writes a single byte.
func (b *Buffer) WriteUint8(v uint8) error {
	if b.offset >= len(b.data) {
		return ErrBufferTooSmall
	}
	b.data[b.offset] = v
	b.offset++
	if b.offset > b.length {
		b.length = b.offset
	}
	return nil
}

// WriteUint16 writes a 16-bit value in big-endian format.
func (b *Buffer) WriteUint16(v uint16) error {
	if b.offset+2 > len(b.data) {
		return ErrBufferTooSmall
	}
	binary.BigEndian.PutUint16(b.data[b.offset:], v)
	b.offset += 2
	if b.offset > b.length {
		b.length = b.offset
	}
	return nil
}

// WriteUint32 writes a 32-bit value in big-endian format.
func (b *Buffer) WriteUint32(v uint32) error {
	if b.offset+4 > len(b.data) {
		return ErrBufferTooSmall
	}
	binary.BigEndian.PutUint32(b.data[b.offset:], v)
	b.offset += 4
	if b.offset > b.length {
		b.length = b.offset
	}
	return nil
}

// WriteBytes writes a byte slice.
func (b *Buffer) WriteBytes(data []byte) error {
	if b.offset+len(data) > len(b.data) {
		return ErrBufferTooSmall
	}
	copy(b.data[b.offset:], data)
	b.offset += len(data)
	if b.offset > b.length {
		b.length = b.offset
	}
	return nil
}

// ReadUint8 reads a single byte.
func (b *Buffer) ReadUint8() (uint8, error) {
	if b.offset >= b.length {
		return 0, ErrBufferTooSmall
	}
	v := b.data[b.offset]
	b.offset++
	return v, nil
}

// ReadUint16 reads a 16-bit value in big-endian format.
func (b *Buffer) ReadUint16() (uint16, error) {
	if b.offset+2 > b.length {
		return 0, ErrBufferTooSmall
	}
	v := binary.BigEndian.Uint16(b.data[b.offset:])
	b.offset += 2
	return v, nil
}

// ReadUint32 reads a 32-bit value in big-endian format.
func (b *Buffer) ReadUint32() (uint32, error) {
	if b.offset+4 > b.length {
		return 0, ErrBufferTooSmall
	}
	v := binary.BigEndian.Uint32(b.data[b.offset:])
	b.offset += 4
	return v, nil
}

// ReadBytes reads n bytes.
func (b *Buffer) ReadBytes(n int) ([]byte, error) {
	if b.offset+n > b.length {
		return nil, ErrBufferTooSmall
	}
	data := make([]byte, n)
	copy(data, b.data[b.offset:b.offset+n])
	b.offset += n
	return data, nil
}

// PeekUint16 reads a 16-bit value without advancing offset.
func (b *Buffer) PeekUint16() (uint16, error) {
	if b.offset+2 > b.length {
		return 0, ErrBufferTooSmall
	}
	return binary.BigEndian.Uint16(b.data[b.offset:]), nil
}

// Skip advances the offset by n bytes.
func (b *Buffer) Skip(n int) error {
	if b.offset+n > b.length {
		return ErrBufferTooSmall
	}
	b.offset += n
	return nil
}

// bufferPool for efficient buffer reuse.
var bufferPool = sync.Pool{
	New: func() interface{} {
		return NewBuffer(MaxUDPSize)
	},
}

// GetBuffer acquires a buffer from the pool.
func GetBuffer() *Buffer {
	if buf, ok := bufferPool.Get().(*Buffer); ok {
		return buf
	}
	// Fallback if pool returns unexpected type
	return NewBuffer(MaxUDPSize)
}

// PutBuffer returns a buffer to the pool.
func PutBuffer(b *Buffer) {
	if b != nil {
		b.Reset()
		bufferPool.Put(b)
	}
}

// PutBufferSized returns a buffer to the pool if it has a reasonable size.
func PutBufferSized(b *Buffer, maxSize int) {
	if b != nil && b.Capacity() <= maxSize {
		b.Reset()
		bufferPool.Put(b)
	}
	// Buffers larger than maxSize are discarded
}

// Wire format helpers using sync.Pool for byte slices.

// slicePool is a pool for byte slices.
var slicePool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 0, MaxUDPSize)
		return &b
	},
}

// GetSlice acquires a byte slice from the pool.
func GetSlice() *[]byte {
	if slice, ok := slicePool.Get().(*[]byte); ok {
		return slice
	}
	// Fallback if pool returns unexpected type
	b := make([]byte, 0, MaxUDPSize)
	return &b
}

// PutSlice returns a byte slice to the pool.
func PutSlice(b *[]byte) {
	if b != nil {
		*b = (*b)[:0] // Reset length but keep capacity
		slicePool.Put(b)
	}
}

// PutSliceSized returns a byte slice to the pool if it's not too large.
func PutSliceSized(b *[]byte, maxSize int) {
	if b != nil && cap(*b) <= maxSize {
		*b = (*b)[:0]
		slicePool.Put(b)
	}
}

// PutUint16 writes a uint16 to a byte slice in big-endian format.
func PutUint16(b []byte, v uint16) {
	binary.BigEndian.PutUint16(b, v)
}

// PutUint32 writes a uint32 to a byte slice in big-endian format.
func PutUint32(b []byte, v uint32) {
	binary.BigEndian.PutUint32(b, v)
}

// Uint16 reads a uint16 from a byte slice in big-endian format.
func Uint16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}

// Uint32 reads a uint32 from a byte slice in big-endian format.
func Uint32(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}

// Uint48 reads a 48-bit value (6 bytes) from a byte slice.
func Uint48(b []byte) uint64 {
	if len(b) < 6 {
		return 0
	}
	return uint64(b[0])<<40 | uint64(b[1])<<32 | uint64(b[2])<<24 |
		uint64(b[3])<<16 | uint64(b[4])<<8 | uint64(b[5])
}

// PutUint48 writes a 48-bit value to a byte slice.
func PutUint48(b []byte, v uint64) {
	if len(b) < 6 {
		return
	}
	b[0] = byte(v >> 40)
	b[1] = byte(v >> 32)
	b[2] = byte(v >> 24)
	b[3] = byte(v >> 16)
	b[4] = byte(v >> 8)
	b[5] = byte(v)
}

// PackUint16 packs flags into a 16-bit value.
// Each argument represents a bit position (0-15).
func PackUint16(bits ...int) uint16 {
	var result uint16
	for _, bit := range bits {
		if bit >= 0 && bit < 16 {
			result |= 1 << bit
		}
	}
	return result
}

// UnpackUint16 unpacks flags from a 16-bit value.
// Returns true if the bit at position pos is set.
func UnpackUint16(v uint16, pos int) bool {
	return v&(1<<pos) != 0
}

// ValidateMessage performs basic validation on a DNS message.
func ValidateMessage(data []byte) error {
	// Minimum size: 12 bytes header
	if len(data) < 12 {
		return errors.New("message too short")
	}

	// Parse header counts
	qdcount := binary.BigEndian.Uint16(data[4:6])
	ancount := binary.BigEndian.Uint16(data[6:8])
	nscount := binary.BigEndian.Uint16(data[8:10])
	arcount := binary.BigEndian.Uint16(data[10:12])

	// Reasonable limits to prevent abuse (defense-in-depth; message.go enforces stricter caps)
	const maxQuestions = 256
	const maxRecordsPerSection = 512
	if qdcount > maxQuestions || ancount > maxRecordsPerSection ||
		nscount > maxRecordsPerSection || arcount > maxRecordsPerSection {
		return errors.New("record count exceeds reasonable limits")
	}

	return nil
}

// CompactName compresses a domain name using the given offset map.
// Returns the compressed name and true if compression was applied.
// Note: This is a placeholder - actual implementation is in labels.go.
type offsetMap map[string]int

func (m offsetMap) add(name string, offset int) {
	if m != nil {
		m[name] = offset
	}
}

func (m offsetMap) lookup(name string) (int, bool) {
	if m != nil {
		offset, ok := m[name]
		return offset, ok
	}
	return 0, false
}
