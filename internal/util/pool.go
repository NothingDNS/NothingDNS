package util

import (
	"sync"
)

// defaultBufferSize is the default size for pooled buffers.
const defaultBufferSize = 4096

// maxBufferSize is the maximum size for buffers to be returned to the pool.
// Buffers larger than this will be garbage collected.
const maxBufferSize = 65536

// bufferPool is the global pool for byte slices.
var bufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 0, defaultBufferSize)
		return &buf
	},
}

// GetBuffer acquires a buffer from the pool.
// The returned buffer has capacity defaultBufferSize but length 0.
// The buffer should be returned to the pool with PutBuffer when no longer needed.
func GetBuffer() *[]byte {
	return bufferPool.Get().(*[]byte)
}

// PutBuffer returns a buffer to the pool.
// Buffers larger than maxBufferSize are discarded to prevent memory bloat.
// The buffer should not be used after being returned to the pool.
func PutBuffer(buf *[]byte) {
	if buf == nil {
		return
	}
	// Only return buffers up to a certain size to prevent memory bloat
	if cap(*buf) <= maxBufferSize {
		// Reset length but keep capacity
		*buf = (*buf)[:0]
		bufferPool.Put(buf)
	}
}

// GetSizedBuffer acquires a buffer with at least the specified capacity.
// If the pooled buffer is too small, a new buffer is allocated.
func GetSizedBuffer(minCapacity int) *[]byte {
	buf := GetBuffer()
	if cap(*buf) < minCapacity {
		// Buffer too small, allocate new one
		newBuf := make([]byte, 0, minCapacity)
		// Return the small buffer to pool
		PutBuffer(buf)
		return &newBuf
	}
	return buf
}

// PooledBuffer wraps a pooled byte slice for easier management.
type PooledBuffer struct {
	buf *[]byte
}

// NewPooledBuffer acquires a new pooled buffer.
func NewPooledBuffer() *PooledBuffer {
	return &PooledBuffer{buf: GetBuffer()}
}

// NewPooledBufferSized acquires a new pooled buffer with minimum capacity.
func NewPooledBufferSized(minCapacity int) *PooledBuffer {
	return &PooledBuffer{buf: GetSizedBuffer(minCapacity)}
}

// Bytes returns the underlying byte slice.
func (p *PooledBuffer) Bytes() []byte {
	return *p.buf
}

// Len returns the length of the buffer.
func (p *PooledBuffer) Len() int {
	return len(*p.buf)
}

// Cap returns the capacity of the buffer.
func (p *PooledBuffer) Cap() int {
	return cap(*p.buf)
}

// Write appends bytes to the buffer.
func (p *PooledBuffer) Write(data []byte) (int, error) {
	*p.buf = append(*p.buf, data...)
	return len(data), nil
}

// WriteByte appends a single byte to the buffer.
func (p *PooledBuffer) WriteByte(b byte) error {
	*p.buf = append(*p.buf, b)
	return nil
}

// WriteString appends a string to the buffer.
func (p *PooledBuffer) WriteString(s string) (int, error) {
	*p.buf = append(*p.buf, s...)
	return len(s), nil
}

// Reset clears the buffer while keeping the capacity.
func (p *PooledBuffer) Reset() {
	*p.buf = (*p.buf)[:0]
}

// Release returns the buffer to the pool.
// The PooledBuffer should not be used after calling Release.
func (p *PooledBuffer) Release() {
	if p.buf != nil {
		PutBuffer(p.buf)
		p.buf = nil
	}
}

// Grow ensures the buffer has room for n more bytes.
// The capacity will be increased if necessary.
func (p *PooledBuffer) Grow(n int) {
	if n < 0 {
		panic("cannot grow buffer by negative amount")
	}
	if cap(*p.buf)-len(*p.buf) < n {
		// Need more capacity - allocate new underlying array
		newCap := len(*p.buf) + n
		newBuf := make([]byte, len(*p.buf), newCap)
		copy(newBuf, *p.buf)
		*p.buf = newBuf
	}
}
