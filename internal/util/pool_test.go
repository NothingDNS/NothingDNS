package util

import (
	"testing"
)

func TestGetPutBuffer(t *testing.T) {
	// Get a buffer
	buf := GetBuffer()
	if buf == nil {
		t.Fatal("GetBuffer returned nil")
	}

	// Verify initial state
	if len(*buf) != 0 {
		t.Errorf("New buffer should have length 0, got %d", len(*buf))
	}
	if cap(*buf) < defaultBufferSize {
		t.Errorf("Buffer capacity should be at least %d, got %d", defaultBufferSize, cap(*buf))
	}

	// Write some data
	*buf = append(*buf, []byte("test data")...)
	if string(*buf) != "test data" {
		t.Errorf("Buffer content mismatch, got %q", string(*buf))
	}

	// Return to pool
	PutBuffer(buf)

	// Get another buffer - should be reused
	buf2 := GetBuffer()
	if len(*buf2) != 0 {
		t.Errorf("Reused buffer should have length 0, got %d", len(*buf2))
	}

	PutBuffer(buf2)
}

func TestGetSizedBuffer(t *testing.T) {
	// Get a buffer with minimum capacity
	minCap := 8192
	buf := GetSizedBuffer(minCap)
	if buf == nil {
		t.Fatal("GetSizedBuffer returned nil")
	}

	if cap(*buf) < minCap {
		t.Errorf("Buffer capacity should be at least %d, got %d", minCap, cap(*buf))
	}

	PutBuffer(buf)
}

func TestPooledBuffer(t *testing.T) {
	p := NewPooledBuffer()
	if p == nil {
		t.Fatal("NewPooledBuffer returned nil")
	}
	defer p.Release()

	// Test Write
	data := []byte("hello")
	n, err := p.Write(data)
	if err != nil {
		t.Errorf("Write error: %v", err)
	}
	if n != len(data) {
		t.Errorf("Write returned %d, expected %d", n, len(data))
	}

	// Test WriteByte
	err = p.WriteByte(' ')
	if err != nil {
		t.Errorf("WriteByte error: %v", err)
	}

	// Test WriteString
	n, err = p.WriteString("world")
	if err != nil {
		t.Errorf("WriteString error: %v", err)
	}
	if n != 5 {
		t.Errorf("WriteString returned %d, expected 5", n)
	}

	// Verify content
	if string(p.Bytes()) != "hello world" {
		t.Errorf("Buffer content = %q, expected 'hello world'", string(p.Bytes()))
	}

	// Test Len and Cap
	if p.Len() != 11 {
		t.Errorf("Len() = %d, expected 11", p.Len())
	}
	if p.Cap() < 11 {
		t.Errorf("Cap() = %d, expected >= 11", p.Cap())
	}

	// Test Reset
	p.Reset()
	if p.Len() != 0 {
		t.Errorf("After Reset, Len() = %d, expected 0", p.Len())
	}
}

func TestPooledBufferGrow(t *testing.T) {
	p := NewPooledBuffer()
	defer p.Release()

	// Write some data to reduce available space
	p.WriteString("test")
	initialCap := p.Cap()

	// Fill buffer to capacity so Grow must allocate
	for i := 0; i < initialCap; i++ {
		p.WriteByte('x')
	}

	// Now we are at capacity, Grow should increase it
	p.Grow(1000)

	// Grow guarantees room for n more bytes, so cap must be >= len + n
	if p.Cap() < p.Len()+1000 {
		t.Errorf("After Grow(1000), Cap() = %d, expected >= %d", p.Cap(), p.Len()+1000)
	}

	// Length should remain unchanged (4 from WriteString + initialCap bytes)
	if p.Len() != 4+initialCap {
		t.Errorf("After Grow, Len() = %d, expected %d", p.Len(), 4+initialCap)
	}
}

func TestPutBufferNil(t *testing.T) {
	// Should not panic
	PutBuffer(nil)
}

func TestPutBufferLarge(t *testing.T) {
	// Create a large buffer
	largeBuf := make([]byte, 0, maxBufferSize+1)
	buf := &largeBuf

	// Should not be returned to pool
	PutBuffer(buf)
}

func BenchmarkGetPutBuffer(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := GetBuffer()
			PutBuffer(buf)
		}
	})
}
