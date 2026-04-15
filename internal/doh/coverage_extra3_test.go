package doh

import (
	"testing"
)

func TestNewHandler(t *testing.T) {
	h := NewHandler(nil)
	if h == nil {
		t.Fatal("NewHandler returned nil")
	}
	if h.padding {
		t.Error("padding should be false by default")
	}
}

func TestNewHandlerWithPadding(t *testing.T) {
	h := NewHandlerWithPadding(nil)
	if h == nil {
		t.Fatal("NewHandlerWithPadding returned nil")
	}
	if !h.padding {
		t.Error("padding should be true")
	}
}

func TestGeneratePadding(t *testing.T) {
	padding, err := generatePadding()
	if err != nil {
		t.Fatalf("generatePadding failed: %v", err)
	}
	if len(padding) < MinPaddingSize {
		t.Errorf("padding too small: %d < %d", len(padding), MinPaddingSize)
	}
	if len(padding) > MaxPaddingSize {
		t.Errorf("padding too large: %d > %d", len(padding), MaxPaddingSize)
	}
}

func TestGeneratePadding_MultipleCalls(t *testing.T) {
	sizes := make(map[int]bool)
	for i := 0; i < 100; i++ {
		padding, err := generatePadding()
		if err != nil {
			t.Fatalf("generatePadding failed: %v", err)
		}
		sizes[len(padding)] = true
	}
	// With random sizing, we should get multiple distinct sizes
	if len(sizes) < 3 {
		t.Errorf("expected varied padding sizes, got %d distinct values", len(sizes))
	}
}

func TestPadMessage(t *testing.T) {
	original := []byte{0x00, 0x01, 0x02, 0x03}
	padded, err := padMessage(original)
	if err != nil {
		t.Fatalf("padMessage failed: %v", err)
	}
	if len(padded) <= len(original) {
		t.Errorf("padded message should be longer: %d <= %d", len(padded), len(original))
	}
	// Original bytes should be preserved
	for i, b := range original {
		if padded[i] != b {
			t.Errorf("byte %d mismatch: %x != %x", i, padded[i], b)
		}
	}
}

func TestPadMessage_Empty(t *testing.T) {
	padded, err := padMessage([]byte{})
	if err != nil {
		t.Fatalf("padMessage failed: %v", err)
	}
	if len(padded) < MinPaddingSize {
		t.Errorf("padded empty should have at least MinPaddingSize: %d", len(padded))
	}
}

func TestDohResponseWriter_MaxSize(t *testing.T) {
	rw := &dohResponseWriter{}
	if rw.MaxSize() != MaxDNSMessageSize {
		t.Errorf("MaxSize should be %d, got %d", MaxDNSMessageSize, rw.MaxSize())
	}
}

func TestWsResponseWriter_MaxSize(t *testing.T) {
	rw := &wsResponseWriter{}
	if rw.MaxSize() != MaxDNSMessageSize {
		t.Errorf("MaxSize should be %d, got %d", MaxDNSMessageSize, rw.MaxSize())
	}
}
