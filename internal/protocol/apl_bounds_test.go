package protocol

import (
	"bytes"
	"errors"
	"testing"
)

// F112: RFC 3123 §4 bounds AFDLENGTH and PREFIX by address family. Unpack
// must reject out-of-range items; otherwise String() renders them lossily
// and the AXFR secondary path (which stores rr.Data.String()) corrupts or
// drops the record.
func TestRDataAPLUnpackRejectsFamilyBoundViolations(t *testing.T) {
	bad := [][]byte{
		{0, 1, 32, 5, 10, 0, 0, 1, 7},
		{0, 1, 33, 4, 10, 0, 0, 1},
		append([]byte{0, 2, 128, 17}, bytes.Repeat([]byte{0x20}, 17)...),
		{0, 2, 129, 2, 0x20, 0x01},
		{0, 1, 8, 1, 10, 0, 1, 33, 1, 10},
	}
	for _, w := range bad {
		var rd RDataAPL
		if _, err := rd.Unpack(w, 0, uint16(len(w))); err == nil {
			t.Errorf("Unpack(%x) accepted out-of-range APL item: %q", w, rd.String())
		}
	}
	good := [][]byte{
		{0, 1, 32, 4, 10, 0, 0, 1},
		append([]byte{0, 2, 128, 16}, bytes.Repeat([]byte{0x20}, 16)...),
		{0, 2, 0, 0x80},
		{},
		append([]byte{0, 9, 255, 20}, bytes.Repeat([]byte{1}, 20)...),
	}
	for _, w := range good {
		var rd RDataAPL
		n, err := rd.Unpack(w, 0, uint16(len(w)))
		if err != nil || n != len(w) {
			t.Errorf("Unpack(%x) = %d, %v; want %d, nil", w, n, err, len(w))
		}
	}
}

// F113: APL Pack/Unpack must not panic on a negative offset.
func TestRDataAPLNegativeOffset(t *testing.T) {
	apl := &RDataAPL{Items: []APLItem{{AddressFamily: 1, Prefix: 8, Address: []byte{10}}}}
	if _, err := apl.Pack(make([]byte, 16), -2); !errors.Is(err, ErrBufferTooSmall) {
		t.Errorf("Pack(offset=-2) err = %v, want ErrBufferTooSmall", err)
	}
	var rd RDataAPL
	if _, err := rd.Unpack([]byte{0, 1, 8, 1, 10, 0, 0, 0}, -3, 8); !errors.Is(err, ErrBufferTooSmall) {
		t.Errorf("Unpack(offset=-3) err = %v, want ErrBufferTooSmall", err)
	}
}
