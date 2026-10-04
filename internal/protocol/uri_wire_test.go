package protocol

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestURIWireRFC7553(t *testing.T) {
	for _, target := range []string{"x:", "https://example.test/path", "https://example.test/" + strings.Repeat("x", 256), "x:" + strings.Repeat("x", 65529)} {
		for _, offset := range []int{0, 7} {
			r := &RDataURI{Priority: 10, Weight: 20, Target: target}
			expected := make([]byte, 4+len(target))
			binary.BigEndian.PutUint16(expected, 10)
			binary.BigEndian.PutUint16(expected[2:], 20)
			copy(expected[4:], target)
			if r.Len() != len(expected) {
				t.Fatalf("Len=%d want %d", r.Len(), len(expected))
			}
			buf := make([]byte, offset+len(expected))
			n, err := r.Pack(buf, offset)
			if err != nil || n != len(expected) || !bytes.Equal(buf[offset:], expected) {
				t.Fatalf("Pack target length %d offset %d: n=%d err=%v", len(target), offset, n, err)
			}
			// Decode independently constructed RFC bytes, rather than Pack's output.
			copy(buf[offset:], expected)
			var got RDataURI
			n, err = got.Unpack(buf, offset, uint16(len(expected)))
			if err != nil || n != len(expected) || got != *r {
				t.Fatalf("Unpack target length %d offset %d: n=%d err=%v", len(target), offset, n, err)
			}
		}
	}
}

func TestURIWireRequiresNonemptyTarget(t *testing.T) {
	if _, err := (&RDataURI{}).Pack(make([]byte, 4), 0); err == nil {
		t.Fatal("empty URI target accepted")
	}
	if _, err := (&RDataURI{}).Unpack(make([]byte, 4), 0, 4); err == nil {
		t.Fatal("empty wire URI target accepted")
	}
}
