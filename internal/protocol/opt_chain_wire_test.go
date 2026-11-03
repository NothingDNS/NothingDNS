package protocol

import (
	"bytes"
	"testing"
)

func TestEDNS0ChainRFC7901WireFormat(t *testing.T) {
	want := []byte{3, 'c', 'o', 'm', 0}
	if got := NewEDNS0Chain([]string{"Com."}).Pack(); !bytes.Equal(got, want) {
		t.Fatalf("CHAIN wire = %x, want %x", got, want)
	}

	discovery, err := UnpackEDNS0Chain(nil)
	if err != nil || len(discovery.ChainNS) != 0 {
		t.Fatalf("discovery decode = (%+v, %v), want empty success", discovery, err)
	}

	decoded, err := UnpackEDNS0Chain(want)
	if err != nil {
		t.Fatalf("closest trust point decode: %v", err)
	}
	if len(decoded.ChainNS) != 1 || decoded.ChainNS[0] != "com." {
		t.Fatalf("decoded CHAIN = %#v, want com.", decoded.ChainNS)
	}

	malformed := [][]byte{
		{3, 'c', 'o', 'm'},       // missing root
		{3, 'c', 'o', 'm', 0, 0}, // second terminator
		{0xc0, 0},                // compression pointer
		{3, 'c', 'o', 'm', 0, 3, 'n', 'e', 't', 0}, // second name
	}
	for _, wire := range malformed {
		if _, err := UnpackEDNS0Chain(wire); err == nil {
			t.Errorf("accepted malformed CHAIN payload %x", wire)
		}
	}
	if got := NewEDNS0Chain([]string{"com.", "net."}).Pack(); got != nil {
		t.Fatalf("multi-name CHAIN encoded non-RFC payload %x", got)
	}
}
