package protocol

import "testing"

func TestDNSSECTypeBitmapRejectsNonCanonicalBlocks(t *testing.T) {
	badBlocks := map[string][]byte{
		"zero length":       {0, 0},
		"length over 32":    append([]byte{0, 33}, append(make([]byte, 32), 1)...),
		"trailing zero":     {0, 2, 0x40, 0},
		"repeated window":   {0, 1, 0x40, 0, 1, 0x20},
		"descending window": {1, 1, 0x40, 0, 1, 0x20},
	}
	for name, block := range badBlocks {
		t.Run(name, func(t *testing.T) {
			nsecWire := append([]byte{0}, block...)
			if _, err := (&RDataNSEC{}).Unpack(nsecWire, 0, uint16(len(nsecWire))); err == nil {
				t.Error("NSEC accepted malformed bitmap")
			}

			nsec3Wire := append([]byte{1, 0, 0, 0, 0, 1, 0xaa}, block...)
			if _, err := (&RDataNSEC3{}).Unpack(nsec3Wire, 0, uint16(len(nsec3Wire))); err == nil {
				t.Error("NSEC3 accepted malformed bitmap")
			}
		})
	}
}

func TestDNSSECTypeBitmapAcceptsCanonicalBlocks(t *testing.T) {
	block := []byte{0, 1, 0x40, 1, 1, 0x20}
	nsecWire := append([]byte{0}, block...)
	if _, err := (&RDataNSEC{}).Unpack(nsecWire, 0, uint16(len(nsecWire))); err != nil {
		t.Fatalf("NSEC canonical bitmap: %v", err)
	}
	nsec3Wire := append([]byte{1, 0, 0, 0, 0, 1, 0xaa}, block...)
	if _, err := (&RDataNSEC3{}).Unpack(nsec3Wire, 0, uint16(len(nsec3Wire))); err != nil {
		t.Fatalf("NSEC3 canonical bitmap: %v", err)
	}
}
