package protocol

import "testing"

func TestRDataOPTRejectsInvalidOffsets(t *testing.T) {
	packRecord := &RDataOPT{Options: []EDNS0Option{{Code: OptionCodeNSID}}}
	for _, offset := range []int{-1, 5} {
		if n, err := packRecord.Pack(make([]byte, 4), offset); err == nil || n != 0 {
			t.Fatalf("Pack offset %d = (%d, %v), want (0, error)", offset, n, err)
		}
	}

	for _, offset := range []int{-1, 5} {
		if n, err := (&RDataOPT{}).Unpack(make([]byte, 4), offset, 0); err == nil || n != 0 {
			t.Fatalf("Unpack offset %d = (%d, %v), want (0, error)", offset, n, err)
		}
	}
	if n, err := (&RDataOPT{}).Unpack(make([]byte, 4), 2, 3); err == nil || n != 0 {
		t.Fatalf("Unpack overflowing RDLENGTH = (%d, %v), want (0, error)", n, err)
	}
}

func TestRDataOPTPackEnforcesOptionLimit_F817(t *testing.T) {
	opt := &RDataOPT{Options: make([]EDNS0Option, MaxEDNS0Options)}
	buf := make([]byte, opt.Len())
	if _, err := opt.Pack(buf, 0); err != nil {
		t.Fatalf("Pack at option limit: %v", err)
	}

	opt.Options = append(opt.Options, EDNS0Option{})
	buf = make([]byte, opt.Len())
	if _, err := opt.Pack(buf, 0); err == nil {
		t.Fatal("Pack above option limit succeeded")
	}
}
