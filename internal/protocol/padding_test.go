package protocol

import "testing"

func TestPadResponseStaysWithinLimit(t *testing.T) {
	for _, tc := range []struct {
		packed, max int
		want        bool
	}{
		{100, 65535, true},
		{65531, 65535, true}, // room for the option header only
		{65532, 65535, false},
	} {
		m := &Message{}
		m.SetEDNS0(4096, false)
		if got := PadResponse(m, tc.packed, tc.max); got != tc.want {
			t.Fatalf("PadResponse(%d, %d) = %v, want %v", tc.packed, tc.max, got, tc.want)
		}
		if !tc.want {
			continue
		}
		pad := m.GetOPT().Data.(*RDataOPT).GetOption(OptionCodePadding)
		if total := tc.packed + 4 + len(pad.Data); total > tc.max {
			t.Fatalf("padded size %d exceeds %d", total, tc.max)
		}
	}
}

func TestPadResponseToFollowsTheQuery(t *testing.T) {
	plain := &Message{}
	plain.SetEDNS0(1232, false)
	if PadResponseTo(plain, &Message{}, 50, 65535) {
		t.Fatal("answer to an unpadded query was padded")
	}

	padded := &Message{}
	padded.SetEDNS0(1232, false)
	padded.GetOPT().Data.(*RDataOPT).AddOption(OptionCodePadding, nil)
	resp := &Message{} // no OPT, as in a filtered answer
	if !PadResponseTo(padded, resp, 50, 65535) {
		t.Fatal("answer to a padded query was not padded")
	}
	if !HasPaddingOption(resp) {
		t.Fatal("padded answer carries no Padding option")
	}
}

func TestPaddingHelpersRejectInvalidBounds(t *testing.T) {
	if PadResponse(nil, 0, 512) {
		t.Fatal("PadResponse accepted nil message")
	}
	m := &Message{}
	m.SetEDNS0(1232, false)
	for _, tc := range []struct{ packed, max int }{
		{-1, 512},
		{0, -1},
		{513, 512},
		{0, 3},
	} {
		if PadResponse(m, tc.packed, tc.max) {
			t.Errorf("PadResponse(%d, %d) accepted invalid bounds", tc.packed, tc.max)
		}
	}

	query := &Message{}
	query.SetEDNS0(1232, false)
	query.GetOPT().Data.(*RDataOPT).AddOption(OptionCodePadding, nil)
	for _, tc := range []struct{ packed, max int }{
		{-1, 512},
		{0, -1},
		{513, 512},
		{0, 14},
	} {
		resp := &Message{}
		if PadResponseTo(query, resp, tc.packed, tc.max) {
			t.Errorf("PadResponseTo(%d, %d) accepted invalid bounds", tc.packed, tc.max)
		}
		if resp.GetOPT() != nil {
			t.Errorf("PadResponseTo(%d, %d) mutated rejected response", tc.packed, tc.max)
		}
	}
}
