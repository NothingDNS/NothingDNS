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
