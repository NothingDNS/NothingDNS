package transfer

// F688: a type the server does not model (RFC 3597) transferred to a slave is stored
// as \# <len> <hex> and must still be served.

import (
	"bytes"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// wire RR of type tp with rdata rd -> what a slave stores -> what is served.
func f688Served(t *testing.T, tp uint16, rd []byte) []byte {
	wire := append([]byte{0, byte(tp >> 8), byte(tp), 0, 1, 0, 0, 0, 60, byte(len(rd) >> 8), byte(len(rd))}, rd...)
	rr, _, err := protocol.UnpackResourceRecord(wire, 0)
	if err != nil {
		t.Fatalf("%v", err)
	}
	rec := recordFromRR(rr)
	d := protocol.ParseRDataText(rec.Type, rec.RData)
	if d == nil {
		return nil
	}
	b := make([]byte, 4096)
	n, _ := d.Pack(b, 0)
	return b[:n]
}

func TestSlaveUnknownTypeServed(t *testing.T) {
	// control: a modelled type round-trips
	if got := f688Served(t, protocol.TypeA, []byte{192, 0, 2, 1}); !bytes.Equal(got, []byte{192, 0, 2, 1}) {
		t.Fatalf("control A: %x", got)
	}
	for _, c := range []struct {
		tp uint16
		rd []byte
	}{{65280, []byte{1, 2, 3, 4}}, {999, []byte{9}}, {1234, nil}} {
		got := f688Served(t, c.tp, c.rd)
		if !bytes.Equal(got, c.rd) || (c.rd == nil && got == nil) {
			t.Errorf("TYPE%d served %x (nil=%v), want %x", c.tp, got, got == nil, c.rd)
		}
	}
}
