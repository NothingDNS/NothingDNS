package transfer

// F684: a TXT record split across character-strings keeps its boundaries when a
// slave stores it from the wire (recordFromRR) and the zone later serves it.

import (
	"bytes"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestSlaveTXTMultiStringKeepsBoundaries(t *testing.T) {
	rd := []byte{20}
	rd = append(rd, "v=DKIM1;k=rsa;p=MIIB"...)
	rd = append(rd, 8)
	rd = append(rd, "IjANBgkq"...)
	wire := append([]byte{0, 0, 16, 0, 1, 0, 0, 0, 60, 0, byte(len(rd))}, rd...)
	rr, _, err := protocol.UnpackResourceRecord(wire, 0)
	if err != nil {
		t.Fatal(err)
	}
	rec := recordFromRR(rr)
	d := protocol.ParseRDataText(rec.Type, rec.RData)
	if d == nil {
		t.Fatalf("stored %q does not parse", rec.RData)
	}
	buf := make([]byte, 512)
	n, _ := d.Pack(buf, 0)
	if !bytes.Equal(buf[:n], rd) {
		t.Fatalf("served %x, want %x (stored %q)", buf[:n], rd, rec.RData)
	}
}
