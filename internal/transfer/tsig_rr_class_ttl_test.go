package transfer

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// F710: the TSIG RR's CLASS and TTL are not covered by the MAC (the digest
// uses the mandated constants ANY and 0), so a record with another CLASS or a
// non-zero TTL verified. RFC 8945 §4.2 requires CLASS ANY and TTL 0.
func TestVerifyTSIGRequiresClassAnyTTLZero(t *testing.T) {
	key, err := ParseTSIGKey("xfr-key.", HmacSHA256, "c2VjcmV0c2VjcmV0c2VjcmV0")
	if err != nil {
		t.Fatal(err)
	}
	name, _ := protocol.ParseName("www.example.com.")
	signed := func() *protocol.Message {
		msg := &protocol.Message{
			Header:    protocol.Header{ID: 0x1234, QDCount: 1, Flags: protocol.Flags{RD: true}},
			Questions: []*protocol.Question{{Name: name, QType: protocol.TypeA, QClass: protocol.ClassIN}},
		}
		rr, err := SignMessage(msg, key, 300)
		if err != nil {
			t.Fatal(err)
		}
		msg.Additionals = append(msg.Additionals, rr)
		msg.Header.ARCount = 1
		buf := make([]byte, 1024)
		n, err := msg.Pack(buf)
		if err != nil {
			t.Fatal(err)
		}
		m, err := protocol.UnpackMessage(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	if err := VerifyMessage(signed(), key, nil); err != nil {
		t.Fatalf("control: well-formed TSIG rejected: %v", err)
	}
	m := signed()
	m.Additionals[len(m.Additionals)-1].Class = protocol.ClassIN
	if err := VerifyMessage(m, key, nil); err == nil {
		t.Error("TSIG with CLASS IN verified")
	}
	m = signed()
	m.Additionals[len(m.Additionals)-1].TTL = 3600
	if err := VerifyMessage(m, key, nil); err == nil {
		t.Error("TSIG with TTL 3600 verified")
	}
}
