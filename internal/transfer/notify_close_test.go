package transfer

import (
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func TestNOTIFYSlaveHandlerHandleAfterCloseDoesNotPanic(t *testing.T) {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{Serial: 10}
	h := NewNOTIFYSlaveHandler(map[string]*zone.Zone{"example.com.": z})
	if err := h.AddNotifyAllowed("127.0.0.1/32"); err != nil {
		t.Fatal(err)
	}
	h.Close()

	origin, _ := protocol.ParseName("example.com.")
	mname, _ := protocol.ParseName("ns1.example.com.")
	rname, _ := protocol.ParseName("admin.example.com.")
	req := &protocol.Message{
		Header:    protocol.Header{Flags: protocol.Flags{Opcode: protocol.OpcodeNotify}},
		Questions: []*protocol.Question{{Name: origin, QType: protocol.TypeSOA, QClass: protocol.ClassIN}},
		Answers: []*protocol.ResourceRecord{{
			Name: origin, Type: protocol.TypeSOA, Class: protocol.ClassIN,
			Data: &protocol.RDataSOA{MName: mname, RName: rname, Serial: 11},
		}},
	}

	resp, err := h.HandleNOTIFY(req, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("HandleNOTIFY after Close: %v", err)
	}
	if resp == nil || resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Fatalf("HandleNOTIFY after Close response = %#v", resp)
	}
}
