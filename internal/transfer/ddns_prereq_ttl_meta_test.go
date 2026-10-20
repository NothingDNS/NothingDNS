package transfer

import (
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// RFC 2136 §3.2.3: a value-dependent (class IN) prerequisite RR carries TTL 0.
// §3.4.1.2: a meta-type (IXFR, AXFR, MAILB, MAILA) is never a valid update RR.
// Either makes the message FORMERR, and nothing in it is applied.
func TestHandleUpdateRejectsPrerequisiteTTLAndMetaTypes(t *testing.T) {
	key := &TSIGKey{Name: "ddns.example.", Algorithm: HmacSHA256, Secret: []byte("meta-type-secret-0123456789abcde")}
	ip := net.ParseIP("127.0.0.1")

	// The prerequisite RRset must equal the zone's whole www A RRset (two RRs).
	wwwA := func(class uint16, ttl uint32) []*protocol.ResourceRecord {
		n, _ := protocol.ParseName("www.example.com.")
		var out []*protocol.ResourceRecord
		for _, last := range []byte{1, 2} {
			out = append(out, &protocol.ResourceRecord{Name: n, Type: protocol.TypeA, Class: class, TTL: ttl,
				Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, last}}})
		}
		return out
	}
	meta := func(class uint16, rrtype uint16) *protocol.ResourceRecord {
		n, _ := protocol.ParseName("www.example.com.")
		return &protocol.ResourceRecord{Name: n, Type: rrtype, Class: class, TTL: 0,
			Data: &protocol.RDataRaw{TypeVal: rrtype}}
	}
	deleteWWW := func() *protocol.ResourceRecord {
		n, _ := protocol.ParseName("www.example.com.")
		return &protocol.ResourceRecord{Name: n, Type: protocol.TypeA, Class: protocol.ClassANY,
			Data: &protocol.RDataRaw{TypeVal: protocol.TypeA}}
	}
	send := func(prereqs, updates []*protocol.ResourceRecord) (uint8, int) {
		z := policyZone()
		h := NewDynamicDNSHandler(map[string]*zone.Zone{"example.com.": z})
		ks := NewKeyStore()
		ks.AddKey(key)
		h.SetKeyStore(ks)
		h.AllowKeyUpdate("ddns.example.", "example.com.")
		req := policyUpdate(t, nil, updates...)
		req.Answers = prereqs
		tsig, err := SignMessage(req, key, 300)
		if err != nil {
			t.Fatal(err)
		}
		req.Additionals = append(req.Additionals, tsig)
		resp, _, err := h.HandleUpdateRequest(req, ip, nil)
		if err != nil {
			t.Fatal(err)
		}
		return resp.Header.Flags.RCODE, len(z.Records["www.example.com."])
	}

	// Control: a class-IN prerequisite with TTL 0 that holds lets the update run.
	if rcode, n := send(wwwA(protocol.ClassIN, 0), []*protocol.ResourceRecord{deleteWWW()}); rcode != protocol.RcodeSuccess || n != 0 {
		t.Fatalf("control: rcode=%d www records=%d, want success and the RRset deleted", rcode, n)
	}

	if rcode, n := send(wwwA(protocol.ClassIN, 300), []*protocol.ResourceRecord{deleteWWW()}); rcode != protocol.RcodeFormatError || n != 2 {
		t.Errorf("FAIL class-IN prerequisite with TTL 300: rcode=%d www records=%d, want FORMERR and an untouched zone", rcode, n)
	}

	for _, rrtype := range []uint16{protocol.TypeAXFR, protocol.TypeIXFR, protocol.TypeMAILA, protocol.TypeMAILB} {
		for _, class := range []uint16{protocol.ClassIN, protocol.ClassANY, protocol.ClassNONE} {
			updates := []*protocol.ResourceRecord{deleteWWW(), meta(class, rrtype)}
			if rcode, n := send(nil, updates); rcode != protocol.RcodeFormatError || n != 2 {
				t.Errorf("FAIL %s update RR of class %d: rcode=%d www records=%d, want FORMERR and an untouched zone",
					protocol.TypeString(rrtype), class, rcode, n)
			}
		}
	}
}
