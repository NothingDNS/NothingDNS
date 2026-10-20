package transfer

import (
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// RFC 2136 §3.2.3 and §3.4.1.2: an ANY- or NONE-class RR carries TTL 0, an
// ANY-class RR carries no RDATA, and a prerequisite RR of either class carries
// no RDATA; a message that breaks this is FORMERR and changes nothing.
func TestHandleUpdateRejectsMalformedAnyNoneRRs(t *testing.T) {
	key := &TSIGKey{Name: "ddns.example.", Algorithm: HmacSHA256, Secret: []byte("any-none-secret-0123456789abcdef")}
	ip := net.ParseIP("127.0.0.1")

	rr := func(class uint16, rrtype uint16, ttl uint32, withData bool) *protocol.ResourceRecord {
		n, _ := protocol.ParseName("www.example.com.")
		r := &protocol.ResourceRecord{Name: n, Type: rrtype, Class: class, TTL: ttl}
		r.Data = &protocol.RDataRaw{TypeVal: rrtype} // RDLENGTH 0
		if withData {
			r.Data = &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}}
		}
		return r
	}
	send := func(prereqs, updates []*protocol.ResourceRecord) (uint8, *zone.Zone) {
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
		return resp.Header.Flags.RCODE, z
	}
	wwwA := func(z *zone.Zone) int { return len(z.Records["www.example.com."]) }

	// Controls: well-formed ANY / NONE RRs are applied.
	if rcode, z := send(nil, []*protocol.ResourceRecord{rr(protocol.ClassANY, protocol.TypeA, 0, false)}); rcode != protocol.RcodeSuccess || wwwA(z) != 0 {
		t.Fatalf("control delete-RRset: rcode=%d records=%d", rcode, wwwA(z))
	}
	if rcode, z := send(nil, []*protocol.ResourceRecord{rr(protocol.ClassNONE, protocol.TypeA, 0, true)}); rcode != protocol.RcodeSuccess || wwwA(z) != 1 {
		t.Fatalf("control delete-RR: rcode=%d records=%d", rcode, wwwA(z))
	}

	for _, tc := range []struct {
		name            string
		prereqs, update []*protocol.ResourceRecord
	}{
		{"update ANY with TTL", nil, []*protocol.ResourceRecord{rr(protocol.ClassANY, protocol.TypeA, 300, false)}},
		{"update ANY with RDATA", nil, []*protocol.ResourceRecord{rr(protocol.ClassANY, protocol.TypeA, 0, true)}},
		{"update NONE with TTL", nil, []*protocol.ResourceRecord{rr(protocol.ClassNONE, protocol.TypeA, 300, true)}},
		{"prerequisite ANY with TTL", []*protocol.ResourceRecord{rr(protocol.ClassANY, protocol.TypeA, 300, false)}, nil},
		{"prerequisite ANY with RDATA", []*protocol.ResourceRecord{rr(protocol.ClassANY, protocol.TypeA, 0, true)}, nil},
		{"prerequisite NONE with TTL", []*protocol.ResourceRecord{rr(protocol.ClassNONE, protocol.TypeA, 300, false)}, nil},
		{"prerequisite NONE with RDATA", []*protocol.ResourceRecord{rr(protocol.ClassNONE, protocol.TypeA, 0, true)}, nil},
	} {
		// Pair each malformed RR with a delete that would change the zone, so a
		// message that is accepted shows as a mutation.
		updates := append([]*protocol.ResourceRecord{rr(protocol.ClassANY, protocol.TypeA, 0, false)}, tc.update...)
		if tc.update == nil {
			updates = []*protocol.ResourceRecord{rr(protocol.ClassANY, protocol.TypeA, 0, false)}
		}
		rcode, z := send(tc.prereqs, updates)
		if rcode != protocol.RcodeFormatError || wwwA(z) != 2 {
			t.Errorf("FAIL %s: rcode=%d www records=%d, want FORMERR and an untouched zone", tc.name, rcode, wwwA(z))
		}
	}
}
