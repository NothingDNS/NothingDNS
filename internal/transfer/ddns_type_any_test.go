package transfer

import (
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// RFC 2136 §3.4.1.3: TYPE ANY is valid in the update section only with CLASS
// ANY (delete all RRsets at a name); with CLASS IN or NONE the message is
// FORMERR and nothing in it is applied.
func TestHandleUpdateTypeANYRequiresClassANY(t *testing.T) {
	key := &TSIGKey{Name: "ddns.example.", Algorithm: HmacSHA256, Secret: []byte("type-any-secret-0123456789abcdef")}
	ip := net.ParseIP("127.0.0.1")

	anyType := func(class uint16) *protocol.ResourceRecord {
		n, _ := protocol.ParseName("www.example.com.")
		return &protocol.ResourceRecord{Name: n, Type: protocol.TypeANY, Class: class,
			Data: &protocol.RDataRaw{TypeVal: protocol.TypeANY}}
	}
	deleteOther := func() *protocol.ResourceRecord {
		n, _ := protocol.ParseName("other.example.com.")
		return &protocol.ResourceRecord{Name: n, Type: protocol.TypeA, Class: protocol.ClassANY,
			Data: &protocol.RDataRaw{TypeVal: protocol.TypeA}}
	}
	send := func(updates ...*protocol.ResourceRecord) (uint8, *zone.Zone) {
		z := policyZone()
		z.Records["other.example.com."] = []zone.Record{{Name: "other.example.com.", Type: "A", TTL: 300, Class: "IN", RData: "192.0.2.77"}}
		h := NewDynamicDNSHandler(map[string]*zone.Zone{"example.com.": z})
		ks := NewKeyStore()
		ks.AddKey(key)
		h.SetKeyStore(ks)
		h.AllowKeyUpdate("ddns.example.", "example.com.")
		resp, _, err := h.HandleUpdateRequest(policyUpdate(t, key, updates...), ip, nil)
		if err != nil {
			t.Fatal(err)
		}
		return resp.Header.Flags.RCODE, z
	}

	// Control: ANY/ANY deletes every RRset at the name.
	if rcode, z := send(anyType(protocol.ClassANY)); rcode != protocol.RcodeSuccess || len(z.Records["www.example.com."]) != 0 {
		t.Fatalf("control: rcode=%d www records=%d, want success and the name deleted", rcode, len(z.Records["www.example.com."]))
	}

	for _, class := range []uint16{protocol.ClassIN, protocol.ClassNONE} {
		// A well-formed delete rides along: if the message were accepted it would run.
		rcode, z := send(deleteOther(), anyType(class))
		if rcode != protocol.RcodeFormatError || len(z.Records["other.example.com."]) != 1 {
			t.Errorf("FAIL TYPE ANY with class %d: rcode=%d other records=%d, want FORMERR and an untouched zone",
				class, rcode, len(z.Records["other.example.com."]))
		}
	}
}
