package transfer

import (
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// RFC 2136 §3.4.1.2 / §3.2.3: an UPDATE-section or prerequisite RR whose CLASS
// is neither the zone's class nor ANY/NONE makes the message FORMERR. The
// handler treated every other class as an add of an IN record, so a CH or HS RR
// was stored as an IN record.
func TestHandleUpdateRejectsForeignClassRRs(t *testing.T) {
	key := &TSIGKey{Name: "ddns.example.", Algorithm: HmacSHA256, Secret: []byte("class-test-secret-0123456789abc!")}
	newHandler := func() (*DynamicDNSHandler, *zone.Zone) {
		z := policyZone()
		h := NewDynamicDNSHandler(map[string]*zone.Zone{"example.com.": z})
		ks := NewKeyStore()
		ks.AddKey(key)
		h.SetKeyStore(ks)
		h.AllowKeyUpdate("ddns.example.", "example.com.")
		return h, z
	}
	ip := net.ParseIP("127.0.0.1")

	// Control: an IN-class add is applied.
	h, z := newHandler()
	resp, _, err := h.HandleUpdateRequest(policyUpdate(t, key, policyA(t, "ok.example.com.", "192.0.2.50", protocol.ClassIN)), ip, nil)
	if err != nil || resp.Header.Flags.RCODE != protocol.RcodeSuccess || len(z.Records["ok.example.com."]) != 1 {
		t.Fatalf("control: rcode=%d err=%v records=%v", resp.Header.Flags.RCODE, err, z.Records["ok.example.com."])
	}

	// A CH-class add in the update section.
	h, z = newHandler()
	chRR := policyA(t, "ch.example.com.", "192.0.2.51", protocol.ClassCH)
	chRR.TTL = 300
	resp, _, err = h.HandleUpdateRequest(policyUpdate(t, key, chRR), ip, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Flags.RCODE != protocol.RcodeFormatError || len(z.Records["ch.example.com."]) != 0 {
		t.Fatalf("FAIL: CH-class update RR: rcode=%d, records=%+v; want FORMERR and no record", resp.Header.Flags.RCODE, z.Records["ch.example.com."])
	}
}
