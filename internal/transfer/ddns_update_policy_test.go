package transfer

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// F452 (P2-C2): per-key zone grants, the verified key returned for response
// signing, the commit hook used for Raft replication, and PlanUpdate.

func policyZone() *zone.Zone {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{Name: "example.com.", TTL: 300, MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 7}
	z.Records["example.com."] = []zone.Record{{Name: "example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns1.example.com."}}
	z.Records["www.example.com."] = []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.1"},
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.2"},
	}
	return z
}

func policyUpdate(t *testing.T, key *TSIGKey, rrs ...*protocol.ResourceRecord) *protocol.Message {
	t.Helper()
	name, _ := protocol.ParseName("example.com.")
	req := &protocol.Message{
		Header:      protocol.Header{ID: 0x452, QDCount: 1, Flags: protocol.Flags{Opcode: protocol.OpcodeUpdate}},
		Questions:   []*protocol.Question{{Name: name, QType: protocol.TypeSOA, QClass: protocol.ClassIN}},
		Authorities: rrs,
	}
	if key != nil {
		tsigRR, err := SignMessage(req, key, 300)
		if err != nil {
			t.Fatalf("SignMessage: %v", err)
		}
		req.Additionals = append(req.Additionals, tsigRR)
	}
	return req
}

func policyA(t *testing.T, name, ip string, class uint16) *protocol.ResourceRecord {
	t.Helper()
	n, _ := protocol.ParseName(name)
	var a [4]byte
	copy(a[:], net.ParseIP(ip).To4())
	ttl := uint32(300)
	if class != protocol.ClassIN {
		ttl = 0
	}
	return &protocol.ResourceRecord{Name: n, Type: protocol.TypeA, Class: class, TTL: ttl, Data: &protocol.RDataA{Address: a}}
}

func TestHandleUpdateRequest_KeyZoneGrant(t *testing.T) {
	key := &TSIGKey{Name: "ddns.example.", Algorithm: HmacSHA256, Secret: []byte("F452-policy-secret-0123456789ab!")}
	z := policyZone()
	h := NewDynamicDNSHandler(map[string]*zone.Zone{"example.com.": z})
	ks := NewKeyStore()
	ks.AddKey(key)
	h.SetKeyStore(ks)
	ip := net.ParseIP("127.0.0.1")

	// Valid key, no grant: REFUSED, key returned so the reply is signed.
	resp, got, err := h.HandleUpdateRequest(policyUpdate(t, key, policyA(t, "n.example.com.", "192.0.2.9", protocol.ClassIN)), ip, nil)
	if err != nil || resp.Header.Flags.RCODE != protocol.RcodeRefused || got != key {
		t.Fatalf("no grant: rcode=%d key=%v err=%v, want REFUSED with key", resp.Header.Flags.RCODE, got, err)
	}
	// Grant for another zone only: still REFUSED.
	h.AllowKeyUpdate("DDNS.example", "example.net")
	if resp, _, _ := h.HandleUpdateRequest(policyUpdate(t, key, policyA(t, "n.example.com.", "192.0.2.9", protocol.ClassIN)), ip, nil); resp.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Fatalf("other-zone grant: rcode=%d, want REFUSED", resp.Header.Flags.RCODE)
	}
	if len(z.Records["n.example.com."]) != 0 {
		t.Fatal("refused update changed the zone")
	}
	// Unsigned: REFUSED, no key.
	if resp, got, _ := h.HandleUpdateRequest(policyUpdate(t, nil, policyA(t, "n.example.com.", "192.0.2.9", protocol.ClassIN)), ip, nil); resp.Header.Flags.RCODE != protocol.RcodeRefused || got != nil {
		t.Fatalf("unsigned: rcode=%d key=%v, want REFUSED without key", resp.Header.Flags.RCODE, got)
	}
	// Grant (case/trailing-dot insensitive): accepted and applied locally.
	h.AllowKeyUpdate("ddns.example.", "Example.COM")
	if !h.KeyMayUpdate("ddns.example", "example.com.") || h.KeyMayUpdate("ddns.example.", "sub.example.com.") {
		t.Fatal("KeyMayUpdate: grant must match the exact zone only")
	}
	resp, got, err = h.HandleUpdateRequest(policyUpdate(t, key, policyA(t, "n.example.com.", "192.0.2.9", protocol.ClassIN)), ip, nil)
	if err != nil || resp.Header.Flags.RCODE != protocol.RcodeSuccess || got != key || len(z.Records["n.example.com."]) != 1 {
		t.Fatalf("granted: rcode=%d key=%v err=%v records=%v", resp.Header.Flags.RCODE, got, err, z.Records["n.example.com."])
	}
}

func TestHandleUpdateRequest_CommitHook(t *testing.T) {
	key := &TSIGKey{Name: "ddns.example.", Algorithm: HmacSHA256, Secret: []byte("F452-policy-secret-0123456789ab!")}
	z := policyZone()
	h := NewDynamicDNSHandler(map[string]*zone.Zone{"example.com.": z})
	ks := NewKeyStore()
	ks.AddKey(key)
	h.SetKeyStore(ks)
	h.AllowKeyUpdate("ddns.example.", "example.com.")
	ip := net.ParseIP("127.0.0.1")

	cases := []struct {
		err   error
		rcode uint8
	}{
		{nil, protocol.RcodeSuccess},
		{ErrUpdateRefused, protocol.RcodeRefused},
		{ErrPrereqFailed, protocol.RcodeNXRRSet},
		{ErrNotZone, protocol.RcodeNotZone},
		{errors.New("raft: leadership lost"), protocol.RcodeServerFailure},
	}
	for _, tc := range cases {
		var calls int
		commit := func(cz *zone.Zone, req *UpdateRequest) error {
			calls++
			if cz != z || req.ZoneName != "example.com." || req.TSIGKeyName != "ddns.example." || len(req.Updates) != 1 {
				t.Errorf("commit got zone=%p req=%+v", cz, req)
			}
			return tc.err
		}
		resp, _, err := h.HandleUpdateRequest(policyUpdate(t, key, policyA(t, "c.example.com.", "192.0.2.3", protocol.ClassIN)), ip, commit)
		if err != nil || calls != 1 || resp.Header.Flags.RCODE != tc.rcode {
			t.Fatalf("commit err %v: calls=%d rcode=%d err=%v, want rcode %d", tc.err, calls, resp.Header.Flags.RCODE, err, tc.rcode)
		}
	}
	if len(z.Records["c.example.com."]) != 0 {
		t.Fatal("commit path must not apply the update locally")
	}
	select {
	case req := <-h.GetUpdateChannel():
		t.Fatalf("commit path sent an update event: %+v", req)
	default:
	}
}

func TestPlanUpdate_DiffWithoutMutation(t *testing.T) {
	z := policyZone()
	req := &UpdateRequest{ZoneName: "example.com.", Updates: []UpdateOperation{
		{Name: "www.example.com.", Type: protocol.TypeA, RData: "192.0.2.1", Operation: UpdateOpDelete},
		{Name: "new.example.com.", Type: protocol.TypeA, TTL: 60, RData: "192.0.2.50", Operation: UpdateOpAdd},
		{Name: "www.example.com.", Type: protocol.TypeA, TTL: 300, RData: "192.0.2.2", Operation: UpdateOpAdd}, // duplicate: no-op
		{Name: "example.com.", Type: protocol.TypeNS, Operation: UpdateOpDeleteRRSet},                          // apex NS: ignored
	}}
	removed, added, soa, err := PlanUpdate(z, req)
	if err != nil || soa {
		t.Fatalf("PlanUpdate: err=%v soa=%v", err, soa)
	}
	if len(removed) != 1 || removed[0].Name != "www.example.com." || removed[0].RData != "192.0.2.1" {
		t.Errorf("removed = %+v", removed)
	}
	if len(added) != 1 || added[0].Name != "new.example.com." || added[0].RData != "192.0.2.50" || added[0].TTL != 60 {
		t.Errorf("added = %+v", added)
	}
	if z.SOA.Serial != 7 || len(z.Records["www.example.com."]) != 2 || len(z.Records["new.example.com."]) != 0 {
		t.Errorf("PlanUpdate mutated the zone: serial=%d www=%v", z.SOA.Serial, z.Records["www.example.com."])
	}

	// A failed prerequisite is reported like ApplyUpdate.
	pre := &UpdateRequest{ZoneName: "example.com.", Prerequisites: []UpdatePrerequisite{{Name: "nx.example.com.", Type: protocol.TypeA, Condition: PrecondExists}}}
	if _, _, _, err := PlanUpdate(z, pre); !errors.Is(err, ErrPrereqFailed) {
		t.Errorf("prereq: err=%v, want ErrPrereqFailed", err)
	}
	// SOA add is flagged.
	soaReq := &UpdateRequest{ZoneName: "example.com.", Updates: []UpdateOperation{{Name: "example.com.", Type: protocol.TypeSOA, TTL: 300, RData: "ns1.example.com. admin.example.com. 99 3600 600 86400 300", Operation: UpdateOpAdd}}}
	if _, _, soa, err := PlanUpdate(z, soaReq); err != nil || !soa {
		t.Errorf("SOA add: soa=%v err=%v, want flagged", soa, err)
	}
	if !strings.HasPrefix(z.SOA.MName, "ns1") || z.SOA.Serial != 7 {
		t.Error("SOA plan mutated the zone")
	}
}
