package dnssec

import (
	"slices"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// SignZone with NSEC3 publishes one apex NSEC3PARAM (RFC 5155 §7.3), signed
// and listed in the apex NSEC3 bitmap, with the SOA's TTL; an NSEC zone has
// none, and a zone that already holds one is not given a second (F758).
func TestSignZoneNSEC3Param(t *testing.T) {
	sign := func(nsec3 bool, extra ...*protocol.ResourceRecord) []*protocol.ResourceRecord {
		cfg := DefaultSignerConfig()
		cfg.NSEC3Enabled = nsec3
		cfg.NSEC3Iterations = 0
		cfg.NSEC3Salt = []byte{0xab, 0xcd}
		s := NewSigner("p3.test.", cfg)
		for _, ksk := range []bool{true, false} {
			k, err := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, ksk)
			if err != nil {
				t.Fatal(err)
			}
			s.SetKeyState(k.KeyTag, KeyStateActive)
		}
		n := func(x string) *protocol.Name { y, _ := protocol.ParseName(x); return y }
		soa, _ := protocol.NewResourceRecord("p3.test.", protocol.TypeSOA, protocol.ClassIN, 1234, &protocol.RDataSOA{MName: n("ns1.p3.test."), RName: n("h.p3.test."), Serial: 1, Minimum: 300})
		a, _ := protocol.NewResourceRecord("www.p3.test.", protocol.TypeA, protocol.ClassIN, 300, &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}})
		out, err := s.SignZone(append([]*protocol.ResourceRecord{soa, a}, extra...))
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	count := func(rrs []*protocol.ResourceRecord) (params int, ttl uint32, salt []byte, signed, inBitmap bool) {
		for _, rr := range rrs {
			switch d := rr.Data.(type) {
			case *protocol.RDataNSEC3PARAM:
				params++
				ttl, salt = rr.TTL, d.Salt
			case *protocol.RDataRRSIG:
				signed = signed || d.TypeCovered == protocol.TypeNSEC3PARAM
			case *protocol.RDataNSEC3:
				inBitmap = inBitmap || slices.Contains(d.TypeBitMap, protocol.TypeNSEC3PARAM)
			}
		}
		return
	}
	if p, ttl, salt, signed, bm := count(sign(true)); p != 1 || ttl != 1234 || !slices.Equal(salt, []byte{0xab, 0xcd}) || !signed || !bm {
		t.Fatalf("NSEC3 zone: params=%d ttl=%d salt=%x signed=%v bitmap=%v", p, ttl, salt, signed, bm)
	}
	if p, _, _, _, _ := count(sign(false)); p != 0 {
		t.Fatalf("NSEC zone got %d NSEC3PARAM", p)
	}
	apex, _ := protocol.ParseName("p3.test.")
	existing := &protocol.ResourceRecord{Name: apex, Type: protocol.TypeNSEC3PARAM, Class: protocol.ClassIN, TTL: 60, Data: &protocol.RDataNSEC3PARAM{HashAlgorithm: 1, Salt: []byte{0xab, 0xcd}}}
	if p, _, _, _, _ := count(sign(true, existing)); p != 1 {
		t.Fatalf("zone with an NSEC3PARAM got %d", p)
	}
}
