package cache

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestNSECCacheLookupReturnsDetachedProof(t *testing.T) {
	nc := cnameNSECFixture(t, []uint16{protocol.TypeA, protocol.TypeRRSIG, protocol.TypeNSEC})

	first := nc.Lookup("alias.example.com.", protocol.TypeAAAA)
	if first == nil || len(first.Authorities) < 2 {
		t.Fatalf("expected synthesized NODATA proof, got %#v", first)
	}
	proof, ok := first.Authorities[len(first.Authorities)-1].Data.(*protocol.RDataNSEC)
	if !ok || len(proof.TypeBitMap) == 0 {
		t.Fatalf("missing NSEC proof: %#v", first.Authorities)
	}
	proof.TypeBitMap[0] = protocol.TypeAAAA

	second := nc.Lookup("alias.example.com.", protocol.TypeAAAA)
	if second == nil {
		t.Fatal("caller mutation changed the cached NSEC bitmap")
	}
	secondProof, ok := second.Authorities[len(second.Authorities)-1].Data.(*protocol.RDataNSEC)
	if !ok || len(secondProof.TypeBitMap) == 0 || secondProof.TypeBitMap[0] != protocol.TypeA {
		t.Fatalf("cached proof was mutated through prior result: %#v", secondProof)
	}
}
