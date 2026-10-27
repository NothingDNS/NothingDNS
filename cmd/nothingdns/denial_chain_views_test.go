package main

import (
	"fmt"
	"testing"

	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// Split-horizon views hold zones of the same origin. Each keeps its own cached
// denial chain: sharing one cache entry rebuilt the chain — a walk of the
// whole zone — on every negative answer that alternated between views (F744).
func TestDenialChainCachedPerViewZone(t *testing.T) {
	h := newTestHandler()
	h.zoneSigners = map[string]*dnssec.Signer{"example.com.": dnssecRegSigner(t, "example.com.")}
	view := func() *zone.Zone {
		z := zone.NewZone("example.com.")
		z.Records["example.com."] = []zone.Record{{Name: "example.com.", Type: "SOA", TTL: 300, RData: "ns1.example.com. h.example.com. 1 3600 600 604800 300"}}
		for i := 0; i < 10; i++ {
			name := fmt.Sprintf("h%d.example.com.", i)
			z.Records[name] = []zone.Record{{Name: name, Type: "A", TTL: 300, RData: "192.0.2.1"}}
		}
		return z
	}
	internal, external := view(), view()
	ci, ce := h.denialChainFor(internal), h.denialChainFor(external)
	if h.denialChainFor(internal) != ci || h.denialChainFor(external) != ce {
		t.Fatal("alternating views rebuilt their denial chains")
	}
	if ci == ce {
		t.Fatal("two view zones share one denial chain")
	}
}
