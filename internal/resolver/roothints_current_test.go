package resolver

import (
	"net"
	"testing"
)

func TestRootHintsPublishedBRoot(t *testing.T) {
	// Pinned to InterNIC named.root version 2026093001; no live network access.
	found := false
	for _, h := range RootHints() {
		for _, s := range append(append([]string{}, h.IPv4...), h.IPv6...) {
			if net.ParseIP(s) == nil {
				t.Fatalf("invalid hint %q", s)
			}
		}
		if h.Name == "b.root-servers.net." {
			found = true
			if len(h.IPv4) != 1 || h.IPv4[0] != "170.247.170.2" || len(h.IPv6) != 1 || h.IPv6[0] != "2801:1b8:10::b" {
				t.Fatalf("B-root differs from pinned published pair: %+v", h)
			}
		}
	}
	if !found {
		t.Fatal("B-root missing")
	}
}
