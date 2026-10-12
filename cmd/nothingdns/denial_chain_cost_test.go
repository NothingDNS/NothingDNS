package main

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// F706: every NXDOMAIN/NODATA denial in a signed zone rebuilt the whole
// denial chain (a walk, canonicalisation and allocation per zone name) and
// then scanned every node again to find a neighbour, so a unique-name flood
// (which bypasses the answer cache) cost O(zone size) CPU per query: 117 ms
// at 100k names, over a second at a million.
func denialCostZone(n int) *zone.Zone {
	z := zone.NewZone("example.com.")
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("h%d.example.com.", i)
		z.Records[name] = []zone.Record{{Name: name, Type: "A", TTL: 60, Class: "IN", RData: "192.0.2.1"}}
	}
	z.Records["example.com."] = []zone.Record{{Name: "example.com.", Type: "NS", TTL: 60, Class: "IN", RData: "ns.example.com."}}
	return z
}

func TestDenialCostDoesNotScaleWithZoneSize(t *testing.T) {
	const n, reps = 50000, 20
	z := denialCostZone(n)
	h := &integratedHandler{}
	h.denialRRs(z, "warm.example.com.", denialNXDomain) // first call may build the chain
	start := time.Now()
	for i := 0; i < reps; i++ {
		if rrs := h.denialRRs(z, fmt.Sprintf("nx%d.example.com.", i), denialNXDomain); len(rrs) == 0 {
			t.Fatal("no denial records")
		}
	}
	per := time.Since(start) / reps
	t.Logf("N=%d: %v per NXDOMAIN denial", n, per)
	// baseline: a few hundred microseconds; the unfixed code needs ~55 ms here
	if per > 5*time.Millisecond {
		t.Errorf("denial for a %d-name zone took %v per query (limit 5ms)", n, per)
	}
}

// The neighbour search must give the same NSEC/NSEC3 as a brute-force scan.
func TestDenialChainNeighboursMatchScan(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for round := 0; round < 20; round++ {
		z := zone.NewZone("example.com.")
		z.Records["example.com."] = []zone.Record{{Name: "example.com.", Type: "NS", TTL: 60, Class: "IN", RData: "ns.example.com."}}
		labels := []string{"a", "b", "aa", "z", "m", "mx", "_x", "*", "0", "sub", "sub.sub"}
		for i := 0; i < 40; i++ {
			name := labels[r.Intn(len(labels))] + "." + labels[r.Intn(len(labels))] + ".example.com."
			z.Records[name] = []zone.Record{{Name: name, Type: "A", TTL: 60, Class: "IN", RData: "192.0.2.1"}}
		}
		for _, params := range []*nsec3Params{nil, {iterations: 2, salt: []byte{1, 2}}} {
			c := buildDenialChain(z, nil, params, &nsec3HashMemo{})
			for i := 0; i < 60; i++ {
				q := labels[r.Intn(len(labels))] + fmt.Sprintf("%d.", r.Intn(5)) + labels[r.Intn(len(labels))] + ".example.com."
				if params == nil {
					for node := range c.nodes {
						want := scanNext(c, node)
						if got := c.nsecData(node).Next; got != want {
							t.Fatalf("next of %s = %s, want %s", node, got, want)
						}
					}
					if got, want := c.nsecCovering(q).Owner, scanCovering(c, q); got != want {
						t.Fatalf("covering %s = %s, want %s", q, got, want)
					}
				} else {
					got, ok := c.nsec3Covering(q)
					want, wok := scanNSEC3Covering(c, q)
					if got != want || ok != wok {
						t.Fatalf("nsec3 covering %s = %s/%v, want %s/%v", q, got, ok, want, wok)
					}
					for member := range c.hashes {
						rr := c.nsec3Record(member, 60)
						next := rr.Data.(*protocol.RDataNSEC3).NextHashed
						if string(next) != string(scanNSEC3Next(c, member)) {
							t.Fatalf("nsec3 next of %s differs", member)
						}
					}
				}
			}
		}
	}
}

// brute-force references (the previous O(n) implementations)
func scanNext(c *denialChain, owner string) string {
	next := c.origin
	for node := range c.nodes {
		if canonicalNameCompare(node, owner) > 0 && (next == c.origin || canonicalNameCompare(node, next) < 0) {
			next = node
		}
	}
	return next
}

func scanCovering(c *denialChain, name string) string {
	name = canonicalize(name)
	prev, last := "", c.origin
	for node := range c.nodes {
		if canonicalNameCompare(node, name) < 0 && (prev == "" || canonicalNameCompare(node, prev) > 0) {
			prev = node
		}
		if canonicalNameCompare(node, last) > 0 {
			last = node
		}
	}
	if prev == "" {
		prev = last
	}
	return prev
}

func scanNSEC3Covering(c *denialChain, name string) (string, bool) {
	h, ok := c.hash(canonicalize(name))
	if !ok || len(c.hashes) == 0 {
		return "", false
	}
	var prev, last string
	var prevH, lastH []byte
	for member, mh := range c.hashes {
		if string(mh) < string(h) && (prevH == nil || string(mh) > string(prevH)) {
			prev, prevH = member, mh
		}
		if lastH == nil || string(mh) > string(lastH) {
			last, lastH = member, mh
		}
	}
	if prevH == nil {
		return last, true
	}
	return prev, true
}

func scanNSEC3Next(c *denialChain, owner string) []byte {
	h := c.hashes[owner]
	var next []byte
	for _, other := range c.hashes {
		if string(other) > string(h) && (next == nil || string(other) < string(next)) {
			next = other
		}
	}
	if next == nil {
		for _, other := range c.hashes {
			if next == nil || string(other) < string(next) {
				next = other
			}
		}
	}
	return next
}

// The cached chain is reused while the zone is unchanged and rebuilt after
// any edit made under z.Lock/Unlock.
func TestDenialChainCacheFollowsZoneChanges(t *testing.T) {
	z := denialCostZone(10)
	h := &integratedHandler{}
	c1 := h.denialChainFor(z)
	if c2 := h.denialChainFor(z); c2 != c1 {
		t.Fatal("unchanged zone rebuilt its chain")
	}
	z.Lock()
	z.Records["new.example.com."] = []zone.Record{{Name: "new.example.com.", Type: "A", TTL: 60, Class: "IN", RData: "192.0.2.9"}}
	z.Unlock()
	c3 := h.denialChainFor(z)
	if c3 == c1 {
		t.Fatal("edited zone served the stale chain")
	}
	if _, ok := c3.nodes["new.example.com."]; !ok {
		t.Fatal("new name missing from the rebuilt chain")
	}
	if other := h.denialChainFor(zone.NewZone("other.org.")); other == c3 {
		t.Fatal("different zones share a chain")
	}
}
