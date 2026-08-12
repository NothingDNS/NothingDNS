package main

import (
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
)

// namedNegativeCacheShape and namedNegativeTTLCacheShape mirror the optional
// interfaces the resolver type-asserts against (resolver.namedNegativeCache /
// namedNegativeTTLCache). Those are unexported, so they cannot be referenced
// from this package directly and are duplicated structurally here.
//
// The resolver discovers these methods by type assertion, which fails
// silently: if resolverCacheAdapter ever loses one, the resolver quietly falls
// back to the unnamed setter, the query name stops being retained, and
// operator-driven InvalidatePattern goes back to skipping every resolver
// negative — with no other test failing. These assertions turn that silent
// regression into a compile error.
type namedNegativeCacheShape interface {
	SetNegativeNamed(key, name string, rcode uint8)
}

type namedNegativeTTLCacheShape interface {
	SetNegativeWithTTLNamed(key, name string, rcode uint8, ttl uint32)
}

var (
	_ namedNegativeCacheShape    = (*resolverCacheAdapter)(nil)
	_ namedNegativeTTLCacheShape = (*resolverCacheAdapter)(nil)
)

// TestResolverCacheAdapter_NamedNegativeWiring exercises both named setters
// through the adapter and proves the retained name makes the entry reachable
// by pattern invalidation under the resolver's own "name:qtype" key format —
// the format ExtractQueryInfo cannot parse.
func TestResolverCacheAdapter_NamedNegativeWiring(t *testing.T) {
	c := cache.New(cache.Config{
		Capacity:   128,
		DefaultTTL: 60 * time.Second,
		MinTTL:     time.Second,
		MaxTTL:     300 * time.Second,
	})
	a := &resolverCacheAdapter{cache: c}

	a.SetNegativeNamed("plain.example.com.:1", "plain.example.com.", 3)
	a.SetNegativeWithTTLNamed("ttl.example.com.:28", "ttl.example.com.", 3, 30)

	invalidated := c.InvalidatePattern("example.com")
	if len(invalidated) != 2 {
		t.Fatalf("expected both adapter-stored negatives to be invalidated, got %v", invalidated)
	}
}
