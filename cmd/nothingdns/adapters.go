// NothingDNS - Resolver adapter types

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/resolver"
	"github.com/nothingdns/nothingdns/internal/upstream"
)

// dnssecResolverAdapter adapts upstream.Client or upstream.LoadBalancer to dnssec.Resolver interface
type dnssecResolverAdapter struct {
	upstream interface {
		Query(msg *protocol.Message) (*protocol.Message, error)
	}
}

// Query implements dnssec.Resolver interface
func (d *dnssecResolverAdapter) Query(ctx context.Context, name string, qtype uint16) (*protocol.Message, error) {
	parsedName, err := protocol.ParseName(name)
	if err != nil {
		return nil, fmt.Errorf("parsing name %q: %w", name, err)
	}
	// Create a query message
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1,
			Flags:   protocol.NewQueryFlags(),
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   parsedName,
				QType:  qtype,
				QClass: protocol.ClassIN,
			},
		},
	}
	return d.upstream.Query(msg)
}

// resolverTransportAdapter adapts the iterative resolver's queries to direct
// network transport. For iterative resolution, we must query specific nameservers
// directly (not through upstream forwarders), so we use StdioTransport.
type resolverTransportAdapter struct {
	inner *resolver.StdioTransport
}

func newResolverTransport(_ *upstream.Client, _ *upstream.LoadBalancer) *resolverTransportAdapter {
	return &resolverTransportAdapter{
		inner: resolver.NewStdioTransport(5 * time.Second),
	}
}

func (t *resolverTransportAdapter) QueryContext(ctx context.Context, msg *protocol.Message, addr string) (*protocol.Message, error) {
	return t.inner.QueryContext(ctx, msg, addr)
}

// resolverCacheAdapter adapts cache.Cache to the resolver.Cache interface.
type resolverCacheAdapter struct {
	cache *cache.Cache
}

func (a *resolverCacheAdapter) Get(key string) *resolver.CacheEntry {
	entry := a.cache.Get(key)
	if entry == nil {
		return nil
	}
	return &resolver.CacheEntry{
		Message:    entry.Message,
		IsNegative: entry.IsNegative,
		RCode:      entry.RCode,
	}
}

func (a *resolverCacheAdapter) Set(key string, msg *protocol.Message, ttl uint32) {
	a.cache.Set(key, msg, ttl)
}

func (a *resolverCacheAdapter) SetNegative(key string, rcode uint8) {
	a.cache.SetNegative(key, rcode)
}
