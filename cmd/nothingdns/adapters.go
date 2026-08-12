// NothingDNS - Resolver adapter types

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/quic"
	"github.com/nothingdns/nothingdns/internal/resolver"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/upstream"
)

// dnssecResolverAdapter adapts upstream.Client or upstream.LoadBalancer to dnssec.Resolver interface
type dnssecResolverAdapter struct {
	upstream interface {
		Query(msg *protocol.Message) (*protocol.Message, error)
	}
	// iterative, when set, routes the validator's chain fetches (DNSKEY/DS/
	// NSEC3PARAM) through the iterative resolver instead of an upstream
	// forwarder. This is the only working fetch path in recursive-only
	// deployments, where no upstream client exists at all.
	iterative *resolver.Resolver
}

// SetIterative wires the iterative resolver in as the fetch path. Called from
// main after the resolver is constructed (the DNSSEC manager is built before
// the resolver, so this cannot happen at construction time).
func (d *dnssecResolverAdapter) SetIterative(r *resolver.Resolver) {
	if d != nil {
		d.iterative = r
	}
}

// Query implements dnssec.Resolver interface
func (d *dnssecResolverAdapter) Query(ctx context.Context, name string, qtype uint16) (*protocol.Message, error) {
	if d.iterative != nil {
		return d.iterative.Resolve(ctx, name, qtype)
	}
	if d.upstream == nil {
		return nil, fmt.Errorf("dnssec fetch: no upstream or iterative resolver configured")
	}
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
	// The validator fetches DNSKEY/DS RRsets and needs their covering RRSIGs;
	// upstreams only include those when the query carries EDNS0 with the DO
	// bit set (RFC 4035 §3.2.1). Without it every chain build fails and all
	// validated answers go Bogus.
	msg.SetEDNS0(4096, true)
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

func (a *resolverCacheAdapter) SetNegativeWithTTL(key string, rcode uint8, ttl uint32) {
	a.cache.SetNegativeWithTTL(key, rcode, ttl)
}

// SetNegativeNamed and SetNegativeWithTTLNamed retain the query name on the
// cached negative. The resolver keys negatives as "name:qtype", which
// cache.ExtractQueryInfo cannot parse, so without these the entry's domain is
// unrecoverable and InvalidatePattern silently skips it. These satisfy the
// resolver's optional namedNegativeCache / namedNegativeTTLCache interfaces;
// dropping them makes the resolver fall back to the unnamed variants and
// silently reopens that gap.
func (a *resolverCacheAdapter) SetNegativeNamed(key, name string, rcode uint8) {
	a.cache.SetNegativeNamed(key, name, rcode)
}

func (a *resolverCacheAdapter) SetNegativeWithTTLNamed(key, name string, rcode uint8, ttl uint32) {
	a.cache.SetNegativeWithTTLNamed(key, name, rcode, ttl)
}

// SetNegativeMessage keeps the full negative response (SOA + NSEC/NSEC3
// denial proofs) so DNSSEC chain building can validate cached negatives.
func (a *resolverCacheAdapter) SetNegativeMessage(key string, rcode uint8, msg *protocol.Message, ttl uint32) {
	a.cache.SetNegativeMessage(key, rcode, msg, ttl)
}

// doqHandlerAdapter adapts a server.Handler (ServeDNS) into a quic.DoQHandler (ServeDoQ).
// It unpacks the DNS query from raw bytes, runs it through the DNS handler, and
// writes the wire-format response back to the QUIC stream.
type doqHandlerAdapter struct {
	handler server.Handler
}

func (a *doqHandlerAdapter) ServeDoQ(stream *quic.Stream, queryData []byte) {
	defer func() {
		if r := recover(); r != nil {
			util.Warnf("doq handler panic: %v", r)
		}
	}()

	msg, err := protocol.UnpackMessage(queryData)
	if err != nil {
		return
	}
	if len(msg.Questions) == 0 {
		return
	}

	rw := &doqResponseWriter{stream: stream, remoteAddr: stream.RemoteAddr()}
	a.handler.ServeDNS(rw, msg)
}

// doqResponseWriter implements server.ResponseWriter for QUIC streams.
type doqResponseWriter struct {
	stream     doqStreamWriter
	remoteAddr net.Addr
}

type doqStreamWriter interface {
	Write([]byte) (int, error)
}

func (w *doqResponseWriter) Write(msg *protocol.Message) (int, error) {
	// The 2-octet length prefix (RFC 9250) caps a DoQ message at 65535 bytes.
	// Truncate record-boundary-aware (sets TC) rather than letting uint16(n)
	// silently wrap and emit a garbled frame — matching the TCP/DoT writers.
	wireLen := msg.WireLength()
	if wireLen > 65535 {
		msg.Truncate(65535)
		wireLen = msg.WireLength()
	}
	buf := make([]byte, wireLen+2)
	n, err := msg.Pack(buf[2:])
	if err != nil {
		return 0, err
	}
	if n > 65535 {
		return 0, fmt.Errorf("doq: response %d bytes exceeds 65535 after truncation", n)
	}
	binary.BigEndian.PutUint16(buf[0:2], uint16(n))
	if err := util.WriteFull(w.stream, buf[:n+2]); err != nil {
		return 0, err
	}
	return n + 2, nil
}

func (w *doqResponseWriter) ClientInfo() *server.ClientInfo {
	// Carry the real QUIC client address so per-client pipeline stages (ACL,
	// rate limiting, RPZ client policy, split-horizon views, DNS cookies) see a
	// non-nil IP. Falling back to an empty address here would silently exempt
	// every DoQ query from those controls (open-resolver / RRL-bypass over DoQ).
	addr := w.remoteAddr
	if addr == nil {
		addr = &net.UDPAddr{}
	}
	return &server.ClientInfo{
		Addr:     addr,
		Protocol: "quic",
	}
}

func (w *doqResponseWriter) MaxSize() int {
	return quic.DoQMaxMessageSize
}
