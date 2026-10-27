// NothingDNS - Cache prefetch
//
// cache.prefetch ("refresh entries that are about to expire", see
// docs/CONFIG_REFERENCE.md) is implemented in two halves. internal/cache decides
// WHEN: a hit inside the prefetch window fires a callback once per entry. This
// file is the other half, WHAT the callback does: re-resolve the name and hand
// the fresh answer back to the cache. Without it the option was accepted,
// hot-reloaded and shown in the API, and did nothing.

package main

import (
	"context"
	"strings"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/upstream"
)

// maxConcurrentPrefetch bounds the background refreshes in flight. The cache
// fires the callback once per entry, so a burst of hot entries entering their
// window together must not become a burst of upstream queries.
const maxConcurrentPrefetch = 16

// prefetchSlots is the shared concurrency limiter for prefetch refreshes.
var prefetchSlots = make(chan struct{}, maxConcurrentPrefetch)

// wirePrefetch installs the prefetch callback on the handler's cache.
func (h *integratedHandler) wirePrefetch() {
	if h.cache != nil {
		h.cache.SetPrefetchFunc(h.prefetch)
	}
}

// prefetchDiscardWriter swallows the response an RPZ rule would have written:
// a refresh that would be blocked is simply not stored.
type prefetchDiscardWriter struct{}

func (prefetchDiscardWriter) Write(*protocol.Message) (int, error) { return 0, nil }
func (prefetchDiscardWriter) ClientInfo() *server.ClientInfo       { return nil }
func (prefetchDiscardWriter) MaxSize() int                         { return 512 }

// prefetch re-resolves the entry stored under key and replaces it, so a popular
// name is refreshed before it expires instead of costing a client a full miss.
//
// A refresh is accepted under exactly the rules of a client miss — matching
// transaction ID and question, DNSSEC verdict, RPZ response policy, answer
// present, cache TTL policy — and is otherwise dropped, leaving the old entry
// to expire normally. It must never store anything a client query would not.
func (h *integratedHandler) prefetch(key string, qtype uint16) {
	prefetchSlots <- struct{}{}
	defer func() { <-prefetchSlots }()

	// Hold the runtime read lock like a request does: a hot reload swaps the
	// resolver/upstream under the write lock and then stops the old ones.
	h.runtimeMu.RLock()
	defer h.runtimeMu.RUnlock()

	name, keyType := cache.ExtractQueryInfo(key)
	if name == "" || keyType != qtype {
		return
	}
	doBit := strings.HasSuffix(key, "|1")
	// Names over the key's length limit are stored as a decimal hash and cannot
	// be recovered from the key. The hash would round-trip through MakeKey as a
	// (digits-only) "name", so reject by shape: a real name has a letter or a
	// separator somewhere, a hash is nothing but digits. Skipping beats
	// resolving a made-up name.
	if name == "" || isAllDigits(name) || cache.MakeKey(name, qtype, doBit) != key {
		return
	}

	ctx := h.serverCtx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, iterativeResolveTimeout(h.config))
	defer cancel()

	query, err := protocol.NewQuery(upstream.RandomTXID(), name, qtype)
	if err != nil || len(query.Questions) != 1 {
		return
	}
	defer query.Release()
	question := query.Questions[0]

	var resp *protocol.Message
	viaResolver := false
	switch {
	case h.resolver != nil:
		viaResolver = true
		resp, err = h.resolver.Resolve(ctx, name, qtype)
	case h.loadBalancer != nil || h.upstream != nil:
		out := query
		if h.validator != nil {
			out = withDOBit(query)
		}
		if h.loadBalancer != nil {
			resp, err = h.loadBalancer.QueryContext(ctx, out)
		} else {
			resp, err = h.upstream.QueryContext(ctx, out)
		}
	default:
		return
	}
	if err != nil || resp == nil {
		return
	}
	defer resp.Release()
	sanitizePipelineResponse(resp)

	if viaResolver {
		// The resolver returns the authority's header: neither AA nor AD is
		// this server's claim on a recursive answer.
		resp.Header.Flags.AA = false
		resp.Header.Flags.AD = false
	} else {
		if resp.Header.ID != query.Header.ID || !upstreamResponseMatchesQuestion(resp, question) {
			return
		}
		if h.validator != nil {
			resp.Header.Flags.AD = false
		}
	}

	// Only a positive answer replaces a positive entry.
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess || len(resp.Answers) == 0 {
		return
	}

	if h.validator != nil {
		result, _ := h.validator.ValidateResponse(ctx, resp, name)
		switch result {
		case dnssec.ValidationSecure:
			resp.Header.Flags.AD = true
		case dnssec.ValidationBogus, dnssec.ValidationIndeterminate:
			if h.config != nil && h.config.DNSSEC.Enabled {
				return // a client query would have been answered SERVFAIL
			}
		}
	}

	if handled, _ := h.applyRPZResponsePolicyWithError(prefetchDiscardWriter{}, query, question, resp, name); handled {
		return
	}
	// A client miss is blocked, not cached, when the chain reaches a blocked
	// name; refreshing it would keep resolving the blocked name (F728).
	if _, blocked := h.blockedCNAMETarget(question.Name.String(), resp); blocked {
		return
	}

	ttl := answerCacheTTL(resp)
	if ttl == 0 {
		return // a TTL 0 answer is not cacheable (RFC 1035 §3.2.1)
	}
	ttl = h.cache.ApplyTTLPolicy(resp, ttl)
	h.cache.OnPrefetchComplete(key, resp, ttl)
}

// isAllDigits reports whether s is non-empty and made only of ASCII digits.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
