// NothingDNS - DNS request handler

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/audit"
	"github.com/nothingdns/nothingdns/internal/blocklist"
	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/cluster"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/dns64"
	"github.com/nothingdns/nothingdns/internal/dnscookie"
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/dso"
	"github.com/nothingdns/nothingdns/internal/filter"
	"github.com/nothingdns/nothingdns/internal/geodns"
	"github.com/nothingdns/nothingdns/internal/idna"
	"github.com/nothingdns/nothingdns/internal/mdns"
	"github.com/nothingdns/nothingdns/internal/metrics"
	"github.com/nothingdns/nothingdns/internal/otel"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/resolver"
	"github.com/nothingdns/nothingdns/internal/rpz"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/upstream"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// integratedHandler is the DNS request handler that uses all components.
type integratedHandler struct {
	config        *config.Config
	logger        *util.Logger
	cache         *cache.Cache
	upstream      *upstream.Client
	loadBalancer  *upstream.LoadBalancer
	resolver      *resolver.Resolver
	zones         map[string]*zone.Zone
	zonesMu       sync.RWMutex
	zoneManager   *zone.Manager
	kvPersistence *zone.KVPersistence
	blocklist     *blocklist.Blocklist
	rpzEngine     *rpz.Engine
	geoEngine     *geodns.Engine
	metrics       *metrics.MetricsCollector
	validator     *dnssec.Validator
	zoneSigners   map[string]*dnssec.Signer
	zoneSignersMu sync.RWMutex
	zoneTree      *zone.RadixTree // Radix tree for O(log n) zone matching
	cluster       *cluster.Cluster
	axfrServer    *transfer.AXFRServer
	ixfrServer    *transfer.IXFRServer
	notifyHandler *transfer.NOTIFYSlaveHandler
	ddnsHandler   *transfer.DynamicDNSHandler
	slaveManager  *transfer.SlaveManager
	aclChecker    *filter.ACLChecker
	rateLimiter   *filter.RateLimiter
	splitHorizon  *filter.SplitHorizon
	viewZones     map[string]map[string]*zone.Zone // view name -> origin -> Zone
	auditLogger   *audit.AuditLogger
	tracer        *otel.Tracer
	nsecCache     *cache.NSECCache // RFC 8198 aggressive NSEC caching
	dns64Synth    *dns64.Synthesizer
	cookieJar     *dnscookie.CookieJar
	idnaEnabled   bool // RFC 5891 IDNA validation enabled
	mdnsResponder *mdns.Responder
	dsoManager    *dso.Manager

	notifyOnce sync.Once
	updateOnce sync.Once
}

// ServeDNS implements the server.Handler interface.
func (h *integratedHandler) ServeDNS(w server.ResponseWriter, r *protocol.Message) {
	// Panic recovery — prevents handler crashes from crashing the server
	defer func() {
		if rec := recover(); rec != nil {
			h.logger.Errorf("Panic in ServeDNS: %v", rec)
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendErrorWithEDE(w, r, protocol.RcodeServerFailure, protocol.EDEOtherError, "internal server error")
		}
	}()

	start := time.Now()
	reqID := util.GenerateRequestID()

	// OpenTelemetry tracing: create a span for this DNS query
	var span *otel.Span
	if h.tracer != nil {
		_, span = h.tracer.StartSpan(context.Background(), "dns.query",
			otel.WithAttr("req.id", reqID),
		)
	}

	// Defer latency recording and audit logging
	var qtypeStr string
	var qnameAudit string
	var cacheHit bool
	defer func() {
		latency := time.Since(start)
		if h.metrics != nil && qtypeStr != "" {
			h.metrics.RecordQueryLatency(qtypeStr, latency)
		}
		if h.auditLogger != nil && qtypeStr != "" {
			clientIP := "-"
			if ci := w.ClientInfo(); ci != nil && ci.IP() != nil {
				clientIP = ci.IP().String()
			}
			h.auditLogger.LogQuery(audit.QueryAuditEntry{
				RequestID: reqID,
				Timestamp: start.UTC().Format(time.RFC3339),
				ClientIP:  clientIP,
				QueryName: qnameAudit,
				QueryType: qtypeStr,
				Latency:   latency,
				CacheHit:  cacheHit,
			})
		}
		// End tracing span with DNS attributes
		if span != nil {
			if qtypeStr != "" {
				span.Attrs = append(span.Attrs,
					otel.Attr{Key: "dns.qname", Value: qnameAudit},
					otel.Attr{Key: "dns.qtype", Value: qtypeStr},
					otel.Attr{Key: "dns.cache_hit", Value: cacheHit},
				)
			}
			h.tracer.EndSpan(span, nil)
		}
	}()

	// Check if we have questions
	if len(r.Questions) == 0 {
		h.logger.Debug("Query with no questions")
		sendError(w, r, protocol.RcodeFormatError)
		return
	}

	q := r.Questions[0]
	qname := q.Name.String()
	qtype := q.QType
	qtypeStr = typeToString(qtype)
	qnameAudit = qname

	h.logger.Debugf("[%s] Query: %s %s", reqID, qname, typeToString(qtype))

	// RFC 5891: Validate IDNA (internationalized domain names)
	if h.idnaEnabled {
		// Check if the domain name is valid IDNA
		if _, err := idna.ToASCII(qname); err != nil {
			h.logger.Debugf("IDNA validation failed for %s: %v", qname, err)
			sendErrorWithEDE(w, r, protocol.RcodeFormatError, protocol.EDEProhibited, "invalid IDNA")
			return
		}
	}

	// Record query metric
	if h.metrics != nil {
		h.metrics.RecordQuery(typeToString(qtype))
	}

	// Check ACL
	clientIP := w.ClientInfo().IP()
	if h.aclChecker != nil && clientIP != nil {
		allowed, redirect := h.aclChecker.IsAllowed(clientIP, qtype)
		if !allowed {
			if redirect != "" {
				h.logger.Infof("ACL redirect: %s %s from %s -> %s", qname, typeToString(qtype), clientIP, redirect)
				h.handleACLRedirect(w, r, q, redirect)
			} else {
				h.logger.Infof("ACL denied: %s %s from %s", qname, typeToString(qtype), clientIP)
				sendError(w, r, protocol.RcodeRefused)
			}
			return
		}
	}

	// Check RPZ client IP policy
	if h.rpzEngine != nil && clientIP != nil {
		if rule := h.rpzEngine.ClientIPPolicy(clientIP); rule != nil {
			h.applyRPZRule(w, r, q, rule)
			return
		}
	}

	// Check rate limit
	if h.rateLimiter != nil && clientIP != nil {
		if !h.rateLimiter.Allow(clientIP) {
			h.logger.Debugf("RRL dropped: %s %s from %s", qname, typeToString(qtype), clientIP)
			if h.metrics != nil {
				h.metrics.RecordRateLimited()
			}
			sendError(w, r, protocol.RcodeRefused)
			return
		}
	}

	// RFC 7873: DNS Cookie validation
	if h.cookieJar != nil && clientIP != nil {
		cookieData, valid := h.processCookies(r, clientIP)
		if !valid {
			// Client sent an invalid server cookie — respond with BADCOOKIE
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:    r.Header.ID,
					Flags: protocol.NewResponseFlags(protocol.RcodeBadCookie),
				},
				Questions: r.Questions,
			}
			// Include a fresh server cookie so the client can retry
			resp.SetEDNS0(4096, false)
			if opt := resp.GetOPT(); opt != nil {
				if optData, ok := opt.Data.(*protocol.RDataOPT); ok {
					optData.AddOption(protocol.OptionCodeCookie, cookieData)
				}
			}
			if _, err := w.Write(resp); err != nil {
				fmt.Fprintf(os.Stderr, "failed to write BADCOOKIE response: %v\n", err)
			}
			return
		}
		// Wrap the response writer to inject the server cookie into every response
		if cookieData != nil {
			w = &cookieResponseWriter{inner: w, cookieData: cookieData}
		}
	}

	// Handle AXFR (zone transfer) requests
	if qtype == protocol.TypeAXFR {
		h.handleAXFR(w, r, q)
		return
	}

	// Handle IXFR (incremental zone transfer) requests
	if qtype == protocol.TypeIXFR {
		h.handleIXFR(w, r, q)
		return
	}

	// Handle NOTIFY requests (RFC 1996)
	if transfer.IsNOTIFYRequest(r) {
		h.handleNOTIFY(w, r, q)
		return
	}

	// Handle Dynamic DNS UPDATE requests (RFC 2136)
	if transfer.IsUpdateRequest(r) {
		h.handleUPDATE(w, r, q)
		return
	}

	// Check blocklist — return EDE with Filtered code per RFC 8914
	if h.blocklist != nil && h.blocklist.IsBlocked(qname) {
		h.logger.Infof("Blocked query for %s", qname)
		if h.metrics != nil {
			h.metrics.RecordBlocklistBlock()
		}
		sendErrorWithEDE(w, r, protocol.RcodeNameError, protocol.EDEFiltered, "blocked by blocklist")
		return
	}

	// Check RPZ QNAME policy
	if h.rpzEngine != nil {
		if rule := h.rpzEngine.QNAMEPolicy(qname); rule != nil {
			if h.applyRPZRule(w, r, q, rule) {
				return
			}
		}
	}

	// Check cache first
	cacheKey := cache.MakeKey(qname, qtype)
	if entry := h.cache.Get(cacheKey); entry != nil {
		cacheHit = true
		if entry.IsNegative {
			h.logger.Debugf("Cache hit (negative) for %s", qname)
			if h.metrics != nil {
				h.metrics.RecordCacheHit()
				h.metrics.RecordResponse(entry.RCode)
			}
			sendError(w, r, entry.RCode)
			return
		}
		h.logger.Debugf("Cache hit for %s", qname)
		if h.metrics != nil {
			h.metrics.RecordCacheHit()
			h.metrics.RecordResponse(protocol.RcodeSuccess)
		}
		reply(w, r, entry.Message)
		return
	}

	// Record cache miss
	if h.metrics != nil {
		h.metrics.RecordCacheMiss()
	}

	// RFC 8198: Check aggressive NSEC cache before going upstream
	if h.nsecCache != nil {
		if synthResp := h.nsecCache.Lookup(qname, qtype); synthResp != nil {
			h.logger.Debugf("NSEC cache hit for %s (aggressive negative)", qname)
			if h.metrics != nil {
				h.metrics.RecordResponse(synthResp.Header.Flags.RCODE)
			}
			reply(w, r, synthResp)
			return
		}
	}

	// Split-horizon: if views are configured, check view-specific zones first.
	if h.splitHorizon != nil && clientIP != nil {
		if view := h.splitHorizon.SelectView(clientIP); view != nil {
			if vzMap, ok := h.viewZones[view.Name]; ok {
				for origin, z := range vzMap {
					if isSubdomain(qname, origin) {
						h.logger.Debugf("View %s: checking zone %s for %s", view.Name, origin, qname)
						if h.handleAuthoritative(z, w, r, q) {
							return
						}
					}
				}
			}
		}
	}

	// Check authoritative zones — try direct lookup first.
	// If no zone has a direct record, attempt CNAME chasing across zones,
	// then cache, then upstream.
	// Collect matching zones under the read lock, then release before processing
	// to avoid blocking reload writers (zonesMu.Lock()) for extended periods.
	h.zonesMu.RLock()
	tree := h.zoneTree
	var matchedZones []struct {
		name string
		z    *zone.Zone
	}
	seenZones := make(map[string]struct{})
	// Fast path: use radix tree for O(log n) best-match lookup
	if tree != nil {
		if best := tree.Find(qname); best != nil {
			matchedZones = append(matchedZones, struct {
				name string
				z    *zone.Zone
			}{best.Origin, best})
			seenZones[best.Origin] = struct{}{}
		}
	}
	// Include zones from the static map and runtime zone manager.
	// Runtime-created zones (API, DDNS) may not be in the radix tree.
	for origin, z := range h.zones {
		if isSubdomain(qname, origin) {
			if _, seen := seenZones[origin]; !seen {
				matchedZones = append(matchedZones, struct {
					name string
					z    *zone.Zone
				}{origin, z})
				seenZones[origin] = struct{}{}
			}
		}
	}
	if h.kvPersistence != nil {
		for name, z := range h.kvPersistence.Manager().List() {
			if isSubdomain(qname, name) {
				if _, seen := seenZones[name]; !seen {
					matchedZones = append(matchedZones, struct {
						name string
						z    *zone.Zone
					}{name, z})
					seenZones[name] = struct{}{}
				}
			}
		}
	}
	if h.zoneManager != nil {
		for name, z := range h.zoneManager.List() {
			if isSubdomain(qname, name) {
				if _, seen := seenZones[name]; !seen {
					matchedZones = append(matchedZones, struct {
						name string
						z    *zone.Zone
					}{name, z})
					seenZones[name] = struct{}{}
				}
			}
		}
	}
	// Sort by origin length descending so the most specific zone is checked first
	sort.Slice(matchedZones, func(i, j int) bool {
		return len(matchedZones[i].name) > len(matchedZones[j].name)
	})
	h.zonesMu.RUnlock()

	var matchedZone bool
	for _, m := range matchedZones {
		matchedZone = true
		h.logger.Debugf("Checking zone %s for %s", m.name, qname)
		if h.handleAuthoritative(m.z, w, r, q) {
			return
		}
	}

	// If the query name falls within one of our zones but no direct record
	// was found, chase CNAME chains before falling through to upstream.
	if matchedZone {
		result := h.chaseCNAMEInZones(qname)
		if result.loopDetected {
			h.logger.Warnf("CNAME loop detected for %s", qname)
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendErrorWithEDE(w, r, protocol.RcodeServerFailure, protocol.EDERecursiveLoop, "CNAME loop detected")
			return
		}
		if len(result.cnameRecords) > 0 {
			// We have a CNAME chain — resolve the target
			targetAnswers := h.resolveCNAMETarget(w, r, q, result.targetName, qtype)
			resp := h.buildCNAMEResponse(r, result.cnameRecords, targetAnswers)

			// Check RPZ response IP policy on the resolved target
			if h.rpzEngine != nil {
				respIPs := extractResponseIPs(resp)
				if len(respIPs) > 0 {
					if rule := h.rpzEngine.ResponseIPPolicy(respIPs); rule != nil {
						h.logger.Debugf("RPZ response IP match for CNAME target %s (policy: %s)", result.targetName, rule.PolicyName)
						if h.applyRPZRule(w, r, q, rule) {
							return
						}
					}
				}
			}

			// Check RPZ NSDNAME policy on CNAME target response authority section
			if h.rpzEngine != nil {
				for _, nsName := range extractNSNames(resp) {
					if rule := h.rpzEngine.QNAMEPolicy(nsName); rule != nil {
						h.logger.Debugf("RPZ NSDNAME match for CNAME target %s (policy: %s)", nsName, rule.PolicyName)
						if h.applyRPZRule(w, r, q, rule) {
							return
						}
					}
				}
			}

			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeSuccess)
			}
			reply(w, r, resp)
			return
		}
	}

	// Use iterative recursive resolver if enabled
	if h.resolver != nil {
		h.logger.Debugf("Resolving %s iteratively", qname)
		resp, err := h.resolver.Resolve(context.Background(), qname, qtype)
		if err != nil {
			h.logger.Warnf("Iterative resolution failed for %s: %v", qname, err)
			// RFC 8767: Try serve-stale when resolution fails
			if stale := h.cache.GetStale(cacheKey); stale != nil && stale.Message != nil {
				h.logger.Debugf("Serving stale cache entry for %s (resolver failed)", qname)
				if h.metrics != nil {
					h.metrics.RecordResponse(protocol.RcodeSuccess)
				}
				reply(w, r, stale.Message)
				return
			}
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendErrorWithEDE(w, r, protocol.RcodeServerFailure, protocol.EDENetworkError, "iterative resolution failed")
			return
		}

		// Copy query ID from original request
		resp.Header.ID = r.Header.ID

		// Check RPZ response IP policy
		if h.rpzEngine != nil {
			respIPs := extractResponseIPs(resp)
			if len(respIPs) > 0 {
				if rule := h.rpzEngine.ResponseIPPolicy(respIPs); rule != nil {
					h.logger.Debugf("RPZ response IP match for %s (policy: %s)", qname, rule.PolicyName)
					if h.applyRPZRule(w, r, q, rule) {
						return
					}
				}
			}
		}

		// Check RPZ NSDNAME policy (TriggerNSDNAME): check NS names in authority section
		if h.rpzEngine != nil {
			for _, nsName := range extractNSNames(resp) {
				if rule := h.rpzEngine.QNAMEPolicy(nsName); rule != nil {
					h.logger.Debugf("RPZ NSDNAME match for %s (policy: %s)", nsName, rule.PolicyName)
					if h.applyRPZRule(w, r, q, rule) {
						return
					}
				}
			}
		}

		// DNS64: synthesize AAAA from A if the AAAA response is empty
		if h.tryDNS64Synthesis(w, r, q, resp) {
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeSuccess)
			}
			return
		}

		if h.metrics != nil {
			h.metrics.RecordResponse(resp.Header.Flags.RCODE)
		}
		reply(w, r, resp)
		return
	}

	// Forward to upstream only if configured (authoritative-only mode skips this)
	if h.upstream != nil || h.loadBalancer != nil {
		h.logger.Debugf("Forwarding query for %s to upstream", qname)
		if h.metrics != nil {
			if len(h.config.Upstream.Servers) > 0 {
				h.metrics.RecordUpstreamQuery(h.config.Upstream.Servers[0])
			} else if len(h.config.Upstream.AnycastGroups) > 0 {
				h.metrics.RecordUpstreamQuery(h.config.Upstream.AnycastGroups[0].AnycastIP + ":53")
			}
		}

		var resp *protocol.Message
		var err error
		if h.loadBalancer != nil {
			resp, err = h.loadBalancer.Query(r)
		} else {
			resp, err = h.upstream.Query(r)
		}
		if err != nil {
			h.logger.Warnf("Upstream query failed for %s: %v", qname, err)
			// RFC 8767: Try serve-stale when upstream is unavailable
			if stale := h.cache.GetStale(cacheKey); stale != nil && stale.Message != nil {
				h.logger.Debugf("Serving stale cache entry for %s (upstream failed)", qname)
				if h.metrics != nil {
					h.metrics.RecordResponse(protocol.RcodeSuccess)
				}
				reply(w, r, stale.Message)
				return
			}
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendErrorWithEDE(w, r, protocol.RcodeServerFailure, protocol.EDENetworkError, "upstream unavailable")
			return
		}

		// Validate response ID matches query ID to prevent spoofing
		if resp.Header.ID != r.Header.ID {
			h.logger.Warnf("Upstream response ID mismatch for %s: got %d, want %d", qname, resp.Header.ID, r.Header.ID)
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendErrorWithEDE(w, r, protocol.RcodeServerFailure, protocol.EDENetworkError, "invalid upstream response")
			return
		}

		// Validate DNSSEC if enabled and response has signatures
		dnssecValidated := false
		if h.validator != nil && dnssec.HasSignature(resp) {
			ctx := context.Background()
			result, err := h.validator.ValidateResponse(ctx, resp, qname)
			if err != nil {
				h.logger.Warnf("DNSSEC validation error for %s: %v", qname, err)
			}

			switch result {
			case dnssec.ValidationSecure:
				h.logger.Debugf("DNSSEC validation secure for %s", qname)
				// Set AD bit if validation succeeded
				resp.Header.Flags.AD = true
				dnssecValidated = true
			case dnssec.ValidationBogus:
				h.logger.Warnf("DNSSEC validation failed (bogus) for %s", qname)
				if h.config.DNSSEC.Enabled {
					// Return SERVFAIL if DNSSEC validation failed
					if h.metrics != nil {
						h.metrics.RecordResponse(protocol.RcodeServerFailure)
					}
					sendErrorWithEDE(w, r, protocol.RcodeServerFailure, protocol.EDEDNSSECBogus, "DNSSEC validation failed")
					return
				}
			case dnssec.ValidationInsecure:
				h.logger.Debugf("DNSSEC insecure zone for %s", qname)
			case dnssec.ValidationIndeterminate:
				h.logger.Debugf("DNSSEC indeterminate for %s", qname)
				if h.config.DNSSEC.Enabled {
					if h.metrics != nil {
						h.metrics.RecordResponse(protocol.RcodeServerFailure)
					}
					sendErrorWithEDE(w, r, protocol.RcodeServerFailure, protocol.EDEDNSSECIndeterminate, "DNSSEC indeterminate")
					return
				}
			}
		}

		// Check RPZ response IP policy
		if h.rpzEngine != nil {
			respIPs := extractResponseIPs(resp)
			if len(respIPs) > 0 {
				if rule := h.rpzEngine.ResponseIPPolicy(respIPs); rule != nil {
					h.logger.Debugf("RPZ response IP match for %s (policy: %s)", qname, rule.PolicyName)
					if h.applyRPZRule(w, r, q, rule) {
						return
					}
				}
			}
		}

		// Check RPZ NSDNAME policy (TriggerNSDNAME): check NS names in authority section
		if h.rpzEngine != nil {
			for _, nsName := range extractNSNames(resp) {
				if rule := h.rpzEngine.QNAMEPolicy(nsName); rule != nil {
					h.logger.Debugf("RPZ NSDNAME match for %s (policy: %s)", nsName, rule.PolicyName)
					if h.applyRPZRule(w, r, q, rule) {
						return
					}
				}
			}
		}

		// DNS64: synthesize AAAA from A if the AAAA response is empty
		if h.tryDNS64Synthesis(w, r, q, resp) {
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeSuccess)
			}
			return
		}

		// Cache the response
		if resp.Header.Flags.RCODE == protocol.RcodeSuccess && len(resp.Answers) > 0 {
			ttl := extractTTL(resp)
			h.cache.Set(cacheKey, resp, ttl)
		} else if resp.Header.Flags.RCODE == protocol.RcodeNameError ||
			(resp.Header.Flags.RCODE == protocol.RcodeSuccess && len(resp.Answers) == 0) {
			// Negative caching per RFC 2308 §5
			// Use SOA minimum TTL from authority section, or default 300s
			negTTL := uint32(300)
			for _, rr := range resp.Authorities {
				if soa, ok := rr.Data.(*protocol.RDataSOA); ok {
					if soa.Minimum > 0 {
						negTTL = soa.Minimum
					}
					break
				}
			}
			h.cache.SetNegative(cacheKey, resp.Header.Flags.RCODE)
			h.logger.Debugf("Cached negative response for %s (rcode=%d, negTTL=%d)", qname, resp.Header.Flags.RCODE, negTTL)

			// RFC 8198: Cache NSEC records from NXDOMAIN responses for aggressive negative caching
			// Only cache if DNSSEC validation was successful - unvalidated NSEC records could enable cache poisoning
			if h.nsecCache != nil && resp.Header.Flags.RCODE == protocol.RcodeNameError {
				h.nsecCache.AddFromResponse(resp, dnssecValidated)
			}
		}

		if h.metrics != nil {
			h.metrics.RecordResponse(resp.Header.Flags.RCODE)
		}
		reply(w, r, resp)
		return
	}

	// No upstream configured
	h.logger.Debugf("No upstream configured, returning NXDOMAIN for %s", qname)
	if h.metrics != nil {
		h.metrics.RecordResponse(protocol.RcodeNameError)
	}
	sendErrorWithEDE(w, r, protocol.RcodeNameError, protocol.EDENotAuthoritative, "no upstream configured")
}

// tryDNS64Synthesis checks whether DNS64 synthesis is needed for an AAAA query
// that received no AAAA answers. If synthesis is appropriate, it re-queries for
// A records via the same upstream path and returns a synthesized AAAA response.
// Returns true if a synthesized response was written, false otherwise.
func (h *integratedHandler) tryDNS64Synthesis(w server.ResponseWriter, r *protocol.Message, q *protocol.Question, resp *protocol.Message) bool {
	if h.dns64Synth == nil {
		return false
	}
	if !h.dns64Synth.ShouldSynthesize(q, resp) {
		return false
	}

	// Build a new query for the same name but type A.
	qname := q.Name.String()
	aQuery, err := protocol.NewQuery(r.Header.ID, qname, protocol.TypeA)
	if err != nil {
		h.logger.Warnf("DNS64: failed to build A query for %s: %v", qname, err)
		return false
	}

	// Send the A query through the same upstream path.
	var aResp *protocol.Message
	if h.loadBalancer != nil {
		aResp, err = h.loadBalancer.Query(aQuery)
	} else if h.upstream != nil {
		aResp, err = h.upstream.Query(aQuery)
	} else {
		return false
	}
	if err != nil {
		h.logger.Warnf("DNS64: upstream A query failed for %s: %v", qname, err)
		return false
	}

	// Only synthesize if the A response has answers.
	if aResp.Header.Flags.RCODE != protocol.RcodeSuccess || len(aResp.Answers) == 0 {
		return false
	}

	synthesized := h.dns64Synth.SynthesizeResponse(q, aResp)
	if synthesized == nil || len(synthesized.Answers) == 0 {
		return false
	}

	h.logger.Debugf("DNS64: synthesized %d AAAA records for %s", len(synthesized.Answers), qname)
	reply(w, r, synthesized)
	return true
}

// reply sends a response message.
func reply(w server.ResponseWriter, query, response *protocol.Message) {
	response.Header.ID = query.Header.ID
	response.Header.Flags.QR = true
	if len(response.Questions) == 0 {
		response.Questions = query.Questions
	}
	minimizeResponse(response)
	if _, err := w.Write(response); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write response: %v\n", err)
	}
}

// sendError sends an error response.
func sendError(w server.ResponseWriter, query *protocol.Message, rcode uint8) {
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    query.Header.ID,
			Flags: protocol.NewResponseFlags(rcode),
		},
		Questions: query.Questions,
	}
	if _, err := w.Write(resp); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write error response: %v\n", err)
	}
}

// sendErrorWithEDE sends an error response with Extended DNS Error (RFC 8914).
// infoCode is the EDE info code (0-65535), extraText is optional context.
func sendErrorWithEDE(w server.ResponseWriter, query *protocol.Message, rcode uint8, infoCode uint16, extraText string) {
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    query.Header.ID,
			Flags: protocol.NewResponseFlags(rcode),
		},
		Questions: query.Questions,
	}
	// Add EDNS0 OPT record with EDE if client sent EDNS0
	if query.GetOPT() != nil {
		// Get UDP payload size from client's OPT record
		udpPayload := uint16(4096)
		if opt := query.GetOPT(); opt != nil {
			if opt.Class > 0 {
				udpPayload = opt.Class
			}
		}
		// Create EDE option
		ede := protocol.NewEDNS0ExtendedError(infoCode, extraText)
		optRR := &protocol.ResourceRecord{
			Type:  protocol.TypeOPT,
			Class: udpPayload,
			Data: &protocol.RDataOPT{
				Options: []protocol.EDNS0Option{ede.ToEDNS0Option()},
			},
		}
		resp.AddAdditional(optRR)
	}
	if _, err := w.Write(resp); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write error response: %v\n", err)
	}
}

// handleACLRedirect sends a CNAME redirect response for ACL-redirected queries.
func (h *integratedHandler) handleACLRedirect(w server.ResponseWriter, r *protocol.Message, q *protocol.Question, target string) {
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    r.Header.ID,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: r.Questions,
	}

	targetName, err := protocol.ParseName(target)
	if err != nil {
		sendError(w, r, protocol.RcodeServerFailure)
		return
	}

	rr := &protocol.ResourceRecord{
		Name:  q.Name,
		Type:  protocol.TypeCNAME,
		Class: protocol.ClassIN,
		TTL:   60,
		Data:  &protocol.RDataCNAME{CName: targetName},
	}
	resp.AddAnswer(rr)

	if _, err := w.Write(resp); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write redirect response: %v\n", err)
	}
}

// buildResponse builds a DNS response from zone records.
func (h *integratedHandler) buildResponse(query *protocol.Message, records []zone.Record) *protocol.Message {
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    query.Header.ID,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: query.Questions,
	}

	for _, rec := range records {
		data := parseRData(rec.Type, rec.RData)
		if data == nil {
			continue // Skip records with unparseable RData
		}
		rr := &protocol.ResourceRecord{
			Name:  query.Questions[0].Name,
			Type:  stringToType(rec.Type),
			Class: protocol.ClassIN,
			TTL:   rec.TTL,
			Data:  data,
		}
		resp.AddAnswer(rr)
	}

	return resp
}

// buildSignedResponse builds a DNS response with DNSSEC signatures.
// This adds RRSIG records to the response if the zone has a signer configured.
func (h *integratedHandler) buildSignedResponse(query *protocol.Message, records []zone.Record, signer *dnssec.Signer, wantsDNSSEC bool) *protocol.Message {
	resp := h.buildResponse(query, records)

	if !wantsDNSSEC || signer == nil {
		return resp
	}

	// Convert zone records to protocol.ResourceRecord for signing
	var rrs []*protocol.ResourceRecord
	for _, rec := range records {
		rr := &protocol.ResourceRecord{
			Name:  query.Questions[0].Name,
			Type:  stringToType(rec.Type),
			Class: protocol.ClassIN,
			TTL:   rec.TTL,
			Data:  parseRData(rec.Type, rec.RData),
		}
		rrs = append(rrs, rr)
	}

	// Sign the RRSet and add RRSIG to answers
	if len(rrs) > 0 {
		inception := time.Now().UTC()
		expiration := inception.Add(24 * time.Hour * 30) // 30 days

		// Find ZSK for signing
		zsks := signer.GetZSKs()
		if len(zsks) > 0 {
			zsk := zsks[0] // Use first ZSK
			rrsig, err := signer.SignRRSet(
				rrs,
				zsk,
				uint32(inception.Unix()),
				uint32(expiration.Unix()),
			)
			if err == nil && rrsig != nil {
				resp.AddAnswer(rrsig)
				h.logger.Debugf("Added RRSIG for %s", query.Questions[0].Name.String())
			}
		}
	}

	return resp
}

// minimizeResponse strips unnecessary authority and additional section records
// from a DNS response per RFC 6604 minimal responses guidance.
//
// Rules:
//  1. Authoritative (AA=true): keep authority only if it contains SOA (negative caching).
//  2. Non-authoritative (forwarded): keep authority NS (referrals) and SOA (negative caching),
//     strip everything else.
//  3. Additional section: keep only glue records (A/AAAA whose name matches an NS
//     target in the authority section). Always preserve OPT pseudo-records.
func minimizeResponse(resp *protocol.Message) {
	if resp == nil {
		return
	}

	// Collect NS target names from authority section for glue filtering.
	nsNames := make(map[string]struct{})
	hasSOA := false
	hasNS := false
	for _, rr := range resp.Authorities {
		if rr == nil {
			continue
		}
		switch rr.Type {
		case protocol.TypeSOA:
			hasSOA = true
		case protocol.TypeNS:
			hasNS = true
			if ns, ok := rr.Data.(*protocol.RDataNS); ok && ns.NSDName != nil {
				nsNames[strings.ToLower(ns.NSDName.String())] = struct{}{}
			}
		}
	}

	// Filter authority section.
	if resp.Header.Flags.AA {
		// Authoritative: keep only SOA records (for negative caching).
		if hasSOA {
			filtered := make([]*protocol.ResourceRecord, 0, len(resp.Authorities))
			for _, rr := range resp.Authorities {
				if rr != nil && rr.Type == protocol.TypeSOA {
					filtered = append(filtered, rr)
				}
			}
			resp.Authorities = filtered
		} else {
			resp.Authorities = nil
		}
	} else {
		// Non-authoritative: keep NS (referrals) and SOA (negative caching).
		if hasSOA || hasNS {
			filtered := make([]*protocol.ResourceRecord, 0, len(resp.Authorities))
			for _, rr := range resp.Authorities {
				if rr == nil {
					continue
				}
				if rr.Type == protocol.TypeSOA || rr.Type == protocol.TypeNS {
					filtered = append(filtered, rr)
				}
			}
			resp.Authorities = filtered
		} else {
			resp.Authorities = nil
		}
	}

	// Filter additional section: keep OPT (EDNS0) and glue (A/AAAA for NS names).
	if len(resp.Additionals) > 0 {
		filtered := make([]*protocol.ResourceRecord, 0, len(resp.Additionals))
		for _, rr := range resp.Additionals {
			if rr == nil {
				continue
			}
			// Always keep OPT pseudo-records.
			if rr.Type == protocol.TypeOPT {
				filtered = append(filtered, rr)
				continue
			}
			// Keep A/AAAA if the name matches an NS target (glue record).
			if (rr.Type == protocol.TypeA || rr.Type == protocol.TypeAAAA) && rr.Name != nil {
				name := strings.ToLower(rr.Name.String())
				if _, isGlue := nsNames[name]; isGlue {
					filtered = append(filtered, rr)
				}
			}
		}
		resp.Additionals = filtered
	}
}

// processCookies extracts and validates DNS cookies from the query (RFC 7873).
// It returns the packed cookie option data to include in the response and whether
// the cookie validation passed. If the client did not send a cookie at all, this
// returns (nil, true) so the query proceeds normally — cookies are optional.
// If the client sent only a client cookie (first query), a fresh server cookie is
// generated and returned with valid=true. If the client sent a server cookie that
// fails validation, a fresh cookie option is returned with valid=false.
func (h *integratedHandler) processCookies(r *protocol.Message, clientIP net.IP) (cookieOptionData []byte, valid bool) {
	// Find the OPT record in the query
	opt := r.GetOPT()
	if opt == nil {
		return nil, true // No EDNS0, no cookies — allow the query
	}

	optData, ok := opt.Data.(*protocol.RDataOPT)
	if !ok {
		return nil, true
	}

	// Look for the cookie option
	cookieOpt := optData.GetOption(protocol.OptionCodeCookie)
	if cookieOpt == nil {
		return nil, true // Client did not send a cookie — allow the query
	}

	// Parse the cookie option
	cookie, err := dnscookie.ParseCookieOption(cookieOpt.Data)
	if err != nil {
		h.logger.Debugf("Invalid cookie option from %s: %v", clientIP, err)
		// Malformed cookie — generate a fresh response cookie
		var emptyClient [dnscookie.ClientCookieLen]byte
		serverCookie := h.cookieJar.GenerateServerCookie(emptyClient, clientIP)
		return dnscookie.PackCookieOption(emptyClient, serverCookie), false
	}

	// Generate a fresh server cookie for the response
	serverCookie := h.cookieJar.GenerateServerCookie(cookie.ClientCookie, clientIP)
	responseCookieData := dnscookie.PackCookieOption(cookie.ClientCookie, serverCookie)

	// If the client sent a server cookie, validate it
	if len(cookie.ServerCookie) > 0 {
		if !h.cookieJar.ValidateServerCookie(cookie.ClientCookie, cookie.ServerCookie, clientIP) {
			h.logger.Debugf("Invalid server cookie from %s", clientIP)
			return responseCookieData, false
		}
	}

	// Cookie is valid (or client only sent a client cookie — first query)
	return responseCookieData, true
}

// cookieResponseWriter wraps a server.ResponseWriter to inject DNS cookie
// option data into the OPT record of every outgoing response.
type cookieResponseWriter struct {
	inner      server.ResponseWriter
	cookieData []byte // packed cookie option (client + server cookie)
}

// Write injects the cookie into the response OPT record, then delegates
// to the inner writer.
func (cw *cookieResponseWriter) Write(msg *protocol.Message) (int, error) {
	if msg != nil && cw.cookieData != nil {
		opt := msg.GetOPT()
		if opt == nil {
			msg.SetEDNS0(4096, false)
			opt = msg.GetOPT()
		}
		if opt != nil {
			if optData, ok := opt.Data.(*protocol.RDataOPT); ok {
				// Remove any existing cookie option to avoid duplicates
				optData.RemoveOption(protocol.OptionCodeCookie)
				optData.AddOption(protocol.OptionCodeCookie, cw.cookieData)
			}
		}
	}
	return cw.inner.Write(msg)
}

// ClientInfo delegates to the inner writer.
func (cw *cookieResponseWriter) ClientInfo() *server.ClientInfo {
	return cw.inner.ClientInfo()
}

// MaxSize delegates to the inner writer.
func (cw *cookieResponseWriter) MaxSize() int {
	return cw.inner.MaxSize()
}

// applyRPZRule applies an RPZ rule action and returns true if the query was handled.
// This handles all RPZ policy actions consistently.
func (h *integratedHandler) applyRPZRule(w server.ResponseWriter, r *protocol.Message, q *protocol.Question, rule *rpz.Rule) bool {
	switch rule.Action {
	case rpz.ActionNXDOMAIN:
		h.logger.Debugf("RPZ NXDOMAIN for %s (policy: %s)", q.Name.String(), rule.PolicyName)
		if h.metrics != nil {
			h.metrics.RecordBlocklistBlock()
		}
		sendError(w, r, protocol.RcodeNameError)
		return true
	case rpz.ActionNODATA:
		h.logger.Debugf("RPZ NODATA for %s (policy: %s)", q.Name.String(), rule.PolicyName)
		if h.metrics != nil {
			h.metrics.RecordBlocklistBlock()
		}
		sendError(w, r, protocol.RcodeSuccess)
		return true
	case rpz.ActionDrop:
		h.logger.Debugf("RPZ DROP for %s (policy: %s)", q.Name.String(), rule.PolicyName)
		return true // silently drop
	case rpz.ActionPassThrough:
		// Allow the query to proceed normally
		return false
	case rpz.ActionTCPOnly:
		// Set TC bit to force TCP retry
		resp := r.Copy()
		resp.Header.Flags.TC = true
		resp.Header.Flags.QR = true
		resp.Header.Flags.RCODE = protocol.RcodeSuccess
		w.Write(resp)
		return true
	case rpz.ActionOverride:
		// Return override IP
		overrideIP := net.ParseIP(rule.OverrideData)
		if overrideIP == nil {
			h.logger.Warnf("RPZ override invalid IP: %s", rule.OverrideData)
			return false
		}
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    r.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: r.Questions,
		}
		if ip4 := overrideIP.To4(); ip4 != nil {
			var addr [4]byte
			copy(addr[:], ip4)
			resp.AddAnswer(&protocol.ResourceRecord{
				Name:  q.Name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   rule.TTL,
				Data:  &protocol.RDataA{Address: addr},
			})
		} else {
			var addr [16]byte
			copy(addr[:], overrideIP.To16())
			resp.AddAnswer(&protocol.ResourceRecord{
				Name:  q.Name,
				Type:  protocol.TypeAAAA,
				Class: protocol.ClassIN,
				TTL:   rule.TTL,
				Data:  &protocol.RDataAAAA{Address: addr},
			})
		}
		w.Write(resp)
		return true
	case rpz.ActionCNAME:
		targetName, err := protocol.ParseName(rule.OverrideData)
		if err != nil {
			h.logger.Warnf("RPZ CNAME invalid target: %s", rule.OverrideData)
			return false
		}
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    r.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: r.Questions,
		}
		resp.AddAnswer(&protocol.ResourceRecord{
			Name:  q.Name,
			Type:  protocol.TypeCNAME,
			Class: protocol.ClassIN,
			TTL:   rule.TTL,
			Data:  &protocol.RDataCNAME{CName: targetName},
		})
		w.Write(resp)
		return true
	default:
		return false
	}
}

// extractResponseIPs extracts IP addresses from answer, authority, and additional sections of a DNS response.
// This is used for RPZ response IP policy checking (TriggerResponseIP and TriggerNSIP).
func extractResponseIPs(resp *protocol.Message) []net.IP {
	var ips []net.IP
	for _, rr := range resp.Answers {
		switch rdata := rr.Data.(type) {
		case *protocol.RDataA:
			if rdata != nil {
				ips = append(ips, net.IP(rdata.Address[:]))
			}
		case *protocol.RDataAAAA:
			if rdata != nil {
				ips = append(ips, net.IP(rdata.Address[:]))
			}
		}
	}
	for _, rr := range resp.Authorities {
		switch rdata := rr.Data.(type) {
		case *protocol.RDataA:
			if rdata != nil {
				ips = append(ips, net.IP(rdata.Address[:]))
			}
		case *protocol.RDataAAAA:
			if rdata != nil {
				ips = append(ips, net.IP(rdata.Address[:]))
			}
		}
	}
	// Additional section contains glue A/AAAA records for nameservers (NSIP matching)
	for _, rr := range resp.Additionals {
		switch rdata := rr.Data.(type) {
		case *protocol.RDataA:
			if rdata != nil {
				ips = append(ips, net.IP(rdata.Address[:]))
			}
		case *protocol.RDataAAAA:
			if rdata != nil {
				ips = append(ips, net.IP(rdata.Address[:]))
			}
		}
	}
	return ips
}

// extractNSNames extracts nameserver names from authority NS records in a DNS response.
// This is used for RPZ TriggerNSDNAME policy checking.
func extractNSNames(resp *protocol.Message) []string {
	var nsNames []string
	for _, rr := range resp.Authorities {
		if ns, ok := rr.Data.(*protocol.RDataNS); ok && ns != nil && ns.NSDName != nil {
			nsNames = append(nsNames, ns.NSDName.String())
		}
	}
	return nsNames
}

// RebuildZoneTree rebuilds the zone radix tree from all zone sources.
// Call after adding or removing zones to maintain O(log n) zone lookup.
func (h *integratedHandler) RebuildZoneTree() {
	h.zonesMu.Lock()
	defer h.zonesMu.Unlock()

	// Merge all zone sources into one map for the radix tree
	merged := make(map[string]*zone.Zone)
	for k, v := range h.zones {
		merged[k] = v
	}
	if h.kvPersistence != nil {
		for k, v := range h.kvPersistence.Manager().List() {
			merged[k] = v
		}
	}
	if h.zoneManager != nil {
		for k, v := range h.zoneManager.List() {
			merged[k] = v
		}
	}
	h.zoneTree = zone.BuildRadixTree(merged)
}

// ReloadViews reloads split-horizon view configuration and zone files.
// Called during config reload to pick up view changes without restart.
func (h *integratedHandler) ReloadViews(viewConfigs []filter.ViewConfig, loadZoneFileFunc func(string) (*zone.Zone, error)) error {
	if len(viewConfigs) == 0 {
		h.splitHorizon = nil
		h.viewZones = nil
		return nil
	}

	newSH, err := filter.NewSplitHorizon(viewConfigs)
	if err != nil {
		return fmt.Errorf("reloading split-horizon: %w", err)
	}

	newViewZones := make(map[string]map[string]*zone.Zone)
	for _, v := range viewConfigs {
		vzMap := make(map[string]*zone.Zone)
		for _, zf := range v.ZoneFiles {
			vz, err := loadZoneFileFunc(zf)
			if err != nil {
				h.logger.Warnf("Failed to load zone file %q for view %q: %v", zf, v.Name, err)
				continue
			}
			vzMap[vz.Origin] = vz
		}
		newViewZones[v.Name] = vzMap
	}

	h.splitHorizon = newSH
	h.viewZones = newViewZones
	return nil
}
