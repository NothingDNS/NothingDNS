// NothingDNS - DNS query pipeline stages

package main

import (
	"context"
	"reflect"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/idna"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/upstream"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// setupStage creates per-request context, tracing span, and deferred cleanup.
// This is always the first stage.
func setupStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if q.reqID == "" {
			q.reqID = util.GenerateRequestID()
		}
		if q.start.IsZero() {
			q.start = time.Now()
		}

		// Defer latency recording and audit logging
		// (defer is handled at the ServeDNS wrapper level to keep stages simple)
		return false, nil
	}
}

// validationStage checks for empty questions and validates IDNA.
func validationStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if q.msg == nil {
			h.logger.Debug("Nil DNS query")
			sendError(q.currentWriter, nil, protocol.RcodeFormatError)
			return true, nil
		}
		if len(q.msg.Questions) == 0 || q.msg.Questions[0] == nil || q.msg.Questions[0].Name == nil {
			h.logger.Debug("Query with invalid questions")
			sendError(q.currentWriter, q.msg, protocol.RcodeFormatError)
			return true, nil
		}

		q.q = q.msg.Questions[0]
		q.qname = q.q.Name.String()
		q.qtype = q.q.QType

		h.logger.Debugf("[%s] Query: %s %s", q.reqID, q.qname, typeToString(q.qtype))

		// RFC 5891: Validate IDNA (internationalized domain names)
		if h.idnaEnabled {
			if _, err := idna.ToASCII(q.qname); err != nil {
				h.logger.Debugf("IDNA validation failed for %s: %v", q.qname, err)
				sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeFormatError, protocol.EDEProhibited, "invalid IDNA")
				return true, nil
			}
		}

		return false, nil
	}
}

// metricsStage records the incoming query metric.
func metricsStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		// Populate the human-readable qtype and the audit qname here, once and
		// unconditionally. Several downstream consumers (the audit logger and
		// the dashboard query log) gate on q.qtypeStr != "", and these fields
		// were previously never assigned — so audit logging and the dashboard
		// Query Log / live stream silently never fired.
		q.qtypeStr = typeToString(q.qtype)
		q.qnameAudit = q.qname

		if h.metrics != nil {
			h.metrics.RecordQuery(q.qtypeStr)
		}
		return false, nil
	}
}

// aclStage checks the access control list.
func aclStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		clientIP := w.ClientInfo().IP()
		if h.security.ACLChecker != nil && clientIP != nil {
			allowed, redirect := h.security.ACLChecker.IsAllowed(clientIP, q.qtype)
			if !allowed {
				if redirect != "" {
					h.logger.Infof("ACL redirect: %s %s from %s -> %s", q.qname, typeToString(q.qtype), clientIP, redirect)
					h.handleACLRedirect(q.currentWriter, q.msg, q.q, redirect)
				} else {
					h.logger.Infof("ACL denied: %s %s from %s", q.qname, typeToString(q.qtype), clientIP)
					sendError(q.currentWriter, q.msg, protocol.RcodeRefused)
				}
				return true, nil
			}
		}
		return false, nil
	}
}

// rpzClientStage checks RPZ client IP policy.
func rpzClientStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		clientIP := w.ClientInfo().IP()
		if h.security.RPZEngine != nil && clientIP != nil {
			if rule := h.security.RPZEngine.ClientIPPolicy(clientIP); rule != nil {
				// applyRPZRule returns false for PASSTHRU (whitelist) and writes
				// no response — the query must then CONTINUE through the pipeline.
				// The previous unconditional `return true` turned a client-IP
				// passthru rule into a silent drop. Mirror rpzQnameStage.
				handled, err := h.applyRPZRuleWithError(w, q.msg, q.q, rule)
				if handled || err != nil {
					return handled, err
				}
			}
		}
		return false, nil
	}
}

// rateLimitStage checks per-IP rate limits.
func rateLimitStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		clientIP := w.ClientInfo().IP()
		if h.security.RateLimiter != nil && clientIP != nil {
			if !h.security.RateLimiter.Allow(clientIP) {
				h.logger.Debugf("RRL dropped: %s %s from %s", q.qname, typeToString(q.qtype), clientIP)
				if h.metrics != nil {
					h.metrics.RecordRateLimited()
				}
				sendError(q.currentWriter, q.msg, protocol.RcodeRefused)
				return true, nil
			}
		}
		return false, nil
	}
}

// doBitStage extracts the DO bit from the OPT record for cache key calculation.
// Run after validation so q.q is set, and before cache lookup.
func doBitStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if opt := q.msg.GetOPT(); opt != nil {
			if optHdr := protocol.ParseEDNS0Header(opt); optHdr != nil {
				q.doBit = optHdr.DO
			}
		}
		q.cacheKey = cache.MakeKey(q.qname, q.qtype, q.doBit)
		return false, nil
	}
}

// cacheStage checks the DNS cache before any upstream resolution.
// Returns (handled=true) if a cached response was found and sent.
func cacheStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if entry := h.cache.Get(q.cacheKey); entry != nil {
			q.cacheHit = true
			if entry.IsNegative {
				h.logger.Debugf("Cache hit (negative) for %s", q.qname)
				if h.metrics != nil {
					h.metrics.RecordCacheHit()
					h.metrics.RecordResponse(entry.RCode)
				}
				// Prefer the stored negative message: it carries the SOA
				// (RFC 2308 — downstream resolvers need it for their own
				// negative TTL) and any NSEC/NSEC3 proofs. COPY — reply()
				// mutates in place. Bare rcode fallback for legacy entries.
				if entry.Message != nil {
					// Age-adjusted copy: decrement TTLs (incl. the SOA in the
					// Authority section) by how long the entry has been cached,
					// so downstream negative caching honors the remaining TTL.
					resp := entry.AgeAdjustedMessage(time.Now())
					resp.Header.Flags.RCODE = entry.RCode
					reply(q.currentWriter, q.msg, resp)
					return true, nil
				}
				sendError(q.currentWriter, q.msg, entry.RCode)
				return true, nil
			}
			h.logger.Debugf("Cache hit for %s", q.qname)
			if h.metrics != nil {
				h.metrics.RecordCacheHit()
				h.metrics.RecordResponse(protocol.RcodeSuccess)
			}
			// Serve an age-adjusted COPY of the cached message. The copy is
			// mandatory: reply()/minimizeResponse() and UDP truncation mutate the
			// response in place (header ID & flags, authority/additional sections,
			// answer trimming). entry.Message is the SHARED cached object —
			// mutating it would permanently corrupt the cache for every future
			// client and race across concurrent hits (a client could even receive
			// another client's transaction ID). AgeAdjustedMessage also decrements
			// each RR TTL by the entry's cache age (RFC 1035 §4.1.3 / RFC 2181).
			reply(q.currentWriter, q.msg, entry.AgeAdjustedMessage(time.Now()))
			return true, nil
		}

		if h.metrics != nil {
			h.metrics.RecordCacheMiss()
		}
		return false, nil
	}
}

// nsecCacheStage checks RFC 8198 aggressive NSEC cache before upstream.
func nsecCacheStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if h.nsecCache != nil {
			if synthResp := h.nsecCache.Lookup(q.qname, q.qtype); synthResp != nil {
				h.logger.Debugf("NSEC cache hit for %s (aggressive negative)", q.qname)
				if h.metrics != nil {
					h.metrics.RecordResponse(synthResp.Header.Flags.RCODE)
				}
				reply(q.currentWriter, q.msg, synthResp)
				return true, nil
			}
		}
		return false, nil
	}
}

// blocklistStage checks if the query domain is blocklisted.
func blocklistStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if h.security.Blocklist != nil && h.security.Blocklist.IsBlocked(q.qname) {
			// Debug, not Info: blocked queries are a large fraction of traffic
			// with ad/tracker blocklists active, so Info here floods the log at
			// query rate. The block is still counted via RecordBlocklistBlock.
			h.logger.Debugf("Blocked query for %s", q.qname)
			q.blocked = true
			if h.metrics != nil {
				h.metrics.RecordBlocklistBlock()
			}
			sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeNameError, protocol.EDEFiltered, "blocked by blocklist")
			return true, nil
		}
		return false, nil
	}
}

// rpzQnameStage checks RPZ QNAME policy.
func rpzQnameStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if h.security.RPZEngine != nil {
			if rule := h.security.RPZEngine.QNAMEPolicy(q.qname); rule != nil {
				handled, err := h.applyRPZRuleWithError(w, q.msg, q.q, rule)
				if handled || err != nil {
					return handled, err
				}
			}
		}
		return false, nil
	}
}

// splitHorizonStage checks view-specific zones (split-horizon DNS).
func splitHorizonStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		clientIP := w.ClientInfo().IP()
		if h.splitHorizon == nil || clientIP == nil {
			return false, nil
		}
		view := h.splitHorizon.SelectView(clientIP)
		if view == nil {
			return false, nil
		}
		vzMap, ok := h.viewZones[view.Name]
		if !ok {
			return false, nil
		}

		inView := false
		for origin, z := range vzMap {
			if !isSubdomain(q.qname, origin) {
				continue
			}
			inView = true
			h.logger.Debugf("View %s: checking zone %s for %s", view.Name, origin, q.qname)
			if h.handleAuthoritative(z, w, q.msg, q.q, q.qname) {
				return true, nil
			}
		}
		if !inView {
			return false, nil
		}

		// handleAuthoritative returns false when the name carries a CNAME, as
		// a signal to chase it. Falling through with that signal sent the
		// query on to the global zones, which do not contain view zones — so
		// the chase never happened, and an authoritative-only server answered
		// REFUSED ("name is outside all configured zones") for an alias it was
		// authoritative for. Every CNAME inside a split-horizon view was
		// unresolvable. The chase stays inside this view: following it across
		// the whole server would resolve one horizon's aliases against
		// another's data.
		return h.answerViewCNAME(q, w, vzMap)
	}
}

// answerViewCNAME resolves a CNAME chain within a single view's zones.
func (h *integratedHandler) answerViewCNAME(q *query, w server.ResponseWriter, vzMap map[string]*zone.Zone) (bool, error) {
	result := chaseCNAMEInZoneSet(q.qname, vzMap)
	if result.loopDetected {
		h.logger.Warnf("CNAME loop detected for %s in view zones", q.qname)
		if h.metrics != nil {
			h.metrics.RecordResponse(protocol.RcodeServerFailure)
		}
		sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeServerFailure,
			protocol.EDEOtherError, "CNAME loop detected")
		return true, nil
	}
	if len(result.cnameRecords) == 0 {
		return false, nil
	}

	// Resolve the chain's endpoint inside the view first. Anything the view
	// does not hold falls back to the ordinary path (global zones, cache,
	// upstream) — the same answer any client would get, so nothing private
	// to this view leaks and nothing public is hidden from it.
	targetAnswers := lookupInZoneSet(vzMap, result.targetName, q.qtype)
	if len(targetAnswers) == 0 {
		targetAnswers = h.resolveCNAMETarget(w, q.msg, q.q, result.targetName, q.qtype)
	}

	resp := h.buildCNAMEResponse(q.msg, result.cnameRecords, targetAnswers)
	handled, err := h.applyRPZResponsePolicyWithError(w, q.msg, q.q, resp, result.targetName)
	if handled || err != nil {
		return handled, err
	}
	if h.metrics != nil {
		h.metrics.RecordResponse(protocol.RcodeSuccess)
	}
	reply(q.currentWriter, q.msg, resp)
	return true, nil
}

// lookupInZoneSet returns answer records of qtype for name from one set of
// zones.
func lookupInZoneSet(zones map[string]*zone.Zone, name string, qtype uint16) []*protocol.ResourceRecord {
	qtypeStr := typeToString(qtype)
	parsed, err := protocol.ParseName(name)
	if err != nil {
		return nil
	}
	var answers []*protocol.ResourceRecord
	for _, z := range zones {
		for _, rec := range z.Lookup(name, qtypeStr) {
			data := parseRData(rec.Type, rec.RData)
			if data == nil {
				continue
			}
			answers = append(answers, &protocol.ResourceRecord{
				Name:  parsed,
				Type:  qtype,
				Class: protocol.ClassIN,
				TTL:   rec.TTL,
				Data:  data,
			})
		}
		if len(answers) > 0 {
			return answers
		}
	}
	return nil
}

// authoritativeStage checks local authoritative zones for a direct answer.
func authoritativeStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		h.zonesMu.RLock()
		var matchedZones []struct {
			name string
			z    *zone.Zone
		}
		if h.zoneProvider != nil {
			for _, match := range h.zoneProvider.FindZones(q.qname) {
				matchedZones = append(matchedZones, struct {
					name string
					z    *zone.Zone
				}{match.Origin, match.Zone})
			}
		}
		h.zonesMu.RUnlock()

		for _, m := range matchedZones {
			h.logger.Debugf("Checking zone %s for %s", m.name, q.qname)
			if h.handleAuthoritative(m.z, w, q.msg, q.q, q.qname) {
				return true, nil
			}
		}
		return false, nil
	}
}

// cnameStage checks if a CNAME chain exists in local zones and resolves it.
// Only runs when the query name fell within a zone but had no direct record.
func cnameStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		// Only run if we had a zone match with no direct record.
		h.zonesMu.RLock()
		hasZoneMatch := false
		if h.zoneProvider != nil {
			matches := h.zoneProvider.FindZones(q.qname)
			hasZoneMatch = len(matches) > 0
		}
		h.zonesMu.RUnlock()

		if !hasZoneMatch {
			return false, nil // no zone match means this stage doesn't apply
		}

		result := h.chaseCNAMEInZones(q.qname)
		if result.loopDetected {
			h.logger.Warnf("CNAME loop detected for %s", q.qname)
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeServerFailure, protocol.EDEOtherError, "CNAME loop detected")
			return true, nil
		}
		if len(result.cnameRecords) > 0 {
			targetAnswers := h.resolveCNAMETarget(w, q.msg, q.q, result.targetName, q.qtype)
			resp := h.buildCNAMEResponse(q.msg, result.cnameRecords, targetAnswers)

			handled, err := h.applyRPZResponsePolicyWithError(w, q.msg, q.q, resp, result.targetName)
			if handled || err != nil {
				return handled, err
			}

			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeSuccess)
			}
			reply(q.currentWriter, q.msg, resp)
			return true, nil
		}
		return false, nil
	}
}

// authoritativeOnlyStage short-circuits if server is authoritative-only.
// Returns REFUSED for names outside all local zones (no upstream leak).
func authoritativeOnlyStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if h.config != nil && h.config.Resolution.AuthoritativeOnly {
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeRefused)
			}
			sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeRefused, protocol.EDENotAuthoritative, "authoritative-only server: name is outside all configured zones")
			return true, nil
		}
		return false, nil
	}
}

// resolverStage uses iterative recursive resolver if enabled.
func resolverStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if h.resolver == nil {
			return false, nil
		}

		h.logger.Debugf("Resolving %s iteratively", q.qname)
		resp, err := func() (*protocol.Message, error) {
			resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			return h.resolver.Resolve(resolveCtx, q.qname, q.qtype)
		}()
		if err != nil {
			h.logger.Warnf("Iterative resolution failed for %s: %v", q.qname, err)
			// RFC 8767: Try serve-stale when resolution fails
			if stale := h.cache.GetStale(q.cacheKey); stale != nil && stale.Message != nil {
				h.logger.Debugf("Serving stale cache entry for %s (resolver failed)", q.qname)
				if h.metrics != nil {
					h.metrics.RecordResponse(protocol.RcodeSuccess)
				}
				// GetStale returns a private copy, safe for reply to mutate.
				reply(q.currentWriter, q.msg, stale.Message)
				return true, nil
			}
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeServerFailure, protocol.EDENetworkError, "iterative resolution failed")
			return true, nil
		}
		if resp == nil {
			h.logger.Warnf("Iterative resolution returned nil response for %s", q.qname)
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeServerFailure, protocol.EDENetworkError, "iterative resolution failed")
			return true, nil
		}
		defer resp.Release()
		sanitizePipelineResponse(resp)

		resp.Header.ID = q.msg.Header.ID

		// Validate DNSSEC on recursively-resolved answers, exactly like the
		// upstream path — recursion without validation would silently skip
		// the validator for every query the resolver handles.
		if handled, _ := h.validateDNSSECResponse(ctx, q.currentWriter, q.msg, q.qname, resp); handled {
			return true, nil
		}

		handled, err := h.applyRPZResponsePolicyWithError(w, q.msg, q.q, resp, q.qname)
		if handled || err != nil {
			return handled, err
		}

		if h.tryDNS64Synthesis(ctx, w, q.msg, q.q, resp) {
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeSuccess)
			}
			return true, nil
		}

		if h.metrics != nil {
			h.metrics.RecordResponse(resp.Header.Flags.RCODE)
		}
		reply(q.currentWriter, q.msg, resp)
		return true, nil
	}
}

// upstreamStage forwards queries to configured upstream servers.
// This is the terminal stage when upstream is configured.
func upstreamStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if h.upstream == nil && h.loadBalancer == nil {
			return false, nil // fall through to noUpstreamStage
		}

		h.logger.Debugf("Forwarding query for %s to upstream", q.qname)
		if h.metrics != nil && h.config != nil {
			if len(h.config.Upstream.Servers) > 0 {
				h.metrics.RecordUpstreamQuery(h.config.Upstream.Servers[0])
			} else if len(h.config.Upstream.AnycastGroups) > 0 {
				h.metrics.RecordUpstreamQuery(h.config.Upstream.AnycastGroups[0].AnycastIP + ":53")
			}
		}

		var resp *protocol.Message
		var err error
		origID := q.msg.Header.ID
		q.msg.Header.ID = upstream.RandomTXID()
		// When validation is on, the upstream query must request DNSSEC
		// records (DO bit) or the answer arrives without RRSIGs and the
		// validator rejects it as a stripped-signature downgrade. The copy
		// keeps the client's own message (and its OPT, or lack of one)
		// untouched for the downstream reply.
		outMsg := q.msg
		if h.validator != nil {
			outMsg = withDOBit(q.msg)
		}
		if h.loadBalancer != nil {
			resp, err = h.loadBalancer.Query(outMsg)
		} else {
			resp, err = h.upstream.Query(outMsg)
		}
		if err != nil {
			q.msg.Header.ID = origID
			h.logger.Warnf("Upstream query failed for %s: %v", q.qname, err)
			if stale := h.cache.GetStale(q.cacheKey); stale != nil && stale.Message != nil {
				h.logger.Debugf("Serving stale cache entry for %s (upstream failed)", q.qname)
				if h.metrics != nil {
					h.metrics.RecordResponse(protocol.RcodeSuccess)
				}
				// GetStale returns a private copy, safe for reply to mutate.
				reply(q.currentWriter, q.msg, stale.Message)
				return true, nil
			}
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeServerFailure, protocol.EDENetworkError, "upstream unavailable")
			return true, nil
		}
		if resp == nil {
			q.msg.Header.ID = origID
			h.logger.Warnf("Upstream returned nil response for %s", q.qname)
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeServerFailure, protocol.EDENetworkError, "invalid upstream response")
			return true, nil
		}
		defer resp.Release()
		sanitizePipelineResponse(resp)

		if resp.Header.ID != q.msg.Header.ID {
			q.msg.Header.ID = origID
			h.logger.Warnf("Upstream response ID mismatch for %s: got %d, want %d", q.qname, resp.Header.ID, q.msg.Header.ID)
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeServerFailure, protocol.EDENetworkError, "invalid upstream response")
			return true, nil
		}

		// Verify the reply echoes the question we asked (name/type/class).
		// Together with the random transaction ID and connected-UDP source
		// filtering this is defense-in-depth against off-path cache poisoning:
		// a spoofed reply that wins the TXID race but answers a different
		// question is rejected before it can be cached.
		if !upstreamResponseMatchesQuestion(resp, q.q) {
			q.msg.Header.ID = origID
			h.logger.Warnf("Upstream response question mismatch for %s", q.qname)
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeServerFailure, protocol.EDENetworkError, "invalid upstream response")
			return true, nil
		}
		q.msg.Header.ID = origID

		handled, dnssecValidated := h.validateDNSSECResponse(ctx, q.currentWriter, q.msg, q.qname, resp)
		if handled {
			return true, nil
		}

		handled, err = h.applyRPZResponsePolicyWithError(w, q.msg, q.q, resp, q.qname)
		if handled || err != nil {
			return handled, err
		}

		if h.tryDNS64Synthesis(ctx, w, q.msg, q.q, resp) {
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeSuccess)
			}
			return true, nil
		}

		// Cache the response (Set deep-copies internally)
		if resp.Header.Flags.RCODE == protocol.RcodeSuccess && len(resp.Answers) > 0 {
			ttl := extractTTL(resp)
			// Bound resp's own TTLs by the cache policy BEFORE Set copies it,
			// so the client and the cached entry agree on how long this answer
			// is good for. Skipping this left the miss response — the one that
			// seeds every downstream cache — carrying the raw upstream TTL.
			h.cache.ApplyTTLPolicy(resp, ttl)
			h.cache.Set(q.cacheKey, resp, ttl)
		} else if resp.Header.Flags.RCODE == protocol.RcodeNameError ||
			(resp.Header.Flags.RCODE == protocol.RcodeSuccess && len(resp.Answers) == 0) {
			// Store the full message so negative cache hits can serve the
			// SOA (RFC 2308) and any NSEC/NSEC3 proofs back to the client.
			// negTTL==0 falls back to the cache's configured negative TTL.
			negTTL, _ := negativeCacheTTL(resp)
			h.cache.SetNegativeMessage(q.cacheKey, resp.Header.Flags.RCODE, resp, negTTL)
			h.logger.Debugf("Cached negative response for %s (rcode=%d, negTTL=%d)", q.qname, resp.Header.Flags.RCODE, negTTL)

			if h.nsecCache != nil && resp.Header.Flags.RCODE == protocol.RcodeNameError {
				h.nsecCache.AddFromResponse(resp, dnssecValidated)
			}
		}

		if h.metrics != nil {
			h.metrics.RecordResponse(resp.Header.Flags.RCODE)
		}

		// RRL check
		if h.security.RRL != nil {
			clientIP := w.ClientInfo().IP()
			if clientIP != nil {
				qtype := uint16(0)
				if len(resp.Questions) > 0 {
					qtype = resp.Questions[0].QType
				}
				queryLen := q.msg.WireLength()
				responseLen := resp.WireLength()
				h.security.RRL.LogSuperlative(clientIP, qtype, resp.Header.Flags.RCODE, queryLen, responseLen)
				if allowed, suppressed := h.security.RRL.Allow(clientIP, qtype, resp.Header.Flags.RCODE); !allowed {
					if suppressed {
						h.sendRefused(q.currentWriter, q.msg)
						return true, nil
					}
				}
			}
		}

		reply(q.currentWriter, q.msg, resp)
		return true, nil
	}
}

// upstreamResponseMatchesQuestion reports whether an upstream reply echoes the
// question we asked: exactly one question with matching name (case-insensitive
// per RFC 4343), type, and class. A response that omits or alters the question
// is treated as invalid (potential off-path spoof) rather than trusted.
func upstreamResponseMatchesQuestion(resp *protocol.Message, want *protocol.Question) bool {
	if want == nil {
		return true // nothing to compare against; ID check already passed
	}
	if len(resp.Questions) != 1 {
		return false
	}
	got := resp.Questions[0]
	if got == nil {
		return false
	}
	return got.QType == want.QType && got.QClass == want.QClass && got.Name.Equal(want.Name)
}

func negativeCacheTTL(resp *protocol.Message) (uint32, bool) {
	if resp == nil {
		return 0, false
	}
	for _, rr := range resp.Authorities {
		if rr == nil {
			continue
		}
		soa, ok := rr.Data.(*protocol.RDataSOA)
		if !ok || soa == nil {
			continue
		}
		negTTL := rr.TTL
		if soa.Minimum < negTTL {
			negTTL = soa.Minimum
		}
		return negTTL, true
	}
	return 0, false
}

// withDOBit returns msg unchanged if it already carries EDNS0 with the DO bit
// set; otherwise it returns a shallow copy whose OPT record requests DNSSEC
// records (RFC 4035 §3.2.1). Existing EDNS0 options (cookies, ECS) and the
// client's advertised payload size are preserved; a client without EDNS0 gets
// a fresh OPT on the copy only — the original message is never mutated, so
// the downstream reply still honors what the client actually sent.
func withDOBit(msg *protocol.Message) *protocol.Message {
	opt := msg.GetOPT()
	if opt != nil {
		if h := protocol.ParseEDNS0Header(opt); h != nil && h.DO {
			return msg
		}
	}

	fwd := *msg
	fwd.Additionals = make([]*protocol.ResourceRecord, 0, len(msg.Additionals)+1)
	for _, rr := range msg.Additionals {
		if rr == nil || rr.Type == protocol.TypeOPT {
			continue
		}
		fwd.Additionals = append(fwd.Additionals, rr)
	}

	newOPT := &protocol.ResourceRecord{
		Name:  protocol.NewName(nil, true), // OPT owner name is root
		Type:  protocol.TypeOPT,
		Class: 4096,
		TTL:   protocol.BuildEDNSTTL(0, 0, true, 0),
		Data:  &protocol.RDataOPT{},
	}
	if opt != nil {
		newOPT.Class = opt.Class
		newOPT.TTL = opt.TTL | 0x8000 // set DO, keep extended RCODE/version/Z
		newOPT.Data = opt.Data
	}
	fwd.AddAdditional(newOPT) // also refreshes fwd.Header.ARCount

	return &fwd
}

func sanitizePipelineResponse(resp *protocol.Message) {
	if resp == nil {
		return
	}
	resp.Questions = filterValidQuestions(resp.Questions)
	resp.Answers = filterValidResourceRecords(resp.Answers)
	resp.Authorities = filterValidResourceRecords(resp.Authorities)
	resp.Additionals = filterValidResourceRecords(resp.Additionals)
}

func filterValidQuestions(questions []*protocol.Question) []*protocol.Question {
	if len(questions) == 0 {
		return questions
	}
	out := questions[:0]
	for _, q := range questions {
		if q == nil || q.Name == nil {
			continue
		}
		out = append(out, q)
	}
	return out
}

func filterValidResourceRecords(records []*protocol.ResourceRecord) []*protocol.ResourceRecord {
	if len(records) == 0 {
		return records
	}
	out := records[:0]
	for _, rr := range records {
		if rr == nil || rr.Name == nil || isNilPipelineRData(rr.Data) {
			continue
		}
		out = append(out, rr)
	}
	return out
}

func isNilPipelineRData(data protocol.RData) bool {
	if data == nil {
		return true
	}
	value := reflect.ValueOf(data)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// noUpstreamStage is the terminal stage when no upstream is configured.
// Returns NXDOMAIN with EDE per RFC 8914 §4.21.
func noUpstreamStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		h.logger.Debugf("No upstream configured, returning NXDOMAIN for %s", q.qname)
		if h.metrics != nil {
			h.metrics.RecordResponse(protocol.RcodeNameError)
		}
		sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeNameError, protocol.EDENotAuthoritative, "no upstream configured")
		return true, nil
	}
}

// cookieStage handles RFC 7873 DNS Cookie validation.
// Wraps the response writer to inject server cookies into every response.
func cookieStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if h.cookieJar == nil {
			return false, nil
		}
		clientIP := w.ClientInfo().IP()
		if clientIP == nil {
			return false, nil
		}
		cookieData, valid := h.processCookies(q.msg, clientIP)
		if !valid {
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:    q.msg.Header.ID,
					Flags: protocol.NewResponseFlags(protocol.RcodeBadCookie),
				},
				Questions: q.msg.Questions,
			}
			resp.SetEDNS0(4096, false)
			if opt := resp.GetOPT(); opt != nil {
				if optData, ok := opt.Data.(*protocol.RDataOPT); ok {
					optData.AddOption(protocol.OptionCodeCookie, cookieData)
				}
			}
			if _, err := q.currentWriter.Write(resp); err != nil {
				return true, err
			}
			return true, nil
		}
		if cookieData != nil {
			q.currentWriter = &cookieResponseWriter{inner: q.currentWriter, cookieData: cookieData}
		}
		return false, nil
	}
}

// anyStage handles RFC 8482 ANY query. For UDP, set TC=1 to force TCP retry.
func anyStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if q.qtype == protocol.TypeANY {
			if w.ClientInfo().Protocol == "udp" {
				h.handleANYTruncated(q.currentWriter, q.msg, q.q)
				return true, nil
			}
		}
		return false, nil
	}
}

// transferStage handles AXFR, IXFR, NOTIFY, and UPDATE requests.
// Each handler is nil-guarded: if the corresponding sub-server was not
// initialised (disabled config or startup failure), the request is refused
// rather than panicking on a nil pointer dereference.
func transferStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if q.qtype == protocol.TypeAXFR {
			if h.transfer.AXFRServer == nil {
				sendError(q.currentWriter, q.msg, protocol.RcodeRefused)
				return true, nil
			}
			h.handleAXFR(q.currentWriter, q.msg, q.q)
			return true, nil
		}
		if q.qtype == protocol.TypeIXFR {
			if h.transfer.IXFRServer == nil {
				sendError(q.currentWriter, q.msg, protocol.RcodeRefused)
				return true, nil
			}
			h.handleIXFR(q.currentWriter, q.msg, q.q)
			return true, nil
		}
		if transfer.IsNOTIFYRequest(q.msg) {
			if h.transfer.NotifyHandler == nil {
				sendError(q.currentWriter, q.msg, protocol.RcodeRefused)
				return true, nil
			}
			h.handleNOTIFY(q.currentWriter, q.msg, q.q)
			return true, nil
		}
		if transfer.IsUpdateRequest(q.msg) {
			if h.transfer.DDNSHandler == nil {
				sendError(q.currentWriter, q.msg, protocol.RcodeRefused)
				return true, nil
			}
			h.handleUPDATE(q.currentWriter, q.msg, q.q)
			return true, nil
		}
		return false, nil
	}
}
