// NothingDNS - DNS query pipeline stages

package main

import (
	"context"
	"reflect"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/config"
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

		// RFC 5891: Validate IDNA (internationalized domain names) with the
		// configured idna.* options (F621).
		if h.idnaEnabled {
			profile := idna.Profile{UseSTD3Rules: true, AllowUnassigned: true}
			if h.config != nil {
				profile = idnaProfileFromConfig(h.config.IDNA)
			}
			if _, err := profile.ToASCII(q.qname); err != nil {
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
			// Bound the metric label to known types only. protocol.TypeToString
			// falls back to "TYPE<number>" for unknown QTYPEs, which is
			// unbounded (65 536 distinct labels from attacker-controlled input).
			// We collapse unknown types to a single "OTHER" label instead.
			if _, known := protocol.TypeToString[q.qtype]; known {
				h.metrics.RecordQuery(q.qtypeStr)
			} else {
				h.metrics.RecordQuery("OTHER")
			}
		}
		return false, nil
	}
}

// aclStage checks the access control list.
func aclStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		clientIP := w.ClientInfo().IP()
		// A nil (unknown) client IP is still evaluated: it matches no rule,
		// so it is refused once any rule exists (fail closed, F427). Skipping
		// the check let transports without a client address bypass the ACL.
		if h.security.ACLChecker != nil {
			allowed, redirect := h.security.ACLChecker.IsAllowed(clientIP, q.qtype)
			if !allowed {
				if redirect != "" {
					h.logger.Infof("ACL redirect: %s %s from %s -> %s", q.qname, typeToString(q.qtype), clientIP, redirect)
					h.handleACLRedirect(q.currentWriter, q.msg, q.q, redirect)
				} else {
					h.logger.Infof("ACL denied: %s %s from %s", q.qname, typeToString(q.qtype), clientIP)
					// EDE 18 tells the client why (RFC 8914 §4.19), as the
					// recursion refusal does (F748).
					sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeRefused, protocol.EDEProhibited, "")
				}
				return true, nil
			}
		}
		return false, nil
	}
}

// recursionPolicyStage decides whether this client may use recursion
// (allow_recursion). A client that may not still gets answers from the
// server's own zones; cache, NSEC-cache, resolver and upstream stages are
// skipped for it and names outside the zones are refused.
func recursionPolicyStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		policy := h.security.RecursionPolicy
		if policy == nil {
			return false, nil
		}
		clientIP := w.ClientInfo().IP()
		if clientIP == nil || !policy.Allowed(clientIP) {
			denyRecursion(q.currentWriter)
		}
		return false, nil
	}
}

// recursionRefusedStage answers names outside the local zones with REFUSED
// for clients that may not use recursion (RFC 8914 EDE 18, Prohibited).
func recursionRefusedStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if recursionAllowedFor(q.currentWriter) {
			return false, nil
		}
		h.logger.Debugf("Recursion refused: %s %s from %s", q.qname, typeToString(q.qtype), w.ClientInfo().IP())
		if h.metrics != nil {
			h.metrics.RecordResponse(protocol.RcodeRefused)
		}
		sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeRefused, protocol.EDEProhibited, "recursion not allowed for this client")
		return true, nil
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
				sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeRefused, protocol.EDEOtherError, "rate limited") // as RRL (F748)
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
		// The shared cache holds recursively resolved data; serving it to a
		// client without recursion rights would leak other clients' lookups
		// (cache snooping) and act as partial recursion.
		if !recursionAllowedFor(q.currentWriter) {
			return false, nil
		}
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
			resp := entry.AgeAdjustedMessage(time.Now())
			// The blocklist may have gained a CNAME target since the
			// answer was cached.
			if h.blockCNAMETarget(q, resp) {
				return true, nil
			}
			reply(q.currentWriter, q.msg, resp)
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
		if h.nsecCache != nil && recursionAllowedFor(q.currentWriter) {
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

// blockCNAMETarget answers q as blocked (NXDOMAIN, EDE Filtered, like
// blocklistStage) when resp's CNAME chain leads to a blocked name and
// blocklist.cname_inspection is on. It is applied to recursive answers before
// they are cached and to cache and stale hits, since the blocklist may have
// gained the target since; local zones are not inspected.
func (h *integratedHandler) blockCNAMETarget(q *query, resp *protocol.Message) bool {
	if q.q == nil || q.q.Name == nil {
		return false
	}
	target, blocked := h.blockedCNAMETarget(q.q.Name.String(), resp)
	if !blocked {
		return false
	}
	h.logger.Debugf("Blocked query for %s (CNAME target %s)", q.qname, target)
	q.blocked = true
	if h.metrics != nil {
		h.metrics.RecordBlocklistBlock()
	}
	sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeNameError, protocol.EDEFiltered, "blocked by blocklist (CNAME target)")
	return true
}

// blockedCNAMETarget returns the blocked name resp's CNAME chain from qname
// leads to, when blocklist CNAME inspection is on.
func (h *integratedHandler) blockedCNAMETarget(qname string, resp *protocol.Message) (string, bool) {
	bl := h.security.Blocklist
	if bl == nil || resp == nil {
		return "", false
	}
	return bl.BlockedCNAMETarget(extractCNAMETargets(resp, qname))
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

		// The view's zones are held in a map, so a bare range would decide which
		// zone answers by Go's randomized iteration order. Answer from the most
		// specific (longest) matching origin, exactly as ZoneProvider.FindZones
		// documents (zone_provider.go:16-18) and authoritativeStage relies on:
		// with both example.com. and sub.example.com. in one view, the parent's
		// delegation NS RRset would otherwise answer a name the child zone owns
		// with a referral, non-deterministically.
		var viewMatches []ZoneMatch
		for origin, z := range vzMap {
			if !isSubdomain(q.qname, origin) {
				continue
			}
			viewMatches = append(viewMatches, ZoneMatch{Origin: origin, Zone: z})
		}
		if len(viewMatches) == 0 {
			return false, nil
		}
		sortZonesByLength(viewMatches)
		for i, m := range viewMatches {
			if dsAnsweredByParent(q.qtype, q.qname, m.Origin, i < len(viewMatches)-1) {
				continue // F383
			}
			h.logger.Debugf("View %s: checking zone %s for %s", view.Name, m.Origin, q.qname)
			if h.handleAuthoritative(m.Zone, w, q.msg, q.q, q.qname, &q.cacheHit) {
				return true, nil
			}
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

	// Resolve the chain's endpoint inside the view first. A name no view
	// zone covers falls back to the ordinary path (global zones, cache,
	// upstream) — the same answer any client would get, so nothing private
	// to this view leaks and nothing public is hidden from it. F517/F518:
	// each link is signed by its own zone for DO=1, and a negative endpoint
	// carries its zone's SOA and denial proof.
	sign := hasDOBit(q.msg)
	tgt := h.resolveChainTarget(w, q.msg, vzMap, result.targetName, q.qtype, sign)
	resp := h.buildChainResponse(q.msg, result, tgt, sign)
	handled, err := h.applyRPZResponsePolicyWithError(w, q.msg, q.q, resp, result.targetName)
	if handled || err != nil {
		return handled, err
	}
	if h.metrics != nil {
		h.metrics.RecordResponse(resp.Header.Flags.RCODE)
	}
	reply(q.currentWriter, q.msg, resp)
	return true, nil
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

		for i, m := range matchedZones {
			if dsAnsweredByParent(q.qtype, q.qname, m.name, i < len(matchedZones)-1) {
				continue // F383
			}
			h.logger.Debugf("Checking zone %s for %s", m.name, q.qname)
			if h.handleAuthoritative(m.z, w, q.msg, q.q, q.qname, &q.cacheHit) {
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
			// F517/F518: sign each link with its own zone for DO=1; a
			// negative endpoint carries its zone's SOA and denial proof.
			sign := hasDOBit(q.msg)
			tgt := h.resolveChainTarget(w, q.msg, nil, result.targetName, q.qtype, sign)
			resp := h.buildChainResponse(q.msg, result, tgt, sign)

			handled, err := h.applyRPZResponsePolicyWithError(w, q.msg, q.q, resp, result.targetName)
			if handled || err != nil {
				return handled, err
			}

			if h.metrics != nil {
				h.metrics.RecordResponse(resp.Header.Flags.RCODE)
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

// maxIterativeResolveTimeout bounds the whole-resolution budget of one
// iterative lookup, whatever resolution.timeout says (F625).
const maxIterativeResolveTimeout = 30 * time.Second

// iterativeResolveTimeout is the budget for one iterative resolution:
// resolution.timeout (5s when unset or unparsable, at most
// maxIterativeResolveTimeout). It is read from cfg per query, so a reload
// applies it (F625; previously a hard-coded 5s capped every resolution).
func iterativeResolveTimeout(cfg *config.Config) time.Duration {
	if cfg == nil {
		return 5 * time.Second
	}
	d := parseDurationOrDefault(cfg.Resolution.Timeout, 5*time.Second)
	if d <= 0 {
		d = 5 * time.Second
	}
	if d > maxIterativeResolveTimeout {
		d = maxIterativeResolveTimeout
	}
	return d
}

// resolverStage uses iterative recursive resolver if enabled.
func resolverStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if h.resolver == nil {
			return false, nil
		}

		h.logger.Debugf("Resolving %s iteratively", q.qname)
		// RFC 9520: no outgoing query while a failure is cached (F750).
		if h.answerCachedFailure(q) {
			return true, nil
		}
		failKey := failureKey(q)
		resp, err := func() (*protocol.Message, error) {
			resolveCtx, cancel := context.WithTimeout(ctx, iterativeResolveTimeout(h.config))
			defer cancel()
			return h.resolver.Resolve(resolveCtx, q.qname, q.qtype)
		}()
		if err != nil {
			h.failures.add(failKey)
			h.logger.Warnf("Iterative resolution failed for %s: %v", q.qname, err)
			// RFC 8767: Try serve-stale when resolution fails
			if h.serveStaleOnFailedRefresh(q, "resolver failed") {
				return true, nil
			}
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeServerFailure, protocol.EDENetworkError, "iterative resolution failed")
			return true, nil
		}
		if resp == nil {
			h.failures.add(failKey)
			h.logger.Warnf("Iterative resolution returned nil response for %s", q.qname)
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeServerFailure, protocol.EDENetworkError, "iterative resolution failed")
			return true, nil
		}
		defer resp.Release()
		sanitizePipelineResponse(resp)

		// The iterative resolver reports an unreachable or lame authority
		// as a SERVFAIL response, not as an error (RFC 8767 §4).
		if failedRefresh(resp) {
			h.failures.add(failKey)
			if h.serveStaleOnFailedRefresh(q, "resolver returned "+rcodeToString(resp.Header.Flags.RCODE)) {
				return true, nil
			}
		}

		resp.Header.ID = q.msg.Header.ID
		// The resolver returns the authoritative server's header: AA is not
		// this server's claim on a recursive answer, and AD may only come
		// from the local validator's Secure verdict (RFC 4035 §3.2.3, F659).
		resp.Header.Flags.AA = false
		resp.Header.Flags.AD = false

		// Validate DNSSEC on recursively-resolved answers, exactly like the
		// upstream path — recursion without validation would silently skip
		// the validator for every query the resolver handles.
		handled, dnssecValidated, dnssecBogus := h.validateDNSSECResponse(ctx, q.currentWriter, q.msg, q.qname, resp)
		if handled {
			h.failures.add(failKey) // validation failure (RFC 9520 §3.4)
			return true, nil
		}

		handled, err = h.applyRPZResponsePolicyWithError(w, q.msg, q.q, resp, q.qname)
		if handled || err != nil {
			return handled, err
		}
		if h.blockCNAMETarget(q, resp) {
			return true, nil
		}

		if h.tryDNS64Synthesis(ctx, w, q.msg, q.q, resp) {
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeSuccess)
			}
			return true, nil
		}

		// Cached under the pipeline key like forwarded answers: the
		// resolver's own entries use other keys, so without this the cache
		// stage never hit and serve-stale never found an entry (F669).
		h.cachePipelineResponse(q, resp, dnssecValidated, dnssecBogus)

		if h.metrics != nil {
			h.metrics.RecordResponse(resp.Header.Flags.RCODE)
		}
		reply(q.currentWriter, q.msg, resp)
		return true, nil
	}
}

// failedRefresh reports whether resp is an error answer that does not refresh
// cached data. RFC 8767 §4: only NOERROR and NXDOMAIN are answers; any other
// RCODE (SERVFAIL, REFUSED, ...) "SHOULD be considered a failure to refresh the
// data and therefore leave any previous state intact". A recursive upstream
// that cannot reach the authority reports the outage exactly this way — as a
// SERVFAIL response, not as a transport error.
func failedRefresh(resp *protocol.Message) bool {
	if resp == nil {
		return false
	}
	switch resp.Header.Flags.RCODE {
	case protocol.RcodeSuccess, protocol.RcodeNameError:
		return false
	default:
		return true
	}
}

// serveStaleOnFailedRefresh answers q from the stale cache (RFC 8767) after a
// failed refresh and reports whether it did. GetStale returns a private copy
// with TTLs clamped to 30s, safe for reply to mutate; it is nil when serve-stale
// is off or nothing usable is cached, in which case the caller's error answer
// goes out unchanged.
func (h *integratedHandler) serveStaleOnFailedRefresh(q *query, why string) bool {
	stale := h.cache.GetStale(q.cacheKey)
	if stale == nil || stale.Message == nil {
		return false
	}
	if h.blockCNAMETarget(q, stale.Message) {
		return true
	}
	h.logger.Debugf("Serving stale cache entry for %s (%s)", q.qname, why)
	if h.metrics != nil {
		h.metrics.RecordResponse(protocol.RcodeSuccess)
	}
	reply(q.currentWriter, q.msg, stale.Message)
	return true
}

// cachePipelineResponse caches a validated, policy-checked answer under the
// query's pipeline key (Set deep-copies internally). Bogus data served to a
// CD=1 client is never cached (F662).
func (h *integratedHandler) cachePipelineResponse(q *query, resp *protocol.Message, dnssecValidated, dnssecBogus bool) {
	if dnssecBogus {
		return
	}
	if resp.Header.Flags.RCODE == protocol.RcodeSuccess && len(resp.Answers) > 0 {
		ttl := answerCacheTTL(resp)
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
		// negTTL==0 with no SOA falls back to the cache's configured negative
		// TTL. A SOA that says 0 is different: the negative TTL is
		// min(SOA TTL, SOA MINIMUM) (RFC 2308 §5), and zero means the answer
		// can only be used for the transaction in progress (RFC 1035 §3.2.1),
		// so it is not cached — passing the 0 on would be read as "unknown".
		negTTL, hasSOA := negativeCacheTTL(resp)
		if hasSOA && negTTL == 0 {
			return
		}
		h.cache.SetNegativeMessage(q.cacheKey, resp.Header.Flags.RCODE, resp, negTTL)
		h.logger.Debugf("Cached negative response for %s (rcode=%d, negTTL=%d)", q.qname, resp.Header.Flags.RCODE, negTTL)

		if h.nsecCache != nil && resp.Header.Flags.RCODE == protocol.RcodeNameError {
			h.nsecCache.AddFromResponse(resp, dnssecValidated)
		}
	}
}

// upstreamStage forwards queries to configured upstream servers.
// This is the terminal stage when upstream is configured.
func upstreamStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if h.upstream == nil && h.loadBalancer == nil {
			return false, nil // fall through to noUpstreamStage
		}
		// RFC 9520: no outgoing query while a failure is cached (F750).
		if h.answerCachedFailure(q) {
			return true, nil
		}
		failKey := failureKey(q)

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
		outMsg := forwardedQuery(q.msg, h.validator != nil)
		if h.loadBalancer != nil {
			resp, err = h.loadBalancer.Query(outMsg)
		} else {
			resp, err = h.upstream.Query(outMsg)
		}
		if err != nil {
			q.msg.Header.ID = origID
			h.failures.add(failKey)
			h.logger.Warnf("Upstream query failed for %s: %v", q.qname, err)
			if h.serveStaleOnFailedRefresh(q, "upstream failed") {
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
			h.failures.add(failKey)
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
			h.failures.add(failKey)
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
			h.failures.add(failKey)
			h.logger.Warnf("Upstream response question mismatch for %s", q.qname)
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeServerFailure, protocol.EDENetworkError, "invalid upstream response")
			return true, nil
		}
		q.msg.Header.ID = origID

		// An upstream that is up but cannot resolve answers SERVFAIL (or
		// REFUSED): a failed refresh, so stale data is served just as when
		// the upstream does not answer at all (RFC 8767 §4).
		if failedRefresh(resp) {
			h.failures.add(failKey)
			if h.serveStaleOnFailedRefresh(q, "upstream returned "+rcodeToString(resp.Header.Flags.RCODE)) {
				return true, nil
			}
		}

		// AD is this server's own claim (RFC 4035 §3.2.3): with a validator
		// configured, only its Secure verdict may set it. The upstream's AD
		// bit would otherwise reach the client — and the cache — even when
		// the local validator found the answer Insecure.
		if h.validator != nil {
			resp.Header.Flags.AD = false
		}

		handled, dnssecValidated, dnssecBogus := h.validateDNSSECResponse(ctx, q.currentWriter, q.msg, q.qname, resp)
		if handled {
			h.failures.add(failKey) // validation failure (RFC 9520 §3.4)
			return true, nil
		}

		handled, err = h.applyRPZResponsePolicyWithError(w, q.msg, q.q, resp, q.qname)
		if handled || err != nil {
			return handled, err
		}
		if h.blockCNAMETarget(q, resp) {
			return true, nil
		}

		if h.tryDNS64Synthesis(ctx, w, q.msg, q.q, resp) {
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeSuccess)
			}
			return true, nil
		}

		h.cachePipelineResponse(q, resp, dnssecValidated, dnssecBogus)

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

// forwardedEDNSBufferSize is the UDP payload size this server advertises to
// upstreams: the DNS Flag Day 2020 value, which avoids IP fragmentation.
const forwardedEDNSBufferSize = 1232

// forwardedQuery is the query sent upstream for a client's query: its header
// and question, and this server's own OPT. OPT is hop-by-hop (RFC 6891
// §6.1.1): the client's options — its Client Subnet (never forwarded, see
// SPECIFICATION §9.4), its cookie for this server, Padding — and any other
// additional record (TSIG) stay here (F749). The OPT keeps the client's DO
// bit, or sets it when forceDO (a validator needs RRSIGs); a client without
// EDNS is forwarded without it unless forceDO.
func forwardedQuery(msg *protocol.Message, forceDO bool) *protocol.Message {
	fwd := &protocol.Message{Header: msg.Header, Questions: msg.Questions}
	fwd.Header.ARCount = 0
	do := forceDO
	opt := msg.GetOPT()
	if opt != nil {
		if h := protocol.ParseEDNS0Header(opt); h != nil && h.DO {
			do = true
		}
	}
	if opt != nil || do {
		fwd.SetEDNS0(forwardedEDNSBufferSize, do)
	}
	return fwd
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

// noUpstreamStage is the terminal stage when neither an upstream nor an
// iterative resolver is configured: the server has no path to the name and no
// basis for a definitive answer, so it reports a transient failure.
//
// It must NOT answer NXDOMAIN. NXDOMAIN is a definitive nonexistence claim
// (RFC 1035 §4.1.1 RCODE 3) for a name the server cannot even look up; it is
// cacheable (RFC 2308 §5) and RFC 8020 resolvers extend it to every name below
// the owner, so a real name gets reported as nonexistent downstream. SERVFAIL is
// the code for "the name server was unable to process this query" (RFC 1035
// §4.1.1 RCODE 2), which is what upstreamStage already answers when a configured
// upstream is unreachable. EDE 20 (Not Authoritative, RFC 8914 §4.20) carries
// the reason.
func noUpstreamStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		h.logger.Debugf("No upstream configured, returning SERVFAIL for %s", q.qname)
		if h.metrics != nil {
			h.metrics.RecordResponse(protocol.RcodeServerFailure)
		}
		sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeServerFailure, protocol.EDENotAuthoritative, "no upstream configured")
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
		// An invalid server cookie is handled as a request with only a client
		// cookie (RFC 7873 §5.2.4). Over TCP, TLS, HTTPS and QUIC the
		// connection authenticates the client, so the request is answered
		// with a fresh cookie instead of BADCOOKIE (§5.2.3), which a client
		// that keeps the old cookie would retry endlessly — e.g. every
		// TCP client once after a restart replaced the secret (F736).
		if !valid && cookieData != nil && w.ClientInfo().Protocol != "udp" {
			valid = true
		}
		if !valid {
			// No cookie data means the option was malformed (F641).
			rcode := uint8(protocol.RcodeBadCookie)
			if cookieData == nil {
				rcode = protocol.RcodeFormatError
			}
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:    q.msg.Header.ID,
					Flags: protocol.NewResponseFlags(rcode),
				},
				Questions: q.msg.Questions,
			}
			resp.SetEDNS0(4096, false)
			if opt := resp.GetOPT(); opt != nil && rcode == protocol.RcodeBadCookie {
				// RFC 6891 §6.1.3: RcodeBadCookie (23) cannot ride in the
				// 4-bit header RCODE alone — the OPT TTL must carry the
				// extended byte (23>>4 = 1) or external clients decode the
				// response as YXRRSET (7). Same pattern as the BADVERS site.
				opt.TTL = protocol.BuildEDNSTTL(protocol.RcodeBadCookie>>4, 0, false, 0)
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
			if h.currentDDNSHandler() == nil {
				sendError(q.currentWriter, q.msg, protocol.RcodeRefused)
				return true, nil
			}
			h.handleUPDATE(q.currentWriter, q.msg, q.q)
			return true, nil
		}
		return false, nil
	}
}
