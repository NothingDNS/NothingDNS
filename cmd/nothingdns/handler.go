// NothingDNS - DNS request handler

package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/audit"
	"github.com/nothingdns/nothingdns/internal/blocklist"
	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/cluster"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/filter"
	"github.com/nothingdns/nothingdns/internal/geodns"
	"github.com/nothingdns/nothingdns/internal/metrics"
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
	blocklist     *blocklist.Blocklist
	rpzEngine     *rpz.Engine
	geoEngine     *geodns.Engine
	metrics       *metrics.MetricsCollector
	validator     *dnssec.Validator
	zoneSigners   map[string]*dnssec.Signer
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

	notifyOnce sync.Once
	updateOnce sync.Once
}

// ServeDNS implements the server.Handler interface.
func (h *integratedHandler) ServeDNS(w server.ResponseWriter, r *protocol.Message) {
	start := time.Now()

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
				Timestamp: start.UTC().Format(time.RFC3339),
				ClientIP:  clientIP,
				QueryName: qnameAudit,
				QueryType: qtypeStr,
				Latency:    latency,
				CacheHit:   cacheHit,
			})
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

	h.logger.Debugf("Query: %s %s", qname, typeToString(qtype))

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

	// Check blocklist
	if h.blocklist != nil && h.blocklist.IsBlocked(qname) {
		h.logger.Infof("Blocked query for %s", qname)
		if h.metrics != nil {
			h.metrics.RecordBlocklistBlock()
		}
		sendError(w, r, protocol.RcodeNameError)
		return
	}

	// Check RPZ QNAME policy
	if h.rpzEngine != nil {
		if rule := h.rpzEngine.QNAMEPolicy(qname); rule != nil {
			switch rule.Action {
			case rpz.ActionNXDOMAIN:
				h.logger.Debugf("RPZ NXDOMAIN for %s (policy: %s)", qname, rule.PolicyName)
				if h.metrics != nil {
					h.metrics.RecordBlocklistBlock()
				}
				sendError(w, r, protocol.RcodeNameError)
				return
			case rpz.ActionNODATA:
				h.logger.Debugf("RPZ NODATA for %s (policy: %s)", qname, rule.PolicyName)
				if h.metrics != nil {
					h.metrics.RecordBlocklistBlock()
				}
				sendError(w, r, protocol.RcodeSuccess)
				return
			case rpz.ActionDrop:
				h.logger.Debugf("RPZ DROP for %s (policy: %s)", qname, rule.PolicyName)
				return // silently drop
			case rpz.ActionPassThrough:
				// Allow the query to proceed normally
			case rpz.ActionTCPOnly:
				// Set TC bit to force TCP retry
				resp := r.Copy()
				resp.Header.Flags.TC = true
				resp.Header.Flags.QR = true
				resp.Header.Flags.RCODE = protocol.RcodeSuccess
				w.Write(resp)
				return
			case rpz.ActionOverride, rpz.ActionCNAME:
				// Will be handled after resolution as override
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
	h.zonesMu.RLock()
	var matchedZone bool
	for origin, z := range h.zones {
		if isSubdomain(qname, origin) {
			matchedZone = true
			h.logger.Debugf("Checking zone %s for %s", origin, qname)
			if h.handleAuthoritative(z, w, r, q) {
				h.zonesMu.RUnlock()
				return
			}
		}
	}
	h.zonesMu.RUnlock()

	// Also check zones created via API (stored in zoneManager)
	if h.zoneManager != nil {
		for name, z := range h.zoneManager.List() {
			if !isSubdomain(qname, name) {
				continue
			}
			// Skip if already checked in h.zones (file-loaded zones)
			h.zonesMu.RLock()
			_, inLocal := h.zones[name]
			h.zonesMu.RUnlock()
			if inLocal {
				matchedZone = true
				continue
			}
			matchedZone = true
			h.logger.Debugf("Checking zone manager zone %s for %s", name, qname)
			if h.handleAuthoritative(z, w, r, q) {
				return
			}
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
			sendError(w, r, protocol.RcodeServerFailure)
			return
		}
		if len(result.cnameRecords) > 0 {
			// We have a CNAME chain — resolve the target
			targetAnswers := h.resolveCNAMETarget(w, r, q, result.targetName, qtype)
			resp := h.buildCNAMEResponse(r, result.cnameRecords, targetAnswers)
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
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendError(w, r, protocol.RcodeServerFailure)
			return
		}

		// Copy query ID from original request
		resp.Header.ID = r.Header.ID

		if h.metrics != nil {
			h.metrics.RecordResponse(resp.Header.Flags.RCODE)
		}
		reply(w, r, resp)
		return
	}

	// Forward to upstream
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
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendError(w, r, protocol.RcodeServerFailure)
			return
		}

		// Validate DNSSEC if enabled and response has signatures
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
			case dnssec.ValidationBogus:
				h.logger.Warnf("DNSSEC validation failed (bogus) for %s", qname)
				if h.config.DNSSEC.Enabled {
					// Return SERVFAIL if DNSSEC validation failed
					if h.metrics != nil {
						h.metrics.RecordResponse(protocol.RcodeServerFailure)
					}
					sendError(w, r, protocol.RcodeServerFailure)
					return
				}
			case dnssec.ValidationInsecure:
				h.logger.Debugf("DNSSEC insecure zone for %s", qname)
			case dnssec.ValidationIndeterminate:
				h.logger.Debugf("DNSSEC indeterminate for %s", qname)
			}
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
	sendError(w, r, protocol.RcodeNameError)
}

// reply sends a response message.
func reply(w server.ResponseWriter, query, response *protocol.Message) {
	response.Header.ID = query.Header.ID
	response.Header.Flags.QR = true
	if len(response.Questions) == 0 {
		response.Questions = query.Questions
	}
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
