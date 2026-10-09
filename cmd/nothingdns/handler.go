// NothingDNS - DNS request handler

package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/audit"
	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/cluster"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/dashboard"
	"github.com/nothingdns/nothingdns/internal/dnscookie"
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/dso"
	"github.com/nothingdns/nothingdns/internal/filter"
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

// handlerLogger is a package-level reference used by package-level helper
// functions (reply, sendError, sendErrorWithEDE) that don't have access to
// h.logger. Set during initialization in main.go.
var handlerLogger *util.Logger

// logErrorf logs an error via the package-level handlerLogger if set.
// Falls back silently when nil (e.g. during tests).
func logErrorf(format string, args ...interface{}) {
	if handlerLogger != nil {
		handlerLogger.Errorf(format, args...)
	}
}

// integratedHandler is the DNS request handler that uses all components.
type integratedHandler struct {
	config        *config.Config
	runtimeMu     sync.RWMutex
	logger        *util.Logger
	upstream      *upstream.Client
	loadBalancer  *upstream.LoadBalancer
	resolver      *resolver.Resolver
	zones         map[string]*zone.Zone
	zonesMu       sync.RWMutex
	zoneManager   *zone.Manager
	kvPersistence *zone.KVPersistence
	metrics       *metrics.MetricsCollector
	// dashboardServer receives a QueryEvent per request to feed the Query Log
	// page and the live WebSocket stream. Optional (nil when no dashboard).
	dashboardServer *dashboard.Server
	validator       *dnssec.Validator
	zoneSigners     map[string]*dnssec.Signer
	zoneSignersMu   sync.RWMutex
	nsec3Memo       nsec3HashMemo   // F488: NSEC3 owner hashes for online denial
	zoneTree        *zone.RadixTree // Radix tree for O(log n) zone matching
	cluster         *cluster.Cluster
	splitHorizon    *filter.SplitHorizon
	viewZones       map[string]map[string]*zone.Zone // view name -> origin -> Zone
	auditLogger     *audit.AuditLogger
	tracer          *otel.Tracer
	serverCtx       context.Context // Root context for all per-query work; cancelled on server shutdown
	cancelServer    context.CancelFunc
	idnaEnabled     bool // RFC 5891 IDNA validation enabled
	mdnsResponder   *mdns.Responder
	dsoManager      *dso.Manager
	cookieJar       *dnscookie.CookieJar

	// Component sub-structs (replaced atomically on hot-reload)
	security SecurityComponents
	transfer TransferComponents

	// Flat cache fields (kept flat to avoid renaming every h.cache → h.cache.ResponseCache)
	cache     *cache.Cache
	nsecCache *cache.NSECCache // RFC 8198 aggressive NSEC caching

	zoneProvider ZoneProvider // unified zone lookup

	pipeline *Pipeline // DNS query pipeline (lazy-initialized)

	notifyOnce sync.Once
	// xferKeysMu makes a SIGHUP change of transfer.tsig_keys atomic for
	// request handling (F583): AXFR/IXFR/UPDATE authentication runs under
	// RLock against one consistent key set and DDNS handler, and the reload
	// swaps them under Lock — in-flight requests finish with the previous
	// set, later ones see only the new one.
	xferKeysMu sync.RWMutex
	// ddnsConsumerMu guards ddnsConsumer, the DDNS handler whose update
	// events processUpdateEvents currently drains (one consumer per
	// handler; a reload swaps the handler, F583).
	ddnsConsumerMu sync.Mutex
	ddnsConsumer   *transfer.DynamicDNSHandler
	// ddnsRaftMu serializes DDNS updates replicated through Raft (F452).
	ddnsRaftMu sync.Mutex
}

// ServeDNS implements the server.Handler interface.
func (h *integratedHandler) ServeDNS(w server.ResponseWriter, r *protocol.Message) {
	h.runtimeMu.RLock()
	pipeline := h.pipeline
	h.runtimeMu.RUnlock()
	if pipeline == nil {
		h.runtimeMu.Lock()
		if h.pipeline == nil {
			h.pipeline = NewPipeline(h)
		}
		pipeline = h.pipeline
		h.runtimeMu.Unlock()
	}

	// The read lock is deliberately held for the WHOLE request, not just
	// field reads: hot reload swaps components under runtimeMu.Lock() and
	// then Stop()s the old ones. Holding the RLock until the request
	// finishes guarantees no in-flight request is still using a component
	// when it is stopped (the writer waits for all readers to drain).
	// Cost: a SIGHUP under load stalls new queries until in-flight ones
	// complete — bounded by the request timeout. Shortening this lock
	// requires refcounted/deferred component teardown first.
	h.runtimeMu.RLock()
	defer h.runtimeMu.RUnlock()
	pipeline.ServeDNS(h, w, r)
}

// tryDNS64Synthesis checks whether DNS64 synthesis is needed for an AAAA query
// that received no AAAA answers. If synthesis is appropriate, it re-queries for
// A records via the same upstream path and returns a synthesized AAAA response.
// Returns true if a synthesized response was written, false otherwise.
func (h *integratedHandler) tryDNS64Synthesis(ctx context.Context, w server.ResponseWriter, r *protocol.Message, q *protocol.Question, resp *protocol.Message) bool {
	if h.security.DNS64Synth == nil {
		return false
	}
	// RFC 6147 §5.5: when the client sets CD=1 it is performing its own DNSSEC
	// validation and would be misled by a synthesised AAAA that we cannot
	// authenticate. Skip synthesis in that case.
	if r.Header.Flags.CD {
		return false
	}
	if !h.security.DNS64Synth.ShouldSynthesize(q, resp) {
		return false
	}

	// Build a new query for the same name but type A.
	qname := q.Name.String()
	aQuery, err := protocol.NewQuery(r.Header.ID, qname, protocol.TypeA)
	if err != nil {
		h.logger.Warnf("DNS64: failed to build A query for %s: %v", qname, err)
		return false
	}
	aQuery.Header.ID = upstream.RandomTXID()

	// Send the A query through the same upstream path, with DO=1 when
	// validating like the main query: without RRSIGs the validator rejects
	// the A answer of a signed zone as Bogus (F655).
	outQuery := aQuery
	if h.validator != nil {
		outQuery = withDOBit(aQuery)
	}
	var aResp *protocol.Message
	if h.resolver != nil {
		// The resolver stage answered the AAAA query, so the A query goes
		// the same way: with only the iterative resolver (no upstream
		// servers) DNS64 never synthesized (F658).
		resolveCtx, cancel := context.WithTimeout(ctx, iterativeResolveTimeout(h.config))
		aResp, err = h.resolver.Resolve(resolveCtx, qname, protocol.TypeA)
		cancel()
		if aResp != nil {
			aResp.Header.ID = aQuery.Header.ID
		}
	} else if h.loadBalancer != nil {
		aResp, err = h.loadBalancer.QueryContext(ctx, outQuery)
	} else if h.upstream != nil {
		aResp, err = h.upstream.QueryContext(ctx, outQuery)
	} else {
		return false
	}
	if err != nil {
		h.logger.Warnf("DNS64: upstream A query failed for %s: %v", qname, err)
		return false
	}
	defer aQuery.Release()
	defer aResp.Release()
	if aResp == nil {
		h.logger.Warnf("DNS64: upstream returned nil A response for %s", qname)
		return false
	}
	sanitizePipelineResponse(aResp)
	if aResp.Header.ID != aQuery.Header.ID {
		h.logger.Warnf("DNS64: upstream A response ID mismatch for %s: got %d, want %d", qname, aResp.Header.ID, aQuery.Header.ID)
		return false
	}

	if handled, _, _ := h.validateDNSSECResponse(ctx, w, r, qname, aResp); handled {
		return true
	}
	if handled, err := h.applyRPZResponsePolicyWithError(w, r, q, aResp, qname); handled || err != nil {
		return handled
	}

	// Only synthesize if the A response has answers.
	if aResp.Header.Flags.RCODE != protocol.RcodeSuccess || len(aResp.Answers) == 0 {
		return false
	}

	synthesized := h.security.DNS64Synth.SynthesizeResponse(q, aResp)
	if synthesized == nil || len(synthesized.Answers) == 0 {
		return false
	}
	// RFC 6147 §5.1.7: the synthesized AAAA lives no longer than the negative
	// AAAA answer it replaces (its SOA's negative TTL, RFC 2308), or 600 s
	// without an SOA, so a real AAAA added later is not hidden (F661).
	ttlCap := uint32(600)
	if negTTL, ok := negativeCacheTTL(resp); ok {
		ttlCap = negTTL
	}
	for _, rr := range synthesized.Answers {
		if rr.Type == protocol.TypeAAAA && rr.TTL > ttlCap {
			rr.TTL = ttlCap
		}
	}

	h.logger.Debugf("DNS64: synthesized %d AAAA records for %s", len(synthesized.Answers), qname)
	reply(w, r, synthesized)
	return true
}

// validateDNSSECResponse returns handled (a SERVFAIL was written), validated
// (Secure, AD set) and bogus (Bogus/Indeterminate data passed through to a
// CD=1 client, which the caller must not cache for CD=0 clients).
func (h *integratedHandler) validateDNSSECResponse(ctx context.Context, w server.ResponseWriter, r *protocol.Message, qname string, resp *protocol.Message) (handled, validated, bogus bool) {
	if h.validator == nil {
		return false, false, false
	}

	result, valErr := h.validator.ValidateResponse(ctx, resp, qname)
	if valErr != nil {
		h.logger.Warnf("DNSSEC validation error for %s: %v", qname, valErr)
	}
	switch result {
	case dnssec.ValidationSecure:
		h.logger.Debugf("DNSSEC validation secure for %s", qname)
		resp.Header.Flags.AD = true
		return false, true, false
	case dnssec.ValidationBogus:
		h.logger.Warnf("DNSSEC validation failed (bogus) for %s", qname)
		if h.config.DNSSEC.Enabled {
			// RFC 4035 §3.2.2: a CD=1 client validates itself and SHOULD
			// get the data our policy rejects; it stays out of the cache (F662).
			if r.Header.Flags.CD {
				return false, false, true
			}
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendErrorWithEDE(w, r, protocol.RcodeServerFailure, protocol.EDEDNSSECBogus, "DNSSEC validation failed")
			return true, false, false
		}
	case dnssec.ValidationInsecure:
		h.logger.Debugf("DNSSEC insecure zone for %s", qname)
	case dnssec.ValidationIndeterminate:
		h.logger.Debugf("DNSSEC indeterminate for %s", qname)
		if h.config.DNSSEC.Enabled {
			// RFC 4035 §3.2.2: a CD=1 client validates itself and SHOULD
			// get the data our policy rejects; it stays out of the cache (F662).
			if r.Header.Flags.CD {
				return false, false, true
			}
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendErrorWithEDE(w, r, protocol.RcodeServerFailure, protocol.EDEDNSSECIndeterminate, "DNSSEC indeterminate")
			return true, false, false
		}
	}

	return false, false, false
}

func (h *integratedHandler) applyRPZResponsePolicy(w server.ResponseWriter, r *protocol.Message, q *protocol.Question, resp *protocol.Message, label string) bool {
	handled, err := h.applyRPZResponsePolicyWithError(w, r, q, resp, label)
	if err != nil {
		h.logger.Errorf("failed to write RPZ response: %v", err)
	}
	return handled
}

// applyRPZResponsePolicyWithError applies RPZ response-IP and NSDNAME policies to resp.
// Returns true if RPZ triggered (caller should return); false to continue.
// This consolidates the 3× duplicated RPZ response-check blocks in ServeDNS.
func (h *integratedHandler) applyRPZResponsePolicyWithError(w server.ResponseWriter, r *protocol.Message, q *protocol.Question, resp *protocol.Message, label string) (bool, error) {
	if h.security.RPZEngine == nil {
		return false, nil
	}
	respIPs := extractResponseIPs(resp)
	if len(respIPs) > 0 {
		if rule := h.security.RPZEngine.ResponseIPPolicy(respIPs); rule != nil {
			h.logger.Debugf("RPZ response IP match for %s (policy: %s)", label, rule.PolicyName)
			handled, err := h.applyRPZRuleWithError(w, r, q, rule)
			if handled || err != nil {
				return handled, err
			}
		}
	}
	for _, nsName := range extractNSNames(resp) {
		if rule := h.security.RPZEngine.NSDNAMEPolicy(nsName); rule != nil {
			h.logger.Debugf("RPZ NSDNAME match for %s (policy: %s)", nsName, rule.PolicyName)
			handled, err := h.applyRPZRuleWithError(w, r, q, rule)
			if handled || err != nil {
				return handled, err
			}
		}
	}
	if rule := h.security.RPZEngine.NSIPPolicy(extractNSAddresses(resp)); rule != nil {
		h.logger.Debugf("RPZ NSIP match for %s (policy: %s)", label, rule.PolicyName)
		return h.applyRPZRuleWithError(w, r, q, rule)
	}
	return false, nil
}

// checkRPZResponseIP checks a DNS response against RPZ response-IP policy.
// If RPZ triggers, applies the rule (writes to w) and returns true.
// Returns false if no RPZ action needed (caller should proceed with normal reply).
//
// This ensures authoritative zone responses are also subject to RPZ filtering,
// closing VULN-064 where the authoritative path bypassed RPZ response-IP checks.
func (h *integratedHandler) checkRPZResponseIP(w server.ResponseWriter, r *protocol.Message, q *protocol.Question, resp *protocol.Message) bool {
	handled, err := h.checkRPZResponseIPWithError(w, r, q, resp)
	if err != nil {
		h.logger.Errorf("failed to write RPZ response: %v", err)
	}
	return handled
}

func (h *integratedHandler) checkRPZResponseIPWithError(w server.ResponseWriter, r *protocol.Message, q *protocol.Question, resp *protocol.Message) (bool, error) {
	if h.security.RPZEngine == nil {
		return false, nil
	}
	qname := "<nil>"
	if q != nil && q.Name != nil {
		qname = q.Name.String()
	}
	if rule := h.security.RPZEngine.ResponseIPPolicy(extractResponseIPs(resp)); rule != nil {
		h.logger.Debugf("RPZ response IP match for %s (policy: %s)", qname, rule.PolicyName)
		handled, err := h.applyRPZRuleWithError(w, r, q, rule)
		if handled || err != nil {
			return handled, err
		}
	}
	// Referral glue is nameserver data: NSIP, not rpz-ip (F652/F653).
	if rule := h.security.RPZEngine.NSIPPolicy(extractNSAddresses(resp)); rule != nil {
		h.logger.Debugf("RPZ NSIP match for %s (policy: %s)", qname, rule.PolicyName)
		return h.applyRPZRuleWithError(w, r, q, rule)
	}
	return false, nil
}

// sendRefused returns a REFUSED response without forwarding to upstream.
// Used by RRL suppression (RFC 8231 §4) and for policy-denied responses.
func (h *integratedHandler) sendRefused(w server.ResponseWriter, r *protocol.Message) {
	if h.metrics != nil {
		h.metrics.RecordResponse(protocol.RcodeRefused)
	}
	sendErrorWithEDE(w, r, protocol.RcodeRefused, protocol.EDEOtherError, "rate limited")
}

// reply sends a response message.
func reply(w server.ResponseWriter, query, response *protocol.Message) {
	response.Header.ID = query.Header.ID
	response.Header.Flags.QR = true
	if len(response.Questions) == 0 {
		response.Questions = query.Questions
	}
	scrubForClient(query, response)
	minimizeResponse(response)
	if _, err := w.Write(response); err != nil {
		logErrorf("failed to write response: %v", err)
	}
}

// scrubForClient trims a response down to what the client's EDNS0 negotiation
// allows. A client that sent no OPT record must not get one back (RFC 6891
// §7), and a client that did not set the DO bit must not receive DNSSEC
// records it never asked for (RFC 4035 §3.2.2) — unless it queried those
// types explicitly. This matters since the upstream query is upgraded to
// DO=1 for validation, so responses carry RRSIGs regardless of what the
// client requested.
func scrubForClient(query, response *protocol.Message) {
	if query == nil || response == nil {
		return
	}
	clientOPT := query.GetOPT()

	if clientOPT == nil && response.GetOPT() != nil {
		filtered := make([]*protocol.ResourceRecord, 0, len(response.Additionals))
		for _, rr := range response.Additionals {
			if rr != nil && rr.Type == protocol.TypeOPT {
				continue
			}
			filtered = append(filtered, rr)
		}
		response.Additionals = filtered
	}

	do := false
	if clientOPT != nil {
		if h := protocol.ParseEDNS0Header(clientOPT); h != nil {
			do = h.DO
		}
	}
	if !do {
		qtype := uint16(0)
		if len(query.Questions) > 0 && query.Questions[0] != nil {
			qtype = query.Questions[0].QType
		}
		response.Answers = removeDNSSECRecords(response.Answers, qtype)
		response.Authorities = removeDNSSECRecords(response.Authorities, qtype)
	}
}

// removeDNSSECRecords filters out RRSIG/NSEC/NSEC3 records from a section for
// clients that did not set the DO bit. Records whose type the client queried
// explicitly (or a TypeANY query) are kept.
func removeDNSSECRecords(rrs []*protocol.ResourceRecord, qtype uint16) []*protocol.ResourceRecord {
	if len(rrs) == 0 || qtype == protocol.TypeANY {
		return rrs
	}
	needsFilter := false
	for _, rr := range rrs {
		if rr != nil && rr.Type != qtype && isDNSSECType(rr.Type) {
			needsFilter = true
			break
		}
	}
	if !needsFilter {
		return rrs
	}
	filtered := make([]*protocol.ResourceRecord, 0, len(rrs))
	for _, rr := range rrs {
		if rr != nil && rr.Type != qtype && isDNSSECType(rr.Type) {
			continue
		}
		filtered = append(filtered, rr)
	}
	return filtered
}

// isDNSSECType reports whether the record type exists purely to prove
// signatures/denial (RFC 4035 §3.2.2's "DNSSEC RR types").
func isDNSSECType(t uint16) bool {
	return t == protocol.TypeRRSIG || t == protocol.TypeNSEC || t == protocol.TypeNSEC3
}

// sendError sends an error response.
func sendError(w server.ResponseWriter, query *protocol.Message, rcode uint8) {
	id := uint16(0)
	var questions []*protocol.Question
	if query != nil {
		id = query.Header.ID
		questions = query.Questions
	}
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    id,
			Flags: protocol.NewResponseFlags(rcode),
		},
		Questions: questions,
	}
	if _, err := w.Write(resp); err != nil {
		logErrorf("failed to write error response: %v", err)
	}
}

// handleANYTruncated responds to a TypeANY query over UDP with TC=1,
// per RFC 8482 §3. This forces the client to retry over TCP, which
// prevents TypeANY amplification attacks (VULN-065).
func (h *integratedHandler) handleANYTruncated(w server.ResponseWriter, r *protocol.Message, q *protocol.Question) {
	qname := "<nil>"
	if q != nil && q.Name != nil {
		qname = q.Name.String()
	}
	h.logger.Debugf("TypeANY over UDP — forcing TCP retry for %s", qname)
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    r.Header.ID,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: r.Questions,
	}
	resp.Header.Flags.TC = true // Truncated — retry over TCP
	// RFC 6891 §7: a truncated response to an EDNS requestor must still carry
	// an OPT record. Without it the requestor sees a TC=1 answer from what
	// looks like a non-EDNS server and retries over TCP with EDNS downgraded.
	if clientOPT := r.GetOPT(); clientOPT != nil {
		payload := clientOPT.Class
		if payload == 0 {
			payload = ednsResponsePayloadSize
		}
		resp.SetEDNS0(payload, false)
	}
	if _, err := w.Write(resp); err != nil {
		h.logger.Errorf("failed to write TC response: %v", err)
	}
}

// sendErrorWithEDE sends an error response with Extended DNS Error (RFC 8914).
// infoCode is the EDE info code (0-65535), extraText is optional context.
func sendErrorWithEDE(w server.ResponseWriter, query *protocol.Message, rcode uint8, infoCode uint16, extraText string) {
	id := uint16(0)
	var questions []*protocol.Question
	if query != nil {
		id = query.Header.ID
		questions = query.Questions
	}
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    id,
			Flags: protocol.NewResponseFlags(rcode),
		},
		Questions: questions,
	}
	// Add EDNS0 OPT record with EDE if client sent EDNS0
	if query != nil && query.GetOPT() != nil {
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
			Name:  protocol.NewName(nil, true), // OPT owner name is root
			Type:  protocol.TypeOPT,
			Class: udpPayload,
			Data: &protocol.RDataOPT{
				Options: []protocol.EDNS0Option{ede.ToEDNS0Option()},
			},
		}
		resp.AddAdditional(optRR)
	}
	if _, err := w.Write(resp); err != nil {
		logErrorf("failed to write error response: %v", err)
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
		h.logger.Errorf("failed to write redirect response: %v", err)
	}
}

// buildResponse builds a DNS response from zone records.
// Every caller serves data owned by a locally hosted zone (exact match,
// wildcard synthesis, GeoDNS override, or DNSSEC-signed via
// buildSignedResponse), so the AA bit is set per RFC 1035 §4.1.1.
// Recursive answers are built by the upstream/resolver stages instead.
func (h *integratedHandler) buildResponse(query *protocol.Message, records []zone.Record) *protocol.Message {
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    query.Header.ID,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: query.Questions,
	}
	resp.Header.Flags.AA = true

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

	// Convert zone records to protocol.ResourceRecord for signing.
	// Skip records with unparseable RData, mirroring buildResponse: they are
	// not in the answer section, and a single nil-Data record would make
	// SignRRSet reject the whole RRset, silently stripping the RRSIG from
	// the otherwise-valid answers.
	var rrs []*protocol.ResourceRecord
	for _, rec := range records {
		data := parseRData(rec.Type, rec.RData)
		if data == nil {
			continue
		}
		rr := &protocol.ResourceRecord{
			Name:  query.Questions[0].Name,
			Type:  stringToType(rec.Type),
			Class: protocol.ClassIN,
			TTL:   rec.TTL,
			Data:  data,
		}
		rrs = append(rrs, rr)
	}

	// Sign the RRSet and add RRSIG to answers.
	//
	// Use Active ZSKs only — same RFC 7583 rationale as Signer.SignZone:
	// Pre-Published / Retired keys must not produce signatures because
	// validators can't (or no longer should) trust them. GetZSKs returns
	// keys regardless of state, which during a rollover would emit RRSIGs
	// that fail chain-of-trust at the validator → response Bogus.
	if len(rrs) > 0 {
		inception := time.Now().UTC()
		expiration := inception.Add(24 * time.Hour * 30) // 30 days

		// Find an Active ZSK for signing.
		zsks := signer.GetActiveZSKs()
		if len(zsks) > 0 {
			zsk := zsks[0] // Use first Active ZSK
			rrsig, err := signer.SignRRSet(
				rrs,
				zsk,
				dnssecSignatureUnixTime(inception),
				dnssecSignatureUnixTime(expiration),
			)
			if err == nil && rrsig != nil {
				resp.AddAnswer(rrsig)
				h.logger.Debugf("Added RRSIG for %s", query.Questions[0].Name.String())
			} else if err != nil {
				// Answer still goes out, but unsigned — validating resolvers
				// will treat it as Bogus, so make the cause visible.
				h.logger.Warnf("Failed to sign RRset for %s: %v", query.Questions[0].Name.String(), err)
			}
		}
	}

	return resp
}

func dnssecSignatureUnixTime(t time.Time) uint32 {
	sec := t.Unix()
	if sec <= 0 {
		return 0
	}
	if sec > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(sec)
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
			if ns, ok := rr.Data.(*protocol.RDataNS); ok && ns != nil && ns.NSDName != nil {
				nsNames[strings.ToLower(ns.NSDName.String())] = struct{}{}
			}
		}
	}

	// Filter authority section.
	if resp.Header.Flags.AA {
		// Authoritative: keep the SOA (negative caching) and the DNSSEC
		// denial records. NSEC/NSEC3 and their RRSIGs are not decoration —
		// RFC 4035 §3.1.3 makes them the proof that the negative answer is
		// genuine, and a validator rejects the answer without them. Stripping
		// them here made every negative answer from a signed zone Bogus.
		// A client that did not set DO never sees them: scrubForClient
		// removes them on the way out (RFC 4035 §3.2.2).
		if hasSOA {
			filtered := make([]*protocol.ResourceRecord, 0, len(resp.Authorities))
			for _, rr := range resp.Authorities {
				if rr == nil {
					continue
				}
				if rr.Type == protocol.TypeSOA || isDNSSECType(rr.Type) {
					filtered = append(filtered, rr)
				}
			}
			resp.Authorities = filtered
		} else {
			// F512: a wildcard-expanded positive answer carries the signed
			// NSEC/NSEC3 proving no closer match (RFC 4035 §3.1.3.3).
			var proof []*protocol.ResourceRecord
			for _, rr := range resp.Authorities {
				if rr == nil {
					continue
				}
				covered := rr.Type
				if sig, ok := rr.Data.(*protocol.RDataRRSIG); ok && rr.Type == protocol.TypeRRSIG {
					covered = sig.TypeCovered
				}
				if covered == protocol.TypeNSEC || covered == protocol.TypeNSEC3 {
					proof = append(proof, rr)
				}
			}
			resp.Authorities = proof
		}
	} else {
		// Non-authoritative: keep NS (referrals) and SOA (negative caching),
		// plus the DNSSEC denial records. Recursive NXDOMAIN/NODATA answers
		// for signed zones arrive with NSEC/NSEC3 and their RRSIGs in the
		// authority section; RFC 4035 §2.2 (DO bit) and §3.1.3 require the
		// response to carry them so the recipient can determine the security
		// status — a validator rejects a proof-less negative answer as Bogus.
		// scrubForClient has already removed every DNSSEC record this client
		// did not ask for (no DO bit), so what survives to this point is
		// exactly what may go out. Same rationale as the AA branch above.
		if hasSOA || hasNS {
			filtered := make([]*protocol.ResourceRecord, 0, len(resp.Authorities))
			for _, rr := range resp.Authorities {
				if rr == nil {
					continue
				}
				// F384: a signed referral's DS RRset rides with the NS RRset
				// (RFC 4035 §3.1.4); dropping it leaves its RRSIG orphaned.
				if rr.Type == protocol.TypeSOA || rr.Type == protocol.TypeNS || isDNSSECType(rr.Type) ||
					(hasNS && rr.Type == protocol.TypeDS) {
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
// A malformed cookie option returns (nil, false).
func (h *integratedHandler) processCookies(r *protocol.Message, clientIP net.IP) (cookieOptionData []byte, valid bool) {
	// Find the OPT record in the query
	opt := r.GetOPT()
	if opt == nil {
		return nil, true // No EDNS0, no cookies — allow the query
	}

	optData, ok := opt.Data.(*protocol.RDataOPT)
	if !ok || optData == nil {
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
		// Malformed cookie: FORMERR without a cookie (RFC 7873 §5.2.2). A
		// BADCOOKIE carrying a zeroed client cookie was discarded by the
		// client as unmatched (§5.3), leaving it to time out (F641).
		return nil, false
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
			if optData, ok := opt.Data.(*protocol.RDataOPT); ok && optData != nil {
				// Remove any existing cookie option to avoid duplicates
				optData.RemoveOption(protocol.OptionCodeCookie)
				optData.AddOption(protocol.OptionCodeCookie, cw.cookieData)
			}
		}
	}
	return cw.inner.Write(msg)
}

// Unwrap returns the wrapped writer.
func (cw *cookieResponseWriter) Unwrap() server.ResponseWriter {
	return cw.inner
}

// ClientInfo delegates to the inner writer.
func (cw *cookieResponseWriter) ClientInfo() *server.ClientInfo {
	return cw.inner.ClientInfo()
}

// MaxSize delegates to the inner writer.
func (cw *cookieResponseWriter) MaxSize() int {
	return cw.inner.MaxSize()
}

func (h *integratedHandler) applyRPZRule(w server.ResponseWriter, r *protocol.Message, q *protocol.Question, rule *rpz.Rule) bool {
	handled, err := h.applyRPZRuleWithError(w, r, q, rule)
	if err != nil {
		h.logger.Errorf("failed to write RPZ response: %v", err)
	}
	return handled
}

// applyRPZRuleWithError applies an RPZ rule action and returns true if the query was handled.
// This handles all RPZ policy actions consistently.
func (h *integratedHandler) applyRPZRuleWithError(w server.ResponseWriter, r *protocol.Message, q *protocol.Question, rule *rpz.Rule) (bool, error) {
	switch rule.Action {
	case rpz.ActionNXDOMAIN:
		h.logger.Debugf("RPZ NXDOMAIN for %s (policy: %s)", q.Name.String(), rule.PolicyName)
		if h.metrics != nil {
			h.metrics.RecordBlocklistBlock()
		}
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    r.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeNameError),
			},
			Questions: r.Questions,
		}
		_, err := w.Write(resp)
		return true, err
	case rpz.ActionNODATA:
		h.logger.Debugf("RPZ NODATA for %s (policy: %s)", q.Name.String(), rule.PolicyName)
		if h.metrics != nil {
			h.metrics.RecordBlocklistBlock()
		}
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    r.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: r.Questions,
		}
		_, err := w.Write(resp)
		return true, err
	case rpz.ActionDrop:
		h.logger.Debugf("RPZ DROP for %s (policy: %s)", q.Name.String(), rule.PolicyName)
		return true, nil // silently drop
	case rpz.ActionPassThrough:
		// Allow the query to proceed normally
		return false, nil
	case rpz.ActionTCPOnly:
		// TC=1 only means something over UDP. Over a stream transport the
		// client has already done what the policy asks; truncating again
		// would make the name unresolvable, so the query proceeds normally.
		if ci := w.ClientInfo(); ci != nil && ci.Protocol != "udp" {
			return false, nil
		}
		// Set TC bit to force TCP retry
		resp := r.Copy()
		resp.Header.Flags.TC = true
		resp.Header.Flags.QR = true
		resp.Header.Flags.RCODE = protocol.RcodeSuccess
		_, err := w.Write(resp)
		return true, err
	case rpz.ActionOverride:
		// Return override IP
		overrideIP := net.ParseIP(rule.OverrideData)
		if overrideIP == nil {
			h.logger.Warnf("RPZ override invalid IP: %s", rule.OverrideData)
			return false, nil
		}
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    r.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: r.Questions,
		}
		// Local data answers only its own type: an A override for an AAAA
		// or MX query is NODATA, not an A record under that question (F654).
		overrideType := uint16(protocol.TypeAAAA)
		if overrideIP.To4() != nil {
			overrideType = protocol.TypeA
		}
		if q.QType != overrideType && q.QType != protocol.TypeANY {
			_, err := w.Write(resp)
			return true, err
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
		_, err := w.Write(resp)
		return true, err
	case rpz.ActionCNAME:
		targetName, err := protocol.ParseName(rule.OverrideData)
		if err != nil {
			h.logger.Warnf("RPZ CNAME invalid target: %s", rule.OverrideData)
			return false, nil
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
		// Chase the target like a zone CNAME: a bare CNAME left stubs
		// with no address for the walled garden (F660).
		if q.QType != protocol.TypeCNAME {
			for _, rr := range h.resolveCNAMETarget(w, r, q, targetName.String(), q.QType) {
				resp.AddAnswer(rr)
			}
		}
		_, err = w.Write(resp)
		return true, err
	default:
		return false, nil
	}
}

// extractResponseIPs extracts the IP addresses of the A/AAAA records in the
// answer section of a DNS response, for RPZ response-IP (rpz-ip) checking.
// Glue in the authority/additional sections is nameserver data, matched only
// by NSIP triggers (extractNSAddresses): rpz-ip rules there blocked every
// answer served via that nameserver (F653).
func extractResponseIPs(resp *protocol.Message) []net.IP {
	var ips []net.IP
	if resp == nil {
		return ips
	}
	for _, rr := range resp.Answers {
		if rr == nil {
			continue
		}
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

// extractNSAddresses returns the addresses (glue A/AAAA in the authority and
// additional sections) of the nameservers named by authority NS records, for
// RPZ NSIP policy checking (F652).
func extractNSAddresses(resp *protocol.Message) []net.IP {
	var ips []net.IP
	if resp == nil {
		return ips
	}
	ns := make(map[string]bool)
	for _, name := range extractNSNames(resp) {
		ns[strings.ToLower(name)] = true
	}
	if len(ns) == 0 {
		return ips
	}
	for _, section := range [][]*protocol.ResourceRecord{resp.Authorities, resp.Additionals} {
		for _, rr := range section {
			if rr == nil || rr.Name == nil || !ns[strings.ToLower(rr.Name.String())] {
				continue
			}
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
	}
	return ips
}

// extractNSNames extracts nameserver names from authority NS records in a DNS response.
// This is used for RPZ TriggerNSDNAME policy checking.
func extractNSNames(resp *protocol.Message) []string {
	var nsNames []string
	if resp == nil {
		return nsNames
	}
	for _, rr := range resp.Authorities {
		if rr == nil {
			continue
		}
		if ns, ok := rr.Data.(*protocol.RDataNS); ok && ns != nil && ns.NSDName != nil {
			nsNames = append(nsNames, ns.NSDName.String())
		}
	}
	return nsNames
}

// RebuildZoneTree rebuilds the zone radix tree from all zone sources.
// Call after adding or removing zones to maintain O(log n) zone lookup.
func (h *integratedHandler) RebuildZoneTree() {
	// F547: after the rebuild (and after zonesMu is released — deferred
	// calls run last-in first-out), let the NOTIFY sender see every
	// transferable zone's serial. It only schedules async sends.
	var notifyZones map[string]*zone.Zone
	defer func() {
		if h.transfer.Notifier != nil {
			h.transfer.Notifier.Observe(notifyZones)
		}
	}()
	h.zonesMu.Lock()
	defer h.zonesMu.Unlock()

	// h.zones is also the AXFR/IXFR/NOTIFY/DDNS zones map. Every entry is a
	// zone loaded into the zone manager (boot, SIGHUP); the manager is the
	// source of truth once API/Raft mutations run. Drop entries the manager
	// deleted and adopt objects it replaced (snapshot restore), so a deleted
	// zone is neither served nor transferred, and AXFR hands out the same
	// data queries see (F402, F403). Done in place: the transfer handlers
	// share this map.
	if h.zoneManager != nil {
		covered := make(map[*zone.Zone]struct{}, len(h.zones))
		for origin, z := range h.zones {
			if cur, ok := h.zoneManager.Get(origin); !ok {
				delete(h.zones, origin)
			} else {
				if cur != z {
					h.zones[origin] = cur
				}
				covered[cur] = struct{}{}
			}
		}
		// Adopt zones that exist only in the manager (created via the API or
		// a Raft create_zone, installed by a snapshot, synced from KV), so
		// they are transferable (AXFR/IXFR/XoT) under the same allow_list /
		// TSIG / XoT ACL as config zones, and NOTIFY/DDNS see them (F449).
		for origin, z := range h.zoneManager.List() {
			if _, ok := covered[z]; !ok {
				if h.zones == nil {
					h.zones = make(map[string]*zone.Zone)
				}
				h.zones[origin] = z
			}
		}
	}

	// Merge all zone sources into one map for the radix tree
	merged := make(map[string]*zone.Zone)
	notifyZones = make(map[string]*zone.Zone, len(h.zones))
	for k, v := range h.zones {
		merged[k] = v
		notifyZones[k] = v
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

	// Rebuild the unified zone provider
	h.zoneProvider = NewMultiZoneProvider(
		merged,
		h.zoneManager,
		h.kvPersistence,
		h.zoneTree,
	).withSlaveZones(h.transfer.SlaveManager)
}

// ReloadViews reloads split-horizon view configuration and zone files.
// Called during config reload to pick up view changes without restart.
func (h *integratedHandler) ReloadViews(viewConfigs []filter.ViewConfig, loadZoneFileFunc func(string) (*zone.Zone, error)) error {
	plan, err := h.prepareReloadViews(viewConfigs, loadZoneFileFunc)
	if err != nil {
		return err
	}
	h.applyReloadViews(plan)
	return nil
}

type viewReloadPlan struct {
	splitHorizon *filter.SplitHorizon
	viewZones    map[string]map[string]*zone.Zone
}

func (h *integratedHandler) prepareReloadViews(viewConfigs []filter.ViewConfig, loadZoneFileFunc func(string) (*zone.Zone, error)) (*viewReloadPlan, error) {
	if len(viewConfigs) == 0 {
		return &viewReloadPlan{}, nil
	}

	newSH, err := filter.NewSplitHorizon(viewConfigs)
	if err != nil {
		return nil, fmt.Errorf("reloading split-horizon: %w", err)
	}

	newViewZones := make(map[string]map[string]*zone.Zone)
	for _, v := range viewConfigs {
		vzMap := make(map[string]*zone.Zone)
		for _, zf := range v.ZoneFiles {
			if loadZoneFileFunc == nil {
				return nil, fmt.Errorf("loading zone file %q for view %q: no loader configured", zf, v.Name)
			}
			vz, err := loadZoneFileFunc(zf)
			if err != nil {
				return nil, fmt.Errorf("loading zone file %q for view %q: %w", zf, v.Name, err)
			}
			vzMap[vz.Origin] = vz
		}
		newViewZones[v.Name] = vzMap
	}

	return &viewReloadPlan{splitHorizon: newSH, viewZones: newViewZones}, nil
}

func (h *integratedHandler) applyReloadViews(plan *viewReloadPlan) {
	if plan == nil {
		return
	}
	h.runtimeMu.Lock()
	defer h.runtimeMu.Unlock()
	h.splitHorizon = plan.splitHorizon
	h.viewZones = plan.viewZones
}
