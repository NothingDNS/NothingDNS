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
	updateOnce sync.Once
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

	// Send the A query through the same upstream path.
	var aResp *protocol.Message
	if h.loadBalancer != nil {
		aResp, err = h.loadBalancer.QueryContext(ctx, aQuery)
	} else if h.upstream != nil {
		aResp, err = h.upstream.QueryContext(ctx, aQuery)
	} else {
		return false
	}
	if err != nil {
		h.logger.Warnf("DNS64: upstream A query failed for %s: %v", qname, err)
		return false
	}
	if aResp == nil {
		h.logger.Warnf("DNS64: upstream returned nil A response for %s", qname)
		return false
	}
	sanitizePipelineResponse(aResp)
	if aResp.Header.ID != aQuery.Header.ID {
		h.logger.Warnf("DNS64: upstream A response ID mismatch for %s: got %d, want %d", qname, aResp.Header.ID, aQuery.Header.ID)
		return false
	}

	if handled, _ := h.validateDNSSECResponse(ctx, w, r, qname, aResp); handled {
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

	h.logger.Debugf("DNS64: synthesized %d AAAA records for %s", len(synthesized.Answers), qname)
	reply(w, r, synthesized)
	return true
}

func (h *integratedHandler) validateDNSSECResponse(ctx context.Context, w server.ResponseWriter, r *protocol.Message, qname string, resp *protocol.Message) (bool, bool) {
	if h.validator == nil {
		return false, false
	}

	result, valErr := h.validator.ValidateResponse(ctx, resp, qname)
	if valErr != nil {
		h.logger.Warnf("DNSSEC validation error for %s: %v", qname, valErr)
	}
	switch result {
	case dnssec.ValidationSecure:
		h.logger.Debugf("DNSSEC validation secure for %s", qname)
		resp.Header.Flags.AD = true
		return false, true
	case dnssec.ValidationBogus:
		h.logger.Warnf("DNSSEC validation failed (bogus) for %s", qname)
		if h.config.DNSSEC.Enabled {
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendErrorWithEDE(w, r, protocol.RcodeServerFailure, protocol.EDEDNSSECBogus, "DNSSEC validation failed")
			return true, false
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
			return true, false
		}
	}

	return false, false
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
		if rule := h.security.RPZEngine.QNAMEPolicy(nsName); rule != nil {
			h.logger.Debugf("RPZ NSDNAME match for %s (policy: %s)", nsName, rule.PolicyName)
			handled, err := h.applyRPZRuleWithError(w, r, q, rule)
			if handled || err != nil {
				return handled, err
			}
		}
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
	respIPs := extractResponseIPs(resp)
	if len(respIPs) == 0 {
		return false, nil
	}
	if rule := h.security.RPZEngine.ResponseIPPolicy(respIPs); rule != nil {
		qname := "<nil>"
		if q != nil && q.Name != nil {
			qname = q.Name.String()
		}
		h.logger.Debugf("RPZ response IP match for %s (policy: %s)", qname, rule.PolicyName)
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
			if optData, ok := opt.Data.(*protocol.RDataOPT); ok && optData != nil {
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
		_, err = w.Write(resp)
		return true, err
	default:
		return false, nil
	}
}

// extractResponseIPs extracts IP addresses from answer, authority, and additional sections of a DNS response.
// This is used for RPZ response IP policy checking (TriggerResponseIP and TriggerNSIP).
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
	for _, rr := range resp.Authorities {
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
	// Additional section contains glue A/AAAA records for nameservers (NSIP matching)
	for _, rr := range resp.Additionals {
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

	// Rebuild the unified zone provider
	h.zoneProvider = NewMultiZoneProvider(
		merged,
		h.zoneManager,
		h.kvPersistence,
		h.zoneTree,
	)
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
