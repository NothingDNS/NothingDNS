// NothingDNS - Authoritative zone handling

package main

import (
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// handleAuthoritative handles queries for authoritative zones.
// It performs: delegation check → exact match → CNAME → wildcard → NXDOMAIN.
// CNAME chasing is deferred to the caller (ServeDNS) which can resolve
// across zones, cache, and upstream.
func (h *integratedHandler) handleAuthoritative(z *zone.Zone, w server.ResponseWriter, r *protocol.Message, q *protocol.Question, qname string) bool {
	qtype := q.QType

	// Check if client wants DNSSEC (DO bit in OPT record)
	wantsDNSSEC := hasDOBit(r)

	// ── Step 0: Check for delegation (zone cut) ──
	// Per RFC 1034 §4.2.1, if the query name is at or below a delegation
	// point, we return a referral (non-authoritative) response with NS
	// records and optional glue.
	if nsRecords, delegation, found := z.FindDelegation(qname); found {
		resp := h.buildReferralResponse(r, z, nsRecords, delegation)
		h.logger.Debugf("Delegation referral for %s at %s", qname, delegation)
		if h.metrics != nil {
			h.metrics.RecordResponse(protocol.RcodeSuccess)
		}
		if handled, err := h.checkRPZResponseIPWithError(w, r, q, resp); handled || err != nil {
			if err != nil {
				h.logger.Warnf("RPZ response write failed for %s: %v", qname, err)
			}
			return true
		}
		reply(w, r, resp)
		return true
	}

	// ── Step 1: GeoDNS override ──
	if h.security.GeoEngine != nil {
		clientIP := w.ClientInfo().IP()
		if clientIP != nil {
			typeStr := typeToString(qtype)
			if geoRData := h.security.GeoEngine.Resolve(qname, typeStr, clientIP); geoRData != "" {
				geoRecords := []zone.Record{
					{
						Name:  qname,
						Type:  typeStr,
						TTL:   z.DefaultTTL,
						Class: "IN",
						RData: geoRData,
					},
				}
				resp := h.buildResponse(r, geoRecords)
				if h.metrics != nil {
					h.metrics.RecordResponse(protocol.RcodeSuccess)
				}
				if handled, err := h.checkRPZResponseIPWithError(w, r, q, resp); handled || err != nil {
					if err != nil {
						h.logger.Warnf("RPZ response write failed for %s: %v", qname, err)
					}
					return true
				}
				reply(w, r, resp)
				return true
			}
		}
	}

	// ── Step 1b: DNSKEY RRset from the zone's signing keys ──
	// A zone signed from configured keys carries no DNSKEY records in its
	// file, so the lookup below finds nothing and the query fell through to
	// NODATA. The zone then served RRSIGs referencing keys no resolver could
	// fetch — signed, but unvalidatable by anyone. Zone-file DNSKEY records,
	// if present, take precedence and are served by the exact-match path.
	if qtype == protocol.TypeDNSKEY && canonicalize(qname) == canonicalize(z.Origin) {
		if len(z.Lookup(qname, "DNSKEY")) == 0 && h.serveZoneDNSKEY(w, r, q, z, wantsDNSSEC) {
			return true
		}
	}

	// ── Step 2: Exact match ──
	records := z.Lookup(qname, typeToString(qtype))
	if len(records) > 0 {
		var resp *protocol.Message
		h.zoneSignersMu.RLock()
		signer, ok := h.zoneSigners[z.Origin]
		h.zoneSignersMu.RUnlock()
		if ok && wantsDNSSEC {
			resp = h.buildSignedResponse(r, records, signer, true)
		} else {
			resp = h.buildResponse(r, records)
		}
		if h.metrics != nil {
			h.metrics.RecordResponse(protocol.RcodeSuccess)
		}
		if handled, err := h.checkRPZResponseIPWithError(w, r, q, resp); handled || err != nil {
			if err != nil {
				h.logger.Warnf("RPZ response write failed for %s: %v", qname, err)
			}
			return true
		}
		reply(w, r, resp)
		return true
	}

	// ── Step 3: CNAME check ──
	// If a CNAME exists for the name, let ServeDNS chase it.
	cnameRecords := z.Lookup(qname, "CNAME")
	if len(cnameRecords) > 0 {
		return false // signal to ServeDNS to chase the CNAME
	}

	// ── Step 3b: DNAME check (RFC 6672) ──
	// Check for a DNAME record whose owner is a suffix of the query name.
	// If found, synthesize a CNAME response and resolve the target.
	if dnameRec, synthTarget, found := z.FindDNAME(qname); found {
		h.handleDNAMERecord(w, r, q, qname, dnameRec, synthTarget)
		return true
	}

	// ── Step 4: Wildcard matching (RFC 4592) ──
	// Only attempt wildcards if the exact name doesn't exist at all.
	// If the name exists but has no records of the requested type,
	// that's NODATA (handled below), not a wildcard case.
	// NodeExists, not NameExists: an empty non-terminal is an existing node,
	// so it is NODATA rather than a wildcard candidate or an NXDOMAIN.
	if !z.NodeExists(qname) {
		wcRecords, _, wcFound := z.LookupWildcard(qname, typeToString(qtype))
		if wcFound {
			if len(wcRecords) > 0 {
				// Synthesize answer: wildcard records with the query name as owner
				synthRecords := make([]zone.Record, len(wcRecords))
				for i, rec := range wcRecords {
					synthRecords[i] = rec
					synthRecords[i].Name = qname
				}
				var resp *protocol.Message
				h.zoneSignersMu.RLock()
				signer, ok := h.zoneSigners[z.Origin]
				h.zoneSignersMu.RUnlock()
				if ok && wantsDNSSEC {
					resp = h.buildSignedResponse(r, synthRecords, signer, true)
				} else {
					resp = h.buildResponse(r, synthRecords)
				}
				if h.metrics != nil {
					h.metrics.RecordResponse(protocol.RcodeSuccess)
				}
				if handled, err := h.checkRPZResponseIPWithError(w, r, q, resp); handled || err != nil {
					if err != nil {
						h.logger.Warnf("RPZ response write failed for %s: %v", qname, err)
					}
					return true
				}
				reply(w, r, resp)
				return true
			}
			// Wildcard exists but no records of the requested type → NODATA
			resp := h.buildNODATAResponse(r, z, qname, wantsDNSSEC)
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeSuccess)
			}
			if handled, err := h.checkRPZResponseIPWithError(w, r, q, resp); handled || err != nil {
				if err != nil {
					h.logger.Warnf("RPZ response write failed for %s: %v", qname, err)
				}
				return true
			}
			reply(w, r, resp)
			return true
		}

		// Name doesn't exist and no wildcard → authoritative NXDOMAIN
		resp := h.buildNXDOMAINResponse(r, z, qname, wantsDNSSEC)
		if h.metrics != nil {
			h.metrics.RecordResponse(protocol.RcodeNameError)
		}
		reply(w, r, resp)
		return true
	}

	// ── Step 5: Name exists but no records of requested type → NODATA ──
	resp := h.buildNODATAResponse(r, z, qname, wantsDNSSEC)
	if h.metrics != nil {
		h.metrics.RecordResponse(protocol.RcodeSuccess)
	}
	reply(w, r, resp)
	return true
}

// buildReferralResponse constructs a delegation (referral) response.
// AA bit is NOT set. Authority section contains NS records from the
// delegation point. Additional section contains glue A/AAAA records
// for nameserver names that are within the zone.
func (h *integratedHandler) buildReferralResponse(query *protocol.Message, z *zone.Zone, nsRecords []zone.Record, delegation string) *protocol.Message {
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    query.Header.ID,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: query.Questions,
	}
	// Clear AA bit — this is a referral, not an authoritative answer
	resp.Header.Flags.AA = false

	delegName, _ := protocol.ParseName(delegation)

	// Add NS records to authority section
	for _, rec := range nsRecords {
		data := parseRData(rec.Type, rec.RData)
		if data == nil {
			continue
		}
		rr := &protocol.ResourceRecord{
			Name:  delegName,
			Type:  protocol.TypeNS,
			Class: protocol.ClassIN,
			TTL:   rec.TTL,
			Data:  data,
		}
		resp.Authorities = append(resp.Authorities, rr)

		// Add glue records (A/AAAA for in-zone nameserver names)
		nsTarget := canonicalize(rec.RData)
		if isSubdomain(nsTarget, z.Origin) {
			for _, glue := range z.FindGlue(nsTarget) {
				glueData := parseRData(glue.Type, glue.RData)
				if glueData == nil {
					continue
				}
				glueName, err := protocol.ParseName(glue.Name)
				if err != nil {
					// Malformed glue record name in zone data; skip it instead
					// of silently using nsTarget as a fallback name.
					h.logger.Debugf("skipping malformed glue name %q for NS %q in zone %q: %v", glue.Name, nsTarget, z.Origin, err)
					continue
				}
				glueRR := &protocol.ResourceRecord{
					Name:  glueName,
					Type:  stringToType(glue.Type),
					Class: protocol.ClassIN,
					TTL:   glue.TTL,
					Data:  glueData,
				}
				resp.Additionals = append(resp.Additionals, glueRR)
			}
		}
	}

	return resp
}

// buildNXDOMAINResponse returns an authoritative NXDOMAIN with the zone's
// SOA in the authority section (for negative caching per RFC 2308).
func (h *integratedHandler) buildNXDOMAINResponse(query *protocol.Message, z *zone.Zone, qname string, wantsDNSSEC bool) *protocol.Message {
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    query.Header.ID,
			Flags: protocol.NewResponseFlags(protocol.RcodeNameError),
		},
		Questions: query.Questions,
	}
	resp.Header.Flags.AA = true
	h.addSOAAuthority(resp, z)
	h.addDenialProof(resp, z, qname, denialNXDomain, wantsDNSSEC)
	return resp
}

// buildNODATAResponse returns an authoritative NODATA response (RCODE=0,
// no answers) with the zone's SOA in the authority section.
func (h *integratedHandler) buildNODATAResponse(query *protocol.Message, z *zone.Zone, qname string, wantsDNSSEC bool) *protocol.Message {
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    query.Header.ID,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: query.Questions,
	}
	resp.Header.Flags.AA = true
	h.addSOAAuthority(resp, z)
	h.addDenialProof(resp, z, qname, denialNoData, wantsDNSSEC)
	return resp
}

// addSOAAuthority appends the zone's SOA record to the authority section
// of a response. This is required for negative caching (RFC 2308).
func (h *integratedHandler) addSOAAuthority(resp *protocol.Message, z *zone.Zone) {
	if z.SOA == nil {
		return
	}
	mname, err := protocol.ParseName(z.SOA.MName)
	if err != nil {
		return
	}
	rname, err := protocol.ParseName(z.SOA.RName)
	if err != nil {
		return
	}
	soaName, err := protocol.ParseName(z.Origin)
	if err != nil {
		return
	}
	rr := &protocol.ResourceRecord{
		Name:  soaName,
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   z.SOA.TTL,
		Data: &protocol.RDataSOA{
			MName:   mname,
			RName:   rname,
			Serial:  z.SOA.Serial,
			Refresh: z.SOA.Refresh,
			Retry:   z.SOA.Retry,
			Expire:  z.SOA.Expire,
			Minimum: z.SOA.Minimum,
		},
	}
	resp.Authorities = append(resp.Authorities, rr)
}

// handleDNAMERecord synthesizes a CNAME from a DNAME record and resolves
// the target, returning a complete DNS response with both DNAME and CNAME
// records plus the resolved target answers.
// Per RFC 6672, a DNAME at a superdomain synthesizes a CNAME for subdomains.
func (h *integratedHandler) handleDNAMERecord(w server.ResponseWriter, r *protocol.Message, q *protocol.Question, qname string, dnameRecord zone.Record, synthCNAMETarget string) {
	qtype := q.QType

	// Build the DNAME resource record
	qnameParsed, err := protocol.ParseName(qname)
	if err != nil {
		h.logger.Debugf("Failed to parse DNAME query name %q: %v", qname, err)
		sendErrorWithEDE(w, r, protocol.RcodeServerFailure, protocol.EDEOtherError, "invalid query name")
		return
	}
	dnameOwner, err := protocol.ParseName(dnameRecord.Name)
	if err != nil {
		h.logger.Debugf("Failed to parse DNAME owner %q: %v", dnameRecord.Name, err)
		sendErrorWithEDE(w, r, protocol.RcodeServerFailure, protocol.EDEOtherError, "invalid DNAME owner")
		return
	}
	dnameData := parseRData("DNAME", dnameRecord.RData)

	dnameRR := &protocol.ResourceRecord{
		Name:  dnameOwner,
		Type:  protocol.TypeDNAME,
		Class: protocol.ClassIN,
		TTL:   dnameRecord.TTL,
		Data:  dnameData,
	}

	// Build the synthesized CNAME resource record
	synthCNAMETargetParsed, err := protocol.ParseName(synthCNAMETarget)
	if err != nil {
		h.logger.Debugf("Failed to parse CNAME target %q: %v", synthCNAMETarget, err)
		sendErrorWithEDE(w, r, protocol.RcodeServerFailure, protocol.EDEOtherError, "invalid CNAME target")
		return
	}
	cnameRR := &protocol.ResourceRecord{
		Name:  qnameParsed,
		Type:  protocol.TypeCNAME,
		Class: protocol.ClassIN,
		TTL:   dnameRecord.TTL,
		Data:  &protocol.RDataCNAME{CName: synthCNAMETargetParsed},
	}

	// Resolve the synthesized CNAME target
	targetAnswers := h.resolveCNAMETarget(w, r, q, synthCNAMETarget, qtype)

	// Build the response
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    r.Header.ID,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: r.Questions,
	}
	resp.Header.Flags.AA = true
	resp.AddAnswer(dnameRR)
	resp.AddAnswer(cnameRR)
	for _, rr := range targetAnswers {
		resp.AddAnswer(rr)
	}

	if h.metrics != nil {
		h.metrics.RecordResponse(protocol.RcodeSuccess)
	}
	if handled, err := h.checkRPZResponseIPWithError(w, r, q, resp); handled || err != nil {
		if err != nil {
			h.logger.Warnf("RPZ response write failed for %s: %v", qname, err)
		}
		return
	}
	reply(w, r, resp)
}

// cnameChainResult holds the result of chasing a CNAME chain.
type cnameChainResult struct {
	// cnameRecords are the collected CNAME records along the chain.
	cnameRecords []zone.Record
	// targetName is the final name the chain resolves to.
	targetName string
	// loopDetected is true if a CNAME loop was detected.
	loopDetected bool
}

// chaseCNAMEInZones follows a CNAME chain across all local zones starting
// from the given name. It collects every CNAME record encountered and
// stops when the target name is not a CNAME in any local zone, or when
// a loop is detected (max chain depth exceeded or revisited name).
//
// The caller must NOT hold zonesMu; this method acquires the read lock
// internally as needed.
func (h *integratedHandler) chaseCNAMEInZones(name string) cnameChainResult {
	return chaseCNAMEChain(name, func(current string) *zone.Record {
		h.zonesMu.RLock()
		defer h.zonesMu.RUnlock()
		return h.findCNAMEInZonesLocked(current)
	})
}

// chaseCNAMEInZoneSet is chaseCNAMEInZones restricted to one set of zones.
// Split-horizon views need it: a CNAME must be followed inside the view that
// answered, never across the whole server, or one horizon's aliases would
// resolve against another horizon's data.
func chaseCNAMEInZoneSet(name string, zones map[string]*zone.Zone) cnameChainResult {
	return chaseCNAMEChain(name, func(current string) *zone.Record {
		return findCNAMEIn(zones, current)
	})
}

// chaseCNAMEChain walks a CNAME chain, asking lookup for the next link.
func chaseCNAMEChain(name string, lookup func(string) *zone.Record) cnameChainResult {
	const maxCNAMEDepth = 16

	visited := make(map[string]struct{}, maxCNAMEDepth)
	var result cnameChainResult
	current := canonicalize(name)

	for i := 0; i < maxCNAMEDepth; i++ {
		// Loop detection
		if _, seen := visited[current]; seen {
			result.loopDetected = true
			return result
		}
		visited[current] = struct{}{}

		cnameRec := lookup(current)
		if cnameRec == nil {
			// No CNAME found; the chain terminates at current.
			result.targetName = current
			return result
		}

		result.cnameRecords = append(result.cnameRecords, *cnameRec)
		current = canonicalize(cnameRec.RData)
	}

	// Chain exceeded maximum depth — treat as loop.
	result.loopDetected = true
	result.targetName = current
	return result
}

// findCNAMEInZonesLocked searches all authoritative zones for a CNAME record
// for the given name. The caller must hold zonesMu (at least RLock).
// Returns nil if no CNAME is found.
//
// File-loaded zones keep the BIND-relative forms in Record.Name/RData
// ("al" / "www") while the Records map key is fully qualified. The
// returned copy is qualified against the owning zone's origin so callers
// can build wire answers and chase the chain with absolute names —
// serving the raw relative forms produced answers like "al. CNAME www."
// (owner and target both wrong, chain resolution broken).
func (h *integratedHandler) findCNAMEInZonesLocked(name string) *zone.Record {
	return findCNAMEIn(h.zones, name)
}

// findCNAMEIn searches one set of zones for a CNAME at name.
func findCNAMEIn(zones map[string]*zone.Zone, name string) *zone.Record {
	cname := canonicalize(name)
	for _, z := range zones {
		recs := z.Lookup(cname, "CNAME")
		if len(recs) > 0 {
			rec := recs[0]
			rec.Name = qualifyAgainstOrigin(rec.Name, z.Origin)
			rec.RData = qualifyAgainstOrigin(rec.RData, z.Origin)
			return &rec
		}
	}
	return nil
}

// qualifyAgainstOrigin expands a BIND-relative name to its absolute form:
// "@" means the origin itself, names without a trailing dot are relative
// to the origin, absolute names pass through unchanged.
func qualifyAgainstOrigin(name, origin string) string {
	if !strings.HasSuffix(origin, ".") {
		origin += "."
	}
	switch {
	case name == "" || name == "@":
		return origin
	case strings.HasSuffix(name, "."):
		return name
	default:
		return name + "." + origin
	}
}

// resolveCNAMETarget attempts to resolve a CNAME target using local zones,
// cache, and upstream. It returns answer records for the original query type
// at the CNAME target, or nil if resolution failed.
func (h *integratedHandler) resolveCNAMETarget(w server.ResponseWriter, r *protocol.Message, q *protocol.Question, targetName string, qtype uint16) []*protocol.ResourceRecord {
	qtypeStr := typeToString(qtype)

	// 1. Try local zones first
	h.zonesMu.RLock()
	for _, z := range h.zones {
		recs := z.Lookup(targetName, qtypeStr)
		if len(recs) > 0 {
			h.zonesMu.RUnlock()
			var answers []*protocol.ResourceRecord
			for _, rec := range recs {
				data := parseRData(rec.Type, rec.RData)
				if data == nil {
					continue
				}
				targetNameParsed, err := protocol.ParseName(targetName)
				if err != nil {
					continue
				}
				answers = append(answers, &protocol.ResourceRecord{
					Name:  targetNameParsed,
					Type:  qtype,
					Class: protocol.ClassIN,
					TTL:   rec.TTL,
					Data:  data,
				})
			}
			return answers
		}
	}
	h.zonesMu.RUnlock()

	// 2. Check cache for the target (no DO bit needed — authoritative zone lookup)
	cacheKey := cache.MakeKey(targetName, qtype, false)
	if entry := h.cache.Get(cacheKey); entry != nil && !entry.IsNegative && entry.Message != nil {
		// Age-adjusted copy already decrements TTLs and returns fresh RRs, so
		// no further rr.Copy() is needed.
		adjusted := entry.AgeAdjustedMessage(time.Now())
		var answers []*protocol.ResourceRecord
		for _, rr := range adjusted.Answers {
			if rr.Type == qtype {
				answers = append(answers, rr)
			}
		}
		if len(answers) > 0 {
			return answers
		}
	}

	// 3. Forward to upstream (only when this server is allowed to act as a
	// resolver as well). In authoritative-only mode the operator has chosen
	// to never forward queries off this server; out-of-zone CNAME targets
	// are returned with whatever in-zone answers we already have rather
	// than being resolved via upstream — that prevents a local CNAME (which
	// any zone writer can set) from being used to weaponise this server as
	// a query proxy against arbitrary external services.
	if h.config != nil && h.config.Resolution.AuthoritativeOnly {
		return nil
	}
	if h.upstream != nil || h.loadBalancer != nil {
		targetNameParsed, err := protocol.ParseName(targetName)
		if err != nil {
			return nil
		}
		upstreamQuery := &protocol.Message{
			Header: protocol.Header{
				ID:      r.Header.ID,
				Flags:   protocol.NewQueryFlags(),
				QDCount: 1,
			},
			Questions: []*protocol.Question{
				{
					Name:   targetNameParsed,
					QType:  qtype,
					QClass: protocol.ClassIN,
				},
			},
		}

		var resp *protocol.Message
		if h.loadBalancer != nil {
			resp, err = h.loadBalancer.Query(upstreamQuery)
		} else {
			resp, err = h.upstream.Query(upstreamQuery)
		}
		if err != nil {
			h.logger.Warnf("Upstream CNAME target query failed for %s: %v", targetName, err)
			return nil
		}

		// Cache the upstream response
		if resp.Header.Flags.RCODE == protocol.RcodeSuccess && len(resp.Answers) > 0 {
			ttl := extractTTL(resp)
			h.cache.Set(cacheKey, resp, ttl)
		}

		// Extract matching answer records
		var answers []*protocol.ResourceRecord
		for _, rr := range resp.Answers {
			if rr.Type == qtype {
				answers = append(answers, rr.Copy())
			}
		}
		return answers
	}

	return nil
}

// buildCNAMEResponse constructs a complete DNS response with a CNAME chain
// and the resolved target records.
func (h *integratedHandler) buildCNAMEResponse(query *protocol.Message, cnameRecords []zone.Record, targetAnswers []*protocol.ResourceRecord) *protocol.Message {
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    query.Header.ID,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: query.Questions,
	}
	resp.Header.Flags.AA = true

	// Add all CNAME records in the chain
	for _, rec := range cnameRecords {
		data := parseRData("CNAME", rec.RData)
		if data == nil {
			continue
		}
		nameParsed, err := protocol.ParseName(rec.Name)
		if err != nil {
			continue
		}
		rr := &protocol.ResourceRecord{
			Name:  nameParsed,
			Type:  protocol.TypeCNAME,
			Class: protocol.ClassIN,
			TTL:   rec.TTL,
			Data:  data,
		}
		resp.AddAnswer(rr)
	}

	// Append the resolved target records
	for _, rr := range targetAnswers {
		resp.AddAnswer(rr)
	}

	return resp
}

// serveZoneDNSKEY answers a DNSKEY query at the apex from the zone's signing
// keys, signing the RRset with an active KSK.
//
// RFC 4035 §2.2: the DNSKEY RRset at the apex is signed by the key-signing
// key, which is what a validator follows down from the parent's DS record.
// Signing it with a ZSK instead would leave the chain of trust broken.
//
// Returns false when there is no signer for the zone or it holds no keys, so
// the caller continues with normal zone processing.
func (h *integratedHandler) serveZoneDNSKEY(w server.ResponseWriter, r *protocol.Message, q *protocol.Question, z *zone.Zone, wantsDNSSEC bool) bool {
	h.zoneSignersMu.RLock()
	signer, ok := h.zoneSigners[z.Origin]
	h.zoneSignersMu.RUnlock()
	if !ok || signer == nil {
		return false
	}

	ttl := z.GetDefaultTTL()
	if ttl == 0 {
		ttl = 3600
	}
	dnskeys, err := signer.DNSKEYRRSet(ttl)
	if err != nil {
		h.logger.Warnf("Building DNSKEY RRset for %s: %v", z.Origin, err)
		return false
	}
	if len(dnskeys) == 0 {
		return false
	}

	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    r.Header.ID,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: r.Questions,
	}
	resp.Header.Flags.AA = true
	for _, rr := range dnskeys {
		resp.AddAnswer(rr)
	}

	if wantsDNSSEC {
		if ksks := signer.GetActiveKSKs(); len(ksks) > 0 {
			inception := time.Now().UTC()
			expiration := inception.Add(30 * 24 * time.Hour)
			rrsig, sigErr := signer.SignRRSet(dnskeys, ksks[0],
				dnssecSignatureUnixTime(inception), dnssecSignatureUnixTime(expiration))
			if sigErr == nil && rrsig != nil {
				resp.AddAnswer(rrsig)
			} else if sigErr != nil {
				// The RRset still goes out; an unsigned DNSKEY set is what a
				// validator will reject, so make the reason visible.
				h.logger.Warnf("Failed to sign DNSKEY RRset for %s: %v", z.Origin, sigErr)
			}
		}
	}

	if h.metrics != nil {
		h.metrics.RecordResponse(protocol.RcodeSuccess)
	}
	if handled, err := h.checkRPZResponseIPWithError(w, r, q, resp); handled || err != nil {
		if err != nil {
			h.logger.Warnf("RPZ response write failed for DNSKEY %s: %v", z.Origin, err)
		}
		return true
	}
	reply(w, r, resp)
	return true
}
