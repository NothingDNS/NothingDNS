// NothingDNS - Authoritative zone handling

package main

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// handleAuthoritative handles queries for authoritative zones.
// It performs: delegation check → exact match → CNAME → wildcard → NXDOMAIN.
// CNAME chasing is deferred to the caller (ServeDNS) which can resolve
// across zones, cache, and upstream. cacheHit, when non-nil, is set when the
// answer came from the authoritative answer cache, so the query log, the
// dashboard and tracing report it as cached.
func (h *integratedHandler) handleAuthoritative(z *zone.Zone, w server.ResponseWriter, r *protocol.Message, q *protocol.Question, qname string, cacheHit *bool) bool {
	qtype := q.QType

	// Check if client wants DNSSEC (DO bit in OPT record)
	wantsDNSSEC := hasDOBit(r)

	// ── Step 0: Check for delegation (zone cut) ──
	// Per RFC 1034 §4.2.1, if the query name is at or below a delegation
	// point, we return a referral (non-authoritative) response with NS
	// records and optional glue.
	// F520: a cut strictly below a DNAME owner is occluded (RFC 6672 §2.4);
	// the DNAME redirects such names (Step 1c) instead of the referral.
	_, _, dnameRedirect, _ := nameAuthority(z, qname, qtype)
	if nsRecords, delegation, found := z.FindDelegation(qname); found && !dnameRedirect {
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
	// F302: FindDelegation only looks strictly above qname, so a query AT a
	// zone cut was answered as authoritative data (AA=1 NODATA, or the
	// delegation NS RRset in the answer section). Everything at the cut
	// except DS belongs to the child zone (RFC 1034 §4.3.2 step 3b, RFC 4035
	// §3.1.4.1), so it gets the same referral as a name below the cut.
	if qtype != protocol.TypeDS && canonicalize(qname) != canonicalize(z.Origin) && !dnameRedirect {
		if nsRecords := z.Lookup(qname, "NS"); len(nsRecords) > 0 {
			resp := h.buildReferralResponse(r, z, nsRecords, canonicalize(qname))
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

	// ── Step 1a: Answer cache ──
	// Everything below is a function of the zone's content (plus the DO bit),
	// so the answer is cached under the zone's CacheTag. Delegation and
	// GeoDNS run first on every query: GeoDNS answers depend on the client.
	authKey := h.authoritativeCacheKey(z, qname, qtype, wantsDNSSEC)
	if authKey != "" && h.serveAuthoritativeFromCache(authKey, w, r, q) {
		if cacheHit != nil {
			*cacheHit = true
		}
		return true
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
	// F488: a zone served with NSEC3 denial publishes its parameters at the
	// apex (RFC 5155 §7.3).
	if qtype == protocol.TypeNSEC3PARAM && canonicalize(qname) == canonicalize(z.Origin) &&
		len(z.Lookup(qname, "NSEC3PARAM")) == 0 && h.serveZoneNSEC3PARAM(w, r, z, wantsDNSSEC) {
		return true
	}

	// ── Step 1c: DNAME (RFC 6672) ──
	// A DNAME redirects every name below its owner. F515: this ran after
	// the exact-match and CNAME steps, so data a zone file holds below a
	// DNAME owner — occluded, RFC 6672 §2.4 — was answered (and signed)
	// instead of the redirection (RFC 1034 §4.3.2 step 3c).
	if dnameRec, synthTarget, found := z.FindDNAME(qname); found {
		h.handleDNAMERecord(z, w, r, q, qname, dnameRec, synthTarget, wantsDNSSEC)
		return true
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
		h.cacheAuthoritative(z, authKey, resp)
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

	// ── Step 4: Wildcard matching (RFC 4592) ──
	// Only attempt wildcards if the exact name doesn't exist at all.
	// If the name exists but has no records of the requested type,
	// that's NODATA (handled below), not a wildcard case.
	// NodeExists, not NameExists: an empty non-terminal is an existing node,
	// so it is NODATA rather than a wildcard candidate or an NXDOMAIN.
	if !z.NodeExists(qname) {
		wcRecords, wildcard, wcFound := z.LookupWildcard(qname, typeToString(qtype))
		if wcFound {
			if len(wcRecords) > 0 {
				// Synthesize answer: wildcard records with the query name as owner
				resp := h.buildWildcardResponse(r, z, wildcard, wcRecords, wantsDNSSEC)
				h.cacheAuthoritative(z, authKey, resp)
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
			// F303: a wildcard CNAME applies to every qtype (RFC 4592 §2.2.1,
			// RFC 1034 §4.3.2 step 3c), not only to CNAME queries.
			if qtype != protocol.TypeCNAME && h.answerWildcardCNAME(z, w, r, q, qname, wantsDNSSEC) {
				return true
			}
			// Wildcard exists but no records of the requested type → NODATA
			resp := h.buildNODATAResponse(r, z, qname, wantsDNSSEC)
			h.cacheAuthoritative(z, authKey, resp)
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
		h.cacheAuthoritative(z, authKey, resp)
		if h.metrics != nil {
			h.metrics.RecordResponse(protocol.RcodeNameError)
		}
		reply(w, r, resp)
		return true
	}

	// ── Step 5: Name exists but no records of requested type → NODATA ──
	resp := h.buildNODATAResponse(r, z, qname, wantsDNSSEC)
	h.cacheAuthoritative(z, authKey, resp)
	if h.metrics != nil {
		h.metrics.RecordResponse(protocol.RcodeSuccess)
	}
	reply(w, r, resp)
	return true
}

// answerWildcardCNAME synthesizes the CNAME owned by the wildcard that covers
// qname and follows its target, first inside z (which may be a view zone that
// the global zone set does not hold), then through resolveCNAMETarget. It
// returns false when the covering wildcard owns no CNAME.
func (h *integratedHandler) answerWildcardCNAME(z *zone.Zone, w server.ResponseWriter, r *protocol.Message, q *protocol.Question, qname string, wantsDNSSEC bool) bool {
	cnames, wildcard, found := z.LookupWildcard(qname, "CNAME")
	if !found || len(cnames) == 0 {
		return false
	}
	synth := cnames[0]
	synth.Name = qname
	synth.RData = qualifyAgainstOrigin(synth.RData, z.Origin)
	target := canonicalize(synth.RData)

	resp := h.buildWildcardResponse(r, z, wildcard, []zone.Record{synth}, wantsDNSSEC)
	// F517/F518: the target is answered by its own zone (z first: it may be
	// a view zone), signed, with a denial proof when it is negative.
	tgt := h.resolveChainTarget(w, r, map[string]*zone.Zone{z.Origin: z}, target, q.QType, wantsDNSSEC)
	for _, rr := range tgt.answers {
		resp.AddAnswer(rr)
	}
	resp.Authorities = append(resp.Authorities, tgt.authority...)
	resp.Header.Flags.RCODE = tgt.rcode

	if handled, err := h.applyRPZResponsePolicyWithError(w, r, q, resp, target); handled || err != nil {
		if err != nil {
			h.logger.Warnf("RPZ response write failed for %s: %v", qname, err)
		}
		return true
	}
	if h.metrics != nil {
		h.metrics.RecordResponse(resp.Header.Flags.RCODE)
	}
	reply(w, r, resp)
	return true
}

// authoritativeCacheKey returns the cache key for an answer built from z, or
// "" when the answer must not be cached. The key embeds the zone's CacheTag,
// so any change to the zone makes earlier answers unreachable instead of
// stale. The leading '|' keeps it disjoint from MakeKey's keys, which start
// with a domain name, so the recursive cache stages never see these entries.
//
// Answers signed on the fly are not cached: their RRSIGs and the zone's
// DNSKEY/NSEC3PARAM sets come from the signer, whose key rollovers the zone
// generation does not track.
func (h *integratedHandler) authoritativeCacheKey(z *zone.Zone, qname string, qtype uint16, wantsDNSSEC bool) string {
	if h.cache == nil {
		return ""
	}
	if wantsDNSSEC || qtype == protocol.TypeDNSKEY || qtype == protocol.TypeNSEC3PARAM {
		h.zoneSignersMu.RLock()
		_, signed := h.zoneSigners[z.Origin]
		h.zoneSignersMu.RUnlock()
		if signed {
			return ""
		}
	}
	return authoritativeCachePrefix(z) + cache.MakeKey(qname, qtype, wantsDNSSEC)
}

// authoritativeCachePrefix is the part of an authoritative cache key that
// names the zone's current CacheTag.
func authoritativeCachePrefix(z *zone.Zone) string {
	id, gen := z.CacheTag()
	var b strings.Builder
	b.WriteString("|auth|")
	b.WriteString(strconv.FormatUint(id, 10))
	b.WriteByte('|')
	b.WriteString(strconv.FormatUint(gen, 10))
	b.WriteByte('|')
	return b.String()
}

// serveAuthoritativeFromCache answers r from a cached authoritative answer.
// Record TTLs are served as stored — an authority's TTLs do not age.
func (h *integratedHandler) serveAuthoritativeFromCache(key string, w server.ResponseWriter, r *protocol.Message, q *protocol.Question) bool {
	entry := h.cache.Get(key)
	if entry == nil || entry.Message == nil {
		if h.metrics != nil {
			h.metrics.RecordCacheMiss()
		}
		return false
	}
	// COPY — reply() mutates in place. Every answer record of a cached
	// authoritative answer is owned by the query name (exact or wildcard
	// match), so restore this client's spelling of it (0x20 case).
	resp := entry.Message.Copy()
	resp.Header.ID = r.Header.ID
	resp.Questions = r.Questions
	for _, rr := range resp.Answers {
		rr.Name = q.Name
	}
	if h.metrics != nil {
		h.metrics.RecordCacheHit()
		h.metrics.RecordResponse(resp.Header.Flags.RCODE)
	}
	if len(resp.Answers) > 0 {
		if handled, err := h.checkRPZResponseIPWithError(w, r, q, resp); handled || err != nil {
			if err != nil {
				h.logger.Warnf("RPZ response write failed for %s: %v", q.Name.String(), err)
			}
			return true
		}
	}
	reply(w, r, resp)
	return true
}

// buildWildcardResponse answers the query with records synthesized from the
// wildcard owner (RFC 4592). F512: for a DO=1 client of a signed zone the
// RRset was signed as if QNAME existed (RRSIG Labels = QNAME labels) and the
// answer carried no proof that QNAME does not exist, contradicting the
// zone's own denial chain; an expansion more than one label below the
// wildcard's closest encloser validated Bogus. The RRset is now signed at the
// wildcard owner, so its RRSIG Labels field marks the expansion (RFC 4034
// §3.1.3, RFC 4035 §5.3.4), and the authority section carries the signed
// NSEC/NSEC3 proving no closer match (RFC 4035 §3.1.3.3, RFC 5155 §7.2.6).
func (h *integratedHandler) buildWildcardResponse(r *protocol.Message, z *zone.Zone, wildcard string, records []zone.Record, wantsDNSSEC bool) *protocol.Message {
	resp := h.buildResponse(r, records) // owners = QNAME
	if !wantsDNSSEC || len(resp.Answers) == 0 {
		return resp
	}
	wcName, err := protocol.ParseName(wildcard)
	if err != nil {
		return resp
	}
	rrs := make([]*protocol.ResourceRecord, 0, len(resp.Answers))
	for _, rr := range resp.Answers {
		cp := *rr
		cp.Name = wcName
		rrs = append(rrs, &cp)
	}
	rrsig := h.signZoneRRSet(z, rrs)
	if rrsig == nil {
		return resp // unsigned zone (or signing failed, logged)
	}
	rrsig.Name = resp.Answers[0].Name
	resp.AddAnswer(rrsig)
	for _, proof := range h.wildcardAnswerRRs(z, r.Questions[0].Name.String(), strings.TrimPrefix(wildcard, "*.")) {
		resp.Authorities = append(resp.Authorities, proof)
		if sig := h.signZoneRRSet(z, []*protocol.ResourceRecord{proof}); sig != nil {
			resp.Authorities = append(resp.Authorities, sig)
		}
	}
	return resp
}

// cacheAuthoritative stores an authoritative answer under key (see
// authoritativeCacheKey). Positive answers live for their shortest record
// TTL, negative ones for the RFC 2308 negative TTL of the SOA they carry.
//
// The answer is dropped when z's CacheTag moved while it was being built: a
// mutation or a reload that handed the tag to a new Zone (InheritCacheTag)
// means resp may hold data the tag in key no longer names.
func (h *integratedHandler) cacheAuthoritative(z *zone.Zone, key string, resp *protocol.Message) {
	if key == "" || resp == nil || !strings.HasPrefix(key, authoritativeCachePrefix(z)) {
		return
	}
	var ttl uint32
	if len(resp.Answers) > 0 {
		ttl = resp.Answers[0].TTL
		for _, rr := range resp.Answers[1:] {
			if rr.TTL < ttl {
				ttl = rr.TTL
			}
		}
	} else if negTTL, ok := negativeCacheTTL(resp); ok {
		ttl = negTTL
	}
	h.cache.SetAuthoritative(key, resp, ttl)
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

	// F384: from a signed zone, a DO=1 referral must say whether the
	// delegation is secure: the DS RRset and its RRSIG, or the NSEC at the
	// cut proving there is no DS, with its RRSIG (RFC 4035 §3.1.4). Without
	// either a validator cannot tell an insecure delegation from a stripped DS.
	if hasDOBit(query) && delegName != nil {
		var dsRRs []*protocol.ResourceRecord
		for _, rec := range z.Lookup(delegation, "DS") {
			if data := parseRData(rec.Type, rec.RData); data != nil {
				dsRRs = append(dsRRs, &protocol.ResourceRecord{
					Name: delegName, Type: protocol.TypeDS, Class: protocol.ClassIN, TTL: rec.TTL, Data: data,
				})
			}
		}
		if rrsig := h.signZoneRRSet(z, dsRRs); rrsig != nil {
			resp.Authorities = append(resp.Authorities, dsRRs...)
			resp.Authorities = append(resp.Authorities, rrsig)
		} else if len(dsRRs) == 0 {
			// F488/F489: the NSEC at the cut, or the NSEC3 matching it (or,
			// with opt-out, the closest provable encloser proof), from the
			// authoritative chain. Each record is its own RRset.
			for _, rr := range h.insecureDelegationProof(z, delegation) {
				if rrsig := h.signZoneRRSet(z, []*protocol.ResourceRecord{rr}); rrsig != nil {
					resp.Authorities = append(resp.Authorities, rr, rrsig)
				}
			}
		}
	}

	return resp
}

// signZoneRRSet signs rrs with z's active ZSK. It returns nil when the zone
// has no signer or active ZSK, or signing fails.
func (h *integratedHandler) signZoneRRSet(z *zone.Zone, rrs []*protocol.ResourceRecord) *protocol.ResourceRecord {
	if z == nil || len(rrs) == 0 {
		return nil
	}
	h.zoneSignersMu.RLock()
	signer, ok := h.zoneSigners[z.Origin]
	h.zoneSignersMu.RUnlock()
	if !ok || signer == nil {
		return nil
	}
	zsks := signer.GetActiveZSKs()
	if len(zsks) == 0 {
		return nil
	}
	inception := time.Now().UTC()
	expiration := inception.Add(30 * 24 * time.Hour)
	rrsig, err := signer.SignRRSet(rrs, zsks[0],
		dnssecSignatureUnixTime(inception), dnssecSignatureUnixTime(expiration))
	if err != nil {
		h.logger.Warnf("Failed to sign %s RRset in %s: %v", typeToString(rrs[0].Type), z.Origin, err)
		return nil
	}
	return rrsig
}

// dsAnsweredByParent reports whether the zone at origin must pass a DS query
// on to a parent zone that follows it in the longest-first match list (F383):
// DS at a zone apex is parent-side data (RFC 4035 §3.1.4.1), so a co-hosted
// child must not answer it with its own NODATA.
func dsAnsweredByParent(qtype uint16, qname, origin string, parentFollows bool) bool {
	return qtype == protocol.TypeDS && parentFollows && canonicalize(qname) == canonicalize(origin)
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
// of a response. This is required for negative caching (RFC 2308). Its TTL is
// the lesser of the SOA TTL and MINIMUM (RFC 2308 §3), which is how long
// resolvers cache the negative answer.
func (h *integratedHandler) addSOAAuthority(resp *protocol.Message, z *zone.Zone) {
	// Read the SOA under the zone's read lock: every serial bump
	// (IncrementSerial, DDNS, the record API) writes it under z.Lock.
	z.RLock()
	if z.SOA == nil {
		z.RUnlock()
		return
	}
	soa := *z.SOA
	z.RUnlock()
	ttl := soa.TTL
	if soa.Minimum < ttl {
		ttl = soa.Minimum
	}
	mname, err := protocol.ParseName(soa.MName)
	if err != nil {
		return
	}
	rname, err := protocol.ParseName(soa.RName)
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
		TTL:   ttl,
		Data: &protocol.RDataSOA{
			MName:   mname,
			RName:   rname,
			Serial:  soa.Serial,
			Refresh: soa.Refresh,
			Retry:   soa.Retry,
			Expire:  soa.Expire,
			Minimum: soa.Minimum,
		},
	}
	resp.Authorities = append(resp.Authorities, rr)
}

// handleDNAMERecord synthesizes a CNAME from a DNAME record and resolves
// the target, returning a complete DNS response with both DNAME and CNAME
// records plus the resolved target answers.
// Per RFC 6672, a DNAME at a superdomain synthesizes a CNAME for subdomains.
func (h *integratedHandler) handleDNAMERecord(z *zone.Zone, w server.ResponseWriter, r *protocol.Message, q *protocol.Question, qname string, dnameRecord zone.Record, synthCNAMETarget string, wantsDNSSEC bool) {
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

	// Resolve the synthesized CNAME target. F517/F518: by its own zone (z
	// first: it may be a view zone), signed, with a denial proof when negative.
	tgt := h.resolveChainTarget(w, r, map[string]*zone.Zone{z.Origin: z}, synthCNAMETarget, qtype, wantsDNSSEC)

	// Build the response
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    r.Header.ID,
			Flags: protocol.NewResponseFlags(tgt.rcode),
		},
		Questions: r.Questions,
	}
	resp.Header.Flags.AA = true
	resp.AddAnswer(dnameRR)
	// F382: the DNAME is authoritative zone data and must be signed for a DO=1
	// client (RFC 6672 §5.3.1); only the synthesized CNAME goes out unsigned —
	// a validator re-derives it from the signed DNAME.
	if wantsDNSSEC {
		if rrsig := h.signZoneRRSet(z, []*protocol.ResourceRecord{dnameRR}); rrsig != nil {
			resp.AddAnswer(rrsig)
		}
	}
	resp.AddAnswer(cnameRR)
	for _, rr := range tgt.answers {
		resp.AddAnswer(rr)
	}
	resp.Authorities = append(resp.Authorities, tgt.authority...)

	if h.metrics != nil {
		h.metrics.RecordResponse(tgt.rcode)
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
	// cnameZones[i] is the zone cnameRecords[i] was read from (F517: each
	// link is signed by its own zone).
	cnameZones []*zone.Zone
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
	return chaseCNAMEChain(name, func(current string) (*zone.Record, *zone.Zone) {
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
	return chaseCNAMEChain(name, func(current string) (*zone.Record, *zone.Zone) {
		return findCNAMEIn(zones, current)
	})
}

// chaseCNAMEChain walks a CNAME chain, asking lookup for the next link.
func chaseCNAMEChain(name string, lookup func(string) (*zone.Record, *zone.Zone)) cnameChainResult {
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

		cnameRec, z := lookup(current)
		if cnameRec == nil {
			// No CNAME found; the chain terminates at current.
			result.targetName = current
			return result
		}

		result.cnameRecords = append(result.cnameRecords, *cnameRec)
		result.cnameZones = append(result.cnameZones, z)
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
func (h *integratedHandler) findCNAMEInZonesLocked(name string) (*zone.Record, *zone.Zone) {
	return findCNAMEIn(h.localZonesLocked(), name)
}

// findCNAMEIn searches one set of zones for a CNAME at name, and returns it
// with the zone it came from. F519: only the zone authoritative for name
// (longest origin) is consulted, and not for a name at or below one of its
// zone cuts or below a DNAME — that data is the child's, or occluded (RFC
// 6672 §2.4); any zone in map order used to answer.
func findCNAMEIn(zones map[string]*zone.Zone, name string) (*zone.Record, *zone.Zone) {
	cname := canonicalize(name)
	z := authoritativeZoneIn(zones, cname)
	if z == nil {
		return nil, nil
	}
	if _, _, redirect, cut := nameAuthority(z, cname, protocol.TypeCNAME); redirect || cut {
		return nil, nil
	}
	recs := z.Lookup(cname, "CNAME")
	if len(recs) == 0 {
		return nil, nil
	}
	rec := recs[0]
	rec.Name = qualifyAgainstOrigin(rec.Name, z.Origin)
	rec.RData = qualifyAgainstOrigin(rec.RData, z.Origin)
	return &rec, z
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
// at the CNAME target, or nil if resolution failed. Local zones answer
// through resolveChainTarget (authoritative zone only, F519), unsigned.
func (h *integratedHandler) resolveCNAMETarget(w server.ResponseWriter, r *protocol.Message, q *protocol.Question, targetName string, qtype uint16) []*protocol.ResourceRecord {
	return h.resolveChainTarget(w, r, nil, targetName, qtype, false).answers
}

// resolveExternalCNAMETarget resolves a chain target no local zone is
// authoritative for, from the cache or upstream (recursion permitting).
func (h *integratedHandler) resolveExternalCNAMETarget(w server.ResponseWriter, r *protocol.Message, targetName string, qtype uint16) []*protocol.ResourceRecord {
	// Out-of-zone targets need the cache or upstream, i.e. recursion; a
	// client without recursion rights gets only the in-zone part.
	if !recursionAllowedFor(w) {
		return nil
	}

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

		// Validate like the upstream stage (DO=1, then the validator): the
		// answer was served and cached under the target's own key unchecked,
		// so a forged answer for a signed name bypassed validation (F656).
		outQuery := upstreamQuery
		if h.validator != nil {
			outQuery = withDOBit(upstreamQuery)
		}
		var resp *protocol.Message
		if h.loadBalancer != nil {
			resp, err = h.loadBalancer.Query(outQuery)
		} else {
			resp, err = h.upstream.Query(outQuery)
		}
		if err != nil {
			h.logger.Warnf("Upstream CNAME target query failed for %s: %v", targetName, err)
			return nil
		}
		// Return the pooled *Message to the sync.Pool after the cache takes a deep
		// copy. Without this, every CNAME target resolution leaks one message
		// from the pool, eventually starving upstream queries and forcing extra
		// allocations under load.
		defer resp.Release()
		if h.validator != nil {
			resp.Header.Flags.AD = false
			result, valErr := h.validator.ValidateResponse(context.Background(), resp, targetName)
			if valErr != nil {
				h.logger.Warnf("DNSSEC validation error for CNAME target %s: %v", targetName, valErr)
			}
			if h.config.DNSSEC.Enabled && (result == dnssec.ValidationBogus || result == dnssec.ValidationIndeterminate) {
				h.logger.Warnf("DNSSEC validation failed for CNAME target %s", targetName)
				return nil
			}
		}

		// Cache the upstream response. ApplyTTLPolicy clamps the response's answer
		// record TTLs in place before caching and before we copy records for the
		// client — this ensures downstream DNS caches receive the configured max_ttl
		// cap, not the upstream's raw TTL (e.g. CDN 999999s).
		if resp.Header.Flags.RCODE == protocol.RcodeSuccess && len(resp.Answers) > 0 {
			ttl := extractTTL(resp)
			clampedTTL := h.cache.ApplyTTLPolicy(resp, ttl)
			h.cache.Set(cacheKey, resp, clampedTTL)
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
// and the resolved target records (unsigned; see buildChainResponse).
func (h *integratedHandler) buildCNAMEResponse(query *protocol.Message, cnameRecords []zone.Record, targetAnswers []*protocol.ResourceRecord) *protocol.Message {
	return h.buildChainResponse(query, cnameChainResult{cnameRecords: cnameRecords}, cnameTarget{answers: targetAnswers}, false)
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

// serveZoneNSEC3PARAM answers an apex NSEC3PARAM query for a signed zone
// served with NSEC3 denial. Returns false when the zone is unsigned or uses
// NSEC, so the caller falls through to NODATA.
func (h *integratedHandler) serveZoneNSEC3PARAM(w server.ResponseWriter, r *protocol.Message, z *zone.Zone, wantsDNSSEC bool) bool {
	h.zoneSignersMu.RLock()
	signer := h.zoneSigners[z.Origin]
	h.zoneSignersMu.RUnlock()
	if signer == nil {
		return false
	}
	rr := h.nsec3ParamRR(z)
	if rr == nil {
		return false
	}
	resp := &protocol.Message{
		Header:    protocol.Header{ID: r.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Questions: r.Questions,
	}
	resp.Header.Flags.AA = true
	resp.AddAnswer(rr)
	if wantsDNSSEC {
		if rrsig := h.signZoneRRSet(z, []*protocol.ResourceRecord{rr}); rrsig != nil {
			resp.AddAnswer(rrsig)
		}
	}
	if h.metrics != nil {
		h.metrics.RecordResponse(protocol.RcodeSuccess)
	}
	reply(w, r, resp)
	return true
}
