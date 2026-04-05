// NothingDNS - Authoritative zone handling

package main

import (
	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// handleAuthoritative handles queries for authoritative zones.
// It performs direct record lookup. If no records match the query type,
// CNAME chasing is deferred to the caller (ServeDNS) which can resolve
// across zones, cache, and upstream.
func (h *integratedHandler) handleAuthoritative(z *zone.Zone, w server.ResponseWriter, r *protocol.Message, q *protocol.Question) bool {
	qname := q.Name.String()
	qtype := q.QType

	// Check if client wants DNSSEC (DO bit in OPT record)
	wantsDNSSEC := hasDOBit(r)

	// Check GeoDNS override
	if h.geoEngine != nil {
		clientIP := w.ClientInfo().IP()
		if clientIP != nil {
			typeStr := typeToString(qtype)
			if geoRData := h.geoEngine.Resolve(qname, typeStr, clientIP); geoRData != "" {
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
				reply(w, r, resp)
				return true
			}
		}
	}

	// Look up records matching the requested type
	records := z.Lookup(qname, typeToString(qtype))
	if len(records) > 0 {
		var resp *protocol.Message
		if signer, ok := h.zoneSigners[z.Origin]; ok && wantsDNSSEC {
			resp = h.buildSignedResponse(r, records, signer, true)
		} else {
			resp = h.buildResponse(r, records)
		}
		if h.metrics != nil {
			h.metrics.RecordResponse(protocol.RcodeSuccess)
		}
		reply(w, r, resp)
		return true
	}

	// No direct records. Check for CNAME — but don't resolve it here.
	// Return false so ServeDNS can do full CNAME chasing (across zones,
	// cache, upstream).
	cnameRecords := z.Lookup(qname, "CNAME")
	if len(cnameRecords) > 0 {
		return false // signal to ServeDNS to chase the CNAME
	}

	return false
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

		// Look for a CNAME record in any authoritative zone
		h.zonesMu.RLock()
		cnameRec := h.findCNAMEInZonesLocked(current)
		h.zonesMu.RUnlock()

		if cnameRec == nil {
			// No CNAME found; the chain terminates at current.
			result.targetName = current
			return result
		}

		result.cnameRecords = append(result.cnameRecords, *cnameRec)
		target := canonicalize(cnameRec.RData)
		current = target
	}

	// Chain exceeded maximum depth — treat as loop.
	result.loopDetected = true
	result.targetName = current
	return result
}

// findCNAMEInZonesLocked searches all authoritative zones for a CNAME record
// for the given name. The caller must hold zonesMu (at least RLock).
// Returns nil if no CNAME is found.
func (h *integratedHandler) findCNAMEInZonesLocked(name string) *zone.Record {
	cname := canonicalize(name)
	for _, z := range h.zones {
		recs := z.Lookup(cname, "CNAME")
		if len(recs) > 0 {
			return &recs[0]
		}
	}
	return nil
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

	// 2. Check cache for the target
	cacheKey := cache.MakeKey(targetName, qtype)
	if entry := h.cache.Get(cacheKey); entry != nil && !entry.IsNegative && entry.Message != nil {
		var answers []*protocol.ResourceRecord
		for _, rr := range entry.Message.Answers {
			if rr.Type == qtype {
				answers = append(answers, rr.Copy())
			}
		}
		if len(answers) > 0 {
			return answers
		}
	}

	// 3. Forward to upstream
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
