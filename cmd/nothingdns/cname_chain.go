// NothingDNS - authoritative CNAME / DNAME chain answers
//
// A CNAME answer is a chain of RRsets that may span several local zones.
// F517: for a DO=1 client every link went out unsigned (CNAME RRsets, the
// chased target RRset), so a validator rejected the whole answer as Bogus.
// F518: a chain ending at a name this server is authoritative for but that
// does not exist (or lacks the type) went out NOERROR with no SOA and no
// denial proof. F519: the target was looked up in every local zone's raw
// records, so glue / parent data below a zone cut and data occluded by a
// DNAME was answered as authoritative.
//
// Each link is now answered by the zone that is authoritative for its owner
// (the longest local origin containing it), honouring zone cuts and DNAME
// redirection, and signed with that zone's own signer; a negative end of the
// chain carries the target zone's SOA and NSEC/NSEC3 proof (RFC 4035 §3.1.3,
// RFC 2308 §2.1/§2.2) and sets RCODE from the last name (RFC 6604 §2.1).

package main

import (
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// authoritativeZoneIn returns the zone of zones whose origin is the longest
// one containing name (the zone authoritative for it, F519), or nil.
func authoritativeZoneIn(zones map[string]*zone.Zone, name string) *zone.Zone {
	var best *zone.Zone
	bestLen := -1
	for origin, z := range zones {
		if z == nil || !isSubdomain(name, origin) {
			continue
		}
		if l := len(canonicalize(origin)); l > bestLen {
			best, bestLen = z, l
		}
	}
	return best
}

// nameAuthority classifies name inside z: redirected by a DNAME above it
// (RFC 6672 §2.4 — the data below the owner is occluded), at or below a
// zone cut (the data is the child's, RFC 1034 §4.2.1), or neither. A cut
// strictly below a DNAME owner is occluded by the DNAME (F520); a DNAME at
// or below a cut is child data, so the cut wins.
func nameAuthority(z *zone.Zone, name string, qtype uint16) (dname zone.Record, synth string, redirect, cut bool) {
	name = canonicalize(name)
	dname, synth, redirect = z.FindDNAME(name)
	_, deleg, below := z.FindDelegation(name)
	atCut := qtype != protocol.TypeDS && name != canonicalize(z.Origin) && len(z.Lookup(name, "NS")) > 0
	if redirect {
		if below && isSubdomain(dname.Name, deleg) {
			return zone.Record{}, "", false, true
		}
		return dname, synth, true, false
	}
	return zone.Record{}, "", false, below || atCut
}

// signedRRsets appends rrs to dst, each type's RRset followed by its RRSIG
// from z's signer when sign is set (no-op signing for unsigned zones).
func (h *integratedHandler) signedRRsets(dst []*protocol.ResourceRecord, z *zone.Zone, rrs []*protocol.ResourceRecord, sign bool) []*protocol.ResourceRecord {
	if len(rrs) == 0 {
		return dst
	}
	byType := map[uint16][]*protocol.ResourceRecord{}
	var order []uint16
	for _, rr := range rrs {
		if _, ok := byType[rr.Type]; !ok {
			order = append(order, rr.Type)
		}
		byType[rr.Type] = append(byType[rr.Type], rr)
	}
	for _, t := range order {
		dst = append(dst, byType[t]...)
		if sign {
			if rrsig := h.signZoneRRSet(z, byType[t]); rrsig != nil {
				dst = append(dst, rrsig)
			}
		}
	}
	return dst
}

// zoneRecordsToRRs converts zone records to wire records owned by owner.
func zoneRecordsToRRs(owner *protocol.Name, recs []zone.Record, origin string) []*protocol.ResourceRecord {
	var out []*protocol.ResourceRecord
	for _, rec := range recs {
		rdata := rec.RData
		if rec.Type == "CNAME" {
			rdata = qualifyAgainstOrigin(rdata, origin)
		}
		data := parseRData(rec.Type, rdata)
		if data == nil {
			continue
		}
		out = append(out, &protocol.ResourceRecord{
			Name: owner, Type: stringToType(rec.Type), Class: protocol.ClassIN, TTL: rec.TTL, Data: data,
		})
	}
	return out
}

// cnameTarget is the end of a CNAME chain: the records appended after the
// chain's CNAMEs, the authority records for a negative end, and the RCODE.
type cnameTarget struct {
	answers   []*protocol.ResourceRecord
	authority []*protocol.ResourceRecord
	rcode     uint8
}

// chainZone returns the zone authoritative for name: inside view when it
// holds one (split-horizon, or the zone a wildcard/DNAME answer came from),
// otherwise among all local zones.
func (h *integratedHandler) chainZone(view map[string]*zone.Zone, name string) *zone.Zone {
	if z := authoritativeZoneIn(view, name); z != nil {
		return z
	}
	h.zonesMu.RLock()
	defer h.zonesMu.RUnlock()
	return authoritativeZoneIn(h.localZonesLocked(), name)
}

// resolveChainTarget answers the end of a CNAME chain (target, qtype). A
// name inside a local zone is answered by that zone alone — data, DNAME
// redirection, further CNAMEs (wildcard or explicit), NODATA or NXDOMAIN
// with SOA and, for sign, the signed denial proof. Names outside every local
// zone, or below a cut to a child this server does not host, go to the cache
// / upstream exactly as before (resolveExternalCNAMETarget).
func (h *integratedHandler) resolveChainTarget(w server.ResponseWriter, r *protocol.Message, view map[string]*zone.Zone, target string, qtype uint16, sign bool) cnameTarget {
	const maxChainSteps = 16
	var out cnameTarget
	qtypeStr := typeToString(qtype)
	current := canonicalize(target)
	for step := 0; step < maxChainSteps; step++ {
		z := h.chainZone(view, current)
		if z == nil {
			out.answers = append(out.answers, h.resolveExternalCNAMETarget(w, r, current, qtype)...)
			return out
		}
		owner, err := protocol.ParseName(current)
		if err != nil {
			return out
		}
		dname, synth, redirect, cut := nameAuthority(z, current, qtype)
		if cut {
			// The child is not hosted here (it would be the longer origin).
			out.answers = append(out.answers, h.resolveExternalCNAMETarget(w, r, current, qtype)...)
			return out
		}
		if redirect {
			dnameOwner, err1 := protocol.ParseName(dname.Name)
			synthName, err2 := protocol.ParseName(synth)
			data := parseRData("DNAME", dname.RData)
			if err1 != nil || err2 != nil || data == nil {
				return out
			}
			out.answers = h.signedRRsets(out.answers, z, []*protocol.ResourceRecord{{
				Name: dnameOwner, Type: protocol.TypeDNAME, Class: protocol.ClassIN, TTL: dname.TTL, Data: data,
			}}, sign)
			// The synthesized CNAME is never signed; validators re-derive it
			// from the signed DNAME (RFC 6672 §5.3.1).
			out.answers = append(out.answers, &protocol.ResourceRecord{
				Name: owner, Type: protocol.TypeCNAME, Class: protocol.ClassIN, TTL: dname.TTL,
				Data: &protocol.RDataCNAME{CName: synthName},
			})
			current = canonicalize(synth)
			continue
		}
		if recs := z.Lookup(current, qtypeStr); len(recs) > 0 {
			out.answers = h.signedRRsets(out.answers, z, zoneRecordsToRRs(owner, recs, z.Origin), sign)
			return out
		}
		if qtype != protocol.TypeCNAME {
			if recs := z.Lookup(current, "CNAME"); len(recs) > 0 {
				out.answers = h.signedRRsets(out.answers, z, zoneRecordsToRRs(owner, recs[:1], z.Origin), sign)
				current = canonicalize(qualifyAgainstOrigin(recs[0].RData, z.Origin))
				continue
			}
		}
		probe := &protocol.Message{Questions: []*protocol.Question{{Name: owner, QType: qtype, QClass: protocol.ClassIN}}}
		if !z.NodeExists(current) {
			wcRecords, wildcard, wcFound := z.LookupWildcard(current, qtypeStr)
			if wcFound && len(wcRecords) > 0 {
				resp := h.buildWildcardResponse(probe, z, wildcard, wcRecords, sign)
				out.answers = append(out.answers, resp.Answers...)
				out.authority = append(out.authority, resp.Authorities...)
				return out
			}
			if wcFound && qtype != protocol.TypeCNAME {
				if cnames, wc, ok := z.LookupWildcard(current, "CNAME"); ok && len(cnames) > 0 {
					synthRec := cnames[0]
					synthRec.RData = qualifyAgainstOrigin(synthRec.RData, z.Origin)
					resp := h.buildWildcardResponse(probe, z, wc, []zone.Record{synthRec}, sign)
					out.answers = append(out.answers, resp.Answers...)
					out.authority = append(out.authority, resp.Authorities...)
					current = canonicalize(synthRec.RData)
					continue
				}
			}
			if !wcFound {
				resp := h.buildNXDOMAINResponse(probe, z, current, sign)
				out.authority = append(out.authority, resp.Authorities...)
				out.rcode = protocol.RcodeNameError
				return out
			}
		}
		resp := h.buildNODATAResponse(probe, z, current, sign)
		out.authority = append(out.authority, resp.Authorities...)
		return out
	}
	return out
}

// buildChainResponse is buildCNAMEResponse for a chain whose links come from
// local zones: each CNAME RRset is signed by its own zone when sign is set,
// and the target's authority records and RCODE are carried over.
func (h *integratedHandler) buildChainResponse(query *protocol.Message, chain cnameChainResult, tgt cnameTarget, sign bool) *protocol.Message {
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    query.Header.ID,
			Flags: protocol.NewResponseFlags(tgt.rcode),
		},
		Questions: query.Questions,
	}
	resp.Header.Flags.AA = true
	for i, rec := range chain.cnameRecords {
		owner, err := protocol.ParseName(rec.Name)
		if err != nil {
			continue
		}
		var z *zone.Zone
		if i < len(chain.cnameZones) {
			z = chain.cnameZones[i]
		}
		rrs := zoneRecordsToRRs(owner, []zone.Record{rec}, rec.Name)
		resp.Answers = h.signedRRsets(resp.Answers, z, rrs, sign)
	}
	resp.Answers = append(resp.Answers, tgt.answers...)
	resp.Authorities = append(resp.Authorities, tgt.authority...)
	resp.Header.ANCount = uint16(len(resp.Answers))
	resp.Header.NSCount = uint16(len(resp.Authorities))
	return resp
}
