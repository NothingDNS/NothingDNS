// NothingDNS - serving zones that carry their own signatures
//
// A zone signed offline (dnsctl dnssec sign-zone), transferred signed from a
// primary (F751, or another server's signed zone under slave_zones) holds its
// DNSKEY, RRSIG and NSEC records as zone data and has no online signer. Those
// signatures were never put in answers: a DO=1 query got the RRset without its
// RRSIG and a negative answer got no NSEC proof, so validators found every
// answer from such a zone Bogus (F753). The helpers below take the stored
// records instead of signing. NSEC3-signed zones get their stored RRSIGs but
// no denial proofs yet.

package main

import (
	"strings"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// storedRRSIGs returns the RRSIG records z holds at owner covering covered.
func storedRRSIGs(z *zone.Zone, owner string, covered uint16) []*protocol.ResourceRecord {
	want := typeToString(covered)
	var out []*protocol.ResourceRecord
	for _, rec := range z.Lookup(owner, "RRSIG") {
		fields := strings.Fields(rec.RData)
		if len(fields) == 0 || !strings.EqualFold(fields[0], want) {
			continue
		}
		if rr := zoneRecordRR(rec); rr != nil {
			out = append(out, rr)
		}
	}
	return out
}

// zoneRecordRR converts a stored zone record to its wire form.
func zoneRecordRR(rec zone.Record) *protocol.ResourceRecord {
	data := parseRData(rec.Type, rec.RData)
	if data == nil {
		return nil
	}
	name, err := protocol.ParseName(canonicalize(rec.Name))
	if err != nil {
		return nil
	}
	return &protocol.ResourceRecord{Name: name, Type: stringToType(rec.Type), Class: protocol.ClassIN, TTL: rec.TTL, Data: data}
}

// zonePresigned reports whether z carries its own signatures: an RRSIG over
// its SOA at the apex.
func zonePresigned(z *zone.Zone) bool {
	return z != nil && len(storedRRSIGs(z, z.Origin, protocol.TypeSOA)) > 0
}

// storedRecord returns the record of type rtype z holds at owner, if any:
// a presigned zone's own NSEC must be served, not one rebuilt here, since
// only the stored one matches its stored signature.
func storedRecord(z *zone.Zone, owner string, rtype uint16) *protocol.ResourceRecord {
	recs := z.Lookup(owner, typeToString(rtype))
	if len(recs) == 0 {
		return nil
	}
	return zoneRecordRR(recs[0])
}

// addStoredDenialProof adds a presigned NSEC zone's own proof to a negative
// answer: the SOA's RRSIG and the stored NSEC records (with their RRSIGs) at
// the owners the denial chain picks for qname.
func (h *integratedHandler) addStoredDenialProof(resp *protocol.Message, z *zone.Zone, qname string, kind denialKind) {
	if !zonePresigned(z) {
		return
	}
	resp.Authorities = append(resp.Authorities, storedRRSIGs(z, z.Origin, protocol.TypeSOA)...)
	if len(z.Lookup(z.Origin, "NSEC3PARAM")) > 0 {
		return // NSEC3: no stored proofs served yet
	}
	for _, data := range h.presignedDenialChain(z).nsecDenial(qname, kind) {
		nsec := storedRecord(z, data.Owner, protocol.TypeNSEC)
		if nsec == nil {
			continue
		}
		resp.Authorities = append(resp.Authorities, nsec)
		resp.Authorities = append(resp.Authorities, storedRRSIGs(z, data.Owner, protocol.TypeNSEC)...)
	}
}

// presignedDenialChain is the zone's NSEC chain as built from its names,
// used only to pick which stored NSEC records prove a denial. It is cached
// like the online chains, under its own key.
func (h *integratedHandler) presignedDenialChain(z *zone.Zone) *denialChain {
	key := "presigned|" + z.Origin
	id, gen := z.CacheTag()
	h.denialChainsMu.Lock()
	for _, e := range h.denialChains[key] {
		if e.id == id && e.gen == gen {
			h.denialChainsMu.Unlock()
			return e.chain
		}
	}
	h.denialChainsMu.Unlock()
	c := buildDenialChain(z, nil, nil, nil, &h.nsec3Memo)
	h.denialChainsMu.Lock()
	if h.denialChains == nil || len(h.denialChains) > maxCachedDenialChains {
		h.denialChains = make(map[string][]denialChainEntry)
	}
	entries := h.denialChains[key]
	kept := entries[:0]
	for _, e := range entries {
		if e.id != id {
			kept = append(kept, e)
		}
	}
	if len(kept) >= maxDenialChainsPerKey {
		kept = kept[1:]
	}
	h.denialChains[key] = append(kept, denialChainEntry{id: id, gen: gen, chain: c})
	h.denialChainsMu.Unlock()
	return c
}
