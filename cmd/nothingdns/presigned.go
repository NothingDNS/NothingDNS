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
	"encoding/hex"
	"strconv"
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
	for _, rr := range h.storedDenialRecords(z, qname, kind) {
		resp.Authorities = append(resp.Authorities, rr)
		resp.Authorities = append(resp.Authorities, storedRRSIGs(z, rr.Name.String(), rr.Type)...)
	}
}

// storedDenialRecords returns the stored NSEC records, or the stored NSEC3
// at each proving member's hash (F757), that prove the denial of qname in a
// presigned zone, without their RRSIGs.
func (h *integratedHandler) storedDenialRecords(z *zone.Zone, qname string, kind denialKind) []*protocol.ResourceRecord {
	var out []*protocol.ResourceRecord
	c := h.presignedDenialChain(z)
	if c.nsec3 != nil {
		for _, member := range c.nsec3Denial(qname, kind) {
			owner := strings.ToLower(nsec3Base32.EncodeToString(c.hashes[member])) + "." + c.origin
			if nsec3 := storedRecord(z, owner, protocol.TypeNSEC3); nsec3 != nil {
				out = append(out, nsec3)
			}
		}
		return out
	}
	for _, data := range c.nsecDenial(qname, kind) {
		if nsec := storedRecord(z, data.Owner, protocol.TypeNSEC); nsec != nil {
			out = append(out, nsec)
		}
	}
	return out
}

// presignedDenialChain is the zone's NSEC chain as built from its names,
// used only to pick which stored NSEC records prove a denial. It is cached
// like the online chains, under its own key.
func (h *integratedHandler) presignedDenialChain(z *zone.Zone) *denialChain {
	params := storedNSEC3Params(z)
	key := "presigned|" + z.Origin
	if params != nil {
		// Membership comes from the stored chain below, not from Opt-Out:
		// the flag may be set on some NSEC3 records only (dnssec.SignZone
		// flags just an unsigned delegation's), so it said nothing reliable
		// about which names the chain holds (F865).
		params.optOut = false
		key += "|nsec3|" + strconv.Itoa(int(params.iterations)) + "/" + hex.EncodeToString(params.salt)
	}
	id, gen := z.CacheTag()
	h.denialChainsMu.Lock()
	for _, e := range h.denialChains[key] {
		if e.id == id && e.gen == gen {
			h.denialChainsMu.Unlock()
			return e.chain
		}
	}
	h.denialChainsMu.Unlock()
	c := buildDenialChain(z, nil, nil, params, &h.nsec3Memo)
	if c.nsec3 != nil {
		// The chain is the zone's stored one: a name whose hash owns no
		// stored NSEC3 (an opted-out delegation) is not a member (F865).
		for name, hash := range c.hashes {
			if storedRecord(z, strings.ToLower(nsec3Base32.EncodeToString(hash))+"."+c.origin, protocol.TypeNSEC3) == nil {
				delete(c.hashes, name)
			}
		}
	}
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

// onlyNSEC3Types reports whether types are those of a hashed NSEC3 owner.
func onlyNSEC3Types(types []uint16) bool {
	for _, t := range types {
		if t != protocol.TypeNSEC3 && t != protocol.TypeRRSIG {
			return false
		}
	}
	return len(types) > 0
}

// storedNSEC3Params reads the chain parameters of a zone signed with NSEC3:
// algorithm/iterations/salt from its NSEC3PARAM — or, for a zone signed before
// SignZone published one (F758), from a stored NSEC3 — and Opt-Out from the
// flags of a stored NSEC3. It returns nil for a zone without NSEC3 records.
func storedNSEC3Params(z *zone.Zone) *nsec3Params {
	var param, any []string // algorithm flags iterations salt ...
	if recs := z.Lookup(z.Origin, "NSEC3PARAM"); len(recs) > 0 {
		param = strings.Fields(recs[0].RData)
	}
	z.RLock()
search:
	for _, recs := range z.Records {
		for _, r := range recs {
			if r.Type == "NSEC3" {
				any = strings.Fields(r.RData)
				break search
			}
		}
	}
	z.RUnlock()
	f := param
	if f == nil {
		f = any
	}
	if len(f) < 4 {
		return nil
	}
	iter, err := strconv.ParseUint(f[2], 10, 16)
	if err != nil {
		return nil
	}
	p := &nsec3Params{iterations: uint16(iter)}
	if f[3] != "-" {
		if p.salt, err = hex.DecodeString(f[3]); err != nil {
			return nil
		}
	}
	p.optOut = len(any) > 1 && any[1] != "0"
	return p
}
