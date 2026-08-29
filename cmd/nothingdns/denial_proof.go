// NothingDNS - authenticated denial of existence for signed zones
//
// A signed zone must prove a negative, not merely assert it. RFC 4035 §3.1.3
// requires an NXDOMAIN or NODATA from a signed zone to carry NSEC records —
// and signatures over them and over the SOA — or a validator rejects the
// answer. The signing path was wired only into the positive-answer builder, so
// negative answers went out with a bare unsigned SOA and every one of them
// failed validation:
//
//	;; validating e2e.test/SOA: got insecure response;
//	   parent indicates it should be secure
//
// Half of DNSSEC was therefore non-functional on any zone this server signed.

package main

import (
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// denialKind distinguishes the two proofs RFC 4035 §3.1.3 defines.
type denialKind int

const (
	// denialNoData: the name exists but not the queried type. One NSEC at the
	// name itself proves it — its type bitmap is the proof (§3.1.3.1).
	denialNoData denialKind = iota
	// denialNXDomain: the name does not exist. Two NSECs are needed — one
	// covering the name, one denying the wildcard at its closest encloser —
	// or a validator cannot tell this from a suppressed wildcard match
	// (§3.1.3.2).
	denialNXDomain
)

// addDenialProof attaches the authenticated-denial records for a negative
// answer from a signed zone, and signs the authority section.
//
// A no-op for unsigned zones and for clients that did not set DO: an
// unsigned negative answer is correct for them, and DNSSEC records they never
// asked for are pure payload (RFC 4035 §3.2.2).
func (h *integratedHandler) addDenialProof(resp *protocol.Message, z *zone.Zone, qname string, kind denialKind, wantsDNSSEC bool) {
	if !wantsDNSSEC || resp == nil || z == nil {
		return
	}

	h.zoneSignersMu.RLock()
	signer, ok := h.zoneSigners[z.Origin]
	h.zoneSignersMu.RUnlock()
	if !ok || signer == nil {
		return
	}
	zsks := signer.GetActiveZSKs()
	if len(zsks) == 0 {
		return
	}
	zsk := zsks[0]

	inception := time.Now().UTC()
	expiration := inception.Add(30 * 24 * time.Hour)
	sign := func(rrs []*protocol.ResourceRecord) {
		if len(rrs) == 0 {
			return
		}
		rrsig, err := signer.SignRRSet(rrs, zsk,
			dnssecSignatureUnixTime(inception), dnssecSignatureUnixTime(expiration))
		if err != nil {
			// The answer still goes out; without the signature a validator
			// will call it Bogus, so make the reason visible.
			h.logger.Warnf("Failed to sign denial RRset for %s: %v", z.Origin, err)
			return
		}
		if rrsig != nil {
			resp.Authorities = append(resp.Authorities, rrsig)
		}
	}

	// The SOA proves the negative TTL and must itself be signed.
	sign(soaRRSet(resp))

	for _, data := range h.denialRecords(z, qname, kind) {
		rr := nsecRecord(data, z.GetDefaultTTL())
		if rr == nil {
			continue
		}
		resp.Authorities = append(resp.Authorities, rr)
		sign([]*protocol.ResourceRecord{rr})
	}
}

// denialRecords picks the NSEC records that prove the denial, de-duplicated:
// one NSEC frequently covers both the queried name and the wildcard, and
// repeating it would just inflate the response.
func (h *integratedHandler) denialRecords(z *zone.Zone, qname string, kind denialKind) []zone.NSECRecordData {
	if kind == denialNoData {
		if data, ok := z.NSECForName(qname); ok {
			return []zone.NSECRecordData{data}
		}
		return nil
	}

	var out []zone.NSECRecordData
	seen := make(map[string]struct{}, 2)
	add := func(data zone.NSECRecordData, ok bool) {
		if !ok {
			return
		}
		if _, dup := seen[data.Owner]; dup {
			return
		}
		seen[data.Owner] = struct{}{}
		out = append(out, data)
	}

	add(z.NSECCovering(qname))
	if encloser, ok := z.ClosestEncloser(qname); ok {
		add(z.NSECCovering("*." + encloser))
	}
	return out
}

// soaRRSet collects the SOA records already placed in the authority section.
func soaRRSet(resp *protocol.Message) []*protocol.ResourceRecord {
	var out []*protocol.ResourceRecord
	for _, rr := range resp.Authorities {
		if rr != nil && rr.Type == protocol.TypeSOA {
			out = append(out, rr)
		}
	}
	return out
}

// nsecRecord builds the wire record for one NSEC proof.
func nsecRecord(data zone.NSECRecordData, ttl uint32) *protocol.ResourceRecord {
	owner, err := protocol.ParseName(data.Owner)
	if err != nil {
		return nil
	}
	next, err := protocol.ParseName(data.Next)
	if err != nil {
		return nil
	}
	if ttl == 0 {
		ttl = 3600
	}

	types := make([]uint16, 0, len(data.Types))
	for _, t := range data.Types {
		if qtype := stringToType(t); qtype != 0 {
			types = append(types, qtype)
		}
	}

	return &protocol.ResourceRecord{
		Name:  owner,
		Type:  protocol.TypeNSEC,
		Class: protocol.ClassIN,
		TTL:   ttl,
		Data: &protocol.RDataNSEC{
			NextDomain: next,
			TypeBitMap: types,
		},
	}
}
