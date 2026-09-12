// Package zone implements DNS zone file parsing and management.
// This file implements RFC 8976 - Message Digests for DNS Zones (ZONEMD).
package zone

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"sort"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// ZONEMD represents a Message Digest for DNS Zones per RFC 8976.
// ZONEMD provides cryptographic verification of zone contents during zone transfer.
type ZONEMD struct {
	ZoneName  string
	Hash      []byte
	Algorithm uint8 // 1=SHA-256, 2=SHA-384
	TTL       uint32
}

// ZONEMDAlgorithm represents the hash algorithm used for zone digests.
type ZONEMDAlgorithm uint8

const (
	// ZONEMDSHA256 is the SHA-256 algorithm for zone digests.
	ZONEMDSHA256 ZONEMDAlgorithm = 1
	// ZONEMDSHA384 is the SHA-384 algorithm for zone digests.
	ZONEMDSHA384 ZONEMDAlgorithm = 2
)

// ZoneMDError represents errors during ZONEMD computation.
type ZoneMDError struct {
	Zone string
	Msg  string
}

func (e *ZoneMDError) Error() string {
	return fmt.Sprintf("zonemd %s: %s", e.Zone, e.Msg)
}

// ComputeZoneMD computes the ZONEMD for a zone per RFC 8976 Section 4.
// The digest is computed over all RRsets in canonical order.
func ComputeZoneMD(z *Zone, algo ZONEMDAlgorithm) (*ZONEMD, error) {
	if z == nil {
		return nil, &ZoneMDError{Zone: "", Msg: "nil zone"}
	}
	if z.Origin == "" {
		return nil, &ZoneMDError{Zone: z.Origin, Msg: "empty origin"}
	}

	// Collect all RRsets for the zone
	rrsets, err := collectZoneRRsets(z)
	if err != nil {
		return nil, &ZoneMDError{Zone: z.Origin, Msg: err.Error()}
	}

	// Sort RRsets in canonical order per RFC 8976 Section 4.2
	sortRRsets(rrsets)

	// Compute hash over sorted RRsets
	var hash []byte
	switch algo {
	case ZONEMDSHA384:
		h := sha512.New384()
		for _, rrset := range rrsets {
			h.Write(rrset)
		}
		hash = h.Sum(nil)
	case ZONEMDSHA256, ZONEMDAlgorithm(0):
		h := sha256.New()
		for _, rrset := range rrsets {
			h.Write(rrset)
		}
		hash = h.Sum(nil)
	default:
		return nil, &ZoneMDError{Zone: z.Origin, Msg: fmt.Sprintf("unknown algorithm: %d", algo)}
	}

	return &ZONEMD{
		ZoneName:  z.Origin,
		Hash:      hash,
		Algorithm: uint8(algo),
		TTL:       0, // ZONEMD TTL is typically 0
	}, nil
}

// collectZoneRRsets collects all RRsets from a zone per RFC 8976 §3.1.1.
// Every RR in the zone is included in the digest EXCEPT:
//
//	the ZONEMD RR(s) themselves; and
//	any RRSIG RR whose Type Covered field is ZONEMD.
//
// SOA, apex NS/DNSKEY/etc. are included like any other RRset. Each RR is
// emitted in its full canonical wire form (owner|type|class|ttl|rdlen|rdata)
// per §3.3.2; concatenating only the RDATA, as an earlier version of this
// file did, produces a digest that does not match any RFC-compliant peer.
func collectZoneRRsets(z *Zone) ([][]byte, error) {
	var rrsets [][]byte

	const typeSOA uint16 = 6
	const typeRRSIG uint16 = 46
	const typeZONEMD uint16 = 63

	// Emit the apex SOA as a canonical RRset of its own. This replaces the
	// previous "bare RDATA" path.
	if z.SOA != nil {
		soaRdata := serializeSOA(z.SOA)
		soaTTL := z.SOA.TTL
		if soaTTL == 0 {
			soaTTL = z.DefaultTTL
		}
		rrset, err := buildCanonicalRRset(z.Origin, typeSOA, soaTTL, [][]byte{soaRdata})
		if err != nil {
			return nil, err
		}
		rrsets = append(rrsets, rrset)
	}

	// Collect every other RR in the zone, grouped into RRsets by (name,type).
	for name, records := range z.Records {
		// Group records by type (RRset). All RRs in an RRset share a TTL
		// (RFC 1035 §3.2.1); we use the TTL of the first encountered RR.
		rrsetMap := make(map[uint16][][]byte)
		rrsetTTL := make(map[uint16]uint32)

		for _, rec := range records {
			rtype, err := parseRecordType(rec.Type)
			if err != nil {
				continue
			}

			// Skip the apex SOA here (emitted above from z.SOA).
			if rtype == typeSOA && (name == z.Origin || name == z.Origin+".") {
				continue
			}

			// RFC 8976 §3.1.1: exclude the ZONEMD RR itself.
			if rtype == typeZONEMD {
				continue
			}

			// And exclude RRSIGs that cover the ZONEMD RR. RRSIG RDATA
			// begins with a uint16 "Type Covered" field; we parse just
			// that to decide whether to skip.
			if rtype == typeRRSIG {
				rdata := serializeRecordData(rec)
				if rdata == nil {
					return nil, fmt.Errorf("RRSIG record %s has malformed RDATA and cannot be serialized", rec.Name)
				}
				if len(rdata) >= 2 {
					covered := uint16(rdata[0])<<8 | uint16(rdata[1])
					if covered == typeZONEMD {
						continue
					}
				}
			}

			rdata := serializeRecordData(rec)
			if rdata == nil {
				return nil, fmt.Errorf("record %s type %s has malformed RDATA and cannot be serialized", rec.Name, rec.Type)
			}
			rrsetMap[rtype] = append(rrsetMap[rtype], rdata)
			if _, ok := rrsetTTL[rtype]; !ok {
				rrsetTTL[rtype] = rec.TTL
			}
		}

		// Emit each RRset in canonical RR-by-RR form.
		for rtype, rdataList := range rrsetMap {
			rrset, err := buildCanonicalRRset(name, rtype, rrsetTTL[rtype], rdataList)
			if err != nil {
				return nil, err
			}
			rrsets = append(rrsets, rrset)
		}
	}

	return rrsets, nil
}

// sortRRsets sorts RRsets in canonical order per RFC 8976 Section 4.2.
// Order is: name (canonical DNS wire format), then type, then rdatas.
func sortRRsets(rrsets [][]byte) {
	sort.Slice(rrsets, func(i, j int) bool {
		return string(rrsets[i]) < string(rrsets[j])
	})
}

// buildCanonicalRRset emits an RRset in RFC 8976 §3.3.2 canonical wire form:
// each constituent RR is written as
//
//	owner name (canonical wire) | type (uint16 BE) |
//	class (uint16 BE = IN) | ttl (uint32 BE) |
//	rdlength (uint16 BE) | rdata
//
// and the RRs are concatenated in canonical-order. All zones served by this
// implementation use class IN; if multi-class zones become supported, this
// helper will need a class parameter as well.
func buildCanonicalRRset(name string, rtype uint16, ttl uint32, rdataList [][]byte) ([]byte, error) {
	const classIN uint16 = 1

	nameWire := canonicalName(name)

	// Canonical RR ordering within the set: sort by RDATA bytewise per
	// RFC 4034 §6.3 (used here for ZONEMD canonicalisation per RFC 8976).
	sorted := make([][]byte, len(rdataList))
	copy(sorted, rdataList)
	sort.Slice(sorted, func(i, j int) bool { return string(sorted[i]) < string(sorted[j]) })

	var result []byte
	for _, rdata := range sorted {
		if len(rdata) > 0xffff {
			return nil, fmt.Errorf("record %s type %d rdata too large: %d bytes (max 65535)", name, rtype, len(rdata))
		}
		result = append(result, nameWire...)
		result = append(result, byte(rtype>>8), byte(rtype&0xff))
		result = append(result, byte(classIN>>8), byte(classIN&0xff))
		result = append(result, byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl&0xff))
		rdlen := uint16(len(rdata))
		result = append(result, byte(rdlen>>8), byte(rdlen&0xff))
		result = append(result, rdata...)
	}
	return result, nil
}

// canonicalName returns the canonical (owner-first, length-prefixed, lowercased)
// wire format of a domain name per RFC 1035 §3.1 / RFC 8976, by delegating to
// the shared protocol.CanonicalWireName encoder.
//
// The previous local implementation emitted labels in REVERSE order
// (TLD-first, e.g. "com.example.www" instead of the wire-correct
// "3www7example3com0"). The whole digest was computed over that non-canonical
// form, so ComputeZoneMD/Verify were internally self-consistent but the digest
// could never match one produced by BIND/Knot or carried in a transferred
// ZONEMD RR — defeating the point of ZONEMD (cross-implementation integrity).
func canonicalName(name string) []byte {
	return protocol.CanonicalWireName(name)
}

// serializeSOA serializes SOA record data in canonical format.
func serializeSOA(soa *SOARecord) []byte {
	var result []byte

	// MName (primary nameserver)
	result = append(result, canonicalName(soa.MName)...)

	// RName (responsible person)
	result = append(result, canonicalName(soa.RName)...)

	// Serial (4 bytes)
	result = append(result, byte(soa.Serial>>24), byte(soa.Serial>>16), byte(soa.Serial>>8), byte(soa.Serial))

	// Refresh (4 bytes)
	result = append(result, byte(soa.Refresh>>24), byte(soa.Refresh>>16), byte(soa.Refresh>>8), byte(soa.Refresh))

	// Retry (4 bytes)
	result = append(result, byte(soa.Retry>>24), byte(soa.Retry>>16), byte(soa.Retry>>8), byte(soa.Retry))

	// Expire (4 bytes)
	result = append(result, byte(soa.Expire>>24), byte(soa.Expire>>16), byte(soa.Expire>>8), byte(soa.Expire))

	// Minimum (4 bytes)
	result = append(result, byte(soa.Minimum>>24), byte(soa.Minimum>>16), byte(soa.Minimum>>8), byte(soa.Minimum))

	return result
}

// serializeRecordData serializes a record's RDATA into canonical wire form by
// routing every type through the shared presentation→wire parser
// (protocol.ParseRDataText) and its Pack encoder. The previous switch only
// handled a handful of types and emitted the raw presentation string for
// everything else (SRV/CAA/DS/DNSKEY/RRSIG/NSEC/…), so the ZONEMD digest never
// matched an RFC-8976 peer — and, worse, the "exclude RRSIG covering ZONEMD"
// check read the first two bytes of that presentation text (e.g. 'Z','O') as
// the Type Covered field instead of the real wire value 63. With proper wire
// RDATA, an RRSIG's first two bytes are its Type Covered, so that check now
// works. Unparseable/unknown RDATA falls back to the presentation bytes.
func serializeRecordData(rec Record) []byte {
	if protocol.RecordTypeFromText(rec.Type) == 0 {
		// Genuinely unknown type — best effort, use the raw presentation bytes.
		return []byte(rec.RData)
	}
	rd := protocol.ParseRDataText(rec.Type, rec.RData)
	if rd == nil {
		// Known type but malformed RDATA — cannot produce canonical wire.
		// Emit nothing rather than injecting presentation garbage that no peer
		// could reproduce. (A validated zone never reaches this path.)
		return nil
	}
	buf := make([]byte, rd.Len())
	if _, err := rd.Pack(buf, 0); err != nil {
		return nil
	}
	return buf
}

// parseRecordType converts a record type string to uint16.
// It delegates to protocol.RecordTypeFromText (mnemonics, the DKIM→TXT
// alias, and RFC 3597 TYPE### names) and maps the unknown-type sentinel
// (0) to an error.
func parseRecordType(typeStr string) (uint16, error) {
	if rtype := protocol.RecordTypeFromText(typeStr); rtype != 0 {
		return rtype, nil
	}
	return 0, fmt.Errorf("unknown record type: %s", typeStr)
}

// String returns a string representation of the ZONEMD.
func (z *ZONEMD) String() string {
	if z == nil {
		return ""
	}
	hashStr := ""
	for _, b := range z.Hash {
		hashStr += fmt.Sprintf("%02x", b)
	}
	return fmt.Sprintf("ZONEMD %s %d %s", z.ZoneName, z.Algorithm, hashStr)
}

// Verify checks if the computed ZONEMD matches an expected value.
func (z *ZONEMD) Verify(expected *ZONEMD) bool {
	if z == nil || expected == nil {
		return false
	}
	if z.ZoneName != expected.ZoneName {
		return false
	}
	if z.Algorithm != expected.Algorithm {
		return false
	}
	if len(z.Hash) != len(expected.Hash) {
		return false
	}
	for i := range z.Hash {
		if z.Hash[i] != expected.Hash[i] {
			return false
		}
	}
	return true
}
