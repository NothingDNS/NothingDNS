// Package cache — Aggressive NSEC Caching (RFC 8198)
//
// When a DNSSEC-validated NXDOMAIN response contains NSEC records, we
// cache those NSEC records. For subsequent queries, we check if any
// cached NSEC record proves that the queried name does not exist
// (the name falls between the NSEC owner and NextDomain in canonical
// DNS name order). If so, we synthesize an NXDOMAIN response locally
// without querying upstream.
//
// This reduces upstream traffic for queries in zones we've already
// proven are empty ranges, and speeds up NXDOMAIN responses.
package cache

import (
	"strings"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// NSECCache stores NSEC records for aggressive negative caching.
type NSECCache struct {
	mu      sync.RWMutex
	entries map[string]*nsecEntry // key: owner name (lowercase)
	maxSize int
}

type nsecEntry struct {
	Owner      *protocol.Name
	NextDomain *protocol.Name
	TypeBitMap []uint16
	ExpireTime time.Time
	SOA        *protocol.ResourceRecord // SOA from the NXDOMAIN response
}

func nsecEntryExpiredAt(entry *nsecEntry, now time.Time) bool {
	return entry == nil || !now.Before(entry.ExpireTime)
}

// nsecEntryZone returns the zone apex that the cached entry was proven for,
// taken from the SOA carried in the same NXDOMAIN response. It returns nil
// when the entry has no usable SOA, in which case the zone the record covers
// is unknown and the entry must not be used to deny any name.
func nsecEntryZone(entry *nsecEntry) *protocol.Name {
	if entry == nil || entry.SOA == nil || entry.SOA.Name == nil {
		return nil
	}
	if _, ok := entry.SOA.Data.(*protocol.RDataSOA); !ok {
		return nil
	}
	return entry.SOA.Name
}

// nameWithinZone reports whether name is zone itself or a subdomain of it.
// Comparison is case-insensitive, as DNS names are.
func nameWithinZone(name, zone *protocol.Name) bool {
	if name == nil || zone == nil {
		return false
	}
	if protocol.CompareNames(name, zone) == 0 {
		return true
	}
	return protocol.IsSubdomain(name, zone)
}

// NewNSECCache creates a new aggressive NSEC cache.
func NewNSECCache(maxSize int) *NSECCache {
	if maxSize <= 0 {
		maxSize = 10000
	}
	return &NSECCache{
		entries: make(map[string]*nsecEntry, maxSize),
		maxSize: maxSize,
	}
}

// AddFromResponse extracts NSEC records from a DNSSEC-validated NXDOMAIN response
// and caches them for future aggressive negative caching.
// The validated parameter must be true - NSEC records from unvalidated responses
// must not be cached as this could enable cache poisoning attacks.
// An NXDOMAIN response is considered validated if it has the AD bit set AND
// came from a response that passed DNSSEC validation (indicated by the validated param).
func (nc *NSECCache) AddFromResponse(resp *protocol.Message, validated bool) {
	// Reject unvalidated responses - caching NSEC records from unvalidated
	// responses could enable cache poisoning attacks
	if !validated {
		return
	}

	if resp == nil || resp.Header.Flags.RCODE != protocol.RcodeNameError {
		return
	}

	// Extract SOA from authority section
	var soa *protocol.ResourceRecord
	for _, rr := range resp.Authorities {
		if rr == nil || rr.Name == nil || rr.Type != protocol.TypeSOA {
			continue
		}
		soaData, ok := rr.Data.(*protocol.RDataSOA)
		if !ok || soaData == nil {
			continue
		}
		soa = rr.Copy()
		break
	}

	// Extract NSEC records from authority section
	for _, rr := range resp.Authorities {
		if rr == nil || rr.Name == nil || rr.Type != protocol.TypeNSEC {
			continue
		}
		nsec, ok := rr.Data.(*protocol.RDataNSEC)
		if !ok || nsec == nil || nsec.NextDomain == nil {
			continue
		}

		// Use the SOA minimum TTL or the NSEC TTL, whichever is smaller
		ttl := rr.TTL
		if soa != nil {
			if soaData, ok := soa.Data.(*protocol.RDataSOA); ok && soaData != nil {
				if soaData.Minimum < ttl {
					ttl = soaData.Minimum
				}
			}
		}

		entry := &nsecEntry{
			// Own copies: the caller releases the pooled response after this
			// stage (pipeline_stages.go:661), so shared Name/TypeBitMap
			// references would read freed wire bytes.
			Owner:      rr.Name.Copy(),
			NextDomain: nsec.NextDomain.Copy(),
			TypeBitMap: append([]uint16(nil), nsec.TypeBitMap...),
			ExpireTime: time.Now().Add(time.Duration(ttl) * time.Second),
			SOA:        soa,
		}

		nc.mu.Lock()
		key := strings.ToLower(rr.Name.String())
		nc.entries[key] = entry

		// Evict expired entries first, then live entries if needed so
		// validated NSEC floods cannot grow the cache past maxSize.
		if len(nc.entries) > nc.maxSize {
			nc.evictToMaxSize()
		}
		nc.mu.Unlock()
	}
}

// Lookup checks if the queried name is provably non-existent based on
// cached NSEC records. Returns a synthesized NXDOMAIN response if so.
func (nc *NSECCache) Lookup(qname string, qtype uint16) *protocol.Message {
	return nc.lookupAt(qname, qtype, time.Now())
}

func (nc *NSECCache) lookupAt(qname string, qtype uint16, now time.Time) *protocol.Message {
	nc.mu.RLock()
	defer nc.mu.RUnlock()

	qnameParsed, err := protocol.ParseName(qname)
	if err != nil {
		return nil
	}

	for _, entry := range nc.entries {
		if entry == nil || entry.Owner == nil || entry.NextDomain == nil {
			continue
		}
		if nsecEntryExpiredAt(entry, now) {
			continue
		}

		// An NSEC only proves non-existence for names inside its OWN zone
		// (RFC 4034 §4.1.1, RFC 8198 §5.3). This cache is global: entries
		// from every zone share one map, and nameInNSECRange is a pure
		// canonical-order comparison. Without this guard a zone's
		// wrap-around record (last owner -> apex) denies unrelated names
		// that sort below its apex, handing out a false AD=1 NXDOMAIN for
		// a zone the resolver has no evidence about. Require the query
		// name to be within the zone this response was for, and fail
		// closed when that zone is unknown.
		zone := nsecEntryZone(entry)
		if zone == nil || !nameWithinZone(qnameParsed, zone) {
			continue
		}

		// An NSEC owned by a zone cut or by a DNAME owner says nothing about
		// the names beneath it (RFC 6840 §4.1). An "ancestor delegation" NSEC
		// (NS set, SOA clear) is the PARENT's record of the cut: the child
		// zone's names and its apex data are not in it. An NSEC with the DNAME
		// bit set sits on a name whose subtree is synthesized, not stored.
		// Skip such an entry for any name it cannot speak for; it still serves
		// as the proof for names outside the subtree and, for a delegation,
		// for the DS type at the cut itself.
		if nsecEntryCannotSpeakFor(entry, qnameParsed, qtype) {
			continue
		}

		// Check if qname falls in the range (owner, nextDomain) in canonical order.
		// NSEC proves: no names exist between owner and nextDomain.
		if nameInNSECRange(qnameParsed, entry.Owner, entry.NextDomain) {
			// RFC 8198 §5.3 allows this synthesis only when the resolver can
			// establish "that a name would not exist without the wildcard
			// match" (RFC 4035 §5.3.4). A covering NSEC proves nothing about a
			// wildcard at the closest encloser, and the covering NSEC of a real
			// response can be owned by the wildcard itself — canonical order
			// puts "*.sub.example.com." before its parent, so its wrap-around
			// range spans the wildcard's own children. Requiring the wildcard
			// denial here keeps a wildcard-matched name resolvable.
			if !nc.wildcardDeniedFor(qnameParsed, zone, entry) {
				continue
			}
			return nc.synthesizeNXDOMAIN(qname, qtype, entry)
		}

		// Also check: if qname matches the NSEC owner but the type is not
		// in the type bitmap, this proves NODATA (name exists, type doesn't).
		//
		// The CNAME bit counts too (RFC 6840 §4.3): a name that owns a CNAME
		// has data for every type — the alias — so a bitmap with CNAME set
		// cannot prove NODATA for any other type. Treating it as NODATA would
		// hide the alias and hand out an AD=1 "no data" for a name that
		// resolves. Leave it to normal resolution.
		if protocol.CompareNames(qnameParsed, entry.Owner) == 0 {
			if !typeInBitmap(qtype, entry.TypeBitMap) && !typeInBitmap(protocol.TypeCNAME, entry.TypeBitMap) {
				return nc.synthesizeNODATA(qname, qtype, entry)
			}
		}
	}

	return nil
}

// Size returns the number of cached NSEC entries.
func (nc *NSECCache) Size() int {
	nc.mu.RLock()
	defer nc.mu.RUnlock()
	return len(nc.entries)
}

// nameInNSECRange checks if name falls strictly between owner and next
// in canonical DNS order. Handles the wrap-around case where next < owner
// (last NSEC record in the zone wraps to the zone apex).
func nameInNSECRange(name, owner, next *protocol.Name) bool {
	cmpOwner := protocol.CompareNames(name, owner)
	cmpNext := protocol.CompareNames(name, next)

	if protocol.CompareNames(owner, next) < 0 {
		// Normal case: owner < next
		// Name must be: owner < name < next
		return cmpOwner > 0 && cmpNext < 0
	}
	// Wrap-around case: next <= owner (last NSEC wraps to apex)
	// Name must be: name > owner OR name < next
	return cmpOwner > 0 || cmpNext < 0
}

// wildcardDeniedFor reports whether the cached NSEC set also proves that no
// wildcard at qname's closest encloser could have matched qname — the second
// half of an aggressive NXDOMAIN (RFC 8198 §5.3, RFC 4035 §5.3.4). Callers must
// hold nc.mu.
//
// The closest encloser is the deepest ancestor of qname that the covering NSEC
// does not itself cover: an ancestor inside the covering range does not exist,
// so it cannot be the encloser. The denial then needs an NSEC from the same zone
// whose range strictly covers "*.<encloser>". Failing closed — no proof cached —
// leaves the query to normal resolution instead of serving an AD=1 denial for a
// name that a wildcard may answer.
func (nc *NSECCache) wildcardDeniedFor(qname, zone *protocol.Name, covering *nsecEntry) bool {
	if qname == nil || zone == nil || covering == nil {
		return false
	}

	labels := strings.Split(strings.ToLower(strings.TrimSuffix(qname.String(), ".")), ".")
	for i := 1; i < len(labels); i++ {
		ancestor, err := protocol.ParseName(strings.Join(labels[i:], ".") + ".")
		if err != nil {
			return false
		}
		if !nameWithinZone(ancestor, zone) {
			return false
		}
		if nameInNSECRange(ancestor, covering.Owner, covering.NextDomain) {
			// Inside the covering range: this ancestor does not exist.
			continue
		}

		wildcard, err := protocol.ParseName("*." + ancestor.String())
		if err != nil {
			return false
		}
		for _, e := range nc.entries {
			if e == nil || e.Owner == nil || e.NextDomain == nil {
				continue
			}
			zoneOfEntry := nsecEntryZone(e)
			if zoneOfEntry == nil || protocol.CompareNames(zoneOfEntry, zone) != 0 {
				continue
			}
			// The same RFC 6840 §4.1 rule as in lookupAt: the wildcard name is
			// below its encloser, so an NSEC owned by a zone cut or a DNAME
			// at or above it cannot be the proof that no wildcard exists.
			if nsecEntryCannotSpeakFor(e, wildcard, protocol.TypeANY) {
				continue
			}
			if nameInNSECRange(wildcard, e.Owner, e.NextDomain) {
				return true
			}
		}
		return false
	}
	return false
}

// nsecEntryCannotSpeakFor reports whether entry must not be used to deny qname
// (type qtype) because of what its own type bitmap says about its owner
// (RFC 6840 §4.1):
//
//   - an ancestor delegation NSEC — NS bit set, SOA bit clear — proves nothing
//     about RRs below the cut, "which include all RRs at that owner name other
//     than DS RRs, and all RRs below that owner name regardless of type";
//   - an NSEC with the DNAME bit set proves nothing about any subdomain of its
//     owner.
//
// Names outside the owner's subtree are unaffected, and so is DS at a
// delegation owner: the parent's NSEC is exactly where its absence is proven.
func nsecEntryCannotSpeakFor(entry *nsecEntry, qname *protocol.Name, qtype uint16) bool {
	if entry == nil || entry.Owner == nil || qname == nil {
		return false
	}
	atOwner := protocol.CompareNames(qname, entry.Owner) == 0
	belowOwner := !atOwner && protocol.IsSubdomain(qname, entry.Owner)

	if typeInBitmap(protocol.TypeDNAME, entry.TypeBitMap) && belowOwner {
		return true
	}
	// RFC 6840 §4.1 defines an ancestor delegation by three conditions: NS set,
	// SOA clear, AND a signer shorter than the owner (the record is signed by
	// the parent zone, not by the zone it sits at). The signer is not kept, but
	// the SOA that came with the response names the zone the proof is for:
	// an NSEC owned by that very name is the zone's own apex record, signed by
	// the zone itself, and is never an ancestor delegation however its bitmap
	// looks. Only an owner strictly below the zone is a cut.
	if zone := nsecEntryZone(entry); zone != nil && protocol.CompareNames(entry.Owner, zone) == 0 {
		return false
	}
	if typeInBitmap(protocol.TypeNS, entry.TypeBitMap) && !typeInBitmap(protocol.TypeSOA, entry.TypeBitMap) {
		if belowOwner {
			return true
		}
		if atOwner && qtype != protocol.TypeDS {
			return true
		}
	}
	return false
}

// typeInBitmap checks if a DNS type is present in an NSEC type bitmap.
func typeInBitmap(qtype uint16, bitmap []uint16) bool {
	for _, t := range bitmap {
		if t == qtype {
			return true
		}
	}
	return false
}

func (nc *NSECCache) synthesizeNXDOMAIN(qname string, qtype uint16, entry *nsecEntry) *protocol.Message {
	name, _ := protocol.ParseName(qname)
	q, _ := protocol.NewQuestion(qname, qtype, protocol.ClassIN)

	resp := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.NewResponseFlags(protocol.RcodeNameError),
		},
		Questions: []*protocol.Question{q},
	}
	resp.Header.Flags.AD = true // This was validated

	// Add SOA to authority section
	ttl := remainingNSECTTL(entry)
	resp.Authorities = appendSOAWithTTL(resp.Authorities, entry, ttl)

	// Add the proving NSEC record
	nsecRR := &protocol.ResourceRecord{
		Name:  entry.Owner,
		Type:  protocol.TypeNSEC,
		Class: protocol.ClassIN,
		TTL:   ttl,
		Data: &protocol.RDataNSEC{
			NextDomain: entry.NextDomain,
			TypeBitMap: entry.TypeBitMap,
		},
	}
	resp.Authorities = append(resp.Authorities, nsecRR)
	_ = name // used by ParseName above

	return resp
}

func (nc *NSECCache) synthesizeNODATA(qname string, qtype uint16, entry *nsecEntry) *protocol.Message {
	q, _ := protocol.NewQuestion(qname, qtype, protocol.ClassIN)

	resp := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: []*protocol.Question{q},
	}
	resp.Header.Flags.AD = true

	// Add SOA to authority section
	ttl := remainingNSECTTL(entry)
	resp.Authorities = appendSOAWithTTL(resp.Authorities, entry, ttl)

	// Add the NSEC proving the type doesn't exist
	nsecRR := &protocol.ResourceRecord{
		Name:  entry.Owner,
		Type:  protocol.TypeNSEC,
		Class: protocol.ClassIN,
		TTL:   ttl,
		Data: &protocol.RDataNSEC{
			NextDomain: entry.NextDomain,
			TypeBitMap: entry.TypeBitMap,
		},
	}
	resp.Authorities = append(resp.Authorities, nsecRR)

	return resp
}

func remainingNSECTTL(entry *nsecEntry) uint32 {
	if entry == nil {
		return 0
	}
	return remainingSecondsUint32(time.Until(entry.ExpireTime))
}

func appendSOAWithTTL(authorities []*protocol.ResourceRecord, entry *nsecEntry, ttl uint32) []*protocol.ResourceRecord {
	if entry == nil || entry.SOA == nil {
		return authorities
	}
	soa := entry.SOA.Copy()
	if soa.TTL > ttl {
		soa.TTL = ttl
	}
	return append(authorities, soa)
}

func (nc *NSECCache) evictExpired() {
	nc.evictExpiredAt(time.Now())
}

func (nc *NSECCache) evictExpiredAt(now time.Time) {
	for key, entry := range nc.entries {
		if nsecEntryExpiredAt(entry, now) {
			delete(nc.entries, key)
		}
	}
}

func (nc *NSECCache) evictToMaxSize() {
	nc.evictExpired()

	for len(nc.entries) > nc.maxSize {
		var oldestKey string
		var oldestExpire time.Time
		for key, entry := range nc.entries {
			if oldestKey == "" || entry.ExpireTime.Before(oldestExpire) {
				oldestKey = key
				oldestExpire = entry.ExpireTime
			}
		}
		if oldestKey == "" {
			return
		}
		delete(nc.entries, oldestKey)
	}
}
