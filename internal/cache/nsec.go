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

		// Check if qname falls in the range (owner, nextDomain) in canonical order.
		// NSEC proves: no names exist between owner and nextDomain.
		if nameInNSECRange(qnameParsed, entry.Owner, entry.NextDomain) {
			return nc.synthesizeNXDOMAIN(qname, qtype, entry)
		}

		// Also check: if qname matches the NSEC owner but the type is not
		// in the type bitmap, this proves NODATA (name exists, type doesn't).
		if protocol.CompareNames(qnameParsed, entry.Owner) == 0 {
			if !typeInBitmap(qtype, entry.TypeBitMap) {
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
