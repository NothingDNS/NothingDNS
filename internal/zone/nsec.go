package zone

import (
	"sort"
	"strings"
)

// Authenticated denial of existence (RFC 4035 §3.1.3).
//
// A signed zone must prove that a name or type does not exist, not merely say
// so: a validator rejects a bare NXDOMAIN/NODATA from a signed zone outright.
// Positive answers were signed but negative ones went out with an unsigned SOA
// and nothing else, so every negative answer from a signed zone failed
// validation — `delv` reported "got insecure response; parent indicates it
// should be secure".
//
// The proof is computed per query from the live zone rather than from a cached
// ordering. A stale NSEC chain is worse than a slow one: it would deny a name
// that exists, and an RFC 8198 resolver caches that denial and stops asking.
// Finding the neighbours of a name is a single pass with no sorting and no
// allocation, so the cost is one comparison per zone node.

// NSECRecordData describes one NSEC record: the node it belongs to, the next
// node in canonical order, and the RR types present at the owner.
type NSECRecordData struct {
	Owner string
	Next  string
	Types []string
}

// NSECForName returns the NSEC record owned by name. The name must exist in
// the zone as a node; callers use this for NODATA, where the type bitmap is
// what proves the queried type is absent.
func (z *Zone) NSECForName(name string) (NSECRecordData, bool) {
	z.ensureENTIndex()
	z.mu.RLock()
	defer z.mu.RUnlock()

	name = strings.ToLower(canonicalize(name))
	if !z.nodeExistsLocked(name) {
		return NSECRecordData{}, false
	}
	next, ok := z.nextNodeLocked(name)
	if !ok {
		return NSECRecordData{}, false
	}
	return NSECRecordData{Owner: name, Next: next, Types: z.typesAtLocked(name)}, true
}

// NSECCovering returns the NSEC record that proves name does not exist: the
// one owned by the closest node before it in canonical order, whose Next field
// sorts after it. Callers use this for NXDOMAIN.
func (z *Zone) NSECCovering(name string) (NSECRecordData, bool) {
	z.ensureENTIndex()
	z.mu.RLock()
	defer z.mu.RUnlock()

	name = strings.ToLower(canonicalize(name))
	owner, ok := z.previousNodeLocked(name)
	if !ok {
		return NSECRecordData{}, false
	}
	next, ok := z.nextNodeLocked(owner)
	if !ok {
		return NSECRecordData{}, false
	}
	return NSECRecordData{Owner: owner, Next: next, Types: z.typesAtLocked(owner)}, true
}

// forEachNodeLocked visits every node of the zone: every name that owns
// records, plus every empty non-terminal. Must hold the read lock, and
// ensureENTIndex must have run.
func (z *Zone) forEachNodeLocked(fn func(name string)) {
	for name := range z.Records {
		fn(name)
	}
	for name := range z.entNames {
		fn(name)
	}
}

// previousNodeLocked returns the greatest zone node that sorts strictly before
// name. The apex is the answer when nothing else does, since the chain wraps
// there.
func (z *Zone) previousNodeLocked(name string) (string, bool) {
	origin := strings.ToLower(canonicalize(z.Origin))
	best := origin
	found := false
	z.forEachNodeLocked(func(node string) {
		if !canonicalNameLess(node, name) {
			return
		}
		if !found || canonicalNameLess(best, node) {
			best = node
			found = true
		}
	})
	if !found {
		// Everything sorts at or after name, so the chain's last node wraps to
		// it. That last node is the greatest in the zone.
		last := origin
		z.forEachNodeLocked(func(node string) {
			if canonicalNameLess(last, node) {
				last = node
			}
		})
		return last, true
	}
	return best, true
}

// nextNodeLocked returns the smallest zone node that sorts strictly after
// name, wrapping to the apex at the end of the chain (RFC 4034 §4.1.1).
func (z *Zone) nextNodeLocked(name string) (string, bool) {
	origin := strings.ToLower(canonicalize(z.Origin))
	best := ""
	z.forEachNodeLocked(func(node string) {
		if !canonicalNameLess(name, node) {
			return
		}
		if best == "" || canonicalNameLess(node, best) {
			best = node
		}
	})
	if best == "" {
		// name is the last node; the chain wraps to the apex.
		return origin, true
	}
	return best, true
}

// typesAtLocked lists the RR types present at name, sorted for a stable
// bitmap.
//
// NSEC and RRSIG are always set, including for an empty non-terminal that owns
// nothing else: RFC 4035 §2.3 gives every name in a signed zone an NSEC, and
// that NSEC is itself a type present at the name. An ENT whose bitmap claimed
// no types at all — not even its own NSEC — sent validators looking for a
// delegation that is not there, and the answer came back as a broken trust
// chain rather than a proven NODATA.
func (z *Zone) typesAtLocked(name string) []string {
	recs := z.Records[name]
	seen := make(map[string]struct{}, len(recs)+2)
	for _, rec := range recs {
		seen[strings.ToUpper(rec.Type)] = struct{}{}
	}
	seen["NSEC"] = struct{}{}
	seen["RRSIG"] = struct{}{}

	types := make([]string, 0, len(seen))
	for t := range seen {
		types = append(types, t)
	}
	sort.Strings(types)
	return types
}

// canonicalNameLess reports whether a sorts before b in DNSSEC canonical name
// order (RFC 4034 §6.1): labels are compared right to left, each as unsigned
// bytes with ASCII letters lowercased, and a name that is a suffix of another
// sorts first.
func canonicalNameLess(a, b string) bool {
	return compareCanonicalName(a, b) < 0
}

func compareCanonicalName(a, b string) int {
	al := canonicalLabels(a)
	bl := canonicalLabels(b)

	// Walk from the rightmost label inward.
	i, j := len(al)-1, len(bl)-1
	for i >= 0 && j >= 0 {
		if c := strings.Compare(al[i], bl[j]); c != 0 {
			return c
		}
		i--
		j--
	}
	switch {
	case i < 0 && j < 0:
		return 0
	case i < 0:
		return -1 // a ran out of labels first, so it is the shorter suffix
	default:
		return 1
	}
}

// canonicalLabels splits a name into lowercase labels, dropping the empty
// label produced by the trailing dot.
func canonicalLabels(name string) []string {
	name = strings.ToLower(strings.TrimSuffix(canonicalize(name), "."))
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

// ClosestEncloser returns the longest ancestor of name (or name itself) that
// exists as a node in this zone. RFC 4035 §3.1.3.2 needs it for an NXDOMAIN
// proof: alongside the NSEC that denies the name, the responder must deny the
// wildcard at the closest encloser, or a validator cannot tell a real NXDOMAIN
// from one that suppressed a wildcard match.
func (z *Zone) ClosestEncloser(name string) (string, bool) {
	z.ensureENTIndex()
	z.mu.RLock()
	defer z.mu.RUnlock()

	origin := strings.ToLower(canonicalize(z.Origin))
	current := strings.ToLower(canonicalize(name))
	if !nameInZone(current, origin) {
		return "", false
	}
	for {
		if z.nodeExistsLocked(current) {
			return current, true
		}
		if current == origin {
			return origin, true
		}
		dot := strings.IndexByte(current, '.')
		if dot < 0 || dot+1 >= len(current) {
			return origin, true
		}
		current = current[dot+1:]
		if !nameInZone(current, origin) {
			return origin, true
		}
	}
}
