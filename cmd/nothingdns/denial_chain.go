// NothingDNS - authoritative denial chain for online signing
//
// The NSEC/NSEC3 records a signed zone serves must describe the zone's
// authoritative data only. Names below a zone cut (glue, and anything else
// occluded by a delegation) are not part of the zone and MUST NOT own NSEC
// records or appear in the chain; at the cut itself only NS and DS belong to
// the parent (RFC 4035 §2.3, RFC 5155 §7.1). The zone package's NSEC helpers
// walk every owner in the zone, so the server named glue as existing data and
// a replayed parent NSEC owned by a glue name proved NODATA for records that
// exist in the signed child (F489).
//
// The same chain also carries the apex types the server serves without a
// zone-file record (DNSKEY from the signing keys, NSEC3PARAM), so the apex
// bitmap does not deny an RRset the server answers (F490), and implements
// NSEC3 (RFC 5155) when dnssec.signing.nsec3 is configured — the online path
// previously served NSEC regardless of that setting (F488).

package main

import (
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// nsec3Params are the zone's NSEC3 parameters (RFC 5155 §3, hash algorithm 1).
type nsec3Params struct {
	iterations uint16
	salt       []byte
	optOut     bool
}

// denialChain is a per-query snapshot of a zone's authoritative nodes.
type denialChain struct {
	origin string
	// nodes maps every authoritative node (owner names that are neither
	// below a zone cut nor outside the zone, plus the empty non-terminals
	// above them) to the RR types present there. At a cut only NS/DS remain.
	nodes map[string][]uint16
	// cuts maps each delegation point to whether it has a DS RRset.
	cuts map[string]bool
	// dnames holds the DNAME owners; names below them are occluded (F514).
	dnames map[string]bool
	// apexExtra are types served at the apex without zone-file records.
	apexExtra []uint16

	nsec3  *nsec3Params
	hashes map[string][]byte // NSEC3 only: chain member -> hash
	memo   *nsec3HashMemo

	// Neighbour lookups binary-search these (F706); built once on first use.
	orderOnce   sync.Once
	sortedNodes []string          // nodes in canonical order
	sortedHash  []string          // NSEC3 chain hashes, ascending
	hashMember  map[string]string // string(hash) -> chain member
}

// order builds the sorted views used by nsecData, nsecCovering, nsec3Record
// and nsec3Covering. The chain is read-only after buildDenialChain, so it can
// be shared between queries.
func (c *denialChain) order() {
	c.orderOnce.Do(func() {
		c.sortedNodes = make([]string, 0, len(c.nodes))
		for n := range c.nodes {
			c.sortedNodes = append(c.sortedNodes, n)
		}
		sort.Slice(c.sortedNodes, func(i, j int) bool {
			return canonicalNameCompare(c.sortedNodes[i], c.sortedNodes[j]) < 0
		})
		c.sortedHash = make([]string, 0, len(c.hashes))
		c.hashMember = make(map[string]string, len(c.hashes))
		for member, h := range c.hashes {
			k := string(h)
			if _, dup := c.hashMember[k]; !dup {
				c.sortedHash = append(c.sortedHash, k)
			}
			c.hashMember[k] = member
		}
		sort.Strings(c.sortedHash)
	})
}

// buildDenialChain snapshots z's authoritative nodes. params selects NSEC3
// (nil = NSEC).
// extraNodes adds owners (with their types) that exist outside the zone's
// records, such as GeoDNS names (F742).
func buildDenialChain(z *zone.Zone, apexExtra []uint16, extraNodes map[string][]uint16, params *nsec3Params, memo *nsec3HashMemo) *denialChain {
	origin := canonicalize(z.Origin)
	c := &denialChain{
		origin:    origin,
		nodes:     make(map[string][]uint16),
		cuts:      make(map[string]bool),
		dnames:    make(map[string]bool),
		apexExtra: apexExtra,
		nsec3:     params,
		memo:      memo,
	}

	owners := make(map[string][]uint16)
	z.RLock()
	for name, recs := range z.Records {
		owner := canonicalize(name)
		if !isSubdomain(owner, origin) {
			continue
		}
		for _, rec := range recs {
			if t := stringToType(rec.Type); t != 0 {
				owners[owner] = append(owners[owner], t)
			}
		}
	}
	z.RUnlock()
	for owner, types := range extraNodes {
		if isSubdomain(owner, origin) {
			owners[owner] = append(owners[owner], types...)
		}
	}

	for owner, types := range owners {
		hasNS, hasDS := false, false
		for _, t := range types {
			hasNS = hasNS || t == protocol.TypeNS
			hasDS = hasDS || t == protocol.TypeDS
			if t == protocol.TypeDNAME {
				c.dnames[owner] = true
			}
		}
		if hasNS && owner != origin {
			c.cuts[owner] = hasDS
		}
	}

	for owner, types := range owners {
		if c.occluded(owner) {
			continue // glue / occluded data: not part of this zone
		}
		if hasDS, isCut := c.cuts[owner]; isCut {
			types = []uint16{protocol.TypeNS}
			if hasDS {
				types = append(types, protocol.TypeDS)
			}
		}
		c.nodes[owner] = dedupTypes(types)
	}
	// Empty non-terminals above authoritative names.
	for owner := range owners {
		if _, ok := c.nodes[owner]; !ok {
			continue
		}
		for anc := parentName(owner); anc != "" && anc != origin && isSubdomain(anc, origin); anc = parentName(anc) {
			if _, ok := c.nodes[anc]; ok {
				break
			}
			c.nodes[anc] = nil
		}
	}
	if _, ok := c.nodes[origin]; !ok {
		c.nodes[origin] = nil
	}

	if params != nil {
		c.hashes = make(map[string][]byte, len(c.nodes))
		for name := range c.nodes {
			if !c.inNSEC3Chain(name) {
				continue
			}
			if h, ok := c.hash(name); ok {
				c.hashes[name] = h
			}
		}
	}
	return c
}

// occluded reports whether name lies strictly below a delegation point or
// below a DNAME owner (the apex included): neither is authoritative data of
// this zone (RFC 4035 §2.3; RFC 6672 §2.4, F514).
func (c *denialChain) occluded(name string) bool {
	for anc := parentName(name); anc != "" && isSubdomain(anc, c.origin); anc = parentName(anc) {
		if _, isCut := c.cuts[anc]; isCut || c.dnames[anc] {
			return true
		}
		if anc == c.origin {
			break
		}
	}
	return false
}

// inNSEC3Chain: with opt-out, insecure delegations get no NSEC3 (RFC 5155 §6).
func (c *denialChain) inNSEC3Chain(name string) bool {
	if hasDS, isCut := c.cuts[name]; isCut && !hasDS && c.nsec3 != nil && c.nsec3.optOut {
		return false
	}
	_, ok := c.nodes[name]
	return ok
}

func (c *denialChain) hash(name string) ([]byte, bool) {
	return c.memo.get(name, c.nsec3)
}

// closestEncloser returns the longest ancestor of name (or name) accepted by
// member, or the origin.
func (c *denialChain) closestEncloser(name string, member func(string) bool) string {
	for cur := canonicalize(name); cur != "" && isSubdomain(cur, c.origin); cur = parentName(cur) {
		if member(cur) {
			return cur
		}
		if cur == c.origin {
			break
		}
	}
	return c.origin
}

func (c *denialChain) isNode(name string) bool { _, ok := c.nodes[name]; return ok }

// ── NSEC ──

func (c *denialChain) nsecTypes(name string) []string {
	types := append([]uint16(nil), c.nodes[name]...)
	if name == c.origin {
		types = append(types, c.apexExtra...)
	}
	types = append(types, protocol.TypeNSEC, protocol.TypeRRSIG)
	types = dedupTypes(types)
	out := make([]string, 0, len(types))
	for _, t := range types {
		out = append(out, typeToString(t))
	}
	return out
}

func (c *denialChain) nsecData(owner string) zone.NSECRecordData {
	c.order()
	next := c.origin
	if i := sort.Search(len(c.sortedNodes), func(i int) bool {
		return canonicalNameCompare(c.sortedNodes[i], owner) > 0
	}); i < len(c.sortedNodes) {
		next = c.sortedNodes[i]
	}
	return zone.NSECRecordData{Owner: owner, Next: next, Types: c.nsecTypes(owner)}
}

// nsecFor returns the NSEC owned by name, if name is a node.
func (c *denialChain) nsecFor(name string) (zone.NSECRecordData, bool) {
	name = canonicalize(name)
	if !c.isNode(name) {
		return zone.NSECRecordData{}, false
	}
	return c.nsecData(name), true
}

// nsecCovering returns the NSEC whose span covers name (RFC 4034 §4.1.1).
func (c *denialChain) nsecCovering(name string) zone.NSECRecordData {
	name = canonicalize(name)
	c.order()
	prev := c.origin
	if n := len(c.sortedNodes); n > 0 {
		prev = c.sortedNodes[n-1] // before every node: the last one wraps
		if i := sort.Search(n, func(i int) bool {
			return canonicalNameCompare(c.sortedNodes[i], name) >= 0
		}); i > 0 {
			prev = c.sortedNodes[i-1]
		}
	}
	return c.nsecData(prev)
}

func (c *denialChain) nsecDenial(qname string, kind denialKind) []zone.NSECRecordData {
	qname = canonicalize(qname)
	if kind == denialNoData {
		if data, ok := c.nsecFor(qname); ok {
			return []zone.NSECRecordData{data}
		}
		// RFC 4035 §3.1.3.4 wildcard NODATA: an NSEC proving QNAME does
		// not exist (F513: it was missing — the wildcard's NSEC covers the
		// QNAME only when no other name sorts between them) plus the
		// wildcard's own NSEC as the type proof.
		ce := c.closestEncloser(qname, c.isNode)
		data, ok := c.nsecFor("*." + ce)
		if !ok {
			return nil
		}
		cover := c.nsecCovering(nextCloser(qname, ce))
		if cover.Owner == data.Owner {
			return []zone.NSECRecordData{data}
		}
		return []zone.NSECRecordData{cover, data}
	}
	var out []zone.NSECRecordData
	seen := make(map[string]struct{}, 2)
	for _, data := range []zone.NSECRecordData{
		c.nsecCovering(qname),
		c.nsecCovering("*." + c.closestEncloser(qname, c.isNode)),
	} {
		if _, dup := seen[data.Owner]; !dup {
			seen[data.Owner] = struct{}{}
			out = append(out, data)
		}
	}
	return out
}

// ── NSEC3 ──

var nsec3Base32 = base32.HexEncoding.WithPadding(base32.NoPadding)

func (c *denialChain) nsec3Types(name string) []uint16 {
	types := append([]uint16(nil), c.nodes[name]...)
	if name == c.origin {
		types = append(types, c.apexExtra...)
	}
	hasDS, isCut := c.cuts[name]
	if len(types) > 0 && (!isCut || hasDS) {
		types = append(types, protocol.TypeRRSIG) // the node owns signed RRsets
	}
	return dedupTypes(types)
}

func (c *denialChain) nsec3Record(owner string, ttl uint32) *protocol.ResourceRecord {
	c.order()
	h := c.hashes[owner]
	var next []byte
	if n := len(c.sortedHash); n > 0 {
		k := c.sortedHash[0] // last in the chain: wrap to the smallest hash
		if i := sort.Search(n, func(i int) bool { return c.sortedHash[i] > string(h) }); i < n {
			k = c.sortedHash[i]
		}
		next = []byte(k)
	}
	name, err := protocol.ParseName(strings.ToLower(nsec3Base32.EncodeToString(h)) + "." + c.origin)
	if err != nil {
		return nil
	}
	var flags uint8
	if c.nsec3.optOut {
		flags = 1
	}
	return &protocol.ResourceRecord{
		Name: name, Type: protocol.TypeNSEC3, Class: protocol.ClassIN, TTL: ttl,
		Data: &protocol.RDataNSEC3{
			HashAlgorithm: 1,
			Flags:         flags,
			Iterations:    c.nsec3.iterations,
			Salt:          append([]byte(nil), c.nsec3.salt...),
			HashLength:    uint8(len(next)),
			NextHashed:    append([]byte(nil), next...),
			TypeBitMap:    c.nsec3Types(owner),
		},
	}
}

// nsec3Matching returns the chain member whose hash equals name's.
func (c *denialChain) nsec3Matching(name string) (string, bool) {
	name = canonicalize(name)
	if _, ok := c.hashes[name]; ok {
		return name, true
	}
	return "", false
}

// nsec3Covering returns the chain member whose NSEC3 span covers name's hash.
func (c *denialChain) nsec3Covering(name string) (string, bool) {
	h, ok := c.hash(canonicalize(name))
	if !ok || len(c.hashes) == 0 {
		return "", false
	}
	c.order()
	n := len(c.sortedHash)
	k := c.sortedHash[n-1] // before every hash: the last one wraps
	if i := sort.Search(n, func(i int) bool { return c.sortedHash[i] >= string(h) }); i > 0 {
		k = c.sortedHash[i-1]
	}
	return c.hashMember[k], true
}

// nextCloser is the ancestor of name one label longer than encloser.
func nextCloser(name, encloser string) string {
	name = canonicalize(name)
	for cur := name; cur != "" && cur != encloser; cur = parentName(cur) {
		if parentName(cur) == encloser {
			return cur
		}
	}
	return name
}

// nsec3Denial returns the owners (chain members) whose NSEC3 records prove
// the denial (RFC 5155 §7.2).
func (c *denialChain) nsec3Denial(qname string, kind denialKind) []string {
	qname = canonicalize(qname)
	inChain := func(n string) bool { _, ok := c.hashes[n]; return ok }
	var owners []string
	add := func(member string, ok bool) {
		if !ok {
			return
		}
		for _, o := range owners {
			if o == member {
				return
			}
		}
		owners = append(owners, member)
	}
	if kind == denialNoData {
		if m, ok := c.nsec3Matching(qname); ok {
			add(m, true) // §7.2.3 / §7.2.4: matching NSEC3
			return owners
		}
	}
	// Closest (provable) encloser proof (§7.2.1): NXDOMAIN (§7.2.2), wildcard
	// NODATA (§7.2.5), and DS NODATA at an opt-out delegation (§7.2.4).
	ce := c.closestEncloser(qname, inChain)
	add(c.nsec3Matching(ce))
	add(c.nsec3Covering(nextCloser(qname, ce)))
	switch {
	case kind == denialNXDomain:
		add(c.nsec3Covering("*." + ce))
	case !c.isNode(qname):
		add(c.nsec3Matching("*." + ce)) // wildcard NODATA
	}
	return owners
}

// ── shared ──

// denialChainFor snapshots z with the server's apex extras and the
// configured denial mode.
func (h *integratedHandler) denialChainFor(z *zone.Zone) *denialChain {
	var apexExtra []uint16
	h.zoneSignersMu.RLock()
	signer := h.zoneSigners[z.Origin]
	h.zoneSignersMu.RUnlock()
	if signer != nil && len(signer.GetKeys()) > 0 {
		apexExtra = append(apexExtra, protocol.TypeDNSKEY) // step 1b serves it
	}
	params := h.nsec3ParamsFor()
	if params != nil {
		apexExtra = append(apexExtra, protocol.TypeNSEC3PARAM)
	}
	// F706: the chain depends only on the zone's content and these settings,
	// so one snapshot serves every query until the zone changes. The tag is
	// read before the build: a zone edited meanwhile stores the older tag and
	// is rebuilt by the next query.
	key := z.Origin + "|" + fmt.Sprint(apexExtra)
	// F742: GeoDNS names are nodes of the zone; a reload replaces the
	// engine and a rule change bumps its version.
	geo := h.security.GeoEngine
	if geo != nil {
		key += fmt.Sprintf("|geo%p/%d", geo, geo.Version())
	}
	if params != nil {
		key += "|" + strconv.Itoa(int(params.iterations)) + "/" + hex.EncodeToString(params.salt) + "/" + strconv.FormatBool(params.optOut)
	}
	// F744: zones of the same origin in different split-horizon views
	// share the key, so each keeps its own entry under it (by zone id);
	// sharing one entry rebuilt the chain on every alternating query.
	id, gen := z.CacheTag()
	h.denialChainsMu.Lock()
	for _, e := range h.denialChains[key] {
		if e.id == id && e.gen == gen {
			h.denialChainsMu.Unlock()
			return e.chain
		}
	}
	h.denialChainsMu.Unlock()
	var geoNodes map[string][]uint16
	if geo != nil {
		for owner, types := range geo.Owners() {
			for _, t := range types {
				if qt := stringToType(t); qt != 0 {
					if geoNodes == nil {
						geoNodes = make(map[string][]uint16)
					}
					geoNodes[canonicalize(owner)] = append(geoNodes[canonicalize(owner)], qt)
				}
			}
		}
	}
	c := buildDenialChain(z, apexExtra, geoNodes, params, &h.nsec3Memo)
	h.denialChainsMu.Lock()
	if h.denialChains == nil || len(h.denialChains) > maxCachedDenialChains {
		h.denialChains = make(map[string][]denialChainEntry)
	}
	entries := h.denialChains[key]
	kept := entries[:0]
	for _, e := range entries {
		if e.id != id { // a zone's older generation is replaced
			kept = append(kept, e)
		}
	}
	if len(kept) >= maxDenialChainsPerKey {
		kept = kept[1:] // drop the oldest: a zone a reload replaced
	}
	h.denialChains[key] = append(kept, denialChainEntry{id: id, gen: gen, chain: c})
	h.denialChainsMu.Unlock()
	return c
}

// maxCachedDenialChains bounds the per-handler chain cache (one key per
// origin and denial configuration); stale entries are replaced on use.
const maxCachedDenialChains = 1024

// maxDenialChainsPerKey bounds the zones (views, or zones a reload replaced)
// that keep a chain under one key.
const maxDenialChainsPerKey = 8

type denialChainEntry struct {
	id, gen uint64
	chain   *denialChain
}

// nsec3ParamsFor returns the configured NSEC3 parameters, or nil for NSEC.
func (h *integratedHandler) nsec3ParamsFor() *nsec3Params {
	if h.config == nil || h.config.DNSSEC.Signing.NSEC3 == nil {
		return nil
	}
	cfg := h.config.DNSSEC.Signing.NSEC3
	p := &nsec3Params{iterations: cfg.Iterations, optOut: cfg.OptOut}
	if cfg.Salt != "" && cfg.Salt != "-" {
		salt, err := hex.DecodeString(cfg.Salt)
		if err != nil {
			return p // loadZoneSigner rejects a bad salt at startup
		}
		p.salt = salt
	}
	return p
}

// denialRRs returns the denial records proving qname's absence (kind) from z.
func (h *integratedHandler) denialRRs(z *zone.Zone, qname string, kind denialKind) []*protocol.ResourceRecord {
	c := h.denialChainFor(z)
	ttl := z.GetDefaultTTL()
	var out []*protocol.ResourceRecord
	if c.nsec3 != nil {
		if len(c.hashes) == 0 && h.logger != nil {
			// dnssec.NSEC3Hash refuses > 150 iterations (RFC 9276).
			h.logger.Warnf("No NSEC3 chain for %s (iterations %d): negative answers go out unproven", z.Origin, c.nsec3.iterations)
		}
		for _, owner := range c.nsec3Denial(qname, kind) {
			if rr := c.nsec3Record(owner, ttl); rr != nil {
				out = append(out, rr)
			}
		}
		return out
	}
	for _, data := range c.nsecDenial(qname, kind) {
		if rr := nsecRecord(data, ttl); rr != nil {
			out = append(out, rr)
		}
	}
	return out
}

// wildcardAnswerRRs returns the record proving that no closer match than the
// wildcard at "*."+ce exists for qname, which a wildcard-expanded positive
// answer must carry (RFC 4035 §3.1.3.3; RFC 5155 §7.2.6: the NSEC3 covering
// the next closer name). F512.
func (h *integratedHandler) wildcardAnswerRRs(z *zone.Zone, qname, ce string) []*protocol.ResourceRecord {
	c := h.denialChainFor(z)
	nc := nextCloser(qname, canonicalize(ce))
	ttl := z.GetDefaultTTL()
	if c.nsec3 != nil {
		// RFC 5155 §8.8 lets a validator derive the closest encloser from
		// the RRSIG Labels field; its matching NSEC3 is included as well
		// because internal/dnssec (and other validators) look for it.
		var out []*protocol.ResourceRecord
		ceMember, ceOK := c.nsec3Matching(ce)
		ncMember, ncOK := c.nsec3Covering(nc)
		if !ncOK {
			return nil
		}
		if ceOK && ceMember != ncMember {
			if rr := c.nsec3Record(ceMember, ttl); rr != nil {
				out = append(out, rr)
			}
		}
		if rr := c.nsec3Record(ncMember, ttl); rr != nil {
			out = append(out, rr)
		}
		return out
	}
	if rr := nsecRecord(c.nsecCovering(nc), ttl); rr != nil {
		return []*protocol.ResourceRecord{rr}
	}
	return nil
}

// insecureDelegationProof returns the records proving the delegation at cut
// has no DS (RFC 4035 §3.1.4 / RFC 5155 §7.2.7).
func (h *integratedHandler) insecureDelegationProof(z *zone.Zone, cut string) []*protocol.ResourceRecord {
	return h.denialRRs(z, cut, denialNoData)
}

// nsec3ParamRR returns the apex NSEC3PARAM record when NSEC3 is configured.
func (h *integratedHandler) nsec3ParamRR(z *zone.Zone) *protocol.ResourceRecord {
	p := h.nsec3ParamsFor()
	if p == nil {
		return nil
	}
	name, err := protocol.ParseName(canonicalize(z.Origin))
	if err != nil {
		return nil
	}
	return &protocol.ResourceRecord{
		Name: name, Type: protocol.TypeNSEC3PARAM, Class: protocol.ClassIN, TTL: z.GetDefaultTTL(),
		// Flags 0: the Opt-Out flag is only meaningful on NSEC3 (RFC 5155 §4.1.2).
		Data: &protocol.RDataNSEC3PARAM{HashAlgorithm: 1, Iterations: p.iterations, Salt: append([]byte(nil), p.salt...)},
	}
}

// nsec3HashMemo caches NSEC3 owner hashes; a hash depends only on the name
// and the parameters, so entries never go stale.
type nsec3HashMemo struct {
	mu  sync.Mutex
	key string
	m   map[string][]byte
}

const nsec3HashMemoMax = 1 << 18

func (m *nsec3HashMemo) get(name string, p *nsec3Params) ([]byte, bool) {
	key := strconv.Itoa(int(p.iterations)) + "/" + hex.EncodeToString(p.salt)
	m.mu.Lock()
	if m.key != key || m.m == nil || len(m.m) >= nsec3HashMemoMax {
		m.key, m.m = key, make(map[string][]byte)
	}
	h, ok := m.m[name]
	m.mu.Unlock()
	if ok {
		return h, true
	}
	h, err := dnssec.NSEC3Hash(name, 1, p.iterations, p.salt)
	if err != nil {
		return nil, false
	}
	m.mu.Lock()
	if m.key == key {
		m.m[name] = h
	}
	m.mu.Unlock()
	return h, true
}

// parentName returns name minus its first label ("" above the root).
func parentName(name string) string {
	if name == "." || name == "" {
		return ""
	}
	i := strings.IndexByte(name, '.')
	if i < 0 || i+1 >= len(name) {
		return "."
	}
	return name[i+1:]
}

// canonicalNameCompare orders lowercase FQDNs canonically (RFC 4034 §6.1):
// labels compared right to left as bytes; a suffix sorts first.
func canonicalNameCompare(a, b string) int {
	a = strings.TrimSuffix(a, ".")
	b = strings.TrimSuffix(b, ".")
	for {
		if a == "" || b == "" {
			switch {
			case a == "" && b == "":
				return 0
			case a == "":
				return -1
			default:
				return 1
			}
		}
		ia, ib := strings.LastIndexByte(a, '.'), strings.LastIndexByte(b, '.')
		if c := strings.Compare(a[ia+1:], b[ib+1:]); c != 0 {
			return c
		}
		if ia < 0 {
			a = ""
		} else {
			a = a[:ia]
		}
		if ib < 0 {
			b = ""
		} else {
			b = b[:ib]
		}
	}
}

func dedupTypes(types []uint16) []uint16 {
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	out := types[:0]
	for i, t := range types {
		if i == 0 || t != types[i-1] {
			out = append(out, t)
		}
	}
	return out
}
