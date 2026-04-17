// Package resolver implements an iterative recursive DNS resolver
// following RFC 1034 §5.3.3 (Resolver Algorithm).
package resolver

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// nextSecureID returns a cryptographically secure random DNS transaction ID.
func nextSecureID() uint16 {
	var b [2]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		// SECURITY: crypto/rand failure indicates a system-level issue.
		// We panic rather than fall back to math/rand, as predictable
		// transaction IDs enable DNS cache poisoning attacks.
		panic("crypto/rand unavailable for DNS transaction ID generation: " + err.Error())
	}
	return binary.BigEndian.Uint16(b[:])
}

// Cache is the interface the resolver uses for caching.
type Cache interface {
	Get(key string) *CacheEntry
	Set(key string, msg *protocol.Message, ttl uint32)
	SetNegative(key string, rcode uint8)
}

// CacheEntry represents a cached DNS response.
type CacheEntry struct {
	Message    *protocol.Message
	IsNegative bool
	RCode      uint8
}

// Transport sends a DNS message over UDP or TCP and returns the response.
type Transport interface {
	QueryContext(ctx context.Context, msg *protocol.Message, addr string) (*protocol.Message, error)
}

// Config holds resolver configuration.
type Config struct {
	MaxDepth          int           // Maximum delegation depth (default 30)
	MaxCNAMEDepth     int           // Maximum CNAME chain length (default 16)
	Timeout           time.Duration // Per-query timeout (default 5s)
	EDNS0BufSize      uint16        // EDNS0 UDP buffer size (default 4096)
	QnameMinimization bool          // RFC 7816 QNAME minimization (default false)
	Use0x20           bool          // DNS 0x20 encoding for spoofing resistance (default false)
	Hints             []RootHint    // Custom root hints (if nil, uses IANA defaults)
}

func DefaultConfig() Config {
	return Config{
		MaxDepth:      30,
		MaxCNAMEDepth: 16,
		Timeout:       5 * time.Second,
		EDNS0BufSize:  4096,
	}
}

// Resolver performs iterative DNS resolution starting from root servers.
type Resolver struct {
	config    Config
	cache     Cache
	transport Transport
	hints     []RootHint
}

// NewResolver creates a new iterative resolver.
func NewResolver(config Config, cache Cache, transport Transport) *Resolver {
	if config.MaxDepth == 0 {
		config.MaxDepth = 30
	}
	if config.MaxCNAMEDepth == 0 {
		config.MaxCNAMEDepth = 16
	}
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second
	}
	if config.EDNS0BufSize == 0 {
		config.EDNS0BufSize = 4096
	}
	hints := config.Hints
	if len(hints) == 0 {
		hints = RootHints()
	}
	return &Resolver{
		config:    config,
		cache:     cache,
		transport: transport,
		hints:     hints,
	}
}

// delegation holds NS names and their resolved addresses for a zone.
type delegation struct {
	nsNames []string            // NS hostnames
	addrs   map[string][]string // nsName -> IP addresses (glue or resolved)
}

// Resolve resolves a DNS query iteratively starting from root servers.
// Implements RFC 1034 §5.3.3 resolver algorithm.
func (r *Resolver) Resolve(ctx context.Context, name string, qtype uint16) (*protocol.Message, error) {
	return r.resolve(ctx, name, qtype, 0)
}

func (r *Resolver) resolve(ctx context.Context, name string, qtype uint16, cnameDepth int) (*protocol.Message, error) {
	if cnameDepth > r.config.MaxCNAMEDepth {
		return nil, fmt.Errorf("resolver: CNAME chain too deep (%d)", cnameDepth)
	}

	// Check cache first
	if r.cache != nil {
		key := cacheKey(name, qtype)
		if entry := r.cache.Get(key); entry != nil {
			if entry.IsNegative {
				resp := protocol.NewMessage(protocol.Header{
					Flags: protocol.Flags{QR: true, RA: true, RCODE: entry.RCode},
				})
				q, _ := protocol.NewQuestion(name, qtype, protocol.ClassIN)
				resp.AddQuestion(q)
				return resp, nil
			}
			if entry.Message != nil {
				return entry.Message, nil
			}
		}
	}

	// Start with root hints
	deleg := &delegation{
		addrs: make(map[string][]string),
	}
	for _, h := range r.hints {
		deleg.nsNames = append(deleg.nsNames, h.Name)
		var all []string
		for _, ip := range h.IPv4 {
			all = append(all, withPort(ip, "53"))
		}
		for _, ip := range h.IPv6 {
			all = append(all, withPort(ip, "53"))
		}
		deleg.addrs[h.Name] = all
	}

	// Track the known zone cut for QNAME minimization (RFC 7816).
	// Starts at "." (root) and narrows as we follow referrals.
	currentZoneCut := "."

	for depth := 0; depth < r.config.MaxDepth; depth++ {
		// Determine query name and type for this iteration.
		qName := name
		qTypeToSend := qtype
		if r.config.QnameMinimization {
			minName := minimizedName(name, currentZoneCut)
			if !isMinimizedTarget(minName, name) {
				// We haven't reached the target zone yet — query for
				// the minimized name with type NS to discover the next
				// delegation without revealing the full query name.
				qName = minName
				qTypeToSend = protocol.TypeNS
			}
		}

		resp, err := r.queryDelegation(ctx, qName, qTypeToSend, deleg)
		if err != nil {
			continue // try was exhausted, fail below
		}

		// If we sent a minimized NS query and got an answer (not a
		// referral), it means the server is authoritative for that
		// zone. Cache the NS records and re-query with the full name + original type.
		if r.config.QnameMinimization && qTypeToSend == protocol.TypeNS && qName != name {
			if isAnswer(resp) || isNXDomain(resp) {
				// Cache the response - it contains valid NS records for this zone
				r.cacheResponse(qName, protocol.TypeNS, resp, currentZoneCut)
				// Update the zone cut and re-query with full name
				currentZoneCut = qName
				// Don't continue - fall through to query with full name
			}
		}

		switch {
		case isAnswer(resp):
			// Got authoritative answer
			r.cacheResponse(name, qtype, resp, currentZoneCut)

			// Check for DNAME that needs synthesis (RFC 6672)
			// DNAME takes precedence over CNAME per RFC 6672 §2.1
			if qtype != protocol.TypeCNAME && qtype != protocol.TypeDNAME && len(resp.Answers) > 0 {
				if dname := findDNAME(resp.Answers, name); dname.found {
					// Synthesize a CNAME from the DNAME and chase it
					cnameName, _ := protocol.ParseName(dname.synthTarget)
					qnameParsed, _ := protocol.ParseName(name)
					synthCNAME := &protocol.ResourceRecord{
						Name:  qnameParsed,
						Type:  protocol.TypeCNAME,
						Class: protocol.ClassIN,
						TTL:   dname.dnameRR.TTL,
						Data:  &protocol.RDataCNAME{CName: cnameName},
					}

					// Resolve the synthesized CNAME target
					target, err := r.resolve(ctx, dname.synthTarget, qtype, cnameDepth+1)
					if err != nil {
						resp.Header.Flags.RA = true
						return resp, nil
					}

					// Build a new response: DNAME + synthesized CNAME + target answers
					result := &protocol.Message{
						Header: protocol.Header{
							ID:    resp.Header.ID,
							Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
						},
						Questions: resp.Questions,
					}
					result.Header.Flags.RA = true
					result.AddAnswer(dname.dnameRR)
					result.AddAnswer(synthCNAME)
					for _, rr := range target.Answers {
						result.AddAnswer(rr)
					}
					return result, nil
				}

				// Check for CNAME that needs chasing (RFC 1034 §4.3.2)
				if cname := findCNAME(resp.Answers, name); cname != "" {
					// Save the CNAME records before chasing
					cnameAnswers := resp.Answers

					target, err := r.resolve(ctx, cname, qtype, cnameDepth+1)
					if err != nil {
						resp.Header.Flags.RA = true
						return resp, nil // Return CNAME at least
					}

					// Merge: prepend CNAME records to the target's answer section
					merged := make([]*protocol.ResourceRecord, 0, len(cnameAnswers)+len(target.Answers))
					merged = append(merged, cnameAnswers...)
					merged = append(merged, target.Answers...)
					target.Answers = merged
					return target, nil
				}
			}

			// Ensure RA bit is set (we are a recursive resolver)
			resp.Header.Flags.RA = true
			return resp, nil

		case isNXDomain(resp):
			r.cacheNegative(name, qtype, resp.Header.Flags.RCODE)
			resp.Header.Flags.RA = true
			return resp, nil

		case isReferral(resp):
			// Follow delegation. extractDelegation bailiwick-filters NS records
			// against currentZoneCut and returns the narrowed zone cut.
			newDeleg, newZoneCut := r.extractDelegation(resp, currentZoneCut)
			if newDeleg == nil || len(newDeleg.nsNames) == 0 {
				// No usable (in-bailiwick) NS records in referral — SERVFAIL.
				return servfail(name, qtype), nil
			}

			// Advance the zone cut to the delegated zone.
			currentZoneCut = newZoneCut

			// Resolve NS names that don't have glue
			r.resolveNSAddresses(ctx, newDeleg)

			// If no NS addresses could be resolved, try next server in current delegation
			if !hasAnyAddress(newDeleg) {
				continue
			}

			deleg = newDeleg
			continue

		default:
			// SERVFAIL or unexpected — try next server
			continue
		}
	}

	return servfail(name, qtype), nil
}

// queryDelegation sends a non-recursive query to each nameserver in the
// delegation until one responds with a usable answer.
func (r *Resolver) queryDelegation(ctx context.Context, name string, qtype uint16, deleg *delegation) (*protocol.Message, error) {
	// Collect all available addresses
	var addrs []string
	for _, nsName := range deleg.nsNames {
		addrs = append(addrs, deleg.addrs[nsName]...)
	}

	// Shuffle for load distribution
	rand.Shuffle(len(addrs), func(i, j int) { addrs[i], addrs[j] = addrs[j], addrs[i] })

	var lastErr error
	for _, addr := range addrs {
		// Apply 0x20 encoding: randomize case of the query name per attempt
		queryName := name
		if r.config.Use0x20 {
			queryName = Encode0x20(name)
		}

		qctx, cancel := context.WithTimeout(ctx, r.config.Timeout)
		resp, err := r.sendQuery(qctx, queryName, qtype, addr)
		cancel()

		if err != nil {
			lastErr = err
			continue
		}

		if resp == nil {
			continue
		}

		// Verify 0x20 encoding: response must echo the exact query name
		if r.config.Use0x20 {
			if !verify0x20Response(queryName, resp) {
				lastErr = fmt.Errorf("resolver: 0x20 verification failed from %s", addr)
				continue
			}
		}

		return resp, nil
	}

	return nil, fmt.Errorf("resolver: all nameservers failed for %s %s: %w",
		name, protocol.TypeString(qtype), lastErr)
}

// sendQuery builds and sends a non-recursive query (RD=0) to addr.
func (r *Resolver) sendQuery(ctx context.Context, name string, qtype uint16, addr string) (*protocol.Message, error) {
	q, err := protocol.NewQuestion(name, qtype, protocol.ClassIN)
	if err != nil {
		return nil, err
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    nextSecureID(),
			Flags: protocol.Flags{RD: false}, // Non-recursive — iterative query
		},
		Questions: []*protocol.Question{q},
	}

	// Add EDNS0
	msg.SetEDNS0(r.config.EDNS0BufSize, false)

	resp, err := r.transport.QueryContext(ctx, msg, addr)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("resolver: nil response from %s", addr)
	}

	// Handle referral with TC bit — re-query over TCP (handled by transport)
	if resp.Header.Flags.TC {
		return resp, nil
	}

	return resp, nil
}

// inBailiwick reports whether name is equal to zone or a subdomain of zone.
// Comparison is case-insensitive and trailing-dot-insensitive. A zone of
// "" or "." is treated as the root and matches any name.
//
// Used to defend against Kaminsky-class cache poisoning (VULN-039): records
// received from an authoritative server must be within that server's zone cut
// before they are cached or used for further resolution.
func inBailiwick(name, zone string) bool {
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	if zone == "" {
		return true // root zone contains everything
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == zone {
		return true
	}
	return strings.HasSuffix(name, "."+zone)
}

// extractDelegation extracts NS records and glue A/AAAA from a referral response,
// filtered against the querier's current zone cut. Only records whose owner is
// in-bailiwick of zoneCut are accepted.
//
// Returns the delegation and the derived new zone cut (the owner of the first
// accepted NS record). If no NS records were accepted, newZoneCut == zoneCut.
func (r *Resolver) extractDelegation(resp *protocol.Message, zoneCut string) (*delegation, string) {
	deleg := &delegation{
		addrs: make(map[string][]string),
	}
	newZoneCut := zoneCut

	// Extract NS names from Authority section. Reject NS records whose owner
	// is outside the current zone cut — e.g., a .com server cannot delegate
	// .net, and must not be allowed to redirect resolution to an attacker.
	nsOwners := make(map[string]bool) // the delegated zones we accepted
	for _, rr := range resp.Authorities {
		if rr.Type != protocol.TypeNS {
			continue
		}
		owner := rr.Name.String()
		if !inBailiwick(owner, zoneCut) {
			continue
		}
		ns, ok := rr.Data.(*protocol.RDataNS)
		if !ok {
			continue
		}
		nsName := ns.NSDName.String()
		if !containsString(deleg.nsNames, nsName) {
			deleg.nsNames = append(deleg.nsNames, nsName)
		}
		nsOwners[strings.ToLower(strings.TrimSuffix(owner, "."))] = true
		if newZoneCut == zoneCut {
			newZoneCut = owner
		}
	}

	// Build the set of NS target names we'll accept glue for.
	nsTargets := make(map[string]bool, len(deleg.nsNames))
	for _, n := range deleg.nsNames {
		nsTargets[strings.ToLower(strings.TrimSuffix(n, "."))] = true
	}

	// Extract glue (A/AAAA in Additional). To be accepted, glue must be:
	//   1. In-bailiwick of the querier's current zone cut (server authority bound).
	//   2. For a name actually listed as an NS target above (no drive-by records).
	for _, rr := range resp.Additionals {
		owner := rr.Name.String()
		if !inBailiwick(owner, zoneCut) {
			continue
		}
		ownerKey := strings.ToLower(strings.TrimSuffix(owner, "."))
		if !nsTargets[ownerKey] {
			continue
		}

		switch rr.Type {
		case protocol.TypeA:
			if a, ok := rr.Data.(*protocol.RDataA); ok {
				ip := net.IP(a.Address[:]).String()
				deleg.addrs[owner] = append(deleg.addrs[owner], withPort(ip, "53"))
			}
		case protocol.TypeAAAA:
			if a, ok := rr.Data.(*protocol.RDataAAAA); ok {
				ip := net.IP(a.Address[:]).String()
				deleg.addrs[owner] = append(deleg.addrs[owner], withPort(ip, "53"))
			}
		}
	}

	return deleg, newZoneCut
}

// resolveNSAddresses resolves A/AAAA for NS names that lack glue.
func (r *Resolver) resolveNSAddresses(ctx context.Context, deleg *delegation) {
	type nsResult struct {
		name  string
		addrs []string
	}

	var wg sync.WaitGroup
	resultCh := make(chan nsResult, len(deleg.nsNames))

	for _, nsName := range deleg.nsNames {
		if len(deleg.addrs[nsName]) > 0 {
			continue // Has glue already
		}

		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			addrs := r.lookupNSAddresses(ctx, name)
			if len(addrs) > 0 {
				resultCh <- nsResult{name: name, addrs: addrs}
			}
		}(nsName)
	}

	// Wait with context cancellation support
	wg.Wait()
	close(resultCh)

	for result := range resultCh {
		deleg.addrs[result.name] = result.addrs
	}
}

// lookupNSAddresses resolves A and AAAA records for an NS name using
// the resolver itself (recursive call). Falls back to cache.
func (r *Resolver) lookupNSAddresses(ctx context.Context, nsName string) []string {
	var addrs []string

	// Try A record
	if aKey := cacheKey(nsName, protocol.TypeA); r.cache != nil {
		if entry := r.cache.Get(aKey); entry != nil && !entry.IsNegative && entry.Message != nil {
			for _, rr := range entry.Message.Answers {
				if rr.Type == protocol.TypeA {
					if a, ok := rr.Data.(*protocol.RDataA); ok {
						addrs = append(addrs, withPort(net.IP(a.Address[:]).String(), "53"))
					}
				}
			}
		}
	}

	// Try AAAA record
	if aaaaKey := cacheKey(nsName, protocol.TypeAAAA); r.cache != nil {
		if entry := r.cache.Get(aaaaKey); entry != nil && !entry.IsNegative && entry.Message != nil {
			for _, rr := range entry.Message.Answers {
				if rr.Type == protocol.TypeAAAA {
					if a, ok := rr.Data.(*protocol.RDataAAAA); ok {
						addrs = append(addrs, withPort(net.IP(a.Address[:]).String(), "53"))
					}
				}
			}
		}
	}

	return addrs
}

// cacheResponse stores a successful response in the cache. The primary entry
// is keyed by (name, qtype) — this is the caller's own query, always safe to
// cache. Side-record entries (individual A/AAAA records from the Answer section
// keyed by their own owner) are only cached when the record is in-bailiwick of
// zoneCut, to prevent Kaminsky-class cache poisoning (VULN-039): without this
// filter, an authoritative server for foo.example could return an Answer for
// www.victim-bank.com and have it accepted as authoritative for victim-bank.
func (r *Resolver) cacheResponse(name string, qtype uint16, msg *protocol.Message, zoneCut string) {
	if r.cache == nil {
		return
	}

	// Use minimum TTL from answer section
	ttl := uint32(0)
	for _, rr := range msg.Answers {
		if ttl == 0 || rr.TTL < ttl {
			ttl = rr.TTL
		}
	}
	if ttl == 0 {
		ttl = 300 // Default 5 minutes
	}

	key := cacheKey(name, qtype)
	r.cache.Set(key, msg, ttl)

	// Cache individual A/AAAA records by their owner name for later NS-address
	// lookups — but only for records in-bailiwick of the serving zone. A record
	// whose owner falls outside zoneCut was not within the answering server's
	// authority and must not be trusted for any other name.
	for _, rr := range msg.Answers {
		switch rr.Type {
		case protocol.TypeA, protocol.TypeAAAA:
		default:
			continue
		}
		owner := rr.Name.String()
		if !inBailiwick(owner, zoneCut) {
			continue
		}
		switch rr.Type {
		case protocol.TypeA:
			if _, ok := rr.Data.(*protocol.RDataA); ok {
				r.cache.Set(cacheKey(owner, protocol.TypeA), msg, rr.TTL)
			}
		case protocol.TypeAAAA:
			if _, ok := rr.Data.(*protocol.RDataAAAA); ok {
				r.cache.Set(cacheKey(owner, protocol.TypeAAAA), msg, rr.TTL)
			}
		}
	}
}

// cacheNegative stores a negative (NXDOMAIN/NODATA) cache entry.
func (r *Resolver) cacheNegative(name string, qtype uint16, rcode uint8) {
	if r.cache == nil {
		return
	}
	key := cacheKey(name, qtype)
	r.cache.SetNegative(key, rcode)
}

// --- Response classification helpers ---

// isAnswer returns true if the response contains answers (AA=1 or direct answer).
func isAnswer(msg *protocol.Message) bool {
	return msg.Header.Flags.RCODE == protocol.RcodeSuccess && len(msg.Answers) > 0
}

// isNXDomain returns true for NXDOMAIN responses.
func isNXDomain(msg *protocol.Message) bool {
	return msg.Header.Flags.RCODE == protocol.RcodeNameError
}

// isReferral returns true if the response is a referral (NS in Authority, AA=0, no answers).
func isReferral(msg *protocol.Message) bool {
	if len(msg.Answers) > 0 {
		return false
	}
	// A referral typically has NS in Authority section and no AA bit
	for _, rr := range msg.Authorities {
		if rr.Type == protocol.TypeNS {
			return true
		}
		// SOA in Authority means negative response, not referral
		if rr.Type == protocol.TypeSOA {
			return false
		}
	}
	return false
}

// findCNAME returns the CNAME target if the answer section contains a CNAME
// for the given name.
func findCNAME(answers []*protocol.ResourceRecord, name string) string {
	for _, rr := range answers {
		if rr.Type == protocol.TypeCNAME {
			if cname, ok := rr.Data.(*protocol.RDataCNAME); ok {
				return cname.CName.String()
			}
		}
	}
	return ""
}

// dnameResult holds the result of finding a DNAME that applies to a query name.
type dnameResult struct {
	// dnameRR is the DNAME resource record found.
	dnameRR *protocol.ResourceRecord
	// synthTarget is the synthesized CNAME target name.
	synthTarget string
	// found is true if a DNAME was found.
	found bool
}

// findDNAME searches the answer section for a DNAME record whose owner is a
// suffix of the given name and returns the synthesized CNAME target per RFC 6672.
// For example, if name="foo.example.com." and a DNAME "example.com. DNAME bar.example.net."
// exists, the synthesized target is "foo.bar.example.net.".
func findDNAME(answers []*protocol.ResourceRecord, name string) dnameResult {
	// Normalize name for suffix comparison
	nameLower := strings.ToLower(name)

	for _, rr := range answers {
		if rr.Type != protocol.TypeDNAME {
			continue
		}
		dnameData, ok := rr.Data.(*protocol.RDataDNAME)
		if !ok {
			continue
		}

		// The DNAME owner must be a suffix of the query name
		dnameOwner := strings.ToLower(rr.Name.String())
		if !strings.HasSuffix(nameLower, dnameOwner) || nameLower == dnameOwner {
			continue
		}

		// Synthesize CNAME target: replace the DNAME owner suffix with the target
		dnameTarget := strings.ToLower(dnameData.DName.String())
		synthTarget := strings.TrimSuffix(nameLower, dnameOwner) + dnameTarget
		return dnameResult{
			dnameRR:     rr,
			synthTarget: synthTarget,
			found:       true,
		}
	}
	return dnameResult{}
}

// hasAnyAddress returns true if any NS name in the delegation has at least one address.
func hasAnyAddress(deleg *delegation) bool {
	for _, nsName := range deleg.nsNames {
		if len(deleg.addrs[nsName]) > 0 {
			return true
		}
	}
	return false
}

// servfail returns a SERVFAIL response for the given query.
func servfail(name string, qtype uint16) *protocol.Message {
	q, _ := protocol.NewQuestion(name, qtype, protocol.ClassIN)
	msg := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.Flags{QR: true, RA: true, RCODE: protocol.RcodeServerFailure},
		},
		Questions: []*protocol.Question{q},
	}
	return msg
}

// cacheKey produces a cache key for name+qtype.
// Uses strings.Builder instead of fmt.Sprintf for efficiency.
func cacheKey(name string, qtype uint16) string {
	var b strings.Builder
	b.Grow(len(name) + 1 + 10)
	b.WriteString(name)
	b.WriteByte(':')
	b.WriteString(strconv.FormatUint(uint64(qtype), 10))
	return b.String()
}

// containsString checks if s is in the slice.
func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// withPort ensures addr has the given port appended (host:port format).
func withPort(addr, port string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, port)
}

// StdioTransport sends DNS queries over UDP with TCP fallback.
// This is the default transport for the resolver.
type StdioTransport struct {
	dialer *net.Dialer
}

// NewStdioTransport creates a transport that queries DNS servers directly.
func NewStdioTransport(timeout time.Duration) *StdioTransport {
	return &StdioTransport{
		dialer: &net.Dialer{Timeout: timeout},
	}
}

// QueryContext sends a DNS message to addr (host:port) and returns the response.
// Tries UDP first, falls back to TCP on truncation or error.
func (t *StdioTransport) QueryContext(ctx context.Context, msg *protocol.Message, addr string) (*protocol.Message, error) {
	// Ensure port is present
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = addr + ":53"
	}

	// Try UDP first
	resp, err := t.queryUDP(ctx, msg, addr)
	if err != nil {
		// Fall back to TCP
		return t.queryTCP(ctx, msg, addr)
	}

	// If truncated, re-query over TCP
	if resp.Header.Flags.TC {
		return t.queryTCP(ctx, msg, addr)
	}

	return resp, nil
}

func (t *StdioTransport) queryUDP(ctx context.Context, msg *protocol.Message, addr string) (*protocol.Message, error) {
	buf := make([]byte, 512)
	n, err := msg.Pack(buf)
	if err != nil {
		return nil, fmt.Errorf("resolver: pack UDP: %w", err)
	}

	conn, err := net.DialTimeout("udp", addr, t.dialer.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(t.dialer.Timeout)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}

	if _, err := conn.Write(buf[:n]); err != nil {
		return nil, fmt.Errorf("resolver: UDP write: %w", err)
	}

	recvBuf := make([]byte, 4096)
	rn, err := conn.Read(recvBuf)
	if err != nil {
		return nil, fmt.Errorf("resolver: UDP read: %w", err)
	}

	resp, err := protocol.UnpackMessage(recvBuf[:rn])
	if err != nil {
		return nil, fmt.Errorf("resolver: UDP unpack: %w", err)
	}

	// Match response ID
	if resp.Header.ID != msg.Header.ID {
		return nil, fmt.Errorf("resolver: UDP ID mismatch")
	}

	return resp, nil
}

func (t *StdioTransport) queryTCP(ctx context.Context, msg *protocol.Message, addr string) (*protocol.Message, error) {
	buf := make([]byte, 65535)
	n, err := msg.Pack(buf)
	if err != nil {
		return nil, fmt.Errorf("resolver: pack TCP: %w", err)
	}

	conn, err := net.DialTimeout("tcp", addr, t.dialer.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(t.dialer.Timeout)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}

	// 2-byte length prefix
	lenBuf := make([]byte, 2)
	protocol.PutUint16(lenBuf, uint16(n))
	if _, err := conn.Write(append(lenBuf, buf[:n]...)); err != nil {
		return nil, fmt.Errorf("resolver: TCP write: %w", err)
	}

	// Read length prefix
	if _, err := readFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("resolver: TCP read length: %w", err)
	}
	respLen := int(protocol.Uint16(lenBuf))

	recvBuf := make([]byte, respLen)
	if _, err := readFull(conn, recvBuf); err != nil {
		return nil, fmt.Errorf("resolver: TCP read body: %w", err)
	}

	resp, err := protocol.UnpackMessage(recvBuf)
	if err != nil {
		return nil, fmt.Errorf("resolver: TCP unpack: %w", err)
	}

	if resp.Header.ID != msg.Header.ID {
		return nil, fmt.Errorf("resolver: TCP ID mismatch")
	}

	return resp, nil
}

// readFull reads exactly len(buf) bytes. Uses io.ReadFull equivalent.
func readFull(conn net.Conn, buf []byte) (int, error) {
	got := 0
	for got < len(buf) {
		n, err := conn.Read(buf[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

// LogTransport wraps a Transport and logs queries.
type LogTransport struct {
	inner  Transport
	logger *log.Logger
}

// NewLogTransport creates a logging transport wrapper.
func NewLogTransport(inner Transport, logger *log.Logger) *LogTransport {
	return &LogTransport{inner: inner, logger: logger}
}

// QueryContext logs and forwards to the inner transport.
func (t *LogTransport) QueryContext(ctx context.Context, msg *protocol.Message, addr string) (*protocol.Message, error) {
	if t.logger != nil && len(msg.Questions) > 0 {
		q := msg.Questions[0]
		t.logger.Printf("resolver: query %s %s @%s", q.Name, protocol.TypeString(q.QType), addr)
	}
	resp, err := t.inner.QueryContext(ctx, msg, addr)
	if t.logger != nil {
		if err != nil {
			t.logger.Printf("resolver: error from %s: %v", addr, err)
		} else if resp != nil {
			t.logger.Printf("resolver: response rcode=%s ans=%d auth=%d add=%d",
				protocol.RcodeString(int(resp.Header.Flags.RCODE)),
				len(resp.Answers), len(resp.Authorities), len(resp.Additionals))
		}
	}
	return resp, err
}
