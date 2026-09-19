package rpz

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

// PolicyAction defines what action to take when a query matches an RPZ rule.
type PolicyAction int

const (
	// ActionNXDOMAIN returns NXDOMAIN for matching queries.
	ActionNXDOMAIN PolicyAction = iota
	// ActionNODATA returns NOERROR with empty answer section.
	ActionNODATA
	// ActionCNAME returns a CNAME pointing to the specified target.
	ActionCNAME
	// ActionOverride returns a custom A/AAAA record.
	ActionOverride
	// ActionDrop silently drops the query (no response).
	ActionDrop
	// ActionPassThrough allows the query (disables policy for this name).
	ActionPassThrough
	// ActionTCPOnly forces the client to retry over TCP (TC bit set).
	ActionTCPOnly
)

// TriggerType defines what triggers an RPZ rule.
type TriggerType int

const (
	// TriggerQNAME matches the query name directly.
	TriggerQNAME TriggerType = iota
	// TriggerResponseIP matches IP addresses in the response.
	TriggerResponseIP
	// TriggerClientIP matches the client's source IP.
	TriggerClientIP
	// TriggerNSDNAME matches nameserver names.
	TriggerNSDNAME
	// TriggerNSIP matches nameserver IP addresses.
	TriggerNSIP
)

// Rule represents a single RPZ policy rule.
type Rule struct {
	// Action to apply when this rule matches.
	Action PolicyAction
	// Trigger type.
	Trigger TriggerType
	// Pattern to match (domain name for QNAME/NSDNAME, CIDR for IP-based).
	Pattern string
	// OverrideData contains replacement data (CNAME target, override IP).
	OverrideData string
	// TTL for synthetic responses.
	TTL uint32
	// PolicyName identifies which policy zone this rule came from.
	PolicyName string
	// Priority for rule ordering (lower = higher priority).
	Priority int
}

// Engine implements RPZ policy evaluation.
type Engine struct {
	mu sync.RWMutex

	// Rules keyed by trigger type for efficient lookup.
	qnameRules    map[string]*Rule // exact + wildcard domain matches
	clientIPRules []*net.IPNet     // CIDR prefixes for client IP matching
	clientActions []*Rule          // corresponding rules for client IP CIDRs
	respIPRules   []*net.IPNet     // CIDR prefixes for response IP matching
	respActions   []*Rule          // corresponding rules for response IPs

	// Zone files loaded.
	files []string

	// Policy zones with their priorities.
	policies map[string]int // name -> priority

	// Enabled flag. atomic.Bool so DNS-hot-path IsEnabled() does not race
	// with admin toggle (VULN-015).
	enabled atomic.Bool

	// Metrics.
	matches     uint64
	lookups     uint64
	parseErrors uint64

	// Logger.
	logger *util.Logger

	// Last reload time.
	lastReload time.Time
}

// Config holds RPZ engine configuration.
type Config struct {
	Enabled bool
	Files   []string
	// Policies maps policy zone names to their priority (lower = higher priority).
	Policies map[string]int
	// Logger for diagnostics. If nil, logging is silently discarded.
	Logger *util.Logger
}

// NewEngine creates a new RPZ engine.
func NewEngine(cfg Config) *Engine {
	if cfg.Policies == nil {
		cfg.Policies = make(map[string]int)
	}
	e := &Engine{
		qnameRules:    make(map[string]*Rule),
		clientActions: make([]*Rule, 0),
		respActions:   make([]*Rule, 0),
		files:         cfg.Files,
		policies:      cfg.Policies,
		logger:        cfg.Logger,
	}
	e.enabled.Store(cfg.Enabled)
	return e
}

// Load loads all configured RPZ zone files.
func (e *Engine) Load() error {
	if !e.enabled.Load() {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Clear existing rules
	e.qnameRules = make(map[string]*Rule)
	e.clientIPRules = make([]*net.IPNet, 0)
	e.clientActions = make([]*Rule, 0)
	e.respIPRules = make([]*net.IPNet, 0)
	e.respActions = make([]*Rule, 0)

	for _, file := range e.files {
		if err := e.loadFile(file); err != nil {
			return fmt.Errorf("rpz: load %s: %w", file, err)
		}
	}

	e.lastReload = time.Now()
	return nil
}

// loadFile parses an RPZ zone file.
// RPZ zone files use BIND zone format where the owner name encodes the trigger:
//
//	QNAME triggers:  bad.example.com.rpz-zone.  -> matches bad.example.com
//	Wildcard QNAME:  *.example.com.rpz-zone.    -> matches *.example.com subdomains
//	Response IP:     32.1.0.168.192.rpz-ip.     -> matches 192.168.0.1/32
//	Client IP:       24.0.168.192.rpz-clientip. -> matches 192.168.0.0/24
//	NSDNAME:         ns.evil.com.rpz-nsdname.   -> matches nameserver ns.evil.com
//	NSIP:            32.1.0.168.192.rpz-nsip.   -> matches NS IP 192.168.0.1/32
//
// The policy action is determined by the RR type and RDATA:
//   - CNAME to *. -> NXDOMAIN
//   - CNAME to *.  with empty target -> NODATA
//   - CNAME to hostname -> CNAME redirect
//   - A record -> Override with that IP
//   - TXT "drop" -> Drop
func (e *Engine) loadFile(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	// Determine policy zone name from file (use filename base as fallback)
	policyName := filename
	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}

		rule, err := e.parseLine(line, policyName)
		if err != nil {
			if e.logger != nil {
				e.logger.Warnf("rpz: skipping malformed line %d in %s: %v", lineNum, filename, err)
			}
			atomic.AddUint64(&e.parseErrors, 1)
			continue
		}
		if rule == nil {
			continue // SOA, NS, or other non-policy records
		}

		e.addRule(rule)
	}

	return scanner.Err()
}

// parseLine parses a single RPZ zone file line.
// Format: <rpz-name> <ttl> IN <type> <rdata>
func (e *Engine) parseLine(line, policyName string) (*Rule, error) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return nil, fmt.Errorf("too few fields")
	}

	owner := fields[0]
	// Skip class field if present, find type and rdata
	typeIdx := -1
	for i := 1; i < len(fields); i++ {
		upper := strings.ToUpper(fields[i])
		if upper == "IN" || upper == "CH" {
			continue
		}
		if upper == "A" || upper == "AAAA" || upper == "CNAME" || upper == "TXT" ||
			upper == "SOA" || upper == "NS" || upper == "PTR" || upper == "MX" {
			typeIdx = i
			break
		}
		// Might be TTL (numeric)
		if typeIdx == -1 {
			continue
		}
	}

	if typeIdx == -1 || typeIdx+1 >= len(fields) {
		return nil, fmt.Errorf("cannot find type/rdata")
	}

	rtype := strings.ToUpper(fields[typeIdx])
	rdata := fields[typeIdx+1]

	// Skip SOA and NS records (zone infrastructure)
	if rtype == "SOA" || rtype == "NS" {
		return nil, nil
	}

	// Parse TTL
	ttl := uint32(0)
	for i := 1; i < typeIdx; i++ {
		upper := strings.ToUpper(fields[i])
		if upper == "IN" || upper == "CH" {
			continue
		}
		t, ok, err := parseTTLField(fields[i])
		if err != nil {
			return nil, err
		}
		if ok {
			ttl = t
			break
		}
	}

	// Parse owner name to determine trigger type and pattern
	owner = strings.TrimSuffix(owner, ".")
	trigger, pattern := e.parseOwnerName(owner)

	// Determine action from record type and rdata
	action, overrideData := e.parseAction(rtype, rdata)

	priority := 0
	if p, ok := e.policies[policyName]; ok {
		priority = p
	}

	return &Rule{
		Action:       action,
		Trigger:      trigger,
		Pattern:      pattern,
		OverrideData: overrideData,
		TTL:          ttl,
		PolicyName:   policyName,
		Priority:     priority,
	}, nil
}

// parseTTLField parses a candidate TTL field. It accepts plain integers and
// BIND-style unit suffixes (s/m/h/d/w, case-insensitive), including compound
// forms like "1h30m". A field that does not start with a digit returns
// (0, false, nil) so the caller treats it as not-a-TTL; a malformed numeric
// field (bad unit, missing digits, uint32 overflow) is an error.
func parseTTLField(field string) (uint32, bool, error) {
	if field == "" || field[0] < '0' || field[0] > '9' {
		return 0, false, nil
	}
	const maxTTL = uint64(1<<32 - 1)
	var total uint64
	for i := 0; i < len(field); {
		start := i
		for i < len(field) && field[i] >= '0' && field[i] <= '9' {
			i++
		}
		if start == i {
			return 0, false, fmt.Errorf("invalid ttl %q", field)
		}
		value, err := strconv.ParseUint(field[start:i], 10, 32)
		if err != nil {
			return 0, false, fmt.Errorf("invalid ttl %q", field)
		}
		multiplier := uint64(1)
		if i < len(field) {
			switch field[i] {
			case 's', 'S':
			case 'm', 'M':
				multiplier = 60
			case 'h', 'H':
				multiplier = 3600
			case 'd', 'D':
				multiplier = 86400
			case 'w', 'W':
				multiplier = 604800
			default:
				return 0, false, fmt.Errorf("invalid ttl %q", field)
			}
			i++
		}
		total += value * multiplier
		if total > maxTTL {
			return 0, false, fmt.Errorf("invalid ttl %q: exceeds uint32 max", field)
		}
	}
	return uint32(total), true, nil
}

// parseOwnerName extracts trigger type and pattern from an RPZ owner name.
func (e *Engine) parseOwnerName(owner string) (TriggerType, string) {
	owner = strings.ToLower(owner)

	// Check for RPZ suffix tags
	if idx := strings.LastIndex(owner, ".rpz-clientip"); idx != -1 {
		ipPart := owner[:idx]
		cidr := reverseRPZToCIDR(ipPart)
		return TriggerClientIP, cidr
	}

	if idx := strings.LastIndex(owner, ".rpz-ip"); idx != -1 {
		ipPart := owner[:idx]
		cidr := reverseRPZToCIDR(ipPart)
		return TriggerResponseIP, cidr
	}

	if idx := strings.LastIndex(owner, ".rpz-nsdname"); idx != -1 {
		name := owner[:idx]
		return TriggerNSDNAME, name
	}

	if idx := strings.LastIndex(owner, ".rpz-nsip"); idx != -1 {
		ipPart := owner[:idx]
		cidr := reverseRPZToCIDR(ipPart)
		return TriggerNSIP, cidr
	}

	// Default: QNAME trigger. Strip any trailing zone name suffix.
	// The owner name IS the pattern to match.
	pattern := owner

	// If the pattern has a zone suffix like ".rpz-zone", strip it
	if idx := strings.LastIndex(pattern, ".rpz-"); idx != -1 {
		// Keep only the trigger-relevant part (already handled above for IP/NS triggers)
		// For QNAME triggers, strip any ".rpz-*" suffix
		pattern = pattern[:idx]
	}

	return TriggerQNAME, pattern
}

// reverseRPZToCIDR converts a reversed RPZ IP encoding to CIDR notation.
// e.g., "32.1.0.168.192" -> "192.168.0.1/32"
// e.g., "24.0.168.192" -> "192.168.0.0/24"
func reverseRPZToCIDR(rpzIP string) string {
	parts := strings.Split(rpzIP, ".")
	if len(parts) < 2 {
		return rpzIP
	}

	// First part is the prefix length
	prefixLen := parts[0]
	ipParts := parts[1:]

	// Reverse the IP octets
	for i, j := 0, len(ipParts)-1; i < j; i, j = i+1, j-1 {
		ipParts[i], ipParts[j] = ipParts[j], ipParts[i]
	}

	// Pad with zeros for IPv4
	for len(ipParts) < 4 {
		ipParts = append(ipParts, "0")
	}

	return strings.Join(ipParts, ".") + "/" + prefixLen
}

// parseAction determines the policy action from record type and rdata.
func (e *Engine) parseAction(rtype, rdata string) (PolicyAction, string) {
	switch rtype {
	case "CNAME":
		rawTarget := strings.Trim(strings.TrimSpace(rdata), "\"")
		target := strings.TrimSuffix(rawTarget, ".")
		switch strings.ToLower(target) {
		case "rpz-passthru":
			return ActionPassThrough, ""
		case "rpz-drop":
			return ActionDrop, ""
		case "rpz-tcp-only":
			return ActionTCPOnly, ""
		}

		// CNAME to "." (root) means NXDOMAIN; CNAME to "*." means NODATA.
		if rawTarget == "." {
			return ActionNXDOMAIN, ""
		}
		if target == "*" {
			return ActionNODATA, ""
		}
		if target == "" {
			return ActionNODATA, ""
		}
		return ActionCNAME, target
	case "A", "AAAA":
		return ActionOverride, rdata
	case "TXT":
		if strings.EqualFold(rdata, "drop") || strings.EqualFold(strings.Trim(rdata, "\""), "drop") {
			return ActionDrop, ""
		}
		if strings.EqualFold(rdata, "passthru") || strings.EqualFold(strings.Trim(rdata, "\""), "passthru") {
			return ActionPassThrough, ""
		}
		if strings.EqualFold(rdata, "tcp-only") || strings.EqualFold(strings.Trim(rdata, "\""), "tcp-only") {
			return ActionTCPOnly, ""
		}
		return ActionNXDOMAIN, ""
	default:
		return ActionNXDOMAIN, ""
	}
}

// addRule adds a rule to the engine's lookup structures.
func (e *Engine) addRule(rule *Rule) {
	switch rule.Trigger {
	case TriggerQNAME, TriggerNSDNAME:
		key := strings.ToLower(rule.Pattern)
		if existing, ok := e.qnameRules[key]; ok {
			// Keep higher priority rule
			if rule.Priority < existing.Priority {
				e.qnameRules[key] = rule
			}
		} else {
			e.qnameRules[key] = rule
		}

	case TriggerClientIP:
		_, cidr, err := net.ParseCIDR(rule.Pattern)
		if err != nil {
			return
		}
		e.clientIPRules = append(e.clientIPRules, cidr)
		e.clientActions = append(e.clientActions, rule)

	case TriggerResponseIP:
		_, cidr, err := net.ParseCIDR(rule.Pattern)
		if err != nil {
			return
		}
		e.respIPRules = append(e.respIPRules, cidr)
		e.respActions = append(e.respActions, rule)

	case TriggerNSIP:
		// Store same as response IP for lookup purposes
		_, cidr, err := net.ParseCIDR(rule.Pattern)
		if err != nil {
			return
		}
		e.respIPRules = append(e.respIPRules, cidr)
		e.respActions = append(e.respActions, rule)
	}
}

// QNAMEPolicy evaluates RPZ policy for a query name.
// Returns the matching rule or nil if no policy applies.
func (e *Engine) QNAMEPolicy(qname string) *Rule {
	if !e.enabled.Load() {
		return nil
	}

	atomic.AddUint64(&e.lookups, 1)

	e.mu.RLock()
	defer e.mu.RUnlock()

	// Trim trailing dot - DNS names from the protocol layer are already
	// lowercase, but callers may pass mixed case, so lower only if needed
	if len(qname) > 0 && qname[len(qname)-1] == '.' {
		qname = qname[:len(qname)-1]
	}
	// Fast check: if the string is already lowercase (common path from
	// protocol layer), skip the allocation. Only call ToLower if needed.
	needsLower := false
	for i := 0; i < len(qname); i++ {
		if qname[i] >= 'A' && qname[i] <= 'Z' {
			needsLower = true
			break
		}
	}
	if needsLower {
		qname = strings.ToLower(qname)
	}

	// Exact match
	if rule, ok := e.qnameRules[qname]; ok {
		atomic.AddUint64(&e.matches, 1)
		return rule
	}

	// Wildcard/suffix matching: walk up domain labels
	// e.g., for "www.ads.example.com", check:
	//   "*.ads.example.com", "*.example.com", "*.com"
	for {
		dot := strings.Index(qname, ".")
		if dot == -1 || dot == len(qname)-1 {
			break
		}
		qname = qname[dot+1:]
		wildcard := "*." + qname

		if rule, ok := e.qnameRules[wildcard]; ok {
			atomic.AddUint64(&e.matches, 1)
			return rule
		}
	}

	return nil
}

// ClientIPPolicy evaluates RPZ policy based on client IP.
func (e *Engine) ClientIPPolicy(clientIP net.IP) *Rule {
	if !e.enabled.Load() {
		return nil
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	// L-8: walk every matching CIDR and return the highest-priority
	// hit (Rule.Priority semantics: lower numeric value = higher
	// priority, same as QNAMEPolicy). The earlier implementation
	// returned the first slice-order match, so insertion order silently
	// won over the operator-declared priority.
	var best *Rule
	for i, cidr := range e.clientIPRules {
		if cidr.Contains(clientIP) {
			r := e.clientActions[i]
			if best == nil || r.Priority < best.Priority {
				best = r
			}
		}
	}
	return best
}

// ResponseIPPolicy evaluates RPZ policy based on response IP addresses.
func (e *Engine) ResponseIPPolicy(ips []net.IP) *Rule {
	if !e.enabled.Load() || len(ips) == 0 {
		return nil
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	// L-8: as for ClientIPPolicy, prefer the highest-priority match
	// across all response IPs and all CIDR rules rather than the first
	// slice-order hit. Iterating IPs as the outer loop preserves the
	// original "any response IP matches" semantics; only the tie-break
	// on multiple matches changes.
	var best *Rule
	for _, ip := range ips {
		for i, cidr := range e.respIPRules {
			if cidr.Contains(ip) {
				r := e.respActions[i]
				if best == nil || r.Priority < best.Priority {
					best = r
				}
			}
		}
	}
	return best
}

// Reload reloads all RPZ zone files.
func (e *Engine) Reload() error {
	return e.Load()
}

// Stats returns RPZ engine statistics.
//
// All map/slice length probes and lastReload reads happen under
// the same RLock — Reload() takes the write lock and rewrites
// every collection plus lastReload as a unit, so dropping the
// lock between counts let Stats() observe a torn picture where
// the summed TotalRules disagrees with the individual category
// counters, or where lastReload reflected an in-flight reload.
func (e *Engine) Stats() Stats {
	e.mu.RLock()
	qn := len(e.qnameRules)
	ci := len(e.clientIPRules)
	ri := len(e.respIPRules)
	files := len(e.files)
	lastReload := e.lastReload
	e.mu.RUnlock()

	return Stats{
		Enabled:       e.enabled.Load(),
		TotalRules:    qn + ci + ri,
		QNAMERules:    qn,
		ClientIPRules: ci,
		RespIPRules:   ri,
		Files:         files,
		TotalMatches:  atomic.LoadUint64(&e.matches),
		TotalLookups:  atomic.LoadUint64(&e.lookups),
		ParseErrors:   atomic.LoadUint64(&e.parseErrors),
		LastReload:    lastReload,
	}
}

// IsEnabled returns whether the engine is enabled.
func (e *Engine) IsEnabled() bool {
	return e.enabled.Load()
}

// SetEnabled enables or disables the RPZ engine.
func (e *Engine) SetEnabled(enabled bool) {
	e.enabled.Store(enabled)
}

// Toggle atomically flips the enabled state and returns the new value.
// Replaces the TOCTOU-prone SetEnabled(!IsEnabled()) pattern (VULN-015).
func (e *Engine) Toggle() bool {
	for {
		cur := e.enabled.Load()
		if e.enabled.CompareAndSwap(cur, !cur) {
			return !cur
		}
	}
}

// AddQNAMERule adds a QNAME trigger rule dynamically.
func (e *Engine) AddQNAMERule(pattern string, action PolicyAction, overrideData string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	rule := &Rule{
		Action:       action,
		Trigger:      TriggerQNAME,
		Pattern:      normalizeQNAMEPattern(pattern),
		OverrideData: overrideData,
		TTL:          300,
		PolicyName:   "dynamic",
		Priority:     0,
	}
	e.addRule(rule)
}

// RemoveQNAMERule removes a QNAME rule by pattern.
func (e *Engine) RemoveQNAMERule(pattern string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	delete(e.qnameRules, normalizeQNAMEPattern(pattern))
}

// normalizeQNAMEPattern matches the key form QNAMEPolicy looks up: lowercase,
// without the trailing root dot. A rule added as "bad.example." was stored
// with its dot and never matched.
func normalizeQNAMEPattern(pattern string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pattern)), ".")
}

// ListQNAMERules returns all QNAME rules as a slice.
func (e *Engine) ListQNAMERules() []*Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rules := make([]*Rule, 0, len(e.qnameRules))
	for _, r := range e.qnameRules {
		rules = append(rules, r)
	}
	return rules
}

// GetPolicies returns the list of policy zone names with their priorities.
func (e *Engine) GetPolicies() map[string]int {
	e.mu.RLock()
	defer e.mu.RUnlock()

	policies := make(map[string]int, len(e.policies))
	for k, v := range e.policies {
		policies[k] = v
	}
	return policies
}

// Stats holds RPZ engine statistics.
type Stats struct {
	Enabled       bool
	TotalRules    int
	QNAMERules    int
	ClientIPRules int
	RespIPRules   int
	Files         int
	TotalMatches  uint64
	TotalLookups  uint64
	ParseErrors   uint64
	LastReload    time.Time
}
