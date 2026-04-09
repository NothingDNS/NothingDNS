package rpz

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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

	// Enabled flag.
	enabled bool

	// Metrics.
	matches uint64
	lookups uint64

	// Last reload time.
	lastReload time.Time
}

// Config holds RPZ engine configuration.
type Config struct {
	Enabled bool
	Files   []string
	// Policies maps policy zone names to their priority (lower = higher priority).
	Policies map[string]int
}

// NewEngine creates a new RPZ engine.
func NewEngine(cfg Config) *Engine {
	if cfg.Policies == nil {
		cfg.Policies = make(map[string]int)
	}
	return &Engine{
		qnameRules:    make(map[string]*Rule),
		clientActions: make([]*Rule, 0),
		respActions:   make([]*Rule, 0),
		files:         cfg.Files,
		policies:      cfg.Policies,
		enabled:       cfg.Enabled,
	}
}

// Load loads all configured RPZ zone files.
func (e *Engine) Load() error {
	if !e.enabled {
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
			continue // Skip malformed lines
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
		var t uint32
		if _, err := fmt.Sscanf(fields[i], "%d", &t); err == nil {
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
		target := strings.TrimSuffix(rdata, ".")
		// CNAME to "." (root) means NODATA (NOERROR with no answers)
		if target == "" || rdata == "." {
			return ActionNODATA, ""
		}
		if target == "*" {
			return ActionNXDOMAIN, ""
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
	if !e.enabled {
		return nil
	}

	atomic.AddUint64(&e.lookups, 1)

	e.mu.RLock()
	defer e.mu.RUnlock()

	qname = strings.ToLower(strings.TrimSuffix(qname, "."))

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
	if !e.enabled {
		return nil
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	for i, cidr := range e.clientIPRules {
		if cidr.Contains(clientIP) {
			return e.clientActions[i]
		}
	}
	return nil
}

// ResponseIPPolicy evaluates RPZ policy based on response IP addresses.
func (e *Engine) ResponseIPPolicy(ips []net.IP) *Rule {
	if !e.enabled || len(ips) == 0 {
		return nil
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, ip := range ips {
		for i, cidr := range e.respIPRules {
			if cidr.Contains(ip) {
				return e.respActions[i]
			}
		}
	}
	return nil
}

// Reload reloads all RPZ zone files.
func (e *Engine) Reload() error {
	return e.Load()
}

// Stats returns RPZ engine statistics.
func (e *Engine) Stats() Stats {
	e.mu.RLock()
	ruleCount := len(e.qnameRules) + len(e.clientIPRules) + len(e.respIPRules)
	e.mu.RUnlock()

	return Stats{
		Enabled:       e.enabled,
		TotalRules:    ruleCount,
		QNAMERules:    len(e.qnameRules),
		ClientIPRules: len(e.clientIPRules),
		RespIPRules:   len(e.respIPRules),
		Files:         len(e.files),
		TotalMatches:  atomic.LoadUint64(&e.matches),
		TotalLookups:  atomic.LoadUint64(&e.lookups),
		LastReload:    e.lastReload,
	}
}

// IsEnabled returns whether the engine is enabled.
func (e *Engine) IsEnabled() bool {
	return e.enabled
}

// SetEnabled enables or disables the RPZ engine.
func (e *Engine) SetEnabled(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enabled = enabled
}

// AddQNAMERule adds a QNAME trigger rule dynamically.
func (e *Engine) AddQNAMERule(pattern string, action PolicyAction, overrideData string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	rule := &Rule{
		Action:       action,
		Trigger:      TriggerQNAME,
		Pattern:      strings.ToLower(pattern),
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

	delete(e.qnameRules, strings.ToLower(pattern))
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
	LastReload    time.Time
}
