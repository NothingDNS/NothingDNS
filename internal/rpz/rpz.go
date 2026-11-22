package rpz

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
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
	// OverrideData contains replacement data (CNAME target, override IP,
	// or the presentation-format RDATA of a Local Data record).
	OverrideData string
	// RRType is the record type of Local Data (ActionOverride) read from a
	// policy zone ("A", "TXT", "MX", …). Empty for an override added through
	// the API, whose OverrideData is an address (A or AAAA by its family).
	RRType string
	// TTL for synthetic responses.
	TTL uint32
	// PolicyName identifies which policy zone this rule came from.
	PolicyName string
	// Priority for rule ordering (lower = higher priority).
	Priority int
	// Order is the position of the rule's policy zone in rpz.files: on
	// equal Priority the earlier zone wins (F886). Zero for a zone with an
	// explicit priority.
	Order int
	// Additional holds the further local-data records (ActionOverride) of
	// the same owner in the same policy zone: local data is an RRset, so
	// "x A …" plus "x AAAA …" or two A records all answer (F668).
	Additional []*Rule
}

// Engine implements RPZ policy evaluation.
type Engine struct {
	mu sync.RWMutex

	// Rules keyed by trigger type for efficient lookup.
	qnameRules    map[string]*Rule // exact + wildcard domain matches
	nsdnameRules  map[string]*Rule // NSDNAME triggers, kept apart from QNAME (F645)
	clientIPRules []*net.IPNet     // CIDR prefixes for client IP matching
	clientActions []*Rule          // corresponding rules for client IP CIDRs
	respIPRules   []*net.IPNet     // CIDR prefixes for response IP matching
	respActions   []*Rule          // corresponding rules for response IPs
	nsipRules     []*net.IPNet     // NSIP triggers, kept apart from response IPs (F652)
	nsipActions   []*Rule          // corresponding rules for NSIP CIDRs

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

	// loadOrder is the index in files of the file being loaded (Rule.Order).
	loadOrder int

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
	policies := make(map[string]int, len(cfg.Policies))
	for name, priority := range cfg.Policies {
		policies[name] = priority
	}
	e := &Engine{
		qnameRules:    make(map[string]*Rule),
		nsdnameRules:  make(map[string]*Rule),
		clientActions: make([]*Rule, 0),
		respActions:   make([]*Rule, 0),
		files:         append([]string(nil), cfg.Files...),
		policies:      policies,
		logger:        cfg.Logger,
	}
	e.enabled.Store(cfg.Enabled)
	return e
}

// Load loads all configured RPZ zone files. They are loaded while the engine
// is disabled too (a disabled engine matches nothing), so enabling it at
// runtime applies the configured policy instead of an empty one (F644).
func (e *Engine) Load() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Load into temporary collections so a parse error in any file leaves
	// the engine's previously-loaded rule set intact. Without this, a
	// transient parse error in one file would silently destroy all
	// previously-loaded rules from every other file.
	newQName := make(map[string]*Rule)
	newNSDName := make(map[string]*Rule)
	newClientCIDRs := make([]*net.IPNet, 0)
	newClientActions := make([]*Rule, 0)
	newRespCIDRs := make([]*net.IPNet, 0)
	newRespActions := make([]*Rule, 0)
	newNSIPCIDRs := make([]*net.IPNet, 0)
	newNSIPActions := make([]*Rule, 0)

	// Save the current collections so we can restore them on failure.
	prevQName := e.qnameRules
	prevNSDName := e.nsdnameRules
	prevClientCIDRs := e.clientIPRules
	prevClientActions := e.clientActions
	prevRespCIDRs := e.respIPRules
	prevRespActions := e.respActions
	prevNSIPCIDRs := e.nsipRules
	prevNSIPActions := e.nsipActions

	// Point the engine at the temporary collections for the duration of
	// the load loop. addRule appends to the engine's current collections.
	e.qnameRules = newQName
	e.nsdnameRules = newNSDName
	e.clientIPRules = newClientCIDRs
	e.clientActions = newClientActions
	e.respIPRules = newRespCIDRs
	e.respActions = newRespActions
	e.nsipRules = newNSIPCIDRs
	e.nsipActions = newNSIPActions

	for i, file := range e.files {
		// A plain rpz.files entry is ranked by its position in the list
		// (draft-vixie-dnsop-dns-rpz-00 §5.2); a zone given an explicit
		// priority is ranked by it alone, equal priorities tying (4f3766b).
		e.loadOrder = 0
		if _, explicit := e.policies[file]; !explicit {
			e.loadOrder = i
		}
		if err := e.loadFile(file); err != nil {
			// Restore the previous rule set before returning the error.
			e.qnameRules = prevQName
			e.nsdnameRules = prevNSDName
			e.clientIPRules = prevClientCIDRs
			e.clientActions = prevClientActions
			e.respIPRules = prevRespCIDRs
			e.respActions = prevRespActions
			e.nsipRules = prevNSIPCIDRs
			e.nsipActions = prevNSIPActions
			if !e.enabled.Load() {
				// A disabled engine never fails start or reload over its
				// files; the error comes back when it is enabled and reloaded.
				if e.logger != nil {
					e.logger.Warnf("rpz: load %s (engine disabled): %v", file, err)
				}
				return nil
			}
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
//	Response IPv6:   128.3.zz.db8.2001.rpz-ip.  -> matches 2001:db8::3/128
//	Client IP:       24.0.168.192.rpz-client-ip. -> matches 192.168.0.0/24 (also .rpz-clientip)
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
	// apex is the policy zone's own name (lower case, no trailing dot),
	// taken from its SOA owner, or from the $ORIGIN in force for an "@"
	// owner. An absolute QNAME trigger owner below it names the trigger
	// relative to it (F860).
	// lastOwner is the owner of the previous record line, as rewritten below.
	origin, apex, lastOwner := "", "", ""
	// defaultTTL is the $TTL in force, the TTL of records that state none
	// (RFC 2308 §4); a $TTL line used to be skipped as malformed and such
	// records answered with TTL 0 (F883).
	var defaultTTL uint32

	for scanner.Scan() {
		lineNum++
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "$ORIGIN") {
			origin = fields[1]
			continue
		}
		if strings.EqualFold(fields[0], "$TTL") {
			ttl, ok, err := uint32(0), false, error(nil)
			if len(fields) >= 2 {
				ttl, ok, err = parseTTLField(fields[1])
			}
			if !ok || err != nil {
				if e.logger != nil {
					e.logger.Warnf("rpz: skipping malformed $TTL on line %d in %s", lineNum, filename)
				}
				atomic.AddUint64(&e.parseErrors, 1)
				continue
			}
			defaultTTL = ttl
			continue
		}
		if raw[0] == ' ' || raw[0] == '\t' {
			// A line that begins with a blank is owned by the last stated
			// owner (RFC 1035 §5.1, F861).
			if lastOwner != "" {
				fields = append([]string{lastOwner}, fields...)
				line = strings.Join(fields, " ")
			}
		} else {
			// A relative owner is relative to the $ORIGIN in force; below
			// the apex, qualify it with the labels between them (F862).
			if sub := subOrigin(origin, apex); sub != "" && !strings.HasPrefix(fields[0], "$") &&
				!strings.HasSuffix(fields[0], ".") {
				if fields[0] == "@" {
					fields[0] = sub
				} else {
					fields[0] += "." + sub
				}
				line = strings.Join(fields, " ")
			}
			if !strings.HasPrefix(fields[0], "$") {
				lastOwner = fields[0]
			}
		}
		if apex == "" && isSOARecord(fields) {
			owner := fields[0]
			if owner == "@" {
				owner = origin
			}
			if len(owner) > 1 && strings.HasSuffix(owner, ".") {
				apex = strings.ToLower(strings.TrimSuffix(owner, "."))
			}
		}

		rule, err := e.parseLineTTL(line, policyName, defaultTTL)
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
		rule.Order = e.loadOrder
		if rule.Trigger == TriggerQNAME && apex != "" && strings.HasSuffix(fields[0], ".") &&
			strings.HasSuffix(rule.Pattern, "."+apex) {
			rule.Pattern = rule.Pattern[:len(rule.Pattern)-len(apex)-1]
		}
		if rule.Trigger == TriggerQNAME && rule.Action == ActionCNAME &&
			strings.EqualFold(rule.OverrideData, rule.Pattern) {
			// draft-vixie-dnsop-dns-rpz-00 §10: a CNAME to the trigger QNAME
			// is the deprecated PASSTHRU encoding, "still recognized by RPZ
			// subscriber implementations"; it was a CNAME to itself (F884).
			rule.Action, rule.OverrideData = ActionPassThrough, ""
		}
		if rule.Action == ActionOverride {
			// Local Data is the set of RRsets at the trigger (F668); IP
			// triggers kept only their first record (F882).
			if existing := e.overrideRuleFor(rule); existing != nil {
				existing.Additional = append(existing.Additional, rule)
				continue
			}
		}

		e.addRule(rule)
	}

	return scanner.Err()
}

// overrideRuleFor returns the Local Data rule already loaded for rule's
// trigger in the same policy zone, or nil.
func (e *Engine) overrideRuleFor(rule *Rule) *Rule {
	same := func(r *Rule) bool {
		return r.Action == ActionOverride && r.PolicyName == rule.PolicyName && r.Pattern == rule.Pattern
	}
	var actions []*Rule
	switch rule.Trigger {
	case TriggerQNAME:
		if existing, ok := e.qnameRules[strings.ToLower(rule.Pattern)]; ok && same(existing) {
			return existing
		}
		return nil
	case TriggerResponseIP:
		actions = e.respActions
	case TriggerClientIP:
		actions = e.clientActions
	case TriggerNSIP:
		actions = e.nsipActions
	}
	for _, r := range actions {
		if same(r) {
			return r
		}
	}
	return nil
}

// rpzLocalDataExcluded lists the record types draft-vixie-dnsop-dns-rpz-00
// §3.6 does not allow as Local Data (SOA and NS are the policy zone's own).
var rpzLocalDataExcluded = map[string]bool{
	"DNAME": true, "DNSKEY": true, "RRSIG": true, "NSEC": true, "NSEC3": true,
	"NSEC3PARAM": true, "DS": true, "CDS": true, "CDNSKEY": true,
}

// rdataText returns the RDATA of a record line: the text after its first
// n fields, without an unquoted ";" comment.
func rdataText(line string, n int) string {
	rest := line
	for i := 0; i < n; i++ {
		rest = strings.TrimLeft(rest, " \t")
		if j := strings.IndexAny(rest, " \t"); j >= 0 {
			rest = rest[j:]
		} else {
			rest = ""
		}
	}
	inQuote := false
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case '\\':
			i++
		case '"':
			inQuote = !inQuote
		case ';':
			if !inQuote {
				return strings.TrimSpace(rest[:i])
			}
		}
	}
	return strings.TrimSpace(rest)
}

// parseLine parses a single RPZ zone file line.
// Format: <rpz-name> [<ttl>] [IN] <type> <rdata> (TTL and class are
// optional, RFC 1035 §5.1, so "name CNAME ." is a whole rule — F859).
func (e *Engine) parseLine(line, policyName string) (*Rule, error) {
	return e.parseLineTTL(line, policyName, 0)
}

// parseLineTTL is parseLine with the TTL of a record that states none.
func (e *Engine) parseLineTTL(line, policyName string, defaultTTL uint32) (*Rule, error) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return nil, fmt.Errorf("too few fields")
	}

	owner := fields[0]
	// The type is the first field after the owner that is neither a class
	// nor a TTL; any type is Local Data (draft-vixie-dnsop-dns-rpz-00 §3.6),
	// not only the few listed before (F881).
	typeIdx := -1
	for i := 1; i < len(fields); i++ {
		upper := strings.ToUpper(fields[i])
		if upper == "IN" || upper == "CH" {
			continue
		}
		if _, ok := protocol.StringToType[upper]; ok {
			typeIdx = i
			break
		}
		if _, ok, _ := parseTTLField(fields[i]); ok {
			continue
		}
		break
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
	if rpzLocalDataExcluded[rtype] {
		return nil, fmt.Errorf("%s records are not allowed as RPZ local data", rtype)
	}
	if rtype != "CNAME" && rtype != "A" && rtype != "AAAA" {
		// Multi-field RDATA (MX, SRV, TXT with spaces) is the rest of the line.
		rdata = rdataText(line, typeIdx+1)
	}

	// Parse TTL
	ttl := defaultTTL
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
	var rrType string
	if action == ActionOverride {
		if protocol.ParseRDataText(rtype, overrideData) == nil {
			return nil, fmt.Errorf("invalid %s local data %q", rtype, overrideData)
		}
		rrType = rtype
	}

	priority := 0
	if p, ok := e.policies[policyName]; ok {
		priority = p
	}

	return &Rule{
		Action:       action,
		Trigger:      trigger,
		Pattern:      pattern,
		OverrideData: overrideData,
		RRType:       rrType,
		TTL:          ttl,
		PolicyName:   policyName,
		Priority:     priority,
	}, nil
}

// subOrigin returns the labels of origin below apex ("example.net" for
// origin "example.net.rpz.example.com." and apex "rpz.example.com"), or ""
// when origin is the apex, is not below it, or the apex is unknown.
func subOrigin(origin, apex string) string {
	origin = strings.ToLower(strings.TrimSuffix(origin, "."))
	if apex == "" || !strings.HasSuffix(origin, "."+apex) {
		return ""
	}
	return origin[:len(origin)-len(apex)-1]
}

// isSOARecord reports whether a record line's type is SOA: the first field
// after the owner that is neither a class nor a TTL.
func isSOARecord(fields []string) bool {
	for _, f := range fields[1:] {
		if strings.EqualFold(f, "IN") || strings.EqualFold(f, "CH") {
			continue
		}
		if _, ok, _ := parseTTLField(f); ok {
			continue
		}
		return strings.EqualFold(f, "SOA")
	}
	return false
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

	// Check for RPZ suffix tags. draft-vixie-dnsop-dns-rpz-00 §4.1 names the
	// client IP trigger "rpz-client-ip" (as BIND does); "rpz-clientip" is
	// this server's earlier spelling, still read (F878).
	if idx := strings.LastIndex(owner, ".rpz-client-ip"); idx != -1 {
		ipPart := owner[:idx]
		cidr := reverseRPZToCIDR(ipPart)
		return TriggerClientIP, cidr
	}
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
// e.g., "48.8.b.d.0.1.0.0.2" -> "2001:0db8:0000:...::/48" (IPv6 nibbles)
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

	// draft-vixie-dnsop-dns-rpz-00 §4.1.1 encodes IPv6 as the address's
	// 16-bit words reversed, "zz" standing for "::" ("128.3.zz.db8.2001" is
	// 2001:db8::3/128). Only nibble labels were decoded, so every IPv6
	// trigger written that way was dropped (F877).
	if cidr := hextetsToCIDR(ipParts, prefixLen); cidr != "" {
		return cidr
	}

	// Reversed single-hex-digit nibbles (up to 32 labels), the form this
	// server read before F877, are still decoded. A dotted-quad string can
	// never have more than four labels, so 5+ all-nibble labels are
	// unambiguously IPv6. Anything with four or fewer labels (every IPv4
	// rule, including single-digit octets) keeps the dotted interpretation
	// below.
	if len(ipParts) > 4 {
		if cidr := reversedNibblesToCIDR(ipParts, prefixLen); cidr != "" {
			return cidr
		}
	}

	// Pad with zeros for IPv4
	for len(ipParts) < 4 {
		ipParts = append(ipParts, "0")
	}

	return strings.Join(ipParts, ".") + "/" + prefixLen
}

// hextetsToCIDR decodes the draft-vixie-dnsop-dns-rpz-00 §4.1.1 IPv6 words
// (already back in address order) plus the prefix length into a CIDR, or
// returns "" when they are not that encoding. A "zz" label marks the
// compressed zero run; without one all eight words are present. Eight
// single-hex-digit labels are also a nibble prefix (the pre-F877 form): they
// are read as words only when they are a valid §4.1.1 encoding, i.e. hold
// no uncompressed run of two or more zero words (RFC 5952 §4.2.1).
func hextetsToCIDR(words []string, prefixLen string) string {
	plen, err := strconv.Atoi(prefixLen)
	if err != nil || plen < 1 || plen > 128 || len(words) == 0 || len(words) > 8 {
		return ""
	}
	isWord := func(s string) bool {
		if len(s) < 1 || len(s) > 4 {
			return false
		}
		for i := 0; i < len(s); i++ {
			c := s[i]
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				return false
			}
		}
		return true
	}
	zz, multi, zeroRun, longestZeroRun := -1, false, 0, 0
	for i, w := range words {
		if w == "zz" {
			if zz >= 0 {
				return ""
			}
			zz = i
			zeroRun = 0
			continue
		}
		if !isWord(w) {
			return ""
		}
		if len(w) > 1 {
			multi = true
		}
		if strings.Trim(w, "0") == "" {
			zeroRun++
			longestZeroRun = max(longestZeroRun, zeroRun)
		} else {
			zeroRun = 0
		}
	}
	var addr string
	switch {
	case zz >= 0:
		if len(words) > 7 {
			return "" // "::" stands for at least one zero word
		}
		addr = strings.Join(words[:zz], ":") + "::" + strings.Join(words[zz+1:], ":")
	case len(words) == 8 && (multi || longestZeroRun < 2):
		addr = strings.Join(words, ":")
	default:
		return ""
	}
	ip := net.ParseIP(addr)
	if ip == nil || strings.Contains(addr, ".") {
		return ""
	}
	return ip.String() + "/" + prefixLen
}

// reversedNibblesToCIDR converts already-reversed IPv6 nibble labels plus an
// RPZ prefix length into a canonical IPv6 CIDR string, e.g.
// [2 0 0 1 0 d b 8], "48" -> "2001:0db8:0000:0000:0000:0000:0000:0000/48".
// It returns "" when the labels are not a valid nibble encoding (e.g. the
// legacy "ip6.arpa"-suffixed form), leaving the caller's legacy dotted-quad
// handling in place.
func reversedNibblesToCIDR(nibbles []string, prefixLen string) string {
	plen, err := strconv.Atoi(prefixLen)
	if err != nil || plen < 0 || plen > 128 {
		return ""
	}
	if len(nibbles) > 32 {
		return ""
	}
	isNibble := func(s string) bool {
		if len(s) != 1 {
			return false
		}
		c := s[0]
		return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
	}
	groups := make([]string, 8)
	for g := range groups {
		var sb strings.Builder
		for n := 0; n < 4; n++ {
			ch := "0"
			if idx := g*4 + n; idx < len(nibbles) {
				ch = nibbles[idx]
			}
			if !isNibble(ch) {
				return ""
			}
			sb.WriteByte(ch[0])
		}
		groups[g] = sb.String()
	}
	return strings.Join(groups, ":") + "/" + prefixLen
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
		// This server's own shorthand; any other TXT is Local Data.
		if strings.EqualFold(rdata, "drop") || strings.EqualFold(strings.Trim(rdata, "\""), "drop") {
			return ActionDrop, ""
		}
		if strings.EqualFold(rdata, "passthru") || strings.EqualFold(strings.Trim(rdata, "\""), "passthru") {
			return ActionPassThrough, ""
		}
		if strings.EqualFold(rdata, "tcp-only") || strings.EqualFold(strings.Trim(rdata, "\""), "tcp-only") {
			return ActionTCPOnly, ""
		}
		return ActionOverride, rdata
	default:
		// draft-vixie-dnsop-dns-rpz-00 §3.6: records of any other type are
		// Local Data answered for that type; they were read as NXDOMAIN (F881).
		return ActionOverride, rdata
	}
}

// addRule adds a rule to the engine's lookup structures.
func (e *Engine) addRule(rule *Rule) {
	switch rule.Trigger {
	case TriggerQNAME, TriggerNSDNAME:
		// NSDNAME triggers match nameserver names, not query names: sharing
		// one map let an NSDNAME passthru replace a QNAME block on the same
		// name, and an NSDNAME rule fire for queries of the name (F645).
		rules := e.qnameRules
		if rule.Trigger == TriggerNSDNAME {
			rules = e.nsdnameRules
		}
		key := strings.ToLower(rule.Pattern)
		if existing, ok := rules[key]; ok {
			// Keep the rule of the earlier policy zone
			if rule.Precedes(existing) {
				rules[key] = rule
			}
		} else {
			rules[key] = rule
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
		// NSIP triggers match nameserver addresses, not answer addresses:
		// stored with the response-IP rules they fired for every A/AAAA
		// answer in the prefix (F652).
		_, cidr, err := net.ParseCIDR(rule.Pattern)
		if err != nil {
			return
		}
		e.nsipRules = append(e.nsipRules, cidr)
		e.nsipActions = append(e.nsipActions, rule)
	}
}

// QNAMEPolicy evaluates RPZ policy for a query name.
// Returns the matching rule or nil if no policy applies.
func (e *Engine) QNAMEPolicy(qname string) *Rule {
	return e.namePolicy(qname, false)
}

// NSDNAMEPolicy evaluates RPZ NSDNAME triggers for a nameserver name.
func (e *Engine) NSDNAMEPolicy(nsName string) *Rule {
	return e.namePolicy(nsName, true)
}

func (e *Engine) namePolicy(qname string, nsdname bool) *Rule {
	if !e.enabled.Load() {
		return nil
	}

	atomic.AddUint64(&e.lookups, 1)

	e.mu.RLock()
	defer e.mu.RUnlock()
	rules := e.qnameRules
	if nsdname {
		rules = e.nsdnameRules
	}

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

	// Policy priority takes precedence over name specificity. On equal
	// priorities, keep the exact match or closest wildcard encountered first.
	best := rules[qname]

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

		// §5.2 before §5.3: an earlier zone's wildcard beats a later
		// zone's exact match; within a zone the exact match and then the
		// closest wildcard, met first, win.
		if rule, ok := rules[wildcard]; ok && (best == nil || rule.Precedes(best)) {
			best = rule
		}
	}

	if best != nil {
		atomic.AddUint64(&e.matches, 1)
	}
	return best
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
	return ipPolicy([]net.IP{clientIP}, e.clientIPRules, e.clientActions)
}

// ResponseIPPolicy evaluates RPZ policy based on response IP addresses.
func (e *Engine) ResponseIPPolicy(ips []net.IP) *Rule {
	if !e.enabled.Load() || len(ips) == 0 {
		return nil
	}

	e.mu.RLock()
	defer e.mu.RUnlock()
	return ipPolicy(ips, e.respIPRules, e.respActions)
}

// NSIPPolicy evaluates RPZ NSIP policy for the addresses of the nameservers
// in a response.
func (e *Engine) NSIPPolicy(ips []net.IP) *Rule {
	if !e.enabled.Load() || len(ips) == 0 {
		return nil
	}

	e.mu.RLock()
	defer e.mu.RUnlock()
	return ipPolicy(ips, e.nsipRules, e.nsipActions)
}

func ipPolicy(ips []net.IP, cidrs []*net.IPNet, actions []*Rule) *Rule {
	// L-8: as for ClientIPPolicy, prefer the highest-priority match
	// across all response IPs and all CIDR rules rather than the first
	// slice-order hit. Iterating IPs as the outer loop preserves the
	// original "any response IP matches" semantics; only the tie-break
	// on multiple matches changes.
	var best *Rule
	var bestNet *net.IPNet
	for _, ip := range ips {
		for i, cidr := range cidrs {
			if cidr.Contains(ip) && (best == nil || ipRuleBetter(actions[i], cidr, best, bestNet)) {
				best, bestNet = actions[i], cidr
			}
		}
	}
	return best
}

// ipRuleBetter reports whether rule r with trigger n is a better match than
// best with trigger bn (draft-vixie-dnsop-dns-rpz-00 §5): the earlier policy
// zone (§5.2), then the longest prefix (§5.6, an IPv4 prefix counting 96 more
// bits), then the smaller address (§5.7). Only the zone was compared, so a
// /24 block listed before a /32 PASSTHRU exception won (F887).
func ipRuleBetter(r *Rule, n *net.IPNet, best *Rule, bn *net.IPNet) bool {
	if r.Precedes(best) {
		return true
	}
	if best.Precedes(r) {
		return false
	}
	if a, b := internalPrefixLen(n), internalPrefixLen(bn); a != b {
		return a > b
	}
	return bytes.Compare(n.IP.To16(), bn.IP.To16()) < 0
}

func internalPrefixLen(n *net.IPNet) int {
	ones, bits := n.Mask.Size()
	if bits == 32 {
		ones += 96
	}
	return ones
}

// Precedes reports whether r comes from an earlier policy zone than o
// (draft-vixie-dnsop-dns-rpz-00 §5.2): a lower Priority, then an earlier
// position in the configured file list.
func (r *Rule) Precedes(o *Rule) bool {
	if r.Priority != o.Priority {
		return r.Priority < o.Priority
	}
	return r.Order < o.Order
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
	qn := len(e.qnameRules) + len(e.nsdnameRules)
	ci := len(e.clientIPRules)
	ri := len(e.respIPRules) + len(e.nsipRules)
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
	// addRule keeps the first rule on a priority tie, so a re-added pattern
	// would be dropped while the API answers 201. Replace an existing rule
	// unless it has a strictly better priority.
	key := strings.ToLower(rule.Pattern)
	if existing, ok := e.qnameRules[key]; ok && existing.Priority >= rule.Priority {
		delete(e.qnameRules, key)
	}
	e.addRule(rule)
}

// RemoveQNAMERule removes a QNAME rule by pattern and reports whether one
// existed.
func (e *Engine) RemoveQNAMERule(pattern string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := normalizeQNAMEPattern(pattern)
	_, existed := e.qnameRules[key]
	delete(e.qnameRules, key)
	return existed
}

// RemoveNSDNAMERule removes an NSDNAME rule by pattern and reports whether one
// existed. ListQNAMERules lists NSDNAME rules too, so they must be removable.
func (e *Engine) RemoveNSDNAMERule(pattern string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := normalizeQNAMEPattern(pattern)
	_, existed := e.nsdnameRules[key]
	delete(e.nsdnameRules, key)
	return existed
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

	rules := make([]*Rule, 0, len(e.qnameRules)+len(e.nsdnameRules))
	for _, r := range e.qnameRules {
		rules = append(rules, r)
	}
	for _, r := range e.nsdnameRules {
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
