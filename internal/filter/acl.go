package filter

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
)

// validateACLAction rejects any ACL action that is not one of the supported
// verbs. Without this an operator typo (e.g. action: "block"/"reject"/"drop")
// compiled cleanly, matched the client's network, then did nothing — the
// switch in IsAllowed has no default case, so the rule fell through and the
// query was permitted by the default policy. A control meant to DENY traffic
// silently failed open with no error at load or -validate-config time. Now such
// a config is rejected up front.
func validateACLAction(ruleName, action, redirect string) error {
	switch action {
	case "allow", "deny":
		return nil
	case "redirect":
		if redirect == "" {
			return fmt.Errorf("ACL rule %q: action %q requires a non-empty redirect target", ruleName, action)
		}
		// The redirect answers with a CNAME to this target, so it must be a
		// domain name; an IP address would become a bogus CNAME.
		if net.ParseIP(strings.TrimSuffix(redirect, ".")) != nil {
			return fmt.Errorf("ACL rule %q: redirect target %q must be a domain name, not an IP address", ruleName, redirect)
		}
		if _, err := protocol.ParseName(redirect); err != nil {
			return fmt.Errorf("ACL rule %q: redirect target %q is not a valid domain name", ruleName, redirect)
		}
		return nil
	case "":
		return fmt.Errorf("ACL rule %q: missing action (expected allow, deny, or redirect)", ruleName)
	default:
		return fmt.Errorf("ACL rule %q: unknown action %q (expected allow, deny, or redirect)", ruleName, action)
	}
}

// compiledRule is a pre-processed ACL rule with parsed networks and types.
type compiledRule struct {
	Name     string
	Networks []*net.IPNet
	Types    map[uint16]bool // empty means all types
	Action   string          // "allow", "deny", "redirect"
	Redirect string
}

// ACLChecker evaluates ACL rules against client IPs and query types.
type ACLChecker struct {
	mu            sync.RWMutex
	rules         []compiledRule
	denyByDefault bool
	// denyUnmatched refuses clients that match no rule once at least one
	// rule exists, while an empty rule set still allows everyone. Used by
	// the checker the server always installs, so rules added later from the
	// dashboard behave like rules loaded from the config file.
	denyUnmatched bool
}

// NewEmptyACLChecker returns a checker with no rules that allows every
// client. Rules added later through UpdateRules take effect with the usual
// semantics: first match wins, and a client matching no rule is refused.
func NewEmptyACLChecker() *ACLChecker {
	return &ACLChecker{denyUnmatched: true}
}

// NewACLChecker creates an ACL checker from configuration rules.
// Returns nil if rules is empty (allow-all default), unless denyByDefault is true.
// When denyByDefault is true, an empty rule set results in deny-by-default behavior.
func NewACLChecker(rules []config.ACLRule, denyByDefault bool) (*ACLChecker, error) {
	if len(rules) == 0 {
		if denyByDefault {
			return &ACLChecker{rules: nil, denyByDefault: true}, nil
		}
		return nil, nil
	}

	compiled, err := compileACLRules(rules)
	if err != nil {
		return nil, err
	}

	return &ACLChecker{rules: compiled, denyByDefault: denyByDefault}, nil
}

// compileACLRules validates rules and pre-parses their networks and types.
// Networks may be CIDRs or single IP addresses (stored as /32 or /128).
func compileACLRules(rules []config.ACLRule) ([]compiledRule, error) {
	compiled := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		cr := compiledRule{
			Name:     r.Name,
			Action:   strings.ToLower(strings.TrimSpace(r.Action)),
			Redirect: strings.TrimSpace(r.Redirect),
		}

		for _, entry := range r.Networks {
			ipNet, err := ParseNetwork(entry)
			if err != nil {
				return nil, fmt.Errorf("ACL rule %q: invalid network %q: %w", r.Name, entry, err)
			}
			cr.Networks = append(cr.Networks, ipNet)
		}

		if len(r.Types) > 0 {
			cr.Types = make(map[uint16]bool, len(r.Types))
			for _, t := range r.Types {
				upper := strings.ToUpper(strings.TrimSpace(t))
				qtype, ok := protocol.StringToType[upper]
				if !ok {
					return nil, fmt.Errorf("ACL rule %q: unknown query type %q", r.Name, t)
				}
				cr.Types[qtype] = true
			}
		}

		if err := validateACLAction(cr.Name, cr.Action, cr.Redirect); err != nil {
			return nil, err
		}
		compiled = append(compiled, cr)
	}
	return compiled, nil
}

// ParseNetwork parses a CIDR or a single IP address (as a /32 or /128).
func ParseNetwork(entry string) (*net.IPNet, error) {
	entry = strings.TrimSpace(entry)
	if !strings.Contains(entry, "/") {
		ip := net.ParseIP(entry)
		if ip == nil {
			return nil, fmt.Errorf("not an IP address or CIDR")
		}
		if v4 := ip.To4(); v4 != nil {
			return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
	}
	_, ipNet, err := net.ParseCIDR(entry)
	if err != nil {
		return nil, fmt.Errorf("not an IP address or CIDR")
	}
	return ipNet, nil
}

// IsAllowed checks if a client IP is allowed to make a query of the given type.
// Returns (allowed bool, redirectTarget string).
// If no rule matches, the default is allow, unless denyByDefault is set.
func (a *ACLChecker) IsAllowed(clientIP net.IP, queryType uint16) (bool, string) {
	if a == nil {
		return true, ""
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	if len(a.rules) == 0 {
		if a.denyByDefault {
			return false, ""
		}
		return true, ""
	}

	ip := normalizeIP(clientIP)

	for _, rule := range a.rules {
		if !matchesNetworks(ip, rule.Networks) {
			continue
		}
		if len(rule.Types) > 0 && !rule.Types[queryType] {
			continue
		}

		switch rule.Action {
		case "allow":
			return true, ""
		case "deny":
			return false, ""
		case "redirect":
			return false, rule.Redirect
		}
	}

	// Default: allow if no rule matched, unless denyByDefault is set
	if a.denyByDefault || a.denyUnmatched {
		return false, ""
	}
	return true, ""
}

// UpdateRules replaces the current ACL rules with new rules.
func (a *ACLChecker) UpdateRules(rules []config.ACLRule) error {
	if a == nil {
		return fmt.Errorf("ACLChecker is nil")
	}
	compiled, err := compileACLRules(rules)
	if err != nil {
		return err
	}

	a.mu.Lock()
	a.rules = compiled
	a.mu.Unlock()

	return nil
}

// Reload reloads ACL rules from config.
func (a *ACLChecker) Reload(rules []config.ACLRule) error {
	return a.UpdateRules(rules)
}

// GetRules returns the current ACL rules in config format.
func (a *ACLChecker) GetRules() []config.ACLRule {
	if a == nil {
		return nil
	}
	a.mu.RLock()
	defer a.mu.RUnlock()

	rules := make([]config.ACLRule, 0, len(a.rules))
	for _, r := range a.rules {
		rule := config.ACLRule{
			Name:     r.Name,
			Action:   r.Action,
			Networks: make([]string, 0, len(r.Networks)),
		}
		if r.Redirect != "" {
			rule.Redirect = r.Redirect
		}
		for _, n := range r.Networks {
			rule.Networks = append(rule.Networks, n.String())
		}
		if len(r.Types) > 0 {
			rule.Types = make([]string, 0, len(r.Types))
			for t := range r.Types {
				rule.Types = append(rule.Types, protocol.TypeString(t))
			}
			sort.Strings(rule.Types)
		}
		rules = append(rules, rule)
	}
	return rules
}

// normalizeIP ensures consistent IP representation for matching.
// IPv4-mapped IPv6 addresses are converted to plain IPv4.
func normalizeIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}

// matchesNetworks checks if an IP falls within any of the given networks.
func matchesNetworks(ip net.IP, networks []*net.IPNet) bool {
	if len(networks) == 0 {
		return true // no network restriction means match all
	}
	for _, n := range networks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
