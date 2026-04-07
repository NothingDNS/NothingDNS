package filter

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
)

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
	mu    sync.RWMutex
	rules []compiledRule
}

// NewACLChecker creates an ACL checker from configuration rules.
// Returns nil if rules is empty (allow-all default).
func NewACLChecker(rules []config.ACLRule) (*ACLChecker, error) {
	if len(rules) == 0 {
		return nil, nil
	}

	compiled := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		cr := compiledRule{
			Name:     r.Name,
			Action:   strings.ToLower(r.Action),
			Redirect: r.Redirect,
		}

		// Parse networks
		for _, cidr := range r.Networks {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("ACL rule %q: invalid CIDR %q: %w", r.Name, cidr, err)
			}
			cr.Networks = append(cr.Networks, ipNet)
		}

		// Parse types
		if len(r.Types) > 0 {
			cr.Types = make(map[uint16]bool, len(r.Types))
			for _, t := range r.Types {
				upper := strings.ToUpper(t)
				if qtype, ok := protocol.StringToType[upper]; ok {
					cr.Types[qtype] = true
				} else {
					return nil, fmt.Errorf("ACL rule %q: unknown query type %q", r.Name, t)
				}
			}
		}

		compiled = append(compiled, cr)
	}

	return &ACLChecker{rules: compiled}, nil
}

// IsAllowed checks if a client IP is allowed to make a query of the given type.
// Returns (allowed bool, redirectTarget string).
// If no rule matches, the default is allow.
func (a *ACLChecker) IsAllowed(clientIP net.IP, queryType uint16) (bool, string) {
	if a == nil {
		return true, ""
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	if len(a.rules) == 0 {
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

	// Default: allow if no rule matched
	return true, ""
}

// UpdateRules replaces the current ACL rules with new rules.
func (a *ACLChecker) UpdateRules(rules []config.ACLRule) error {
	compiled := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		cr := compiledRule{
			Name:     r.Name,
			Action:   strings.ToLower(r.Action),
			Redirect: r.Redirect,
		}

		// Parse networks
		for _, cidr := range r.Networks {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return fmt.Errorf("ACL rule %q: invalid CIDR %q: %w", r.Name, cidr, err)
			}
			cr.Networks = append(cr.Networks, ipNet)
		}

		// Parse types
		if len(r.Types) > 0 {
			cr.Types = make(map[uint16]bool, len(r.Types))
			for _, t := range r.Types {
				upper := strings.ToUpper(t)
				if qtype, ok := protocol.StringToType[upper]; ok {
					cr.Types[qtype] = true
				} else {
					return fmt.Errorf("ACL rule %q: unknown query type %q", r.Name, t)
				}
			}
		}

		compiled = append(compiled, cr)
	}

	a.mu.Lock()
	a.rules = compiled
	a.mu.Unlock()

	return nil
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
