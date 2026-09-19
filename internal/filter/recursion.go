package filter

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/nothingdns/nothingdns/internal/config"
)

// DefaultRecursionNetworks are the clients allowed to use recursion when the
// operator has not configured allow_recursion: loopback, RFC 1918, IPv6
// unique-local and link-local. Everyone else still receives answers from the
// server's own zones, but the server is not an open resolver.
var DefaultRecursionNetworks = []string{
	"127.0.0.0/8",
	"::1/128",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"fc00::/7",
	"fe80::/10",
}

// RecursionPolicy decides which clients may use recursion: upstream
// forwarding, iterative resolution and answers from the shared cache.
// Answers from the server's own zones are not affected.
type RecursionPolicy struct {
	mu       sync.RWMutex
	allowAll bool
	cidrs    []string
	networks []*net.IPNet
}

// NewRecursionPolicy builds a policy allowing the given networks. Entries may
// be CIDRs or single IP addresses. allowAll permits every client and ignores
// the network list.
func NewRecursionPolicy(networks []string, allowAll bool) (*RecursionPolicy, error) {
	p := &RecursionPolicy{}
	if err := p.set(networks, allowAll); err != nil {
		return nil, err
	}
	return p, nil
}

// ParseRecursionNetworks validates and normalizes allow_recursion entries,
// turning bare IP addresses into /32 or /128 networks and dropping
// duplicates.
func ParseRecursionNetworks(entries []string) ([]string, []*net.IPNet, error) {
	cidrs := make([]string, 0, len(entries))
	nets := make([]*net.IPNet, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		ipNet, err := ParseNetwork(entry)
		if err != nil {
			return nil, nil, fmt.Errorf("allow_recursion: invalid IP or CIDR %q", raw)
		}
		canonical := ipNet.String()
		if seen[canonical] {
			continue
		}
		seen[canonical] = true
		cidrs = append(cidrs, canonical)
		nets = append(nets, ipNet)
	}
	return cidrs, nets, nil
}

func (p *RecursionPolicy) set(networks []string, allowAll bool) error {
	cidrs, nets, err := ParseRecursionNetworks(networks)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.allowAll = allowAll
	p.cidrs = cidrs
	p.networks = nets
	p.mu.Unlock()
	return nil
}

// Replace sets both the allowed networks and the allow-all flag.
func (p *RecursionPolicy) Replace(networks []string, allowAll bool) error {
	if p == nil {
		return fmt.Errorf("recursion policy is not available")
	}
	return p.set(networks, allowAll)
}

// Update replaces the allowed networks and turns off allow-all.
func (p *RecursionPolicy) Update(networks []string) error {
	if p == nil {
		return fmt.Errorf("recursion policy is not available")
	}
	return p.set(networks, false)
}

// Allowed reports whether clientIP may use recursion. A nil policy allows
// everyone.
func (p *RecursionPolicy) Allowed(clientIP net.IP) bool {
	if p == nil {
		return true
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.allowAll {
		return true
	}
	ip := normalizeIP(clientIP)
	if ip == nil {
		return false
	}
	for _, n := range p.networks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Networks returns a copy of the allowed networks in canonical CIDR form.
func (p *RecursionPolicy) Networks() []string {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]string(nil), p.cidrs...)
}

// AllowAll reports whether every client may use recursion.
func (p *RecursionPolicy) AllowAll() bool {
	if p == nil {
		return true
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.allowAll
}

// AccessPolicy is the dashboard-managed access configuration persisted to
// the access policy file. When the file exists it takes precedence over the
// acl and allow_recursion settings in the config file.
type AccessPolicy struct {
	ACL            []StoredACLRule `json:"acl"`
	AllowRecursion []string        `json:"allow_recursion"`
}

// StoredACLRule is the on-disk form of an ACL rule.
type StoredACLRule struct {
	Name     string   `json:"name"`
	Action   string   `json:"action"`
	Networks []string `json:"networks"`
	Types    []string `json:"types,omitempty"`
	Redirect string   `json:"redirect,omitempty"`
}

// ConfigRules converts the stored rules to config rules.
func (p *AccessPolicy) ConfigRules() []config.ACLRule {
	rules := make([]config.ACLRule, 0, len(p.ACL))
	for _, r := range p.ACL {
		rules = append(rules, config.ACLRule{
			Name: r.Name, Action: r.Action, Networks: r.Networks, Types: r.Types, Redirect: r.Redirect,
		})
	}
	return rules
}

// StoredRules converts config rules to their on-disk form.
func StoredRules(rules []config.ACLRule) []StoredACLRule {
	out := make([]StoredACLRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, StoredACLRule{
			Name: r.Name, Action: r.Action, Networks: r.Networks, Types: r.Types, Redirect: r.Redirect,
		})
	}
	return out
}

const maxAccessPolicyFileSize = 1 << 20

// AccessPolicyFile returns where dashboard changes to the ACL and recursion
// allow list are stored: <dataDir>/access_policy.json, or "" when there is no
// data directory (changes then last until the next restart or reload).
func AccessPolicyFile(dataDir string) string {
	if strings.TrimSpace(dataDir) == "" {
		return ""
	}
	return filepath.Join(dataDir, "access_policy.json")
}

// LoadAccessPolicy reads a stored access policy. It returns (nil, nil) when
// the file does not exist.
func LoadAccessPolicy(path string) (*AccessPolicy, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxAccessPolicyFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxAccessPolicyFileSize {
		return nil, fmt.Errorf("access policy file %s exceeds %d bytes", path, maxAccessPolicyFileSize)
	}
	var policy AccessPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("parsing access policy file %s: %w", path, err)
	}
	if _, err := NewACLChecker(policy.ConfigRules(), true); err != nil {
		return nil, fmt.Errorf("access policy file %s: %w", path, err)
	}
	if _, _, err := ParseRecursionNetworks(policy.AllowRecursion); err != nil {
		return nil, fmt.Errorf("access policy file %s: %w", path, err)
	}
	return &policy, nil
}

// SaveAccessPolicy atomically writes the policy with owner-only permissions.
func SaveAccessPolicy(path string, policy *AccessPolicy) error {
	if path == "" {
		return fmt.Errorf("no access policy file configured (set storage.data_dir)")
	}
	if policy.ACL == nil {
		policy.ACL = []StoredACLRule{}
	}
	if policy.AllowRecursion == nil {
		policy.AllowRecursion = []string{}
	}
	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".access_policy-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
