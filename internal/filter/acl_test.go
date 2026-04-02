package filter

import (
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestNewACLChecker_EmptyRules(t *testing.T) {
	ac, err := NewACLChecker(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ac != nil {
		t.Error("expected nil ACLChecker for empty rules")
	}
}

func TestNewACLChecker_InvalidCIDR(t *testing.T) {
	_, err := NewACLChecker([]config.ACLRule{
		{Name: "bad", Networks: []string{"not-a-cidr"}, Action: "allow"},
	})
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestNewACLChecker_InvalidType(t *testing.T) {
	_, err := NewACLChecker([]config.ACLRule{
		{Name: "bad", Networks: []string{"10.0.0.0/8"}, Types: []string{"INVALID"}, Action: "allow"},
	})
	if err == nil {
		t.Error("expected error for invalid type")
	}
}

func TestACLChecker_IsAllowed_AllowAll(t *testing.T) {
	ac, _ := NewACLChecker(nil)
	allowed, redirect := ac.IsAllowed(net.ParseIP("10.0.0.1"), protocol.TypeA)
	if !allowed || redirect != "" {
		t.Error("nil checker should allow all")
	}
}

func TestACLChecker_IsAllowed_DenyNetwork(t *testing.T) {
	ac, err := NewACLChecker([]config.ACLRule{
		{Name: "block-bad", Networks: []string{"192.168.1.0/24"}, Action: "deny"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	allowed, _ := ac.IsAllowed(net.ParseIP("192.168.1.100"), protocol.TypeA)
	if allowed {
		t.Error("IP in denied network should be blocked")
	}

	allowed, _ = ac.IsAllowed(net.ParseIP("10.0.0.1"), protocol.TypeA)
	if !allowed {
		t.Error("IP not in denied network should be allowed")
	}
}

func TestACLChecker_IsAllowed_AllowThenDeny(t *testing.T) {
	ac, err := NewACLChecker([]config.ACLRule{
		{Name: "allow-admin", Networks: []string{"10.0.0.1/32"}, Action: "allow"},
		{Name: "deny-all", Networks: []string{"10.0.0.0/8"}, Action: "deny"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Specific allow rule should match first
	allowed, _ := ac.IsAllowed(net.ParseIP("10.0.0.1"), protocol.TypeA)
	if !allowed {
		t.Error("10.0.0.1 should be allowed by specific rule")
	}

	// Other IPs in 10.0.0.0/8 should be denied
	allowed, _ = ac.IsAllowed(net.ParseIP("10.0.0.2"), protocol.TypeA)
	if allowed {
		t.Error("10.0.0.2 should be denied by catch-all rule")
	}
}

func TestACLChecker_IsAllowed_TypeFilter(t *testing.T) {
	ac, err := NewACLChecker([]config.ACLRule{
		{Name: "only-axfr", Networks: []string{"10.0.0.0/8"}, Types: []string{"AXFR"}, Action: "deny"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// AXFR from 10.x should be denied
	allowed, _ := ac.IsAllowed(net.ParseIP("10.0.0.1"), protocol.TypeAXFR)
	if allowed {
		t.Error("AXFR should be denied")
	}

	// A query from 10.x should be allowed (not matching the type filter)
	allowed, _ = ac.IsAllowed(net.ParseIP("10.0.0.1"), protocol.TypeA)
	if !allowed {
		t.Error("A query should be allowed (type doesn't match rule)")
	}
}

func TestACLChecker_IsAllowed_Redirect(t *testing.T) {
	ac, err := NewACLChecker([]config.ACLRule{
		{Name: "redirect-guest", Networks: []string{"172.16.0.0/12"}, Action: "redirect", Redirect: "portal.example.com"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	allowed, redirect := ac.IsAllowed(net.ParseIP("172.16.0.5"), protocol.TypeA)
	if allowed {
		t.Error("redirected query should not be allowed")
	}
	if redirect != "portal.example.com" {
		t.Errorf("expected redirect target 'portal.example.com', got %q", redirect)
	}
}

func TestACLChecker_IsAllowed_IPv6(t *testing.T) {
	ac, err := NewACLChecker([]config.ACLRule{
		{Name: "deny-v6", Networks: []string{"2001:db8::/32"}, Action: "deny"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	allowed, _ := ac.IsAllowed(net.ParseIP("2001:db8::1"), protocol.TypeAAAA)
	if allowed {
		t.Error("IPv6 in denied range should be blocked")
	}

	allowed, _ = ac.IsAllowed(net.ParseIP("::1"), protocol.TypeAAAA)
	if !allowed {
		t.Error("IPv6 not in denied range should be allowed")
	}
}

func TestACLChecker_IsAllowed_IPv4MappedIPv6(t *testing.T) {
	ac, err := NewACLChecker([]config.ACLRule{
		{Name: "deny-10", Networks: []string{"10.0.0.0/8"}, Action: "deny"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// IPv4-mapped IPv6 address should match the IPv4 CIDR
	allowed, _ := ac.IsAllowed(net.ParseIP("::ffff:10.0.0.1"), protocol.TypeA)
	if allowed {
		t.Error("IPv4-mapped IPv6 in denied range should be blocked")
	}
}

func TestACLChecker_IsAllowed_NoNetworkRestriction(t *testing.T) {
	ac, err := NewACLChecker([]config.ACLRule{
		{Name: "deny-axfr-all", Types: []string{"AXFR"}, Action: "deny"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// AXFR from any IP should be denied
	allowed, _ := ac.IsAllowed(net.ParseIP("1.2.3.4"), protocol.TypeAXFR)
	if allowed {
		t.Error("AXFR from any IP should be denied")
	}
}
