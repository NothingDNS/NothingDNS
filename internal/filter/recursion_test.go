package filter

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
)

func TestRecursionPolicyAllowed(t *testing.T) {
	p, err := NewRecursionPolicy([]string{"192.168.1.0/24", "203.0.113.5", "2001:db8::1", " "}, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.168.1.0/24", "203.0.113.5/32", "2001:db8::1/128"}
	if got := p.Networks(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Networks() = %v, want %v", got, want)
	}
	for ip, allowed := range map[string]bool{
		"192.168.1.77": true, "203.0.113.5": true, "203.0.113.6": false,
		"2001:db8::1": true, "2001:db8::2": false, "::ffff:192.168.1.9": true,
	} {
		if got := p.Allowed(net.ParseIP(ip)); got != allowed {
			t.Errorf("Allowed(%s) = %v, want %v", ip, got, allowed)
		}
	}
	if p.Allowed(nil) {
		t.Error("a missing client IP must not be allowed")
	}
}

func TestRecursionPolicyAllowAllAndNil(t *testing.T) {
	all, err := NewRecursionPolicy(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if !all.Allowed(net.ParseIP("198.51.100.1")) || !all.AllowAll() {
		t.Error("allow-all policy must allow every client")
	}
	if err := all.Update([]string{"10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	if all.AllowAll() || all.Allowed(net.ParseIP("198.51.100.1")) {
		t.Error("Update must turn off allow-all")
	}

	var nilPolicy *RecursionPolicy
	if !nilPolicy.Allowed(net.ParseIP("198.51.100.1")) {
		t.Error("nil policy must allow every client")
	}
}

func TestRecursionPolicyRejectsInvalidEntries(t *testing.T) {
	for _, bad := range []string{"not-an-ip", "10.0.0.0/33", "300.1.1.1"} {
		if _, err := NewRecursionPolicy([]string{bad}, false); err == nil {
			t.Errorf("NewRecursionPolicy(%q) succeeded, want error", bad)
		}
	}
	p, _ := NewRecursionPolicy([]string{"10.0.0.0/8"}, false)
	if err := p.Update([]string{"bogus"}); err == nil {
		t.Error("Update with an invalid entry must fail")
	}
	if got := p.Networks(); !reflect.DeepEqual(got, []string{"10.0.0.0/8"}) {
		t.Errorf("failed Update changed the policy: %v", got)
	}
}

// Rules added at runtime to the always-present empty checker must refuse
// unmatched clients, exactly like rules loaded from the config.
func TestEmptyACLCheckerSemantics(t *testing.T) {
	a := NewEmptyACLChecker()
	if ok, _ := a.IsAllowed(net.ParseIP("198.51.100.1"), 1); !ok {
		t.Fatal("empty ACL must allow everyone")
	}
	if err := a.UpdateRules([]config.ACLRule{{Name: "lan", Action: "allow", Networks: []string{"10.0.0.0/8"}}}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := a.IsAllowed(net.ParseIP("10.1.1.1"), 1); !ok {
		t.Error("matching client must be allowed")
	}
	if ok, _ := a.IsAllowed(net.ParseIP("198.51.100.1"), 1); ok {
		t.Error("unmatched client must be refused once rules exist")
	}
	if err := a.UpdateRules(nil); err != nil {
		t.Fatal(err)
	}
	if ok, _ := a.IsAllowed(net.ParseIP("198.51.100.1"), 1); !ok {
		t.Error("clearing all rules must allow everyone again")
	}
}

func TestAccessPolicyFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := AccessPolicyFile(dir)
	if AccessPolicyFile("") != "" {
		t.Error("no data dir must mean no policy file")
	}
	if p, err := LoadAccessPolicy(path); err != nil || p != nil {
		t.Fatalf("missing file: got (%v, %v), want (nil, nil)", p, err)
	}

	in := &AccessPolicy{
		ACL:            []StoredACLRule{{Name: "block", Action: "deny", Networks: []string{"198.51.100.0/24"}, Types: []string{"ANY"}}},
		AllowRecursion: []string{"10.0.0.0/8"},
	}
	if err := SaveAccessPolicy(path, in); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("policy file mode = %v (%v), want 0600", info.Mode().Perm(), err)
	}
	out, err := LoadAccessPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out, in) {
		t.Fatalf("round trip = %+v, want %+v", out, in)
	}

	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte(`{"allow_recursion":["nope"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAccessPolicy(filepath.Join(dir, "bad.json")); err == nil {
		t.Error("an invalid stored policy must be rejected")
	}
	if err := SaveAccessPolicy("", in); err == nil {
		t.Error("saving without a path must fail")
	}
}

func TestACLRulesAcceptSingleIPsAndValidateRedirect(t *testing.T) {
	a := NewEmptyACLChecker()
	if err := a.UpdateRules([]config.ACLRule{
		{Name: "one-host", Action: "deny", Networks: []string{"203.0.113.9", "2001:db8::9"}},
		{Name: "portal", Action: "redirect", Networks: []string{"198.51.100.0/24"}, Redirect: "blocked.example.net."},
		{Name: "rest", Action: "allow", Networks: []string{"0.0.0.0/0", "::/0"}},
	}); err != nil {
		t.Fatal(err)
	}
	rules := a.GetRules()
	if got := rules[0].Networks; !reflect.DeepEqual(got, []string{"203.0.113.9/32", "2001:db8::9/128"}) {
		t.Errorf("single IPs stored as %v", got)
	}
	if ok, _ := a.IsAllowed(net.ParseIP("203.0.113.9"), 1); ok {
		t.Error("single-IP deny rule did not match")
	}
	if ok, target := a.IsAllowed(net.ParseIP("198.51.100.7"), 1); ok || target != "blocked.example.net." {
		t.Errorf("redirect rule = (%v, %q)", ok, target)
	}

	for _, bad := range []string{"192.0.2.1", "not a name!"} {
		err := a.UpdateRules([]config.ACLRule{{Name: "r", Action: "redirect", Networks: []string{"0.0.0.0/0"}, Redirect: bad}})
		if err == nil {
			t.Errorf("redirect target %q accepted", bad)
		}
	}
	if len(a.GetRules()) != 3 {
		t.Error("a rejected update must leave the previous rules in place")
	}
}
