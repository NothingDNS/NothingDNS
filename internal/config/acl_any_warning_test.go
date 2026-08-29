package config

import (
	"strings"
	"testing"
)

// TestWarnACLAllowOnlyANY is the regression for an ACL trap that silently
// refuses every client. `types` filters an ACL rule by query type and "ANY" is
// QTYPE 255, not a wildcard — so an `allow` rule carrying only it matches no
// A/AAAA query, every ordinary query falls through to the default, and with
// recursion enabled that default is deny. The shipped example and three docs
// all showed the pattern, so it was the natural thing to write.
func TestWarnACLAllowOnlyANY(t *testing.T) {
	tests := []struct {
		name     string
		rule     ACLRule
		wantWarn bool
		why      string
	}{
		{
			name:     "allow scoped to ANY only",
			rule:     ACLRule{Name: "allow-private", Action: "allow", Networks: []string{"10.0.0.0/8"}, Types: []string{"ANY"}},
			wantWarn: true,
			why:      "matches nothing an ordinary client sends",
		},
		{
			name:     "allow scoped to ANY, lowercase",
			rule:     ACLRule{Name: "allow-private", Action: "allow", Networks: []string{"10.0.0.0/8"}, Types: []string{"any"}},
			wantWarn: true,
			why:      "type names are case-insensitive",
		},
		{
			name:     "allow with no types",
			rule:     ACLRule{Name: "allow-all-types", Action: "allow", Networks: []string{"10.0.0.0/8"}},
			wantWarn: false,
			why:      "omitting types is the correct way to match every type",
		},
		{
			name:     "allow scoped to ANY plus a real type",
			rule:     ACLRule{Name: "allow-some", Action: "allow", Networks: []string{"10.0.0.0/8"}, Types: []string{"ANY", "A"}},
			wantWarn: false,
			why:      "the rule still matches A queries",
		},
		{
			name:     "deny scoped to ANY",
			rule:     ACLRule{Name: "deny-any", Action: "deny", Networks: []string{"0.0.0.0/0"}, Types: []string{"ANY"}},
			wantWarn: false,
			why:      "a legitimate anti-amplification measure",
		},
		{
			name:     "allow scoped to a real type",
			rule:     ACLRule{Name: "allow-a", Action: "allow", Networks: []string{"10.0.0.0/8"}, Types: []string{"A"}},
			wantWarn: false,
			why:      "deliberate narrowing",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{ACL: []ACLRule{tc.rule}}
			out := captureWarnings(t, cfg.warnACLAllowOnlyANY)
			gotWarn := strings.Contains(out, "QTYPE ANY")
			if gotWarn != tc.wantWarn {
				t.Errorf("warned = %v, want %v (%s); output:\n%s", gotWarn, tc.wantWarn, tc.why, out)
			}
		})
	}
}

// TestValidateIsSideEffectFree pins why the warning lives on the load path:
// Validate() runs more than once per invocation (loadConfig, then the explicit
// -validate-config call, then ValidateProduction), so a warning emitted from
// inside it is printed once per call.
func TestValidateIsSideEffectFree(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ACL = []ACLRule{{
		Name: "allow-private", Action: "allow",
		Networks: []string{"10.0.0.0/8"}, Types: []string{"ANY"},
	}}

	out := captureWarnings(t, func() {
		cfg.Validate()
		cfg.Validate()
	})

	if out != "" {
		t.Errorf("Validate() emitted output; it must stay free of side effects:\n%s", out)
	}
}
