package resolver

import "testing"

func TestResolverInfoFromCapabilitiesCopiesInput(t *testing.T) {
	caps := []string{"dnssec", "filtering"}
	info := ResolverInfoFromCapabilities("resolver", caps)
	caps[0] = "mutated"
	if got := info.Capabilities[0]; got != "dnssec" {
		t.Fatalf("constructor aliased caller capabilities: got %q", got)
	}
}
