package resolver

import "testing"

func TestNewResolverCopiesCustomRootHints(t *testing.T) {
	hints := []RootHint{{
		Name: "a.root.example.",
		IPv4: []string{"192.0.2.53"},
		IPv6: []string{"2001:db8::53"},
	}}
	r := NewResolver(Config{Hints: hints}, nil, nil)
	hints[0].Name = "mutated.example."
	hints[0].IPv4[0] = "198.51.100.53"
	hints[0].IPv6[0] = "2001:db8::99"

	got := r.hints[0]
	if got.Name != "a.root.example." || got.IPv4[0] != "192.0.2.53" || got.IPv6[0] != "2001:db8::53" {
		t.Fatalf("resolver hints changed through caller input: %#v", got)
	}
}
