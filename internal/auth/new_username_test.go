package auth

import (
	"strings"
	"testing"
)

// CreateUser refuses names the API cannot address or that are unreasonably
// long; ValidateUsername, which also loads stored users, stays as it was (F761).
func TestCreateUserRefusesUnaddressableAndHugeNames(t *testing.T) {
	s, err := NewStore(&Config{Secret: "0123456789abcdef0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a/b", "/", strings.Repeat("u", MaxNewUsernameBytes+1)} {
		if _, err := s.CreateUser(name, "Passw0rd!Strong-x", RoleViewer); err == nil {
			t.Errorf("CreateUser(%.20q) accepted", name)
		}
	}
	for _, name := range []string{"alice", "a", "dns.admin@example.com", strings.Repeat("u", MaxNewUsernameBytes)} {
		if _, err := s.CreateUser(name, "Passw0rd!Strong-x", RoleViewer); err != nil {
			t.Errorf("CreateUser(%.20q): %v", name, err)
		}
	}
	// A name stored before these rules still validates.
	if err := ValidateUsername(strings.Repeat("u", 300)); err != nil {
		t.Errorf("ValidateUsername must not reject stored long names: %v", err)
	}
}
