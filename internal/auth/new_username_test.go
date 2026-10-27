package auth

import (
	"strings"
	"testing"
)

// CreateUser refuses unreasonably long names; ValidateUsername, which also
// loads stored users, stays as it was. A name with '/' stays valid: the API
// addresses users by their escaped path (F761).
func TestCreateUserRefusesHugeNames(t *testing.T) {
	s, err := NewStore(&Config{Secret: "0123456789abcdef0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{strings.Repeat("u", MaxNewUsernameBytes+1)} {
		if _, err := s.CreateUser(name, "Passw0rd!Strong-x", RoleViewer); err == nil {
			t.Errorf("CreateUser(%.20q) accepted", name)
		}
	}
	for _, name := range []string{"alice", "a", "team/alice", "dns.admin@example.com", strings.Repeat("u", MaxNewUsernameBytes)} {
		if _, err := s.CreateUser(name, "Passw0rd!Strong-x", RoleViewer); err != nil {
			t.Errorf("CreateUser(%.20q): %v", name, err)
		}
	}
	// A name stored before these rules still validates.
	if err := ValidateUsername(strings.Repeat("u", 300)); err != nil {
		t.Errorf("ValidateUsername must not reject stored long names: %v", err)
	}
}
