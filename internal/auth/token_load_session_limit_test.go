package auth

import (
	"path/filepath"
	"testing"
	"time"
)

func tokenLoadLimitStore(cap int) *Store {
	return &Store{
		users: map[string]*User{
			"admin": {Username: "admin", Role: RoleAdmin},
		},
		tokens:             make(map[string]*Token),
		secret:             []byte("token-load-limit-test-secret"),
		maxSessionsPerUser: cap,
		activeSessions:     make(map[string]int),
	}
}

func TestLoadTokensSignedAppliesCurrentSessionLimit(t *testing.T) {
	source := tokenLoadLimitStore(3)
	base := time.Date(2026, 11, 3, 19, 0, 0, 0, time.UTC)
	tokens := make([]*Token, 0, 3)
	for i := 0; i < 3; i++ {
		token, err := source.GenerateToken("admin", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		source.tokens[token.Token].CreatedAt = base.Add(time.Duration(i) * time.Second)
		tokens = append(tokens, token)
	}
	path := filepath.Join(t.TempDir(), "tokens.enc")
	if err := source.SaveTokensSigned(path); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		cap  int
		want int
	}{
		{name: "unlimited", cap: 0, want: 3},
		{name: "one", cap: 1, want: 1},
		{name: "two", cap: 2, want: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restarted := tokenLoadLimitStore(tc.cap)
			if err := restarted.LoadTokensSigned(path); err != nil {
				t.Fatal(err)
			}
			if got := len(restarted.tokens); got != tc.want {
				t.Fatalf("loaded tokens = %d, want %d", got, tc.want)
			}
			if got := restarted.activeSessions["admin"]; got != tc.want {
				t.Fatalf("active sessions = %d, want %d", got, tc.want)
			}
			for i, token := range tokens {
				_, err := restarted.ValidateToken(token.Token)
				wantValid := tc.cap == 0 || i >= len(tokens)-tc.cap
				if (err == nil) != wantValid {
					t.Errorf("token %d valid = %t, want %t", i, err == nil, wantValid)
				}
			}
		})
	}
}
