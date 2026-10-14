package auth

import (
	"fmt"
	"testing"
	"time"
)

func f714Store(t *testing.T, cap int) *Store {
	s, err := NewStore(&Config{Secret: "0123456789abcdef0123456789abcdef", MaxSessionsPerUser: cap})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser("alice", "correct-horse-1", RoleViewer); err != nil {
		t.Fatal(err)
	}
	return s
}

// An expired token that is never presented again must not stay in memory once
// the same user logs in again.
func TestF714ExpiredTokensArePurged(t *testing.T) {
	s := f714Store(t, 0)
	// control: a live token stays
	if _, err := s.GenerateToken("alice", time.Hour); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		if _, err := s.GenerateToken("alice", -time.Second); err != nil { // already expired
			t.Fatal(err)
		}
	}
	if _, err := s.GenerateToken("alice", time.Hour); err != nil {
		t.Fatal(err)
	}
	s.mu.RLock()
	n := len(s.tokens)
	s.mu.RUnlock()
	fmt.Printf("EXPECTED: 2 live tokens | ACTUAL: %d tokens held\n", n)
	if n != 2 {
		fmt.Println("PROBLEM CONFIRMED")
		t.Fatal("expired tokens retained")
	}
	fmt.Println("PROBLEM NOT REPRODUCED")
}

func TestF714SessionCounterFollowsPurge(t *testing.T) {
	s := f714Store(t, 2)
	for i := 0; i < 2; i++ {
		if _, err := s.GenerateToken("alice", -time.Second); err != nil {
			t.Fatal(err)
		}
	}
	live, err := s.GenerateToken("alice", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.RLock()
	n, c := len(s.tokens), s.activeSessions["alice"]
	s.mu.RUnlock()
	if n != 1 || c != 1 {
		t.Fatalf("tokens=%d sessions=%d, want 1/1", n, c)
	}
	if _, err := s.ValidateToken(live.Token); err != nil {
		t.Fatalf("live token rejected: %v", err)
	}
	// a second live session fits under the cap of 2 without evicting the first
	if _, err := s.GenerateToken("alice", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ValidateToken(live.Token); err != nil {
		t.Fatalf("first live token evicted: %v", err)
	}
}

func TestF714UnknownUserStillFails(t *testing.T) {
	s := f714Store(t, 0)
	if _, err := s.GenerateToken("nobody", time.Hour); err == nil {
		t.Fatal("unknown user must still fail")
	}
}
