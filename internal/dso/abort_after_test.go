package dso

import (
	"net"
	"testing"
	"time"
)

// RFC 8490 §6.4.1: an inactive session is aborted after five seconds or twice
// the inactivity timeout, whichever is greater — not at the timeout itself,
// where a client closing on time would be cut (F743).
func TestInactiveSessionAbortedAfterTwiceTheTimeout(t *testing.T) {
	const inactivity = 10 * time.Second
	m := NewManager(Config{Enabled: true, AllowPlainTCP: true, MaxSessions: 10, InactivityTimeout: inactivity}, nil)
	if got := m.AbortAfter(); got != 2*inactivity {
		t.Fatalf("AbortAfter = %v, want %v", got, 2*inactivity)
	}
	if got := NewManager(Config{Enabled: true, InactivityTimeout: time.Second}, nil).AbortAfter(); got != 5*time.Second {
		t.Fatalf("AbortAfter with a 1 s timeout = %v, want 5 s", got)
	}
	session := func(idle time.Duration) *Session {
		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() })
		s, err := m.CreateSession(a)
		if err != nil {
			t.Fatal(err)
		}
		s.LastActivity = time.Now().Add(-idle)
		return s
	}
	late, early := session(25*time.Second), session(15*time.Second)
	m.cleanupExpiredSessions()
	if !late.IsClosed() {
		t.Error("session idle 2.5x the timeout was not aborted")
	}
	if early.IsClosed() {
		t.Error("session idle 1.5x the timeout was aborted")
	}
}
