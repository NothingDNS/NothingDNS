// Round-024 proof: Session.LastActivity is read and written through two
// DIFFERENT mutexes, so the access pair is a data race.
//
// WRITER (request path): UpdateActivity() writes s.LastActivity under s.mu.
// READER (background expiry sweep): cleanupExpiredSessions() reads
// session.LastActivity while holding only m.sessionsMu — never s.mu.
//
// Neither lock orders the other's access, so the read/write pair is
// unsynchronized per the Go memory model. time.Time is a 24-byte
// multi-word struct, so a torn read is possible (Go defines this as
// undefined behaviour), and `go test -race` reports it deterministically
// for a tight concurrent loop.
//
// Reachability: HandleDSORequest calls session.UpdateActivity() on the
// live DSO request path (dso.go:574), and the manager's cleanupLoop
// calls cleanupExpiredSessions() every 30s (dso.go:534/548). With a
// live session in the map, these run concurrently in production.
package dso

import (
	"sync"
	"testing"
	"time"
)

// newRaceHarness builds a Manager holding one live, non-expiring session
// plus a spare, mirroring a running server with an active DSO peer.
// inactivityTimeout is deliberately long so the sweep never removes or
// closes the session mid-test — we are exercising the read/write pair,
// not the expiry decision.
func newRaceHarness() (*Manager, *Session) {
	m := &Manager{
		sessions:          make(map[uint64]*Session),
		inactivityTimeout: time.Hour, // keep the session alive during the test
		maxSessions:       16,
	}
	s := &Session{
		ID:           1,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
	}
	m.sessions[s.ID] = s
	return m, s
}

// CONTROL: single-threaded update + read must NOT report a race. If this
// ever trips, the harness itself is broken (e.g. a copy of the map) and
// the concurrent proof below would be meaningless.
func TestSessionLastActivityRace_Control_SingleThreaded(t *testing.T) {
	m, s := newRaceHarness()
	for i := 0; i < 5000; i++ {
		s.UpdateActivity()
		_ = m.sessions[s.ID].LastActivity
	}
	if s.LastActivity.IsZero() {
		t.Fatal("control: LastActivity unexpectedly zero after updates")
	}
}

// PROOF: concurrent writer (request path) and reader (background sweep)
// touch LastActivity through different locks -> data race.
func TestSessionLastActivityRace_Concurrent(t *testing.T) {
	m, s := newRaceHarness()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Request-path writer: HandleDSORequest -> session.UpdateActivity().
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			s.UpdateActivity()
		}
	}()

	// Background expiry sweep: the unguarded reader.
	for i := 0; i < 20000; i++ {
		m.cleanupExpiredSessions()
	}

	close(stop)
	wg.Wait()
}
