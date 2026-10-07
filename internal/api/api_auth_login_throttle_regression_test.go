package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/nothingdns/nothingdns/internal/auth"
)

// loginThrottleGateBody blocks the first Read (which happens after the
// handler's per-IP rate-limit admission) until release is closed.
type loginThrottleGateBody struct {
	arrived, release chan struct{}
	once             sync.Once
	r                *strings.Reader
}

func (g *loginThrottleGateBody) Read(p []byte) (int, error) {
	g.once.Do(func() { close(g.arrived); <-g.release })
	return g.r.Read(p)
}

// TestHandleLogin_ConcurrentGuessesFromOneIPAreThrottled is the regression for
// F272: parallel login attempts from one IP all passed checkRateLimit before
// any failure was recorded, bypassing the per-IP progressive delay. Ordering
// is gated: each request starts only after the previous one is parked inside
// the handler (or has finished).
func TestHandleLogin_ConcurrentGuessesFromOneIPAreThrottled(t *testing.T) {
	store := newAuthStoreWithUser(t, "alice", "correct-horse-1", auth.RoleAdmin)
	s := newServerWithAuth(store)

	const n = 6
	release := make(chan struct{})
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		password := fmt.Sprintf("wrong-guess-%d", i)
		if i == n-1 {
			password = "correct-horse-1" // must not be evaluated either
		}
		g := &loginThrottleGateBody{arrived: make(chan struct{}), release: release,
			r: strings.NewReader(fmt.Sprintf(`{"username":"alice","password":%q}`, password))}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", g)
		req.RemoteAddr = "203.0.113.9:40000"
		done := make(chan struct{})
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer close(done)
			rec := httptest.NewRecorder()
			s.handleLogin(rec, req)
			codes[i] = rec.Code
		}(i)
		select {
		case <-g.arrived:
		case <-done:
		}
	}
	close(release)
	wg.Wait()

	if codes[0] != http.StatusUnauthorized {
		t.Fatalf("first guess: got %d, want 401 (codes=%v)", codes[0], codes)
	}
	for i := 1; i < n; i++ {
		if codes[i] != http.StatusTooManyRequests {
			t.Fatalf("concurrent guess %d: got %d, want 429 (codes=%v)", i, codes[i], codes)
		}
	}

	s.loginLimiter.mu.Lock()
	leaked := len(s.loginLimiter.inFlight)
	s.loginLimiter.mu.Unlock()
	if leaked != 0 {
		t.Fatalf("in-flight login slots leaked: %d", leaked)
	}
}

// TestHandleBootstrap_OldPasswordGuessesAreThrottled is the regression for
// F273: the bootstrap password-reset branch verified old_password without the
// login rate limiter, giving an unthrottled password oracle.
func TestHandleBootstrap_OldPasswordGuessesAreThrottled(t *testing.T) {
	store := newAuthStoreWithUser(t, "alice", "correct-horse-1", auth.RoleAdmin)
	s := newServerWithAuth(store)

	post := func(oldPassword string) int {
		body := fmt.Sprintf(`{"username":"alice","password":"new-password-1","old_password":%q}`, oldPassword)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap", strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:40000"
		rec := httptest.NewRecorder()
		s.handleBootstrap(rec, req)
		return rec.Code
	}

	if got := post("wrong-guess-0"); got != http.StatusUnauthorized {
		t.Fatalf("first wrong guess: got %d, want 401", got)
	}
	if got := post("wrong-guess-1"); got != http.StatusTooManyRequests {
		t.Fatalf("second wrong guess: got %d, want 429", got)
	}
	if got := post("correct-horse-1"); got != http.StatusTooManyRequests {
		t.Fatalf("correct guess while throttled: got %d, want 429", got)
	}
	if !store.VerifyUserPassword("alice", "correct-horse-1") {
		t.Fatal("password changed while throttled")
	}
}
