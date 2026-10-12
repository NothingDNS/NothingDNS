package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/auth"
)

// F708: login throttling and the API rate limiter keyed on the full client
// address, so a brute-force client holding an IPv6 /64 (2^64 addresses)
// changed source address for every guess and was never delayed or locked out.
func TestLoginThrottleAggregatesIPv6Prefix(t *testing.T) {
	store := newAuthStoreWithUser(t, "alice", "correct-horse-1", auth.RoleAdmin)
	s := newServerWithAuth(store)

	try := func(remote string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login",
			strings.NewReader(`{"username":"alice","password":"wrong-guess"}`))
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		s.handleLogin(rec, req)
		return rec.Code
	}
	if got := try("[2001:db8:1:2::1]:40000"); got != http.StatusUnauthorized {
		t.Fatalf("first guess: %d, want 401", got)
	}
	// a second source address in the same /64 is the same client
	if got := try("[2001:db8:1:2:aaaa::7]:40001"); got != http.StatusTooManyRequests {
		t.Errorf("same /64, new address: %d, want 429 (progressive delay bypassed)", got)
	}
	// controls: another /64 and another IPv4 host are separate clients
	if got := try("[2001:db8:1:3::1]:40000"); got != http.StatusUnauthorized {
		t.Errorf("different /64: %d, want 401", got)
	}
	if got := try("203.0.113.10:40000"); got != http.StatusUnauthorized {
		t.Errorf("IPv4 client: %d, want 401", got)
	}
	if got := try("203.0.113.11:40000"); got != http.StatusUnauthorized {
		t.Errorf("neighbouring IPv4 client: %d, want 401", got)
	}
}

func TestAPIRateLimitKeyAggregatesIPv6Prefix(t *testing.T) {
	if limiterIPKey("2001:db8:1:2::1") != limiterIPKey("2001:db8:1:2:ffff::9") {
		t.Error("one /64 maps to two limiter keys")
	}
	if limiterIPKey("2001:db8:1:2::1") == limiterIPKey("2001:db8:1:3::1") {
		t.Error("two /64s share a limiter key")
	}
	if limiterIPKey("192.0.2.1") != "192.0.2.1" || limiterIPKey("::ffff:192.0.2.1") != "192.0.2.1" {
		t.Error("IPv4 key changed")
	}
	if limiterIPKey("not-an-ip") != "not-an-ip" {
		t.Error("unparseable address must pass through")
	}
}
