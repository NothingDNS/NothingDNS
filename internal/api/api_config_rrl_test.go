package api

import (
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/filter"
	"github.com/nothingdns/nothingdns/internal/protocol"
)

// rrlSuppressions counts how many of n identical responses the response-side
// RRL suppresses for one client.
func rrlSuppressions(rrl *filter.RRL, n int) int {
	ip := net.ParseIP("192.0.2.7")
	count := 0
	for i := 0; i < n; i++ {
		if _, suppressed := rrl.Allow(ip, protocol.TypeA, protocol.RcodeSuccess); suppressed {
			count++
		}
	}
	return count
}

func newRRLFixture(t *testing.T, enabled bool) (*overridesFixture, *filter.RRL) {
	t.Helper()
	f := newOverridesFixture(t)
	rl := filter.NewRateLimiter(config.RRLConfig{Rate: 1, Burst: 2})
	rl.SetEnabled(enabled)
	rrl := filter.NewRRL(filter.RRLConfig{Enabled: enabled, Rate: 1, Burst: 2, Window: 10, ResponsesOnly: true})
	t.Cleanup(rl.Stop)
	t.Cleanup(rrl.Stop)
	f.server.WithRateLimiter(rl).WithRRL(rrl)
	return f, rrl
}

// F638: PUT /api/v1/config/rrl toggled only the client-side token bucket; the
// response-side RRL kept the state it had at start until the next restart.
func TestHandleConfigRRL_TogglesResponseRRL(t *testing.T) {
	t.Run("disable", func(t *testing.T) {
		f, rrl := newRRLFixture(t, true)
		if rec := f.put(t, f.server.handleConfigRRL, f.admin, "/api/v1/config/rrl", `{"enabled":false}`); rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		if n := rrlSuppressions(rrl, 10); n != 0 {
			t.Errorf("response RRL still suppressed %d responses after enabled=false", n)
		}
	})
	t.Run("enable", func(t *testing.T) {
		f, rrl := newRRLFixture(t, false)
		if rec := f.put(t, f.server.handleConfigRRL, f.admin, "/api/v1/config/rrl", `{"enabled":true}`); rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		if n := rrlSuppressions(rrl, 10); n == 0 {
			t.Error("response RRL suppressed nothing after enabled=true")
		}
	})
	t.Run("enabled omitted keeps state", func(t *testing.T) {
		f, rrl := newRRLFixture(t, true)
		if rec := f.put(t, f.server.handleConfigRRL, f.admin, "/api/v1/config/rrl", `{"rate":50}`); rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		if n := rrlSuppressions(rrl, 10); n == 0 {
			t.Error("a rate-only PUT disabled the response RRL")
		}
	})
	t.Run("failed save leaves it untouched", func(t *testing.T) {
		f, rrl := newRRLFixture(t, false)
		if err := os.WriteFile(f.file, []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if rec := f.put(t, f.server.handleConfigRRL, f.admin, "/api/v1/config/rrl", `{"enabled":true}`); rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
		if n := rrlSuppressions(rrl, 10); n != 0 {
			t.Errorf("response RRL enabled despite the failed save (%d suppressed)", n)
		}
	})
	t.Run("no RRL wired", func(t *testing.T) {
		f := newOverridesFixture(t)
		rl := filter.NewRateLimiter(config.RRLConfig{Rate: 1, Burst: 2})
		t.Cleanup(rl.Stop)
		f.server.WithRateLimiter(rl)
		if rec := f.put(t, f.server.handleConfigRRL, f.admin, "/api/v1/config/rrl", `{"enabled":true}`); rec.Code != http.StatusOK {
			t.Fatalf("expected 200 without an RRL, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}
