package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/resolver"
)

// deadlineTransport records the deadline budget the first upstream exchange
// sees and fails every exchange (no network).
type deadlineTransport struct {
	mu   sync.Mutex
	rem  time.Duration
	seen bool
}

func (d *deadlineTransport) QueryContext(ctx context.Context, _ *protocol.Message, _ string) (*protocol.Message, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.seen {
		d.seen = true
		d.rem = -1
		if dl, ok := ctx.Deadline(); ok {
			d.rem = time.Until(dl)
		}
	}
	return nil, errors.New("deadlineTransport: no network")
}

// TestResolverStage_F625_UsesResolutionTimeout: resolverStage bounds an
// iterative resolution by resolution.timeout (formerly a hard-coded 5s),
// capped at maxIterativeResolveTimeout.
func TestResolverStage_F625_UsesResolutionTimeout(t *testing.T) {
	cases := []struct {
		cfg      string
		min, max time.Duration
	}{
		{"2s", 1500 * time.Millisecond, 2 * time.Second},
		{"12s", 11 * time.Second, 12 * time.Second},
		{"10m", 29 * time.Second, 30 * time.Second}, // upper bound
	}
	for _, c := range cases {
		h := newTestHandler()
		h.config.Resolution.Timeout = c.cfg
		per, _ := time.ParseDuration(c.cfg)
		tr := &deadlineTransport{}
		h.resolver = resolver.NewResolver(resolver.Config{Timeout: per}, nil, tr)
		w := newCaptureWriter("192.0.2.1", "udp")
		q := &query{msg: newTestQuery(t, "example.com.", protocol.TypeA), currentWriter: w, qname: "example.com.", qtype: protocol.TypeA, cacheKey: "example.com.:1"}
		handled, _ := resolverStage(h)(context.Background(), q, w)
		if !handled || !tr.seen {
			t.Fatalf("timeout %s: handled=%v seen=%v", c.cfg, handled, tr.seen)
		}
		if tr.rem <= c.min || tr.rem > c.max {
			t.Errorf("timeout %s: resolution budget %v, want in (%v, %v]", c.cfg, tr.rem, c.min, c.max)
		}
		if w.msg == nil || w.msg.Header.Flags.RCODE != protocol.RcodeServerFailure {
			t.Errorf("timeout %s: failed resolution did not answer SERVFAIL", c.cfg)
		}
	}
}

func TestIterativeResolveTimeout_F625(t *testing.T) {
	cfg := func(s string) *config.Config {
		c := config.DefaultConfig()
		c.Resolution.Timeout = s
		return c
	}
	cases := []struct {
		c    *config.Config
		want time.Duration
	}{
		{nil, 5 * time.Second},
		{cfg(""), 5 * time.Second},
		{cfg("bogus"), 5 * time.Second},
		{cfg("-1s"), 5 * time.Second},
		{cfg("750ms"), 750 * time.Millisecond},
		{cfg("30s"), 30 * time.Second},
		{cfg("31s"), maxIterativeResolveTimeout},
	}
	for _, c := range cases {
		if got := iterativeResolveTimeout(c.c); got != c.want {
			t.Errorf("iterativeResolveTimeout(%v) = %v, want %v", c.c != nil, got, c.want)
		}
	}
}

// TestReloadRuntime_F625_ResolutionTimeoutReloadable: the budget is read
// from the handler's current config, so a reload applies it.
func TestReloadRuntime_F625_ResolutionTimeoutReloadable(t *testing.T) {
	e := reloadRTStart(t, "resolution:\n  timeout: 3s\n")
	budget := func() time.Duration {
		e.h.runtimeMu.RLock()
		defer e.h.runtimeMu.RUnlock()
		return iterativeResolveTimeout(e.h.config)
	}
	if got := budget(); got != 3*time.Second {
		t.Fatalf("start: budget %v, want 3s", got)
	}
	e.mustReload(t, "resolution:\n  timeout: 9s\n")
	if got := budget(); got != 9*time.Second {
		t.Fatalf("after reload: budget %v, want 9s", got)
	}
}

// TestValidationStage_F624_InvalidALabelFormErr: with idna.enabled an
// "xn--" label that is not a valid A-label (RFC 5891 §5.4) is answered
// FORMERR like any other IDNA violation; valid A-labels still pass.
func TestValidationStage_F624_InvalidALabelFormErr(t *testing.T) {
	e := reloadRTStart(t, "idna:\n  enabled: true\n")
	for name, reject := range map[string]bool{
		"xn--bcher-kva8.example.": true,  // does not round-trip
		"xn--mnchen-3y.example.":  true,  // decodes to ASCII
		"xn--abc.example.":        true,  // decodes to C1 controls
		"xn--bcher-kva.example.":  false, // valid A-label
		"xn--4gbrim.example.":     false, // valid Arabic A-label
		"www.example.com.":        false,
	} {
		if got := reloadRTRejected(t, e.h, name); got != reject {
			t.Errorf("%s rejected=%v, want %v", name, got, reject)
		}
	}
}
