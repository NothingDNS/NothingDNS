package filter

// RRL (BIND-style Response Rate Limiting) tests.
//
// Covers all the public surface: NewRRL defaults, Allow under burst,
// rate limit + suppression window, LogSuperlative amplification
// triggering immediate suppression, SetEnabled hot-toggle, and the
// internal bookkeeping helpers (pruneStale + evictOldest).

import (
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/config"
)

func TestNewRRL_Defaults(t *testing.T) {
	// Zeros in config trigger sane defaults so an operator can enable
	// RRL with `rrl: {enabled: true}` and get safe behaviour without
	// tuning every knob.
	r := NewRRL(RRLConfig{Enabled: true})
	defer r.Stop()

	if !r.enabled.Load() {
		t.Error("enabled should be true after NewRRL with Enabled:true")
	}
	if r.rate != 5 {
		t.Errorf("default rate = %v, want 5", r.rate)
	}
	if r.burst != 20 {
		t.Errorf("default burst = %d, want 20", r.burst)
	}
	if r.window != 10*time.Second {
		t.Errorf("default window = %v, want 10s", r.window)
	}
	if r.maxBuckets != 10000 {
		t.Errorf("default maxBuckets = %d, want 10000", r.maxBuckets)
	}
}

func TestRRL_Disabled_AlwaysAllows(t *testing.T) {
	// With enabled=false, Allow must return (true, false) regardless
	// of burst settings; readers shouldn't need to allocate buckets.
	r := NewRRL(RRLConfig{Enabled: false, Rate: 1, Burst: 1})
	defer r.Stop()

	ip := net.ParseIP("203.0.113.1")
	for i := 0; i < 100; i++ {
		allowed, suppressed := r.Allow(ip, 1, 0)
		if !allowed || suppressed {
			t.Fatalf("iter %d: disabled RRL should allow, got allowed=%v suppressed=%v", i, allowed, suppressed)
		}
	}
}

func TestRRL_Allow_BurstThenSuppress(t *testing.T) {
	// Burst=3 means three queries fit, then we trip into the
	// suppression window and Allow returns (false, true).
	r := NewRRL(RRLConfig{
		Enabled: true,
		Rate:    1,
		Burst:   3,
		Window:  60, // 60s — long enough to stay suppressed for the test
	})
	defer r.Stop()

	ip := net.ParseIP("203.0.113.2")
	// First 3 queries should pass — fresh bucket starts with burst-1
	// remaining tokens after the first Allow (which gets the initial
	// "free" credit), so the run is: 1 fresh+ N=burst-1 = 3.
	for i := 0; i < 3; i++ {
		allowed, suppressed := r.Allow(ip, 1, 0)
		if !allowed || suppressed {
			t.Errorf("iter %d (burst phase): want allowed/notSuppressed, got allowed=%v suppressed=%v", i, allowed, suppressed)
		}
	}
	// 4th query exhausts tokens → suppression window opens.
	allowed, suppressed := r.Allow(ip, 1, 0)
	if allowed || !suppressed {
		t.Errorf("4th query: want suppressed, got allowed=%v suppressed=%v", allowed, suppressed)
	}
	// Subsequent queries inside the window stay suppressed.
	for i := 0; i < 5; i++ {
		allowed, suppressed := r.Allow(ip, 1, 0)
		if allowed || !suppressed {
			t.Errorf("during-window iter %d: want suppressed, got allowed=%v suppressed=%v", i, allowed, suppressed)
		}
	}
}

func TestRRL_DistinctBucketsByQTypeAndRCode(t *testing.T) {
	// A flood of TYPE=ANY responses must not hide A-record responses
	// behind the same client IP. The key includes qtype+rcode.
	r := NewRRL(RRLConfig{Enabled: true, Rate: 1, Burst: 1, Window: 60})
	defer r.Stop()

	ip := net.ParseIP("203.0.113.3")
	// Burn the (TYPE=ANY, RCODE=0) bucket.
	r.Allow(ip, 255, 0)
	if allowed, _ := r.Allow(ip, 255, 0); allowed {
		t.Fatal("expected ANY bucket suppressed after burst")
	}
	// (TYPE=A, RCODE=0) for the same IP must still be allowed — fresh bucket.
	if allowed, suppressed := r.Allow(ip, 1, 0); !allowed || suppressed {
		t.Errorf("distinct qtype bucket: want allowed, got allowed=%v suppressed=%v", allowed, suppressed)
	}
	// Different rcode same qtype likewise.
	if allowed, suppressed := r.Allow(ip, 255, 3); !allowed || suppressed {
		t.Errorf("distinct rcode bucket: want allowed, got allowed=%v suppressed=%v", allowed, suppressed)
	}
}

func TestRRL_LogSuperlative_NoOpWhenDisabled(t *testing.T) {
	r := NewRRL(RRLConfig{Enabled: false})
	defer r.Stop()
	// Must not panic; must not create buckets.
	r.LogSuperlative(net.ParseIP("203.0.113.4"), 1, 0, 100, 5000)
	if len(r.buckets) != 0 {
		t.Errorf("disabled RRL should not allocate buckets, got %d", len(r.buckets))
	}
}

func TestRRL_LogSuperlative_BelowAmplificationThreshold(t *testing.T) {
	// Ratio < 50 is ignored — that's normal response sizing.
	r := NewRRL(RRLConfig{Enabled: true, Rate: 1, Burst: 5, Window: 60})
	defer r.Stop()
	r.LogSuperlative(net.ParseIP("203.0.113.5"), 1, 0, 100, 1000) // 10x ratio
	if len(r.buckets) != 0 {
		t.Errorf("low-ratio LogSuperlative should not create bucket, got %d", len(r.buckets))
	}
}

func TestRRL_LogSuperlative_AmplificationSuppresses(t *testing.T) {
	// LogSuperlative only penalises an existing bucket (the design
	// intent: amplification detection kicks in for clients we've
	// already seen, not first-contact). Seed the bucket with one
	// Allow, then a 100x amplified response drains tokens below zero
	// and trips the suppression flag.
	r := NewRRL(RRLConfig{Enabled: true, Rate: 1, Burst: 5, Window: 60})
	defer r.Stop()

	ip := net.ParseIP("203.0.113.6")
	r.Allow(ip, 1, 0)                    // seed bucket
	r.LogSuperlative(ip, 1, 0, 50, 5000) // 100x amplification

	if allowed, suppressed := r.Allow(ip, 1, 0); allowed || !suppressed {
		t.Errorf("after LogSuperlative amplification: want suppressed, got allowed=%v suppressed=%v", allowed, suppressed)
	}
}

func TestRRL_SetEnabled_Toggle(t *testing.T) {
	r := NewRRL(RRLConfig{Enabled: true, Rate: 1, Burst: 1, Window: 60})
	defer r.Stop()

	ip := net.ParseIP("203.0.113.7")
	// Burn the bucket.
	r.Allow(ip, 1, 0)
	if allowed, _ := r.Allow(ip, 1, 0); allowed {
		t.Fatal("expected suppression before disable")
	}

	r.SetEnabled(false)
	// Now Allow short-circuits to (true, false) regardless of bucket state.
	if allowed, suppressed := r.Allow(ip, 1, 0); !allowed || suppressed {
		t.Errorf("after SetEnabled(false): want allowed, got allowed=%v suppressed=%v", allowed, suppressed)
	}

	r.SetEnabled(true)
	// Bucket still has suppression set; query stays suppressed until
	// the window expires.
	if allowed, _ := r.Allow(ip, 1, 0); allowed {
		t.Error("after re-enable, suppressed bucket should still suppress")
	}
}

func TestRRL_SetEnabledStartsCleanupWhenInitiallyDisabled(t *testing.T) {
	r := NewRRL(RRLConfig{Enabled: false, Rate: 1, Burst: 1, Window: 60})
	defer r.Stop()
	r.cleanupInterval = 10 * time.Millisecond

	key := rrlKey(net.ParseIP("203.0.113.70"), 1, 0)
	r.mu.Lock()
	r.buckets[key] = &rrlBucket{
		lastTime:  time.Now().Add(-10 * time.Minute),
		createdAt: time.Now().Add(-10 * time.Minute),
	}
	r.mu.Unlock()

	r.SetEnabled(true)

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		_, present := r.buckets[key]
		r.mu.Unlock()
		if !present {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	r.mu.Lock()
	_, present := r.buckets[key]
	r.mu.Unlock()
	if present {
		t.Fatal("cleanup goroutine did not prune stale bucket after SetEnabled(true)")
	}
}

func TestRRL_SuppressionExpires(t *testing.T) {
	// Tiny window so we can wait it out in a test.
	r := NewRRL(RRLConfig{Enabled: true, Rate: 1, Burst: 1, Window: 1}) // 1s
	defer r.Stop()

	ip := net.ParseIP("203.0.113.8")
	r.Allow(ip, 1, 0)
	if allowed, _ := r.Allow(ip, 1, 0); allowed {
		t.Fatal("expected suppression after burst")
	}

	// Wait for the window to elapse + a small margin.
	time.Sleep(1100 * time.Millisecond)

	// First call after window expiry clears the suppression and
	// re-enters the rate path; with rate=1 token/s and 1.1s elapsed,
	// there are ~1.1 tokens available, so the call succeeds.
	if allowed, suppressed := r.Allow(ip, 1, 0); !allowed || suppressed {
		t.Errorf("after window expired: want allowed, got allowed=%v suppressed=%v", allowed, suppressed)
	}
}

func TestRRL_AllowFutureLastTimeDoesNotSuppress(t *testing.T) {
	r := NewRRL(RRLConfig{Enabled: true, Rate: 1, Burst: 2, Window: 60})
	defer r.Stop()

	ip := net.ParseIP("203.0.113.90")
	if allowed, suppressed := r.Allow(ip, 1, 0); !allowed || suppressed {
		t.Fatalf("first request should seed the bucket, got allowed=%v suppressed=%v", allowed, suppressed)
	}

	key := rrlKey(ip, 1, 0)
	r.mu.Lock()
	b := r.buckets[key]
	b.tokens = 1
	b.lastTime = time.Now().Add(time.Hour)
	r.mu.Unlock()

	if allowed, suppressed := r.Allow(ip, 1, 0); !allowed || suppressed {
		t.Fatalf("future lastTime should not drain tokens or suppress, got allowed=%v suppressed=%v", allowed, suppressed)
	}
}

func TestRRL_PruneStale(t *testing.T) {
	r := NewRRL(RRLConfig{Enabled: true, Rate: 1, Burst: 1, Window: 60})
	defer r.Stop()

	// Inject a stale bucket directly.
	key := rrlKey(net.ParseIP("203.0.113.9"), 1, 0)
	r.mu.Lock()
	r.buckets[key] = &rrlBucket{
		lastTime:  time.Now().Add(-10 * time.Minute), // older than 5min threshold
		createdAt: time.Now().Add(-10 * time.Minute),
	}
	r.mu.Unlock()

	r.pruneStale()

	r.mu.Lock()
	_, present := r.buckets[key]
	r.mu.Unlock()
	if present {
		t.Error("pruneStale should have removed the stale bucket")
	}
}

func TestRRL_EvictOldest_DropsRequestedCount(t *testing.T) {
	r := NewRRL(RRLConfig{Enabled: true, Rate: 1, Burst: 1, MaxBuckets: 5, Window: 60})
	defer r.Stop()

	// Push 5 buckets so the next Allow triggers evictOldest(100).
	for i := 0; i < 5; i++ {
		ip := net.IPv4(203, 0, 113, byte(100+i))
		r.Allow(ip, 1, 0)
		// Sleep a tick so createdAt differs.
		time.Sleep(time.Millisecond)
	}

	// Adding a 6th must invoke eviction.
	r.Allow(net.IPv4(203, 0, 113, 200), 1, 0)
	r.mu.Lock()
	have := len(r.buckets)
	r.mu.Unlock()
	if have > 5 {
		t.Errorf("expected ≤ maxBuckets (5) after evict, got %d", have)
	}
}

func TestRRL_Itoa_TableSanity(t *testing.T) {
	// rrlKey uses itoa16 / itoa8 to avoid strconv.Itoa allocations
	// per query. Sanity-check the helpers against fmt.
	for _, v := range []uint16{0, 1, 9, 10, 99, 100, 999, 1000, 65535} {
		got := u16toa(v)
		if want := stdItoa(int(v)); got != want {
			t.Errorf("u16toa(%d) = %q, want %q", v, got, want)
		}
	}
	for _, v := range []uint8{0, 1, 9, 10, 99, 100, 255} {
		got := u8toa(v)
		if want := stdItoa(int(v)); got != want {
			t.Errorf("u8toa(%d) = %q, want %q", v, got, want)
		}
	}
}

// stdItoa replicates strconv.Itoa without importing it into the test
// file (keeps the comparison honest about exactly the byte format).
func stdItoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [6]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func TestRateLimiter_Reload_UpdatesAllFields(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Rate: 5, Burst: 10, MaxBuckets: 100})
	defer rl.Stop()

	rl.Reload(config.RRLConfig{
		Enabled:    false,
		Rate:       42,
		Burst:      99,
		MaxBuckets: 500,
	})

	rl.mu.Lock()
	r, b, mb := rl.rate, rl.burst, rl.maxBuckets
	rl.mu.Unlock()

	if r != 42 {
		t.Errorf("rate after reload = %v, want 42", r)
	}
	if b != 99 {
		t.Errorf("burst after reload = %d, want 99", b)
	}
	if mb != 500 {
		t.Errorf("maxBuckets after reload = %d, want 500", mb)
	}
	if rl.enabled.Load() {
		t.Error("enabled should be false after Reload(Enabled:false)")
	}
}

func TestRateLimiter_Reload_ZeroValuesKeepCurrent(t *testing.T) {
	// Reload ignores zeros — current values stay put. This lets
	// operators flip a single field via API without re-stating the
	// whole config block.
	rl := NewRateLimiter(config.RRLConfig{Rate: 5, Burst: 10, MaxBuckets: 100})
	defer rl.Stop()

	rl.Reload(config.RRLConfig{Enabled: true}) // zeros elsewhere

	rl.mu.Lock()
	r, b, mb := rl.rate, rl.burst, rl.maxBuckets
	rl.mu.Unlock()
	if r != 5 || b != 10 || mb != 100 {
		t.Errorf("zero-value reload should preserve, got rate=%v burst=%d maxBuckets=%d", r, b, mb)
	}
}

func TestACLChecker_Reload_Delegates(t *testing.T) {
	// Start with one allow rule so the ACL is non-nil; Reload replaces it.
	a, err := NewACLChecker([]config.ACLRule{{
		Name:     "initial_allow",
		Action:   "allow",
		Networks: []string{"0.0.0.0/0"},
	}}, false)
	if err != nil {
		t.Fatalf("NewACLChecker: %v", err)
	}
	if err := a.Reload([]config.ACLRule{{
		Name:     "block_local",
		Action:   "deny",
		Networks: []string{"127.0.0.1/32"},
	}}); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	rules := a.GetRules()
	if len(rules) != 1 || rules[0].Name != "block_local" {
		t.Errorf("after Reload, rules = %+v, want one block_local rule", rules)
	}
}
