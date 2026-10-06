package filter

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// --- harness -----------------------------------------------------------------

// rrlTestIP builds distinct, stable IPs so every client gets its own bucket.
func rrlTestIP(i int) string { return fmt.Sprintf("198.51.%d.%d", i/256, i%256) }

func rrlTestLastTime(t *testing.T, r *RRL, key string) (time.Time, bool) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.buckets[key]
	if !ok {
		return time.Time{}, false
	}
	return b.lastTime, true
}

func rrlTestHasBucket(t *testing.T, r *RRL, key string) bool {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.buckets[key]
	return ok
}

func rrlTestBucketCount(t *testing.T, r *RRL) int {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buckets)
}

// newSuppressedRRL builds an RRL whose second response for a key suppresses:
// rate 1/s with burst 1 means a fresh bucket is created at burst-1 == 0 tokens,
// so the next response refills to well under 1 and enters suppression. The
// window is an hour, so suppression cannot lapse during the test.
func newSuppressedRRL(t *testing.T, maxBuckets int) *RRL {
	t.Helper()
	r := NewRRL(RRLConfig{
		Enabled:    true,
		Rate:       1,
		Burst:      1,
		Window:     3600,
		MaxBuckets: maxBuckets,
	})
	t.Cleanup(r.Stop)
	return r
}

// fillRRLClients creates n distinct clients, returning their bucket keys in
// creation order (oldest first). keepWarm, when non-nil, is invoked after each
// client so a caller can keep its own bucket's recency advancing.
func fillRRLClients(t *testing.T, r *RRL, first, n int, keepWarm func(i int)) []string {
	t.Helper()
	keys := make([]string, 0, n)
	for i := first; i < first+n; i++ {
		ip := net.ParseIP(rrlTestIP(i))
		allowed, suppressed := r.Allow(ip, 1, 0)
		if !allowed || suppressed {
			t.Fatalf("filler client %d: allowed=%v suppressed=%v, want true/false", i, allowed, suppressed)
		}
		keys = append(keys, rrlKey(ip, 1, 0))
		if keepWarm != nil {
			keepWarm(i)
		}
	}
	return keys
}

// suppressRRLClient drives a client into suppression and returns its bucket key.
func suppressRRLClient(t *testing.T, r *RRL, ip net.IP) string {
	t.Helper()
	key := rrlKey(ip, 1, 0)
	if allowed, suppressed := r.Allow(ip, 1, 0); !allowed || suppressed {
		t.Fatalf("%s: first response allowed=%v suppressed=%v, want true/false", ip, allowed, suppressed)
	}
	time.Sleep(5 * time.Millisecond)
	if allowed, suppressed := r.Allow(ip, 1, 0); allowed || !suppressed {
		t.Fatalf("%s: expected suppression on the second response, got allowed=%v suppressed=%v",
			ip, allowed, suppressed)
	}
	return key
}

// fillToMaxAndEvict brings the table to exactly maxBuckets, then issues one
// more distinct response, which is what crosses the threshold inside Allow and
// runs evictOldest. alreadyPresent counts buckets created before the filler
// pass. Returns the keys created by the filler pass, oldest first.
func fillToMaxAndEvict(t *testing.T, r *RRL, maxBuckets, alreadyPresent int, keepWarm func(i int)) []string {
	t.Helper()
	fillers := fillRRLClients(t, r, 0, maxBuckets-alreadyPresent, keepWarm)
	if got := rrlTestBucketCount(t, r); got != maxBuckets {
		t.Fatalf("bucket count = %d, want exactly %d before the triggering response", got, maxBuckets)
	}
	trigger := net.ParseIP(rrlTestIP(maxBuckets))
	r.Allow(trigger, 1, 0) // len == maxBuckets here -> evictOldest(100) runs
	if got := rrlTestBucketCount(t, r); got >= maxBuckets {
		t.Fatalf("bucket count = %d after the triggering response; eviction did not run, "+
			"so this run does not exercise the eviction path", got)
	}
	return fillers
}

// --- tests -------------------------------------------------------------------

// TestRRL_SuppressedClientRecencyAdvances pins the mechanism.
//
// CONTRACT: lastTime is a bucket's recency for the lastTime-ordered LRU in
// evictOldest, so every response for that client must refresh it. A client under
// suppression is still actively sending traffic; if its recency stops advancing
// the LRU cannot tell it apart from an idle client.
func TestRRL_SuppressedClientRecencyAdvances(t *testing.T) {
	r := newSuppressedRRL(t, 200)
	attacker := net.ParseIP("192.0.2.1")
	key := suppressRRLClient(t, r, attacker)

	base, ok := rrlTestLastTime(t, r, key)
	if !ok {
		t.Fatal("bucket missing after entering suppression")
	}

	// The client keeps hammering throughout its (one-hour) suppression window.
	for i := 0; i < 5; i++ {
		time.Sleep(2 * time.Millisecond)
		if allowed, suppressed := r.Allow(attacker, 1, 0); allowed || !suppressed {
			t.Fatalf("suppressed request %d: allowed=%v suppressed=%v, want false/true", i, allowed, suppressed)
		}
	}

	end, ok := rrlTestLastTime(t, r, key)
	if !ok {
		t.Fatal("bucket missing during suppression")
	}
	if !end.After(base) {
		t.Fatalf("recency did not advance while suppressed (%v -> %v); the suppression path "+
			"must refresh lastTime the way the refill path does, or the client RRL is "+
			"actively throttling is reported to the LRU as the coldest entry in the table",
			base, end)
	}
}

// TestRRL_SuppressionSurvivesEvictionPressure is the regression for the defect.
//
// evictOldest is the documented defence against the burst-reset bypass: it
// orders on lastTime so a steadily-seen client outlives cold buckets, and
// eviction drops the bucket so the next response would be rebuilt at a full
// burst and immediately allowed again.
//
// CONTRACT: a client still inside its suppression window must not have that
// suppression reset by unrelated bucket-table pressure.
func TestRRL_SuppressionSurvivesEvictionPressure(t *testing.T) {
	const maxBuckets = 200
	r := newSuppressedRRL(t, maxBuckets)

	attacker := net.ParseIP("192.0.2.1")
	attackerKey := suppressRRLClient(t, r, attacker)

	// The attacker keeps producing responses throughout, exactly as a real
	// flooding client does — production calls Allow once per response. It is
	// therefore the warmest bucket in the table and must survive eviction.
	keepFlooding := func(int) {
		if allowed, suppressed := r.Allow(attacker, 1, 0); allowed || !suppressed {
			t.Fatalf("flooding client: allowed=%v suppressed=%v, want false/true", allowed, suppressed)
		}
	}
	fillers := fillToMaxAndEvict(t, r, maxBuckets, 1, keepFlooding)

	if !rrlTestHasBucket(t, r, fillers[len(fillers)-1]) {
		t.Fatal("control failed: the most recently seen client was evicted, so eviction is " +
			"not ordering on recency and the premise of this test does not hold")
	}

	// The suppression window is an hour and barely any of it has elapsed, so
	// this response must still be refused.
	allowed, suppressed := r.Allow(attacker, 1, 0)
	if allowed || !suppressed {
		t.Fatalf("a suppressed client was allowed again after bucket-table pressure "+
			"(allowed=%v suppressed=%v, its bucket was evicted=%v). Suppressed-window "+
			"responses must keep refreshing lastTime so evictOldest cannot rank the client "+
			"as coldest and drop it — rebuilding at burst tokens would clear the suppression, "+
			"which is the burst-reset bypass evictOldest exists to prevent.",
			allowed, suppressed, !rrlTestHasBucket(t, r, attackerKey))
	}
}

// TestRRL_RecentClientSurvivesEviction is the control on the eviction
// machinery itself: under the same pressure the newest client survives and the
// coldest is removed. That is the documented LRU behaviour working correctly,
// which is what gives the regression above its meaning.
func TestRRL_RecentClientSurvivesEviction(t *testing.T) {
	const maxBuckets = 200
	r := newSuppressedRRL(t, maxBuckets)

	fillers := fillToMaxAndEvict(t, r, maxBuckets, 0, nil)

	oldestKey := fillers[0]
	newestKey := fillers[len(fillers)-1]
	if !rrlTestHasBucket(t, r, newestKey) {
		t.Fatal("control failed: the newest client did not survive eviction")
	}
	if rrlTestHasBucket(t, r, oldestKey) {
		t.Fatal("control failed: the coldest client was not evicted, so eviction is not " +
			"ordering on lastTime as documented")
	}
}

// NOTE: the secondary branch this fix could plausibly break — that suppression
// still lifts once the window elapses — is already covered by the pre-existing
// TestRRL_SuppressionExpires in rrl_test.go, which fails if lastTime is
// refreshed on the window-expiry path (the refill would then see a zero
// interval and re-suppress the client forever). It is deliberately not
// duplicated here.
