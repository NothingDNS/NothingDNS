package filter

import (
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
)

// F707: both limiters keyed on the full client address, so one IPv6 /64 (a
// single subscriber line holds 2^64 addresses) got a fresh bucket per source
// address and was never limited; the RRLConfig documentation says the rate is
// "per subnet". IPv6 clients now share a bucket per /64; IPv4 stays per
// address.
func TestRateLimiterAggregatesIPv6Prefix(t *testing.T) {
	rl := NewRateLimiter(config.RRLConfig{Enabled: true, Rate: 1, Burst: 3, MaxBuckets: 1000})
	defer rl.Stop()

	allowed := 0
	for i := 0; i < 20; i++ {
		ip := net.ParseIP("2001:db8:1:2::1")
		ip[15] = byte(i + 1)
		ip[8] = byte(i) // varies inside the /64
		if rl.Allow(ip) {
			allowed++
		}
	}
	if allowed > 4 { // burst 3 plus at most one refilled token
		t.Errorf("%d queries from one /64 allowed, burst is 3", allowed)
	}

	// controls: another /64 has its own bucket; IPv4 hosts stay independent
	if !rl.Allow(net.ParseIP("2001:db8:1:3::1")) {
		t.Error("a different /64 shares the exhausted bucket")
	}
	for i := 1; i <= 5; i++ {
		if !rl.Allow(net.IPv4(192, 0, 2, byte(i))) {
			t.Errorf("IPv4 host .%d limited by its neighbours", i)
		}
	}
}

func TestRRLKeyAggregatesIPv6Prefix(t *testing.T) {
	a := rrlKey(net.ParseIP("2001:db8:1:2::1"), 1, 0)
	b := rrlKey(net.ParseIP("2001:db8:1:2:ffff::9"), 1, 0)
	c := rrlKey(net.ParseIP("2001:db8:1:3::1"), 1, 0)
	if a != b {
		t.Errorf("addresses in one /64 got different RRL keys: %q vs %q", a, b)
	}
	if a == c {
		t.Errorf("different /64s share an RRL key: %q", a)
	}
	if rrlKey(net.IPv4(192, 0, 2, 1), 1, 0) == rrlKey(net.IPv4(192, 0, 2, 2), 1, 0) {
		t.Error("IPv4 hosts share an RRL key")
	}
}
