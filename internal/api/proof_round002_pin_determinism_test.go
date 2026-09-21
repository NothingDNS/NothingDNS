// Round-002 proof: validateAndPinUpstream must pin a hostname to a
// deterministic address. The current implementation picks the first
// resolved public IP in net.LookupHost iteration order, which is not
// stable across calls. Two consecutive calls to
// validateAndPinUpstream("dns.google:53") can return different addresses
// (e.g. "8.8.8.8:53" on one call and "8.8.4.4:53" on another), which
// defeats the whole point of SSRF-pinning: a hostname added then removed
// via the same string would target different pool entries.
//
// Pre-fix expected: two calls return different addresses when the stub
// resolver returns IPs in a different order on the second call.
// Post-fix expected: the function pins deterministically (e.g. by sorting
// the resolved IPs) so both calls return the same address.
package api

import (
	"fmt"
	"testing"
)

func TestProofRound002_PinDeterminism(t *testing.T) {
	// Install a stub resolver that returns the same set of public IPs in
	// different orders on consecutive calls, to prove that
	// validateAndPinUpstream does not depend on iteration order.
	var callCount int
	origLookup := lookupHostFn
	lookupHostFn = func(host string) ([]string, error) {
		if host == "multi-addr.example.test" {
			callCount++
			if callCount%2 == 1 {
				return []string{"198.51.100.10", "198.51.100.20", "198.51.100.30"}, nil
			}
			return []string{"198.51.100.30", "198.51.100.20", "198.51.100.10"}, nil
		}
		return origLookup(host)
	}
	t.Cleanup(func() { lookupHostFn = origLookup })

	const hostname = "multi-addr.example.test:53"

	first, err := validateAndPinUpstream(hostname)
	if err != nil {
		t.Fatalf("setup: first validateAndPinUpstream(%q) returned error: %v", hostname, err)
	}
	second, err := validateAndPinUpstream(hostname)
	if err != nil {
		t.Fatalf("setup: second validateAndPinUpstream(%q) returned error: %v", hostname, err)
	}

	fmt.Printf("PROOF: first=%q second=%q\n", first, second)

	if first != second {
		t.Fatalf("FAIL: validateAndPinUpstream(%q) is not deterministic: first=%q second=%q. "+
			"This means an add followed by a remove of the same hostname can target different pool entries, "+
			"defeating the SSRF-pinning contract.",
			hostname, first, second)
	}

	fmt.Printf("PROOF PASS: validateAndPinUpstream(%q) is deterministic across calls (pinned=%q)\n", hostname, first)
}
