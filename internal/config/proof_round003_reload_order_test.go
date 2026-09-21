// Round-003 proof: ReloadHandler.Reload must execute the "config" callback
// before "zones" and "blocklist", because zones/blocklist reload reads the
// config and must see the freshly-stored snapshot. The current
// implementation iterates h.callbacks (a map) in non-deterministic order,
// and ReloadPriority constants are defined but never used, so the order is
// random.
//
// Pre-fix expected: across many reload runs, the "config" callback fires
// last (or not first) in a majority of runs, proving the ordering bug.
// Post-fix expected: "config" always fires first (PriorityFirst).
package config

import (
	"fmt"
	"testing"
)

// TestProofRound003_ReloadCallbackOrdering demonstrates that Reload does
// not honor the registered ordering or any priority system. It registers
// callbacks in a known order, runs Reload many times, and records the
// relative order of "config" vs "zones" / "blocklist".
func TestProofRound003_ReloadCallbackOrdering(t *testing.T) {
	h := NewReloadHandler()

	var configFirst int
	var configLast int
	const runs = 200

	for i := 0; i < runs; i++ {
		// Record the call order for this run.
		var order []string
		h.Register("config", func(_ *Config) error {
			order = append(order, "config")
			return nil
		})
		h.Register("zones", func(_ *Config) error {
			order = append(order, "zones")
			return nil
		})
		h.Register("blocklist", func(_ *Config) error {
			order = append(order, "blocklist")
			return nil
		})

		h.Reload(&Config{})

		first := order[0]
		last := order[len(order)-1]
		if first == "config" {
			configFirst++
		}
		if last == "config" {
			configLast++
		}

		// Clear callbacks for the next iteration so we can re-register
		// with fresh closures.
		h.Unregister("config")
		h.Unregister("zones")
		h.Unregister("blocklist")
	}

	fmt.Printf("PROOF: across %d Reload runs, config was first %d times and last %d times\n",
		runs, configFirst, configLast)

	// Contract: "config" must always fire first so zones/blocklist see
	// the freshly-stored config snapshot. Pre-fix, Go map iteration is
	// non-deterministic, so config is first only ~25% of the time.
	if configFirst == runs {
		// Vanishingly unlikely with map iteration; if true, the test is
		// stale or the runtime changed its iteration order.
		t.Logf("NOTE: config was first in all %d runs; the test may be stale", runs)
	}
	if configFirst < runs {
		t.Fatalf("FAIL: in %d/%d Reload runs (%.0f%%) the config callback did NOT fire first. "+
			"Zones and blocklist reload may operate with stale config because they read "+
			"the config that reloadConfig stores atomically. The ReloadPriority constants "+
			"(PriorityFirst=0, PriorityLast=1000) are defined but never used.",
			runs-configFirst, runs, 100*float64(runs-configFirst)/float64(runs))
	}

	fmt.Printf("PROOF PASS: config callback fired first in all %d Reload runs\n", runs)
}
