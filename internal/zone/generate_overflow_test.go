package zone

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

// TestGenerateMaxIntOverflow confirms that $GENERATE with a stop value at
// math.MaxInt does NOT cause an infinite loop in handleGenerate.
//
// The bug: parseGenerateRange computes count = (stop-start)/step+1 using int
// arithmetic. When stop = math.MaxInt and start = math.MaxInt-80,
// count = (MaxInt-(MaxInt-80))/1+1 = 80, which is < maxGenerateRecords(65536),
// so the range is accepted. But the loop: for i := start; i <= stop; i += step
// overflows at i=MaxInt: i+=1 wraps to math.MinInt, and MinInt <= MaxInt is
// always TRUE — infinite loop. This is a Denial-of-Service via crafted zone file.
func TestGenerateMaxIntOverflow(t *testing.T) {
	// Build the overflow zone file.
	// start = MaxInt - 80, stop = MaxInt.
	// count = 80 (within limit) but loop overflows.
	maxInt := fmt.Sprintf("%d", math.MaxInt)
	startVal := fmt.Sprintf("%d", math.MaxInt-80)
	zoneInput := fmt.Sprintf("$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1. admin. 1 3600 1800 604800 86400\n@ IN NS ns1.\n$GENERATE %s-%s host$ A 10.0.0.$\n", startVal, maxInt)

	// Run the parse with a 2-second timeout.
	// On the buggy code, the loop never exits and the test FAILS.
	// On the fixed code, the parse returns an error and the test PASSES.
	done := make(chan error, 1)
	go func() {
		_, err := ParseFile("overflow.zone", strings.NewReader(zoneInput))
		done <- err
	}()

	select {
	case err := <-done:
		// Parse returned without hanging. Check it returned an appropriate error
		// for the overflow range. If it returned nil, the loop completed without
		// overflow — but on 64-bit Go with MaxInt this should overflow.
		if err == nil {
			// This should not happen on 64-bit Go; if it does, the count check
			// worked differently than expected.
			t.Logf("parse succeeded without error — count may have overflowed to a value that triggered the limit")
		} else {
			t.Logf("parse returned error (expected on fixed code): %v", err)
		}
	case <-time.After(2 * time.Second):
		// This branch means the parse hung for 2+ seconds = infinite loop.
		t.Errorf("FAIL: infinite loop detected — parse hung for >2s")
		t.Errorf("  BUG: $GENERATE with stop=math.MaxInt causes infinite loop in handleGenerate")
		t.Errorf("  Root cause: count=(MaxInt-(MaxInt-80))/1+1=80 < maxGenerateRecords=65536 → accepted")
		t.Errorf("  but loop overflows at i=MaxInt: i+=1 wraps to MinInt; MinInt<=MaxInt → always true")
	}
}
