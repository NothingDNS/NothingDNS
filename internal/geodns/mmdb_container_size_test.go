package geodns

import (
	"runtime"
	"testing"
)

// TestMMDBHugeContainerHeaderRejectedCheaply (F874): a map or array whose
// size field claims far more entries than the data holds is rejected
// without preallocating for the claim (it cost >1 GiB per lookup).
func TestMMDBHugeContainerHeaderRejectedCheaply(t *testing.T) {
	for _, buf := range [][]byte{
		{0xFF, 0xFF, 0xFF, 0xFF},       // map, size 16843036
		{0x1F, 0x04, 0xFF, 0xFF, 0xFF}, // array, size 16843036
	} {
		dec := &mmdbDecoder{buf: buf}
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		_, _, err := dec.decodeValue(0, 32)
		runtime.ReadMemStats(&after)
		if err == nil {
			t.Fatalf("% x: malformed container accepted", buf)
		}
		if n := after.TotalAlloc - before.TotalAlloc; n > 64<<20 {
			t.Fatalf("% x: rejecting a %d-byte value allocated %d MiB", buf, len(buf), n>>20)
		}
	}
}
