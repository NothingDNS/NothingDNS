package transfer

import (
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/zone"
)

// TestSlaveZone_GetLastTransfer checks the locked LastTransfer accessor:
// zero before any transfer, stamped by UpdateZone, and safe to read while
// UpdateZone runs (under -race an unlocked read would fail; F537).
func TestSlaveZone_GetLastTransfer(t *testing.T) {
	sz := &SlaveZone{Config: SlaveZoneConfig{ZoneName: "example.com."}}
	if got := sz.GetLastTransfer(); !got.IsZero() {
		t.Fatalf("GetLastTransfer before any transfer = %v, want zero", got)
	}
	before := time.Now()
	sz.UpdateZone(zone.NewZone("example.com."), 1)
	if got := sz.GetLastTransfer(); got.Before(before) {
		t.Fatalf("GetLastTransfer after UpdateZone = %v, want >= %v", got, before)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			sz.UpdateZone(nil, uint32(i+2))
		}
	}()
	for i := 0; i < 200; i++ {
		_ = sz.GetLastTransfer()
	}
	wg.Wait()
}
