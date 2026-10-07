package api

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// TestHandleSlaveZones_ConcurrentUpdateZone_NoRace runs GET /api/v1/slave-zones
// while the slave zone is replaced through UpdateZone (the path a completed
// AXFR/IXFR takes), alternating nil (pending) and populated zones. The handler
// must read Zone, Records, LastSerial and LastTransfer only under the slave
// zone's / zone's locks; under -race any unlocked read fails the test
// (F483, F537).
func TestHandleSlaveZones_ConcurrentUpdateZone_NoRace(t *testing.T) {
	sm := transfer.NewSlaveManager(nil)
	t.Cleanup(sm.Stop)
	if err := sm.AddSlaveZone(transfer.SlaveZoneConfig{
		ZoneName: "f483.example.com.",
		Masters:  []string{"127.0.0.1:1"}, // loopback, refused: initial transfer fails fast
	}); err != nil {
		t.Fatal(err)
	}
	sz := sm.GetSlaveZone("f483.example.com.")
	s := newTestAPIServerV2(t)
	s.slaveManager = sm

	const iters = 300
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iters; i++ {
			if i%2 == 1 {
				sz.UpdateZone(nil, uint32(i+1))
				continue
			}
			z := zone.NewZone("f483.example.com.")
			z.Records["www.f483.example.com."] = []zone.Record{{Type: "A", TTL: 60, RData: "192.0.2.1"}}
			sz.UpdateZone(z, uint32(i+1))
		}
	}()
	close(start)
	for i := 0; i < iters; i++ {
		w := httptest.NewRecorder()
		s.handleSlaveZones(w, withAdminCtx(httptest.NewRequest("GET", "/api/v1/slave-zones", nil)))
		if w.Code != http.StatusOK {
			t.Fatalf("iteration %d: status %d, want 200", i, w.Code)
		}
	}
	wg.Wait()
}
