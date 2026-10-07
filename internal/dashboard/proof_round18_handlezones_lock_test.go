package dashboard

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/zone"
)

// TestRound18HandleZonesConcurrentRecordMutation is a regression test for a
// data race: handleZones read z.SOA.Serial and len(z.Records) WITHOUT holding
// the zone's RWMutex, while zone.Manager.AddRecord (the production writer used
// by the REST API and DDNS) mutates both under z.Lock(). The sibling
// zone_service.ListZones holds z.RLock around the identical count, so the
// unlocked dashboard read violated the package's own convention. Run with
// -race: the unsynchronized reads must produce no race report.
func TestRound18HandleZonesConcurrentRecordMutation(t *testing.T) {
	zm := zone.NewManager()
	z := zone.NewZone("example.test.")
	z.SOA = &zone.SOARecord{
		TTL:    3600,
		MName:  "ns1.example.test.",
		RName:  "admin.example.test.",
		Serial: 1,
	}
	zm.LoadZone(z, "example.test.zone")

	s := NewServer()
	s.SetZoneManager(zm)

	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/zones", nil)

	// Control: sequential handleZones with no concurrent writer must work.
	rr := httptest.NewRecorder()
	s.handleZones(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("control handleZones status = %d, want 200", rr.Code)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	// Production writer: the exact path POST /api/v1/zones/{zone}/records and
	// DDNS updates take.
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			_ = zm.AddRecord("example.test.", zone.Record{
				Name:  fmt.Sprintf("host%d.example.test.", i%32),
				Type:  "A",
				TTL:   300,
				RData: "192.0.2.1",
			})
		}
	}()

	// Production reader: GET /api/dashboard/zones.
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			s.handleZones(httptest.NewRecorder(), req)
		}
	}()

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()

	// Control again: after the writers stop, the handler still serves.
	rr2 := httptest.NewRecorder()
	s.handleZones(rr2, req)
	if rr2.Code != http.StatusOK {
		t.Fatalf("post-race handleZones status = %d, want 200", rr2.Code)
	}
}
