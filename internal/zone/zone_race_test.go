package zone

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestZoneManagerConcurrentGetSetRace exercises the zone Manager's most
// concurrency-exposed paths under a race detector. No races should be reported.
func TestZoneManagerConcurrentGetSetRace(t *testing.T) {
	m := NewManager()

	tmpDir := t.TempDir()
	zonePath := filepath.Join(tmpDir, "test.zone")
	zoneContent := `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1 hostmaster 2024010101 3600 900 604800 86400
@ IN NS ns1
sub IN NS ns2
www IN A 192.0.2.1
`
	if err := os.WriteFile(zonePath, []byte(zoneContent), 0644); err != nil {
		t.Fatal(err)
	}
	if err := m.Load("example.com.", zonePath); err != nil {
		t.Fatal(err)
	}

	goroutines := 8
	iterations := 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Concurrent Get calls
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				m.Get("example.com.")
				m.Count()
			}
		}()
	}

	// Concurrent List calls
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				m.List()
				m.ListShared()
			}
		}()
	}

	wg.Wait()
}

// TestZoneManagerConcurrentCreateDeleteRace exercises concurrent CreateZone
// and DeleteZone calls. No races should be reported.
func TestZoneManagerConcurrentCreateDeleteRace(t *testing.T) {
	m := NewManager()

	goroutines := 4
	iterations := 20
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				origin := "zone" + string(rune('a'+id)) + ".example.com."
				err := m.CreateZone(origin, 300, &SOARecord{}, nil)
				if err == nil {
					m.DeleteZone(origin)
				}
				m.Get(origin)
			}
		}(g)
	}

	wg.Wait()
}

// TestZoneManagerConcurrentListRace exercises concurrent List while other
// goroutines modify the zones map. No races should be reported.
func TestZoneManagerConcurrentListRace(t *testing.T) {
	m := NewManager()

	// Pre-load some zones
	for i := 0; i < 5; i++ {
		tmpDir := t.TempDir()
		zonePath := filepath.Join(tmpDir, "test.zone")
		zoneContent := `$ORIGIN z` + string(rune('0'+i)) + `.example.com.
$TTL 3600
@ IN SOA ns1 hostmaster 2024010101 3600 900 604800 86400
@ IN NS ns1
`
		if err := os.WriteFile(zonePath, []byte(zoneContent), 0644); err != nil {
			t.Fatal(err)
		}
		origin := "z" + string(rune('0'+i)) + ".example.com."
		if err := m.Load(origin, zonePath); err != nil {
			t.Fatal(err)
		}
	}

	goroutines := 8
	iterations := 30
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// List + Count while other goroutines modify
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				m.List()
				m.Count()
			}
		}()
	}

	// Create + Delete while List is running
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				origin := "c" + string(rune('a'+id)) + ".example.com."
				m.CreateZone(origin, 300, &SOARecord{}, nil)
				m.DeleteZone(origin)
			}
		}(g)
	}

	wg.Wait()
}
