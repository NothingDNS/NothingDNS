package zone

import (
	"fmt"
	"sync"
	"testing"
)

func TestComputeZoneMDConcurrentMutation(t *testing.T) {
	z := NewZone("example.com.")
	z.SOA = &SOARecord{
		Name: "example.com.", MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 1, TTL: 300, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 300,
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			name := fmt.Sprintf("host-%d.example.com.", i%8)
			z.Lock()
			z.Records[name] = []Record{{Name: name, Type: "A", Class: "IN", TTL: 300, RData: "192.0.2.1"}}
			if i%2 == 0 {
				delete(z.Records, name)
			}
			z.Unlock()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			if _, err := ComputeZoneMD(z, ZONEMDSHA384); err != nil {
				t.Errorf("ComputeZoneMD: %v", err)
				return
			}
		}
	}()
	wg.Wait()
}
