package main

// F681: addSOAAuthority (NXDOMAIN/NODATA authority section) read z.SOA without the zone's
// read lock while IncrementSerial, DDNS and the record API write it under z.Lock: a data
// race on every negative answer served during an update.

import (
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func soaAuthorityParked() bool {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	for _, g := range strings.Split(string(buf[:n]), "\n\n") {
		if strings.Contains(g, "addSOAAuthority") && strings.Contains(g, "RWMutex).RLock") {
			return true
		}
	}
	return false
}

func TestAddSOAAuthority_ReadsSOAUnderZoneLock(t *testing.T) {
	h, _ := zoneDelBoot(t)
	z := h.zones["example.com."]

	// 1. gated: the reader parks on the writer, then sees the writer's serial
	z.Lock()
	z.SOA.Serial = 41
	done := make(chan *protocol.Message, 1)
	go func() {
		resp := &protocol.Message{}
		h.addSOAAuthority(resp, z)
		done <- resp
	}()
	deadline := time.Now().Add(10 * time.Second)
	for !soaAuthorityParked() {
		select {
		case <-done:
			t.Fatal("reader returned while the zone write lock was held")
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("reader never parked")
		}
		runtime.Gosched()
	}
	z.SOA.Serial = 42 // still under the write lock: the reader must not see 41
	z.Unlock()
	resp := <-done
	if len(resp.Authorities) != 1 {
		t.Fatalf("authorities = %d", len(resp.Authorities))
	}
	if got := resp.Authorities[0].Data.(*protocol.RDataSOA).Serial; got != 42 {
		t.Fatalf("serial = %d, want 42 (written under the lock)", got)
	}

	// 2. no SOA: nothing is added and nothing panics
	z2 := zone.NewZone("nosoa.test.")
	r2 := &protocol.Message{}
	h.addSOAAuthority(r2, z2)
	if len(r2.Authorities) != 0 {
		t.Fatal("authority added for a zone without SOA")
	}

	// 3. concurrent serial bumps and readers (race detector)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for k := 0; k < 4; k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					h.addSOAAuthority(&protocol.Message{}, z)
				}
			}
		}()
	}
	for k := 0; k < 2000; k++ {
		z.Lock()
		z.SOA.Serial++
		z.Unlock()
	}
	close(stop)
	wg.Wait()
}
