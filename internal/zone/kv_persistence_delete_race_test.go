package zone

// F671: a PersistZone that had already fetched a zone saved it again after the
// zone was deleted, so the deleted zone came back from the KV store on the next
// start. KVPersistence.persistMu orders persist against delete.

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/storage"
)

func kvPersistWaitParked(t *testing.T, fn string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		if strings.Contains(string(buf[:n]), fn) {
			return
		}
		runtime.Gosched()
	}
	t.Fatalf("INVALID PROOF: never parked in %s", fn)
}

func kvPersistSetup(t *testing.T, origin string) (*Manager, *KVPersistence, *Zone) {
	m := NewManager()
	kv, err := storage.OpenKVStore(t.TempDir())
	if err != nil {
		t.Fatalf("INVALID PROOF: kv: %v", err)
	}
	t.Cleanup(func() { kv.Close() })
	kvp := NewKVPersistence(m, kv)
	kvp.Enable()
	soa := &SOARecord{MName: "ns1." + origin, RName: "h." + origin, Serial: 1, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 60}
	if err := m.CreateZone(origin, 300, soa, []NSRecord{{NSDName: "ns1." + origin}}); err != nil {
		t.Fatalf("INVALID PROOF: CreateZone: %v", err)
	}
	z, _ := m.Get(origin)
	return m, kvp, z
}

func TestKVPersistence_DeleteNotUndoneByInflightPersist(t *testing.T) {
	// 1. the proof scenario
	m, kvp, z := kvPersistSetup(t, "race.example.")
	z.Lock()
	done := make(chan struct{})
	go func() { defer close(done); _ = kvp.PersistZone("race.example.") }()
	kvPersistWaitParked(t, "zoneToStoredRecords")
	delDone := make(chan error, 1)
	go func() { delDone <- m.DeleteZone("race.example.") }()
	for {
		if _, ok := m.Get("race.example."); !ok {
			break
		}
		runtime.Gosched()
	}
	z.Unlock()
	<-done
	if err := <-delDone; err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, found, _ := kvp.LoadFromKV("race.example."); found {
		t.Fatal("deleted zone resurrected in KV")
	}

	// 2. persist after the delete is a no-op (zone gone from the manager)
	if err := kvp.PersistZone("race.example."); err != nil {
		t.Fatalf("late persist: %v", err)
	}
	if _, found, _ := kvp.LoadFromKV("race.example."); found {
		t.Fatal("late persist re-created the zone")
	}

	// 3. repeated delete/recreate cycles end consistent with the manager
	for i := 0; i < 5; i++ {
		soa := &SOARecord{MName: "ns1.c.example.", RName: "h.c.example.", Serial: uint32(i + 1), Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 60}
		if err := m.CreateZone("c.example.", 300, soa, []NSRecord{{NSDName: "ns1.c.example."}}); err != nil {
			t.Fatalf("create: %v", err)
		}
		if _, found, _ := kvp.LoadFromKV("c.example."); !found {
			t.Fatalf("cycle %d: created zone not in KV", i)
		}
		if err := m.DeleteZone("c.example."); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if _, found, _ := kvp.LoadFromKV("c.example."); found {
			t.Fatalf("cycle %d: deleted zone still in KV", i)
		}
	}

	// 4. concurrent record writes persist the final state
	m2, kvp2, _ := kvPersistSetup(t, "w.example.")
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				_ = m2.AddRecord("w.example.", Record{Name: fmt.Sprintf("w%d-%d", w, i), Type: "TXT", TTL: 60, RData: "x"})
			}
		}(w)
	}
	wg.Wait()
	zz, _ := m2.Get("w.example.")
	mem := 0
	zz.RLock()
	for _, rs := range zz.Records {
		mem += len(rs)
	}
	zz.RUnlock()
	got, _, _ := kvp2.LoadFromKV("w.example.")
	kv := 0
	got.RLock()
	for _, rs := range got.Records {
		kv += len(rs)
	}
	got.RUnlock()
	if kv != mem {
		t.Fatalf("KV holds %d records, memory %d", kv, mem)
	}
}
