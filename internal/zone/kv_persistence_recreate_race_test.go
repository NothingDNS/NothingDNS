package zone

// F672: the delete hook runs after the manager released its lock, so a zone
// created again under the same name could already be live and persisted; the
// late KV delete then removed its copy and the zone vanished on restart.

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/storage"
)

func kvRecreateSetup(t *testing.T, origin string) (*Manager, *KVPersistence) {
	m := NewManager()
	kv, err := storage.OpenKVStore(t.TempDir())
	if err != nil {
		t.Fatalf("kv: %v", err)
	}
	t.Cleanup(func() { kv.Close() })
	kvp := NewKVPersistence(m, kv)
	kvp.Enable()
	kvRecreateZone(t, m, origin)
	return m, kvp
}

func kvRecreateZone(t *testing.T, m *Manager, origin string) {
	soa := &SOARecord{MName: "ns1." + origin, RName: "h." + origin, Serial: 1, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 60}
	if err := m.CreateZone(origin, 300, soa, []NSRecord{{NSDName: "ns1." + origin}}); err != nil {
		t.Fatalf("CreateZone: %v", err)
	}
}

func TestKVPersistence_DeleteHookKeepsRecreatedZone(t *testing.T) {
	// 1. proof scenario: held delete hook, zone re-created meanwhile
	m, kvp := kvRecreateSetup(t, "race.example.")
	orig := m.MutationHook()
	parked := make(chan struct{})
	release := make(chan struct{})
	held := false
	m.SetMutationHook(func(name string, deleted bool) {
		if deleted && !held {
			held = true
			close(parked)
			<-release
		}
		orig(name, deleted)
	})
	delDone := make(chan error, 1)
	go func() { delDone <- m.DeleteZone("race.example.") }()
	<-parked
	kvRecreateZone(t, m, "race.example.")
	close(release)
	if err := <-delDone; err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, found, _ := kvp.LoadFromKV("race.example."); !found {
		t.Fatal("live re-created zone lost from KV")
	}

	// 2. a plain delete still removes the KV copy
	if err := m.DeleteZone("race.example."); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, found, _ := kvp.LoadFromKV("race.example."); found {
		t.Fatal("deleted zone still in KV")
	}

	// 3. repeated delete/create cycles end consistent with the manager
	for i := 0; i < 6; i++ {
		if _, ok := m.Get("cyc.example."); ok {
			if err := m.DeleteZone("cyc.example."); err != nil {
				t.Fatalf("delete: %v", err)
			}
		} else {
			kvRecreateZone(t, m, "cyc.example.")
		}
	}
	_, live := m.Get("cyc.example.")
	if _, found, _ := kvp.LoadFromKV("cyc.example."); found != live {
		t.Fatalf("KV found=%v but manager live=%v", found, live)
	}
}
