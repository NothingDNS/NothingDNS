package cluster

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cluster/raft"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func zoneHooksTestZone(t *testing.T, origin, ip string) *zone.Zone {
	t.Helper()
	txt := "$ORIGIN " + origin + "\n@ 3600 IN SOA ns1." + origin + " hostmaster." + origin +
		" 1 3600 600 604800 86400\n@ 3600 IN NS ns1." + origin + "\nns1 3600 IN A " + ip + "\n"
	z, err := zone.ParseFile(origin, strings.NewReader(txt))
	if err != nil {
		t.Fatal(err)
	}
	return z
}

// zoneHooksView mirrors cmd/nothingdns query routing: it is rebuilt from
// Manager.List() only when the manager's mutation hook fires
// (handler.RebuildZoneTree), so it holds whatever *Zone objects existed then.
type zoneHooksView struct {
	mu    sync.Mutex
	zones map[string]*zone.Zone
}

func (v *zoneHooksView) rebuild(m *zone.Manager) {
	v.mu.Lock()
	v.zones = m.List()
	v.mu.Unlock()
}

// ns1 returns the A RDATA of ns1.<origin> as the view would answer it.
func (v *zoneHooksView) ns1(origin string) string {
	v.mu.Lock()
	z, ok := v.zones[origin]
	v.mu.Unlock()
	if !ok {
		return "<absent>"
	}
	z.RLock()
	defer z.RUnlock()
	for _, r := range z.Records["ns1."+origin] {
		if r.Type == "A" {
			return r.RData
		}
	}
	return "<no A>"
}

// sameAsManager reports whether the view holds exactly the manager's zones.
func (v *zoneHooksView) sameAsManager(m *zone.Manager) bool {
	live := m.List()
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(live) != len(v.zones) {
		return false
	}
	for k, z := range live {
		if v.zones[k] != z {
			return false
		}
	}
	return true
}

func zoneHooksSnapshot(t *testing.T, zones map[string]string) []byte {
	t.Helper()
	leader := zone.NewManager()
	for origin, ip := range zones {
		leader.LoadZone(zoneHooksTestZone(t, origin, ip), "")
	}
	payload, err := (&Cluster{zoneManager: leader}).snapshotZones()
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func zoneHooksFollower(t *testing.T, hook func(*zone.Manager, *zoneHooksView, string)) (*Cluster, *zone.Manager, *zoneHooksView) {
	t.Helper()
	m := zone.NewManager()
	m.LoadZone(zoneHooksTestZone(t, "a.example.", "192.0.2.1"), "")
	m.LoadZone(zoneHooksTestZone(t, "b.example.", "192.0.2.2"), "")
	v := &zoneHooksView{}
	m.SetMutationHook(func(name string, _ bool) {
		if hook != nil {
			hook(m, v, name)
		}
		v.rebuild(m)
	})
	v.rebuild(m)
	return &Cluster{zoneManager: m}, m, v
}

// F342: installing a Raft snapshot replaces zone objects via LoadZone, which
// does not fire the mutation hook. Query routing (and KV persistence) must
// still observe the restored zones, otherwise the node keeps answering from
// the zone objects the snapshot replaced.
func TestRestoreZones_NotifiesMutationHook(t *testing.T) {
	t.Run("replaced and added zones reach the view", func(t *testing.T) {
		c, m, v := zoneHooksFollower(t, nil)
		payload := zoneHooksSnapshot(t, map[string]string{"a.example.": "192.0.2.99", "c.example.": "192.0.2.3"})
		if err := c.restoreZones(payload); err != nil {
			t.Fatal(err)
		}
		if got := v.ns1("a.example."); got != "192.0.2.99" {
			t.Errorf("replaced zone: view answers %s, want 192.0.2.99", got)
		}
		if got := v.ns1("c.example."); got != "192.0.2.3" {
			t.Errorf("added zone: view answers %s, want 192.0.2.3", got)
		}
		if got := v.ns1("b.example."); got != "<absent>" {
			t.Errorf("dropped zone: view answers %s, want <absent>", got)
		}
		if !v.sameAsManager(m) {
			t.Error("view diverges from the manager after restore")
		}
	})

	t.Run("empty snapshot clears the view", func(t *testing.T) {
		c, m, v := zoneHooksFollower(t, nil)
		if err := c.restoreZones([]byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		if len(m.List()) != 0 || !v.sameAsManager(m) {
			t.Errorf("empty snapshot: manager=%d zones, view in sync=%v", len(m.List()), v.sameAsManager(m))
		}
	})

	t.Run("corrupt payload notifies nothing", func(t *testing.T) {
		calls := 0
		c, _, _ := zoneHooksFollower(t, func(*zone.Manager, *zoneHooksView, string) { calls++ })
		if err := c.restoreZones([]byte(`{"a.example.":"$ORIGIN a.example.\n@ IN BOGUS x\n"}`)); err == nil {
			t.Fatal("corrupt zone text accepted")
		}
		if calls != 0 {
			t.Errorf("rejected payload fired the mutation hook %d times", calls)
		}
	})

	t.Run("repeated restore stays consistent", func(t *testing.T) {
		c, m, v := zoneHooksFollower(t, nil)
		payload := zoneHooksSnapshot(t, map[string]string{"a.example.": "192.0.2.99"})
		for i := 0; i < 3; i++ {
			if err := c.restoreZones(payload); err != nil {
				t.Fatal(err)
			}
			if !v.sameAsManager(m) || v.ns1("a.example.") != "192.0.2.99" {
				t.Fatalf("restore #%d: view out of sync (a=%s)", i+1, v.ns1("a.example."))
			}
		}
	})

	// The raft apply loop re-restores the snapshot when an entry was applied
	// concurrently with an install (F174). Gate a log-replayed create_zone to
	// land in the middle of the first restore; the re-restore must converge
	// both the store and the view to exactly the snapshot.
	t.Run("apply interleaved with restore converges on re-restore", func(t *testing.T) {
		inRestore := make(chan struct{})
		release := make(chan struct{})
		var gated atomic.Bool
		c, m, v := zoneHooksFollower(t, func(*zone.Manager, *zoneHooksView, string) {
			// Park only the restore's first notification; later ones
			// (including the interleaved apply's) pass straight through.
			if gated.CompareAndSwap(false, true) {
				close(inRestore)
				<-release
			}
		})
		payload := zoneHooksSnapshot(t, map[string]string{"a.example.": "192.0.2.99"})
		done := make(chan error, 1)
		go func() { done <- c.restoreZones(payload) }()
		<-inRestore
		c.applyRaftZoneCommand(raft.ZoneCommand{Type: "create_zone", Zone: "d.example.", TTL: 3600,
			Nameservers: []string{"ns1.d.example."}, AdminEmail: "hostmaster.d.example."})
		if _, ok := m.Get("d.example."); !ok {
			t.Fatal("precondition: interleaved create_zone did not apply")
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if err := c.restoreZones(payload); err != nil {
			t.Fatal(err)
		}
		if _, ok := m.Get("d.example."); ok {
			t.Error("zone created during the install survived the re-restore")
		}
		if !v.sameAsManager(m) || v.ns1("a.example.") != "192.0.2.99" {
			t.Errorf("view out of sync after re-restore (a=%s)", v.ns1("a.example."))
		}
	})
}

// F343: handleGossip must hand OnNodeUpdate the node after the update, not
// the copy taken before it.
func TestHandleGossip_UpdateCallbackSeesNewState(t *testing.T) {
	gp := newSwimTestGossip(t, newSwimTestConn(false),
		&Node{ID: "P", Addr: "127.0.0.1", Port: 2, State: NodeStateAlive, LastSeen: time.Now()})
	var got []Node
	gp.SetCallbacks(nil, nil, func(n *Node) { got = append(got, *n) }, nil, nil, nil)

	send := func(from string, state NodeState, version uint64) {
		p, _ := encodePayload(GossipPayload{Nodes: []NodeInfo{{ID: "P", Addr: "127.0.0.1", Port: 2, State: state, Version: version}}})
		gp.handleGossip(Message{Type: MessageTypeGossip, From: from, Payload: p}, nil)
	}
	check := func(step string, wantCalls int, want NodeState) {
		t.Helper()
		stored, _ := gp.nodeList.Get("P")
		if len(got) != wantCalls {
			t.Fatalf("%s: %d callbacks, want %d", step, len(got), wantCalls)
		}
		last := got[len(got)-1]
		if last.State != want || last.State != stored.State || last.Version != stored.Version {
			t.Fatalf("%s: callback saw state=%s version=%d, stored state=%s version=%d, want %s",
				step, last.State, last.Version, stored.State, stored.Version, want)
		}
	}

	send("P", NodeStateDraining, 1)
	check("alive->draining", 1, NodeStateDraining)
	send("X", NodeStateDead, 1) // impostor: dropped, no callback
	if len(got) != 1 {
		t.Fatalf("impostor frame fired %d callbacks", len(got)-1)
	}
	send("P", NodeStateAlive, 2)
	check("draining->alive", 2, NodeStateAlive)
	stored, _ := gp.nodeList.Get("P")
	send("P", NodeStateAlive, stored.Version+1) // same state, newer version
	check("version bump", 3, NodeStateAlive)
}
