package cluster

import (
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

const lifecycleTestKey = "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"

func newLifecycleTestNode(t *testing.T, id string, port int) *Cluster {
	t.Helper()
	c, err := New(Config{
		NodeID: id, BindAddr: "127.0.0.1", GossipPort: port,
		ConsensusMode: ConsensusSWIM, EncryptionKey: lifecycleTestKey,
	}, util.NewLogger(util.ERROR, util.TextFormat, nil), nil)
	if err != nil {
		t.Fatalf("New(%s): %v", id, err)
	}
	if err := c.Start(); err != nil {
		t.Fatalf("Start(%s): %v", id, err)
	}
	return c
}

// sendUntil re-broadcasts a cache invalidation from src until done closes.
// The resend only compensates for UDP loss; ordering in the tests is gated on
// channels, never on the resend interval.
func sendUntil(t *testing.T, src *Cluster, key string, done <-chan struct{}) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		_ = src.gossip.BroadcastCacheInvalidation([]string{key})
		select {
		case <-done:
			return
		case <-deadline:
			t.Fatalf("cache invalidation %q never delivered", key)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// TestStop_HandlerCallingAccessorDoesNotDeadlock is the F127 regression.
// Stop used to hold c.mu while gossip.Stop waited for the receive loop; an
// EventHandler running on that loop that called IsHealthy/IsStarted/Stats
// blocked on c.mu forever and Stop never returned.
func TestStop_HandlerCallingAccessorDoesNotDeadlock(t *testing.T) {
	accessors := map[string]func(*Cluster){
		"IsHealthy": func(c *Cluster) { _ = c.IsHealthy() },
		"IsStarted": func(c *Cluster) { _ = c.IsStarted() },
		"Stats":     func(c *Cluster) { _ = c.Stats() },
	}
	for name, accessor := range accessors {
		t.Run(name, func(t *testing.T) {
			pA, pB := pickFreePort(), pickFreePort()
			a := newLifecycleTestNode(t, "A", pA)
			b := newLifecycleTestNode(t, "B", pB)
			defer b.Stop()
			b.nodeList.Add(&Node{ID: "A", Addr: "127.0.0.1", Port: pA, State: NodeStateAlive})

			entered := make(chan struct{})
			release := make(chan struct{})
			handled := make(chan struct{})
			var once sync.Once
			a.AddEventHandler(EventHandlerFunc{OnCacheInvalidFunc: func([]string) {
				first := false
				once.Do(func() { first = true })
				if !first {
					return
				}
				close(entered)
				<-release
				accessor(a)
				close(handled)
			}})

			sendUntil(t, b, "k.", entered)

			stopped := make(chan error, 1)
			go func() { stopped <- a.Stop() }()

			// Gate: release the handler only once Stop has committed to
			// stopping — either it holds c.mu, or it already flipped
			// started=false.
			for {
				if !a.mu.TryRLock() {
					break
				}
				flipped := !a.started
				a.mu.RUnlock()
				if flipped {
					break
				}
				runtime.Gosched()
			}
			close(release)

			select {
			case err := <-stopped:
				if err != nil {
					t.Fatalf("Stop: %v", err)
				}
			case <-time.After(10 * time.Second): // deadlock detector bound only
				t.Fatalf("Stop deadlocked while a handler called %s", name)
			}
			<-handled
			if a.IsStarted() {
				t.Fatal("cluster still reports started after Stop")
			}
			// Repeated Stop is a no-op.
			if err := a.Stop(); err != nil {
				t.Fatalf("second Stop: %v", err)
			}
		})
	}
}

// TestStop_BeforeStartIsNoop pins the not-started edge of the F127 rework.
func TestStop_BeforeStartIsNoop(t *testing.T) {
	c, err := New(Config{
		NodeID: "A", BindAddr: "127.0.0.1", GossipPort: pickFreePort(),
		ConsensusMode: ConsensusSWIM, EncryptionKey: lifecycleTestKey,
	}, util.NewLogger(util.ERROR, util.TextFormat, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("Stop before Start: %v", err)
	}
	if c.IsStarted() {
		t.Fatal("Stop before Start marked the cluster started")
	}
}

// drainingBarrier sends a marker cache invalidation from a to b and waits
// until b's handler sees it. b's single receive goroutine handles a's
// datagrams in order, so every frame a sent before the marker was processed.
func drainingBarrier(t *testing.T, a, b *Cluster, tag string) {
	t.Helper()
	got := make(chan struct{})
	var once sync.Once
	h := EventHandlerFunc{OnCacheInvalidFunc: func(keys []string) {
		if len(keys) == 1 && keys[0] == tag {
			once.Do(func() { close(got) })
		}
	}}
	b.AddEventHandler(h)
	defer b.RemoveEventHandler(h)
	sendUntil(t, a, tag, got)
}

// TestCompleteDraining_LeaveKeepsPeersFromRouting is the F128 regression.
// CompleteDraining(true) — the leave path behind DELETE /cluster/leave —
// broadcast Draining=false, which peers handle as "back to alive", so they
// resumed routing queries to the departing node.
func TestCompleteDraining_LeaveKeepsPeersFromRouting(t *testing.T) {
	cases := []struct {
		name        string
		startDrain  bool
		leave       bool
		wantState   NodeState
		wantRouting bool
	}{
		{"drain then leave", true, true, NodeStateDraining, false},
		{"leave without prior drain announcement", false, true, NodeStateDraining, false},
		{"drain then cancel (control)", true, false, NodeStateAlive, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pA, pB := pickFreePort(), pickFreePort()
			a := newLifecycleTestNode(t, "A", pA)
			b := newLifecycleTestNode(t, "B", pB)
			defer a.Stop()
			defer b.Stop()
			a.nodeList.Add(&Node{ID: "B", Addr: "127.0.0.1", Port: pB, State: NodeStateAlive})
			b.nodeList.Add(&Node{ID: "A", Addr: "127.0.0.1", Port: pA, State: NodeStateAlive})

			if tc.startDrain {
				if err := a.StartDraining(); err != nil {
					t.Fatal(err)
				}
				drainingBarrier(t, a, b, "after-start")
				if n, _ := b.nodeList.Get("A"); n == nil || n.State != NodeStateDraining {
					t.Fatalf("peer did not see StartDraining: %+v", n)
				}
			}
			if err := a.CompleteDraining(tc.leave); err != nil {
				t.Fatal(err)
			}
			drainingBarrier(t, a, b, "after-complete")

			n, ok := b.nodeList.Get("A")
			if !ok {
				t.Fatal("peer lost node A")
			}
			if n.State != tc.wantState {
				t.Errorf("peer view of A = %s, want %s", n.State, tc.wantState)
			}
			best := b.GetNodeForQuery(true)
			routed := best != nil && best.ID == "A"
			if routed != tc.wantRouting {
				t.Errorf("peer routes queries to A = %v, want %v", routed, tc.wantRouting)
			}
		})
	}
}

// TestStartedFlag_ConcurrentWithStop is the F129 regression (meaningful under
// -race): JoinSeed, BroadcastClusterMetrics and UpdateNodeHealth read
// c.started without c.mu while Stop writes it.
func TestStartedFlag_ConcurrentWithStop(t *testing.T) {
	callers := map[string]func(*Cluster){
		"JoinSeed":                func(c *Cluster) { _ = c.JoinSeed("127.0.0.1:9") },
		"BroadcastClusterMetrics": func(c *Cluster) { c.BroadcastClusterMetrics(1, 1, 1, 1, 1, 1, 1) },
		"UpdateNodeHealth":        func(c *Cluster) { c.UpdateNodeHealth(NodeHealthStats{}) },
	}
	for name, call := range callers {
		t.Run(name, func(t *testing.T) {
			c := newLifecycleTestNode(t, "A", pickFreePort())
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				call(c)
			}()
			if err := c.Stop(); err != nil {
				t.Fatalf("Stop: %v", err)
			}
			wg.Wait()
			// After Stop the guarded entry points must refuse/skip.
			if err := c.JoinSeed("127.0.0.1:9"); err == nil {
				t.Fatal("JoinSeed after Stop succeeded")
			}
		})
	}
}
