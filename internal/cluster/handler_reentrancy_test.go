package cluster

import (
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

// newReentrantTestCluster builds a Cluster with a real logger — the gossip
// callbacks log before dispatching, and a nil *util.Logger segfaults, which
// would mask the behaviour under test.
func newReentrantTestCluster() *Cluster {
	return &Cluster{logger: util.NewLogger(util.INFO, util.TextFormat, nil)}
}

// reentrantHandler re-enters the cluster's handler registry from inside a
// gossip callback — once adding, once removing.
type reentrantHandler struct {
	c      *Cluster
	add    func()
	remove func()
	called bool
}

// reenter performs the configured re-entrant calls. Every one of the four
// EventHandler methods routes through it, so a test can dispatch any gossip
// callback and still exercise the re-entrancy — a handler that only re-entered
// from OnNodeJoin would leave the other three callbacks untested, and would
// pass even against the deadlocking implementation.
func (r *reentrantHandler) reenter() {
	r.called = true
	if r.add != nil {
		r.add()
	}
	if r.remove != nil {
		r.remove()
	}
}

func (r *reentrantHandler) OnNodeJoin(*Node)        { r.reenter() }
func (r *reentrantHandler) OnNodeLeave(*Node)       { r.reenter() }
func (r *reentrantHandler) OnNodeUpdate(*Node)      { r.reenter() }
func (r *reentrantHandler) OnCacheInvalid([]string) { r.reenter() }

// dispatchBounded runs fn on another goroutine and fails if it does not
// finish promptly. A self-deadlocked dispatch holds the read lock forever, so
// without this bound the test binary would hang until the package timeout
// instead of reporting a clean failure.
func dispatchBounded(t *testing.T, name string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s DEADLOCKED: a handler calling AddEventHandler/RemoveEventHandler "+
			"from inside a gossip callback self-deadlocks when the callback holds "+
			"handlersMu.RLock and the re-entrant call requests the write lock "+
			"(sync.RWMutex is not reentrant)", name)
	}
}

// TestHandlerReentrancy_AddFromCallback pins that a handler may register
// another handler from inside a gossip callback. Dispatch used to run under
// handlersMu.RLock, so the nested AddEventHandler's Lock() blocked forever and
// wedged the gossip receive path for the whole node.
func TestHandlerReentrancy_AddFromCallback(t *testing.T) {
	c := newReentrantTestCluster()

	added := EventHandlerFunc{OnJoinFunc: func(*Node) {}}
	h := &reentrantHandler{c: c, add: func() { c.AddEventHandler(added) }}
	c.AddEventHandler(h)

	dispatchBounded(t, "handler re-entering AddEventHandler", func() {
		c.handleNodeJoin(&Node{ID: "n1"})
	})

	if !h.called {
		t.Fatal("re-entrant handler was never invoked")
	}
	if len(c.handlers) != 2 {
		t.Errorf("expected the nested AddEventHandler to register a second handler, got %d", len(c.handlers))
	}
}

// TestHandlerReentrancy_RemoveFromCallback is the sibling case: removing a
// handler from inside a callback takes the same write lock and deadlocked
// identically.
func TestHandlerReentrancy_RemoveFromCallback(t *testing.T) {
	c := newReentrantTestCluster()

	victim := EventHandlerFunc{OnJoinFunc: func(*Node) {}}
	c.AddEventHandler(victim)

	h := &reentrantHandler{c: c, remove: func() { c.RemoveEventHandler(victim) }}
	c.AddEventHandler(h)

	dispatchBounded(t, "handler re-entering RemoveEventHandler", func() {
		c.handleNodeJoin(&Node{ID: "n1"})
	})

	if !h.called {
		t.Fatal("re-entrant handler was never invoked")
	}
	if len(c.handlers) != 1 {
		t.Errorf("expected the nested RemoveEventHandler to drop the victim, got %d handler(s)", len(c.handlers))
	}
}

// TestHandlerReentrancy_BothFromSameCallback covers a handler that does BOTH in
// one callback, which is what a real re-registration path looks like.
func TestHandlerReentrancy_BothFromSameCallback(t *testing.T) {
	c := newReentrantTestCluster()

	replacement := EventHandlerFunc{OnJoinFunc: func(*Node) {}}
	victim := EventHandlerFunc{OnJoinFunc: func(*Node) {}}
	c.AddEventHandler(victim)

	h := &reentrantHandler{
		c:      c,
		add:    func() { c.AddEventHandler(replacement) },
		remove: func() { c.RemoveEventHandler(victim) },
	}
	c.AddEventHandler(h)

	dispatchBounded(t, "handler re-entering both Add and Remove", func() {
		c.handleNodeJoin(&Node{ID: "n1"})
	})

	if len(c.handlers) != 2 {
		t.Errorf("expected victim removed and replacement added (2 handlers), got %d", len(c.handlers))
	}
}

// TestHandlerReentrancy_AllCallbacks exercises all four gossip callbacks, so
// the guard cannot be re-introduced on one of them unnoticed.
func TestHandlerReentrancy_AllCallbacks(t *testing.T) {
	tests := []struct {
		name     string
		dispatch func(*Cluster)
	}{
		{"handleNodeJoin", func(c *Cluster) { c.handleNodeJoin(&Node{ID: "n1"}) }},
		{"handleNodeLeave", func(c *Cluster) { c.handleNodeLeave(&Node{ID: "n1"}) }},
		{"handleNodeUpdate", func(c *Cluster) { c.handleNodeUpdate(&Node{ID: "n1"}) }},
		{"handleCacheInvalid", func(c *Cluster) { c.handleCacheInvalid([]string{"k1"}) }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newReentrantTestCluster()
			h := &reentrantHandler{
				c:      c,
				add:    func() { c.AddEventHandler(EventHandlerFunc{OnJoinFunc: func(*Node) {}}) },
				remove: func() { c.RemoveEventHandler(EventHandlerFunc{OnJoinFunc: func(*Node) {}}) },
			}
			c.AddEventHandler(h)

			dispatchBounded(t, tc.name, func() { tc.dispatch(c) })

			if !h.called {
				t.Fatalf("%s: handler was never invoked", tc.name)
			}
		})
	}
}

// TestHandlerDispatch_StillInvokesEveryHandler is the control: ordinary,
// non-re-entrant handlers must all still be dispatched exactly once, in
// registration order — the fix must not silently skip or duplicate anyone.
func TestHandlerDispatch_StillInvokesEveryHandler(t *testing.T) {
	c := newReentrantTestCluster()

	var order []string
	first := EventHandlerFunc{OnJoinFunc: func(*Node) { order = append(order, "first") }}
	second := EventHandlerFunc{OnJoinFunc: func(*Node) { order = append(order, "second") }}
	third := &ptrKindHandler{}
	c.AddEventHandler(first)
	c.AddEventHandler(second)
	c.AddEventHandler(third)

	dispatchBounded(t, "ordinary dispatch", func() { c.handleNodeJoin(&Node{ID: "n1"}) })

	if third.joins != 1 {
		t.Errorf("pointer handler dispatched %d time(s), want 1", third.joins)
	}
	if len(order) != 2 || order[0] != "first" || order[1] != "second" {
		t.Errorf("struct handlers invoked as %v, want [first second] in registration order", order)
	}
}

// TestSnapshotHandlers_ReturnsIndependentCopy pins the helper's contract: the
// returned slice must not alias c.handlers, so a handler mutating its own
// snapshot cannot corrupt the registry.
func TestSnapshotHandlers_ReturnsIndependentCopy(t *testing.T) {
	c := newReentrantTestCluster()
	c.AddEventHandler(&ptrKindHandler{})

	snap := c.snapshotHandlers()
	if len(snap) != 1 {
		t.Fatalf("snapshot has %d handler(s), want 1", len(snap))
	}

	snap[0] = nil
	if c.handlers[0] == nil {
		t.Error("mutating the snapshot corrupted c.handlers — the copy is aliasing")
	}
}
