package cluster

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// swimTestConn is an in-memory gossipUDPConn. When gate is non-nil every
// WriteToUDP parks on it (a durable channel block under synctest).
type swimTestConn struct {
	gate     chan struct{}
	entered  chan struct{}
	closed   chan struct{}
	isClosed atomic.Bool
	writes   atomic.Int32
}

func newSwimTestConn(gated bool) *swimTestConn {
	c := &swimTestConn{entered: make(chan struct{}, 1), closed: make(chan struct{})}
	if gated {
		c.gate = make(chan struct{})
	}
	return c
}

func (c *swimTestConn) ReadFromUDP([]byte) (int, *net.UDPAddr, error) {
	<-c.closed
	return 0, nil, net.ErrClosed
}

func (c *swimTestConn) WriteToUDP(b []byte, _ *net.UDPAddr) (int, error) {
	select {
	case c.entered <- struct{}{}:
	default:
	}
	if c.gate != nil {
		<-c.gate
	}
	c.writes.Add(1)
	return len(b), nil
}

func (c *swimTestConn) SetReadDeadline(time.Time) error { return nil }

func (c *swimTestConn) Close() error {
	if c.isClosed.CompareAndSwap(false, true) {
		close(c.closed)
	}
	return nil
}

func newSwimTestGossip(t *testing.T, conn gossipUDPConn, peers ...*Node) *GossipProtocol {
	t.Helper()
	nl := NewNodeList(&Node{ID: "self", Addr: "127.0.0.1", Port: 1, State: NodeStateAlive})
	for _, p := range peers {
		nl.Add(p)
	}
	gp, err := NewGossipProtocol(GossipConfig{BindAddr: "127.0.0.1", BindPort: 1}, nl, true)
	if err != nil {
		t.Fatal(err)
	}
	gp.conn = conn
	return gp
}

func swimAck(gp *GossipProtocol, id string) {
	p, _ := encodePayload(AckPayload{NodeID: id})
	gp.handleAck(Message{Type: MessageTypeAck, From: id, Payload: p}, nil)
}

func swimPing(gp *GossipProtocol, id string) {
	p, _ := encodePayload(PingPayload{NodeID: id})
	gp.handlePing(Message{Type: MessageTypePing, From: id, Payload: p}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2})
}

// F137: the election goroutine spawned by checkLeaderHealth must be tracked
// by gp.wg — Stop may not return while it is still sending.
func TestGossipStop_WaitsForInFlightElection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newSwimTestConn(true)
		gp := newSwimTestGossip(t, c, &Node{ID: "peer", Addr: "127.0.0.1", Port: 2, State: NodeStateAlive})
		gp.leaderMu.Lock()
		gp.currentLeader = "leader"
		gp.leaderMu.Unlock()

		gp.checkLeaderHealth()
		<-c.entered // election is parked inside its send
		gp.checkLeaderHealth()
		synctest.Wait()

		stopDone := make(chan struct{})
		go func() { _ = gp.Stop(); close(stopDone) }()
		synctest.Wait()
		select {
		case <-stopDone:
			t.Fatal("Stop returned while the election goroutine was still sending")
		default:
		}
		close(c.gate)
		synctest.Wait()
		<-stopDone
		if got := c.writes.Load(); got != 1 {
			t.Fatalf("writes = %d, want 1 (single-flight election, one peer)", got)
		}
	})
}

// F137 edge: an election that starts after Stop sends nothing.
func TestGossipElection_AfterStopSendsNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newSwimTestConn(false)
		gp := newSwimTestGossip(t, c, &Node{ID: "peer", Addr: "127.0.0.1", Port: 2, State: NodeStateAlive})
		if err := gp.Stop(); err != nil {
			t.Fatal(err)
		}
		gp.leaderMu.Lock()
		gp.currentLeader = "leader"
		gp.leaderMu.Unlock()
		gp.checkLeaderHealth()
		gp.wg.Wait()
		if got := c.writes.Load(); got != 0 {
			t.Fatalf("writes after Stop = %d, want 0", got)
		}
		gp.leaderMu.RLock()
		running := gp.electionRunning
		gp.leaderMu.RUnlock()
		if running {
			t.Fatal("electionRunning still set after the election goroutine exited")
		}
	})
}

// F138: a refutation that lands between probeNodes' snapshot and its
// state update must win. The first onNodeLeave delivers the refutation for
// the other expired peer (gated ordering independent of map order).
func TestProbeNodes_RefutationInsideWindowWins(t *testing.T) {
	for _, tc := range []struct {
		name   string
		refute func(gp *GossipProtocol, id string)
	}{
		{"ack", swimAck},
		{"ping", swimPing}, // MarkSeen only: fresh proof of life
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := time.Now().Add(-time.Hour)
			gp := newSwimTestGossip(t, newSwimTestConn(false),
				&Node{ID: "A", Addr: "127.0.0.1", Port: 2, State: NodeStateSuspect, LastSeen: old},
				&Node{ID: "B", Addr: "127.0.0.1", Port: 2, State: NodeStateSuspect, LastSeen: old})
			var mu sync.Mutex
			var left []string
			gp.SetCallbacks(nil, func(n *Node) {
				mu.Lock()
				first := len(left) == 0
				left = append(left, n.ID)
				mu.Unlock()
				if first {
					other := "A"
					if n.ID == "A" {
						other = "B"
					}
					tc.refute(gp, other)
				}
			}, nil, nil, nil, nil)
			gp.probeNodes()
			if len(left) != 1 {
				t.Fatalf("onNodeLeave fired for %v, want exactly the unrefuted peer", left)
			}
			other := "A"
			if left[0] == "A" {
				other = "B"
			}
			if n, _ := gp.nodeList.Get(other); n.State == NodeStateDead {
				t.Fatalf("refuted peer %s declared dead", other)
			}
		})
	}
}

// F138 edges: Alive→Suspect and Dead→Remove also honor a refutation that
// arrives after the snapshot.
func TestProbeNodes_StaleSnapshotDoesNotSuspectOrRemove(t *testing.T) {
	old := time.Now().Add(-time.Hour)
	nl := NewNodeList(&Node{ID: "self", State: NodeStateAlive})
	nl.Add(&Node{ID: "P", State: NodeStateAlive, LastSeen: old})
	nl.Add(&Node{ID: "D", State: NodeStateDead, LastSeen: old})
	nl.MarkSeen("P") // pinged after the snapshot was taken
	if nl.transitionIfUnchanged("P", NodeStateAlive, old, NodeStateSuspect) {
		t.Fatal("stale snapshot suspected a freshly seen peer")
	}
	nl.UpdateState("D", NodeStateAlive) // revived by an Ack after the snapshot
	if nl.removeIfUnchanged("D", NodeStateDead, old) {
		t.Fatal("stale snapshot removed a revived peer")
	}
	if _, ok := nl.Get("D"); !ok {
		t.Fatal("revived peer missing")
	}
	n, _ := nl.Get("P")
	if !nl.transitionIfUnchanged("P", NodeStateAlive, n.LastSeen, NodeStateSuspect) {
		t.Fatal("unchanged snapshot must still transition")
	}
	if nl.transitionIfUnchanged("self", NodeStateAlive, time.Time{}, NodeStateDead) {
		t.Fatal("self must never be transitioned")
	}
}

// F139: an authenticated Gossip frame from the peer itself refreshes its
// liveness; an impostor's frame about it does not.
func TestHandleGossip_SelfDescribingFrameRefreshesLiveness(t *testing.T) {
	run := func(from string) NodeState {
		gp := newSwimTestGossip(t, newSwimTestConn(false),
			&Node{ID: "P", Addr: "127.0.0.1", Port: 2, State: NodeStateAlive, LastSeen: time.Now().Add(-time.Hour)})
		n, _ := gp.nodeList.Get("P")
		p, _ := encodePayload(GossipPayload{Nodes: []NodeInfo{{ID: "P", Addr: "127.0.0.1", Port: 2, State: NodeStateAlive, Version: n.Version}}})
		gp.handleGossip(Message{Type: MessageTypeGossip, From: from, Payload: p}, nil)
		gp.probeNodes()
		got, _ := gp.nodeList.Get("P")
		return got.State
	}
	if got := run("P"); got != NodeStateAlive {
		t.Fatalf("peer gossiping its own state: state=%s, want alive", got)
	}
	if got := run("X"); got != NodeStateSuspect {
		t.Fatalf("impostor gossip about P must not refresh it: state=%s, want suspect", got)
	}
}
