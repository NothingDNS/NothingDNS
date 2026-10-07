package cluster

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"
)

type handlersRegConn struct{ frames [][]byte }

func (c *handlersRegConn) ReadFromUDP([]byte) (int, *net.UDPAddr, error) {
	return 0, nil, net.ErrClosed
}
func (c *handlersRegConn) WriteToUDP(b []byte, _ *net.UDPAddr) (int, error) {
	c.frames = append(c.frames, append([]byte(nil), b...))
	return len(b), nil
}
func (c *handlersRegConn) SetReadDeadline(time.Time) error { return nil }
func (c *handlersRegConn) Close() error                    { return nil }

func newHandlersRegGossip(t *testing.T, id string, key []byte) (*GossipProtocol, *NodeList, *handlersRegConn) {
	t.Helper()
	nl := NewNodeList(&Node{ID: id, Addr: "127.0.0.1", Port: 2, State: NodeStateAlive, Version: 1})
	gp, err := NewGossipProtocol(GossipConfig{BindAddr: "127.0.0.1", BindPort: 2, EncryptionKey: key}, nl, key == nil)
	if err != nil {
		t.Fatalf("NewGossipProtocol: %v", err)
	}
	c := &handlersRegConn{}
	gp.conn = c
	return gp, nl, c
}

// F132: a node restarted under the same node ID must not have its frames
// dropped by peers' replay high-water mark from its previous incarnation,
// while a genuine replay is still rejected.
func TestGossipSequence_RestartedNodeNotSilencedAsReplay(t *testing.T) {
	if gossipSequenceSeed() == 0 {
		t.Fatal("default sequence seed is the 0 sentinel")
	}
	orig := gossipSequenceSeed
	t.Cleanup(func() { gossipSequenceSeed = orig })

	key := bytes.Repeat([]byte{7}, 32)
	recv, _, _ := newHandlersRegGossip(t, "O", key)
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2}
	deliver := func(frames [][]byte) {
		for _, f := range frames {
			recv.handleMessage(f, from)
		}
	}

	gossipSequenceSeed = func() uint64 { return 1000 }
	p1, _, c1 := newHandlersRegGossip(t, "P", key)
	for i := 0; i < 5; i++ {
		if err := p1.Join("127.0.0.1:1"); err != nil {
			t.Fatal(err)
		}
	}
	deliver(c1.frames)
	if got := recv.Stats().PingReceived; got != 5 {
		t.Fatalf("first incarnation: pings accepted=%d, want 5", got)
	}

	// Restart: a later process start seeds a higher sequence.
	gossipSequenceSeed = func() uint64 { return 2000 }
	p2, _, c2 := newHandlersRegGossip(t, "P", key)
	if err := p2.Join("127.0.0.1:1"); err != nil {
		t.Fatal(err)
	}
	deliver(c2.frames)
	if got := recv.Stats().PingReceived; got != 6 {
		t.Fatalf("restarted incarnation: pings accepted=%d, want 6 (dropped as replay)", got)
	}

	// Replaying either incarnation's frames is still rejected.
	deliver(c2.frames)
	deliver(c1.frames[:1])
	if got := recv.Stats().PingReceived; got != 6 {
		t.Fatalf("replayed frames accepted: pings=%d, want 6", got)
	}
}

// F133: the peer's own authenticated gossip about itself must override our
// locally-bumped view, even when our local Version counter is ahead of the
// peer's self-version (restart, or local suspect/ack/draining bumps).
func TestHandleGossip_SelfReportedStateBeatsLocalVersionBumps(t *testing.T) {
	selfReport := func(gp *GossipProtocol, from string, about string, state NodeState, ver uint64) {
		payload, err := encodePayload(GossipPayload{Nodes: []NodeInfo{{
			ID: about, Addr: "127.0.0.1", Port: 3, State: state, Version: ver, LastSeen: time.Now(),
		}}})
		if err != nil {
			t.Fatal(err)
		}
		gp.handleGossip(Message{Type: MessageTypeGossip, From: from, Payload: payload}, nil)
	}
	setup := func() (*GossipProtocol, *NodeList) {
		gp, nl, _ := newHandlersRegGossip(t, "O", nil)
		nl.Add(&Node{ID: "P", Addr: "127.0.0.1", Port: 3, State: NodeStateAlive, Version: 1})
		nl.Add(&Node{ID: "Q", Addr: "127.0.0.1", Port: 4, State: NodeStateAlive, Version: 1})
		return gp, nl
	}
	state := func(nl *NodeList) NodeState {
		n, ok := nl.Get("P")
		if !ok {
			t.Fatal("P missing")
		}
		return n.State
	}

	t.Run("restarted after being declared dead", func(t *testing.T) {
		gp, nl := setup()
		nl.UpdateState("P", NodeStateSuspect)
		nl.UpdateState("P", NodeStateDead)
		selfReport(gp, "P", "P", NodeStateAlive, 1)
		if got := state(nl); got != NodeStateAlive {
			t.Fatalf("P=%s, want alive", got)
		}
	})

	t.Run("undrain frame lost, gossip repairs", func(t *testing.T) {
		gp, nl := setup()
		nl.UpdateState("P", NodeStateSuspect) // earlier suspicion...
		nl.UpdateState("P", NodeStateAlive)   // ...refuted by an ack
		nl.UpdateState("P", NodeStateDraining)
		// P: self-version 1 -> 2 (draining) -> 3 (alive); Draining=false lost.
		selfReport(gp, "P", "P", NodeStateAlive, 3)
		if got := state(nl); got != NodeStateAlive {
			t.Fatalf("P=%s, want alive", got)
		}
	})

	t.Run("impostor cannot change another node", func(t *testing.T) {
		gp, nl := setup()
		nl.UpdateState("P", NodeStateSuspect)
		nl.UpdateState("P", NodeStateDead)
		selfReport(gp, "Q", "P", NodeStateAlive, 99)
		if got := state(nl); got != NodeStateDead {
			t.Fatalf("P=%s after impostor gossip, want dead", got)
		}
	})

	t.Run("same state same version is a no-op", func(t *testing.T) {
		gp, nl := setup()
		updates := 0
		gp.SetCallbacks(nil, nil, func(*Node) { updates++ }, nil, nil, nil)
		selfReport(gp, "P", "P", NodeStateAlive, 1)
		if updates != 0 || state(nl) != NodeStateAlive {
			t.Fatalf("updates=%d state=%s, want 0/alive", updates, state(nl))
		}
	})
}

// F134: metrics from non-member IDs are neither stored nor aggregated.
func TestHandleClusterMetrics_IgnoresNonMembers(t *testing.T) {
	gp, nl, _ := newHandlersRegGossip(t, "O", nil)
	nl.Add(&Node{ID: "P", Addr: "127.0.0.1", Port: 3, State: NodeStateAlive, Version: 1})
	send := func(id string, q uint64) {
		payload, err := encodePayload(ClusterMetricsPayload{NodeID: id, QueriesTotal: q})
		if err != nil {
			t.Fatal(err)
		}
		gp.handleClusterMetrics(Message{Type: MessageTypeClusterMetrics, From: id, Payload: payload}, nil)
	}
	send("P", 100)
	for i := 0; i < 100; i++ {
		send(fmt.Sprintf("ghost-%d", i), 1000)
	}
	send("P", 150) // member update still applies
	gp.nodeMetricsMu.RLock()
	entries := len(gp.nodeMetrics)
	gp.nodeMetricsMu.RUnlock()
	if total := gp.GetClusterMetrics().QueriesTotal; entries != 1 || total != 150 {
		t.Fatalf("entries=%d total=%d, want 1/150", entries, total)
	}
}

// F135: latency averages are taken over the nodes reporting latency, not the
// nodes reporting QPS.
func TestGetClusterMetrics_LatencyAveragedOverReporters(t *testing.T) {
	for _, tc := range []struct {
		name         string
		ms           []ClusterMetricsPayload
		wantAvg, p99 float64
	}{
		{"all busy", []ClusterMetricsPayload{{QueriesPerSec: 5, LatencyMsAvg: 10, LatencyMsP99: 40}, {QueriesPerSec: 7, LatencyMsAvg: 20, LatencyMsP99: 60}}, 15, 50},
		{"all idle", []ClusterMetricsPayload{{LatencyMsAvg: 10, LatencyMsP99: 40}, {LatencyMsAvg: 20, LatencyMsP99: 60}}, 15, 50},
		{"mixed", []ClusterMetricsPayload{{QueriesPerSec: 5, LatencyMsAvg: 10, LatencyMsP99: 40}, {LatencyMsAvg: 20, LatencyMsP99: 60}}, 15, 50},
		{"one without latency", []ClusterMetricsPayload{{QueriesPerSec: 5, LatencyMsAvg: 10, LatencyMsP99: 40}, {QueriesPerSec: 5}}, 10, 40},
		{"empty", nil, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gp, _, _ := newHandlersRegGossip(t, "O", nil)
			for i, m := range tc.ms {
				m.NodeID = fmt.Sprintf("n%d", i)
				gp.nodeMetrics[m.NodeID] = m
			}
			got := gp.GetClusterMetrics()
			if got.LatencyMsAvg != tc.wantAvg || got.LatencyMsP99 != tc.p99 {
				t.Fatalf("avg=%v p99=%v, want %v/%v", got.LatencyMsAvg, got.LatencyMsP99, tc.wantAvg, tc.p99)
			}
		})
	}
}
