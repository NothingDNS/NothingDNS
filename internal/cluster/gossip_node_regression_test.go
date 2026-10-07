package cluster

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// gossipNodeRegConn parks the first WriteToUDP (after sendMessage allocated
// its sequence) until released, and records frames in wire order.
type gossipNodeRegConn struct {
	mu      sync.Mutex
	frames  [][]byte
	writes  int
	parked  chan struct{}
	release chan struct{}
}

func (c *gossipNodeRegConn) ReadFromUDP([]byte) (int, *net.UDPAddr, error) {
	return 0, nil, net.ErrClosed
}
func (c *gossipNodeRegConn) WriteToUDP(b []byte, _ *net.UDPAddr) (int, error) {
	c.mu.Lock()
	c.writes++
	first := c.writes == 1
	c.mu.Unlock()
	if first && c.release != nil {
		close(c.parked)
		<-c.release
	}
	c.mu.Lock()
	c.frames = append(c.frames, append([]byte(nil), b...))
	c.mu.Unlock()
	return len(b), nil
}
func (c *gossipNodeRegConn) SetReadDeadline(time.Time) error { return nil }
func (c *gossipNodeRegConn) Close() error                    { return nil }

// F142: two goroutines sending concurrently put frames on the wire out of
// sequence order; the receiver must accept both, while still rejecting
// exact replays and frames older than the replay window.
func TestGossipSequence_ConcurrentSendsNotDroppedAsReplay(t *testing.T) {
	key := bytes.Repeat([]byte{9}, 32)
	sender, _, _ := newHandlersRegGossip(t, "S", key)
	recv, _, _ := newHandlersRegGossip(t, "R", key)
	conn := &gossipNodeRegConn{parked: make(chan struct{}), release: make(chan struct{})}
	sender.conn = conn
	var got []string
	recv.SetCallbacks(nil, nil, nil, func(k []string) { got = append(got, k...) }, nil, nil)

	to := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2}
	send := func(k string) {
		p, _ := encodePayload(CacheInvalidatePayload{Keys: []string{k}, Source: "S"})
		if err := sender.sendMessage(MessageTypeCacheInvalidate, p, to); err != nil {
			t.Error(err)
		}
	}
	done := make(chan struct{})
	go func() { defer close(done); send("a.") }()
	<-conn.parked // "a." holds seq N but is not on the wire yet
	send("b.")    // seq N+1 written first
	close(conn.release)
	<-done
	deliver := func() {
		for _, f := range conn.frames {
			recv.handleMessage(f, to)
		}
	}
	deliver()
	if fmt.Sprint(got) != "[b. a.]" {
		t.Fatalf("delivered %v, want [b. a.] (lower-sequence frame dropped as replay)", got)
	}
	deliver() // exact replays of both, in either order
	if len(got) != 2 {
		t.Fatalf("replayed frames accepted: %v", got)
	}
}

func TestGossipSequence_ReplayWindowEdges(t *testing.T) {
	gp, _, _ := newHandlersRegGossip(t, "R", bytes.Repeat([]byte{1}, 32))
	steps := []struct {
		seq uint64
		ok  bool
	}{
		{1000, true},                       // first frame
		{1000, false},                      // exact replay
		{1010, true},                       // gap (frames to other peers)
		{1005, true},                       // late, inside window
		{1005, false},                      // replay of the late frame
		{1010 - seqReplayWindow + 1, true}, // oldest still inside the window
		{1010 - seqReplayWindow, false},    // just outside the window
		{1010 + seqReplayWindow + 5, true}, // jump past the window
		{1010, false},                      // now outside the window
	}
	for i, s := range steps {
		err := gp.acceptSequence("P", s.seq)
		if (err == nil) != s.ok {
			t.Fatalf("step %d seq %d: accepted=%v want %v (%v)", i, s.seq, err == nil, s.ok, err)
		}
	}
}

// F143: the per-sender replay table is bounded against fabricated sender IDs;
// eviction never drops a current member's replay state.
func TestGossipSequence_TableBoundedAgainstFabricatedSenders(t *testing.T) {
	orig := maxSequenceEntries
	t.Cleanup(func() { maxSequenceEntries = orig })
	maxSequenceEntries = 8

	gp, nl, _ := newHandlersRegGossip(t, "R", bytes.Repeat([]byte{2}, 32))
	nl.Add(&Node{ID: "P", State: NodeStateAlive, Version: 1})
	if err := gp.acceptSequence("P", 100); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		_ = gp.acceptSequence(fmt.Sprintf("fake-%d", i), 1)
		gp.sequenceMu.RLock()
		n, w := len(gp.sequences), len(gp.seqWindows)
		gp.sequenceMu.RUnlock()
		if n > maxSequenceEntries || w > maxSequenceEntries {
			t.Fatalf("after %d fabricated senders: entries=%d windows=%d, cap %d", i+1, n, w, maxSequenceEntries)
		}
	}
	if err := gp.acceptSequence("P", 100); err == nil {
		t.Fatal("member P lost its replay state to eviction")
	}
	if err := gp.acceptSequence("P", 101); err != nil {
		t.Fatalf("member P new frame rejected: %v", err)
	}

	// A table full of members fails closed for a new sender instead of evicting them.
	maxSequenceEntries = 2
	gp2, nl2, _ := newHandlersRegGossip(t, "R", bytes.Repeat([]byte{2}, 32))
	nl2.Add(&Node{ID: "A", State: NodeStateAlive, Version: 1})
	nl2.Add(&Node{ID: "B", State: NodeStateAlive, Version: 1})
	_ = gp2.acceptSequence("A", 1)
	_ = gp2.acceptSequence("B", 1)
	if err := gp2.acceptSequence("C", 1); err == nil {
		t.Fatal("new sender accepted into a table full of members")
	}
	if err := gp2.acceptSequence("A", 1); err == nil {
		t.Fatal("member A replay accepted after a full-table sweep")
	}
}

// F144: NodeList.Add keeps its own copy, so the *Node handed to OnNodeJoin
// handlers is not the live entry the failure detector mutates under nl.mu.
func TestNodeListAdd_JoinedNodeNotAliasedToTable(t *testing.T) {
	gp, nl, _ := newHandlersRegGossip(t, "R", nil)
	var joined *Node
	gp.SetCallbacks(func(n *Node) { joined = n }, nil, nil, nil, nil, nil)
	p, _ := encodePayload(GossipPayload{Nodes: []NodeInfo{{ID: "P", Addr: "127.0.0.1", Port: 3, State: NodeStateSuspect, Version: 1, LastSeen: time.Now()}}})
	gp.handleGossip(Message{Type: MessageTypeGossip, From: "P", Payload: p}, &net.UDPAddr{})
	if joined == nil {
		t.Fatal("join callback not fired")
	}

	// Race-detector half: handler reads its node while the ack path updates P.
	ack, _ := encodePayload(AckPayload{NodeID: "P"})
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	n := joined
	go func() { defer wg.Done(); <-start; _ = n.State.String() }()
	go func() { defer wg.Done(); <-start; gp.handleAck(Message{From: "P", Payload: ack}, nil) }()
	close(start)
	wg.Wait()

	if joined.State != NodeStateSuspect {
		t.Fatalf("handler's node mutated by NodeList: state=%v", joined.State)
	}
	if live, _ := nl.Get("P"); live.State != NodeStateAlive {
		t.Fatalf("table entry state=%v, want alive after ack", live.State)
	}
	joined.Meta.Region = "handler"
	if live, _ := nl.Get("P"); live.Meta.Region != "" {
		t.Fatalf("handler write leaked into the table: Region=%q", live.Meta.Region)
	}

	// Update path (newer version) also stores a copy.
	upd := &Node{ID: "P", State: NodeStateAlive, Version: 99}
	if !nl.Add(upd) {
		t.Fatal("newer version not applied")
	}
	upd.State = NodeStateDead
	if live, _ := nl.Get("P"); live.State != NodeStateAlive {
		t.Fatalf("caller write leaked into the table on update: state=%v", live.State)
	}
}
