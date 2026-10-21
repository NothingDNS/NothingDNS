package dashboard

import (
	"sync/atomic"
	"testing"
	"time"
)

// With no WebSocket viewer connected the broadcast loop must not serialise
// events (it runs once per DNS query); with a viewer it must still deliver.
func TestBroadcastLoopIdlesWithoutClients(t *testing.T) {
	var calls atomic.Int64
	orig := marshalBroadcast
	marshalBroadcast = func(v any) ([]byte, error) {
		calls.Add(1)
		return orig(v)
	}
	defer func() { marshalBroadcast = orig }()

	s := NewServer()
	defer s.Stop()

	for i := 0; i < 50; i++ {
		s.RecordQuery(&QueryEvent{Domain: "idle.example.com.", QueryType: "A"})
	}
	// Drain: the loop has consumed everything once the channel is empty.
	deadline := time.Now().Add(2 * time.Second)
	for len(s.broadcastChan) > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if n := calls.Load(); n != 0 {
		t.Fatalf("marshalled %d events with no clients connected", n)
	}

	c := &Client{send: make(chan []byte, 4)}
	if !s.tryAddClient(c) {
		t.Fatal("client not added")
	}
	s.RecordQuery(&QueryEvent{Domain: "watched.example.com.", QueryType: "A"})
	select {
	case <-c.send:
	case <-time.After(2 * time.Second):
		t.Fatal("connected client received no event")
	}
	if calls.Load() == 0 {
		t.Fatal("expected a marshal for the connected client")
	}
}
