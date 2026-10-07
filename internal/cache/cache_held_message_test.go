package cache

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// F67 regression: the cache used to Release() an entry's pooled *Message
// whenever the entry was unlinked from the LRU list — including on
// moveToFront, which runs on the first hit of any non-MRU entry. Get/GetStale
// return that same *Message to callers, so promoted hits came back wiped
// (zero answers) and a still-referenced message was handed back to the pool
// for reuse by an unrelated query.

func heldMsg(name string) *protocol.Message {
	n := mustName(name)
	return &protocol.Message{
		Header:    protocol.Header{ID: 1, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Questions: []*protocol.Question{{Name: n, QType: protocol.TypeA, QClass: protocol.ClassIN}},
		Answers: []*protocol.ResourceRecord{{Name: n, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300,
			Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}}}},
	}
}

func assertIntact(t *testing.T, what string, e *Entry) {
	t.Helper()
	if e == nil || e.Message == nil {
		t.Fatalf("%s: entry or message is nil", what)
	}
	if len(e.Message.Answers) != 1 || len(e.Message.Questions) != 1 {
		t.Fatalf("%s: message wiped: %d answers, %d questions; want 1/1",
			what, len(e.Message.Answers), len(e.Message.Questions))
	}
}

func TestCache_PromotedHitKeepsMessage(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Capacity = numShards * 64
	c := New(cfg)
	for i := 0; i < 64; i++ {
		c.Set(fmt.Sprintf("k%d", i), heldMsg(fmt.Sprintf("k%d.example.", i)), 300)
	}
	for round := 0; round < 2; round++ {
		for i := 0; i < 64; i++ {
			assertIntact(t, fmt.Sprintf("round %d Get k%d", round, i), c.Get(fmt.Sprintf("k%d", i)))
		}
	}
}

func TestCache_HeldHitSurvivesReplaceDeleteEvictClear(t *testing.T) {
	cfg := DefaultConfig()
	c := New(cfg)

	c.Set("a", heldMsg("a.example."), 300)
	held := c.Get("a")
	c.Set("a", heldMsg("a.example."), 300)
	assertIntact(t, "after replace", held)

	held = c.Get("a")
	c.Delete("a")
	assertIntact(t, "after Delete", held)

	c.Set("b", heldMsg("b.example."), 300)
	held = c.Get("b")
	c.EvictPercent(100)
	assertIntact(t, "after EvictPercent", held)

	c.Set("c", heldMsg("c.example."), 300)
	held = c.Get("c")
	c.Clear()
	assertIntact(t, "after Clear", held)
}

func TestCache_GetStalePromotedKeepsAnswers(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinTTL = 0
	cfg.ServeStale = true
	cfg.StaleGrace = time.Hour
	c := New(cfg)
	clock := &fakeHeldClock{now: time.Unix(1_700_000_000, 0)}
	c.setClockForTest(clock)
	// Two entries in the same shard so the stale one is not already MRU.
	var keys []string
	target := c.shardOf("stale")
	keys = append(keys, "stale")
	for i := 0; len(keys) < 2; i++ {
		k := fmt.Sprintf("other%d", i)
		if c.shardOf(k) == target {
			keys = append(keys, k)
		}
	}
	c.Set(keys[0], heldMsg("stale.example."), 10)
	c.Set(keys[1], heldMsg("other.example."), 300)
	clock.now = clock.now.Add(20 * time.Second)
	stale := c.GetStale(keys[0])
	assertIntact(t, "GetStale after promotion", stale)
	assertIntact(t, "second GetStale", c.GetStale(keys[0]))
}

type fakeHeldClock struct{ now time.Time }

func (f *fakeHeldClock) Now() time.Time { return f.now }

// Gated ordering: a reader holds a hit, the key is refreshed and the shard
// evicted while the reader is parked, then the reader copies the message.
func TestCache_HeldHitConcurrentRefreshGated(t *testing.T) {
	c := New(DefaultConfig())
	c.Set("g", heldMsg("g.example."), 300)
	gotHit := make(chan struct{})
	proceed := make(chan struct{})
	var wg sync.WaitGroup
	var copied *protocol.Message
	wg.Add(1)
	go func() {
		defer wg.Done()
		e := c.Get("g")
		close(gotHit)
		<-proceed
		if e != nil {
			copied = e.AgeAdjustedMessage(time.Now())
		}
	}()
	<-gotHit
	c.Set("g", heldMsg("g.example."), 300)
	c.Delete("g")
	// Churn the pool so a released message would be reused.
	for i := 0; i < 16; i++ {
		m := heldMsg("noise.example.")
		buf := make([]byte, m.WireLength())
		n, err := m.Pack(buf)
		if err != nil {
			t.Fatal(err)
		}
		if u, err := protocol.UnpackMessage(buf[:n]); err == nil {
			_ = u
		}
	}
	close(proceed)
	wg.Wait()
	if copied == nil || len(copied.Answers) != 1 || copied.Questions[0].Name.String() != "g.example." {
		t.Fatalf("held hit corrupted after concurrent refresh: %+v", copied)
	}
}
