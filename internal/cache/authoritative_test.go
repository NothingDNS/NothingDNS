package cache

import (
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func authoritativeTestMessage(t *testing.T, ttl uint32) *protocol.Message {
	t.Helper()
	msg := newTestMessage()
	if len(msg.Answers) == 0 {
		t.Fatal("test message has no answers")
	}
	for _, rr := range msg.Answers {
		rr.TTL = ttl
	}
	return msg
}

// An authority's TTLs are what it publishes: max_ttl bounds how long this
// server holds forwarded data and must not rewrite them.
func TestSetAuthoritative_KeepsRecordTTLs(t *testing.T) {
	c := New(Config{Capacity: 100, MaxTTL: 300 * time.Second})
	c.SetAuthoritative("|auth|1|0|www.example.com.|1|0", authoritativeTestMessage(t, 86400), 86400)

	entry := c.Get("|auth|1|0|www.example.com.|1|0")
	if entry == nil {
		t.Fatal("expected a cached authoritative entry")
	}
	if got := entry.Message.Answers[0].TTL; got != 86400 {
		t.Errorf("record TTL = %d, want 86400 (unclamped)", got)
	}
	if entry.CanPrefetch {
		t.Error("authoritative entries must never be prefetched")
	}
	if s := c.Stats(); s.Hits != 1 {
		t.Errorf("hits = %d, want 1", s.Hits)
	}
}

func TestSetAuthoritative_ZeroTTLNotCached(t *testing.T) {
	c := New(Config{Capacity: 100})
	c.SetAuthoritative("|auth|1|0|www.example.com.|1|0", authoritativeTestMessage(t, 0), 0)
	if c.Stats().Size != 0 {
		t.Error("a zero-TTL authoritative answer must not be cached")
	}
}

// Keys name this process's zone generations, so a restored entry could never
// be hit — persisting them only wastes capacity.
func TestSave_SkipsAuthoritative(t *testing.T) {
	c := New(Config{Capacity: 100})
	c.SetAuthoritative("|auth|1|0|www.example.com.|1|0", authoritativeTestMessage(t, 300), 300)
	if saved := c.Save(); len(saved) != 0 {
		t.Errorf("Save should skip authoritative entries, got %d", len(saved))
	}
}

func TestSetAuthoritative_NeverServedStale(t *testing.T) {
	c, clock := newStaleTestCache()
	key := "|auth|1|0|www.example.com.|1|0"
	c.SetAuthoritative(key, authoritativeTestMessage(t, 60), 60)

	clock.Advance(61 * time.Second)
	if c.GetStale(key) != nil {
		t.Error("GetStale returned an expired authoritative entry")
	}
	if c.Get(key) != nil {
		t.Error("Get returned an expired authoritative entry")
	}
	if c.Stats().Size != 0 {
		t.Error("expired authoritative entry should be dropped, not kept for stale serving")
	}
}
