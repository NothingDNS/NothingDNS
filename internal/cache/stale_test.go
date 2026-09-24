package cache

import (
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

type fakeCacheClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeCacheClock() *fakeCacheClock {
	return &fakeCacheClock{now: time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeCacheClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeCacheClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newStaleTestCache() (*Cache, *fakeCacheClock) {
	cfg := DefaultConfig()
	cfg.ServeStale = true
	cfg.StaleGrace = 1 * time.Hour
	cfg.MinTTL = 1 * time.Second
	cfg.MaxTTL = 24 * time.Hour
	clock := newFakeCacheClock()
	cache := New(cfg)
	cache.setClockForTest(clock)
	return cache, clock
}

func newTestMessage() *protocol.Message {
	name, _ := protocol.ParseName("example.com.")
	return &protocol.Message{
		Header: protocol.Header{
			ID:    1234,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeA, QClass: protocol.ClassIN},
		},
		Answers: []*protocol.ResourceRecord{
			{
				Name:  name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{93, 184, 216, 34}},
			},
		},
	}
}

func TestGetStaleDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ServeStale = false
	clock := newFakeCacheClock()
	c := New(cfg)
	c.setClockForTest(clock)

	c.Set("test:1", newTestMessage(), 1)
	clock.Advance(2 * time.Second)

	stale := c.GetStale("test:1")
	if stale != nil {
		t.Error("expected nil when serve-stale is disabled")
	}
}

func TestGetStaleEnabled(t *testing.T) {
	c, clock := newStaleTestCache()

	msg := newTestMessage()
	c.Set("test:1", msg, 1) // 1 second TTL

	// Before expiry — GetStale should return nil (not yet stale)
	stale := c.GetStale("test:1")
	if stale != nil {
		t.Error("expected nil for non-expired entry via GetStale")
	}

	// Normal Get should still work
	entry := c.Get("test:1")
	if entry == nil {
		t.Error("expected entry from normal Get before expiry")
	}

	clock.Advance(2 * time.Second)

	// Normal Get should return nil
	entry = c.Get("test:1")
	if entry != nil {
		t.Error("expected nil from normal Get after expiry")
	}

	// GetStale should return the stale entry
	stale = c.GetStale("test:1")
	if stale == nil {
		t.Fatal("expected stale entry after expiry")
	}
	if !stale.IsStale {
		t.Error("expected IsStale=true on stale entry")
	}
	if stale.TTL != 30 {
		t.Errorf("stale TTL = %d, want 30 (RFC 8767)", stale.TTL)
	}
	if stale.Message == nil {
		t.Error("expected non-nil message in stale entry")
	}
}

func TestGetStaleReturnsMessageCopy(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ServeStale = true
	cfg.StaleGrace = time.Hour
	cfg.MinTTL = 0
	cfg.MaxTTL = time.Hour
	clock := newFakeCacheClock()
	c := New(cfg)
	c.setClockForTest(clock)

	// Set the entry while the fake clock is at 2026-07-09 12:00:00.
	// boundedTTL(30)=30s, so expiry=now+30s (2026-07-09 12:00:30).
	// Using ttl=30 (not 1) so answer TTLs survive the setInternal clamp
	// and GetStale's 30s RFC-8767-§4 clamp leaves them at 30.
	c.Set("test:1", newTestMessage(), 30)

	// Advance past the entry's TTL: expiry was fake-clock+30s, advance by 40s.
	clock.Advance(40 * time.Second)

	stale := c.GetStale("test:1")
	if stale == nil || stale.Message == nil {
		t.Fatal("expected stale message")
	}
	if stale.Message.Header.ID != 1234 {
		t.Fatalf("stale message aliases cached header: got %#x", stale.Message.Header.ID)
	}
	// Cached TTL is 300; stale serving clamps it to 30 (RFC 8767 §4). The
	// aliasing check still holds: had the copy aliased the cached message,
	// the previous mutation would make this read 1.
	if stale.Message.Answers[0].TTL != 30 {
		t.Fatalf("stale message aliases cached answer: got TTL %d, want 30", stale.Message.Answers[0].TTL)
	}
}

func TestGetStaleGracePeriodExpired(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ServeStale = true
	cfg.StaleGrace = 1 * time.Second // Very short grace
	cfg.MinTTL = 1 * time.Second
	clock := newFakeCacheClock()
	c := New(cfg)
	c.setClockForTest(clock)

	c.Set("test:1", newTestMessage(), 1)
	clock.Advance(3 * time.Second)

	// Normal Get returns nil (removes the entry since past grace)
	entry := c.Get("test:1")
	if entry != nil {
		t.Error("expected nil after TTL + grace expiry")
	}

	// GetStale should also return nil since grace has passed
	stale := c.GetStale("test:1")
	if stale != nil {
		t.Error("expected nil from GetStale after grace period")
	}
}

func TestStaleDeadlineReachedBoundary(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	entry := &Entry{
		ExpireTime: now.Add(-1 * time.Hour),
	}
	grace := 1 * time.Hour

	if staleDeadlineReached(now.Add(-time.Nanosecond), entry, grace) {
		t.Error("stale deadline should not be reached before the boundary")
	}
	if !staleDeadlineReached(now, entry, grace) {
		t.Error("stale deadline should be reached exactly at the boundary")
	}
	if !staleDeadlineReached(now.Add(time.Nanosecond), entry, grace) {
		t.Error("stale deadline should be reached after the boundary")
	}

	var nilEntry *Entry
	if !staleDeadlineReached(now, nilEntry, grace) {
		t.Error("nil entry should be treated as past stale deadline")
	}
}

func TestGetStaleNotFound(t *testing.T) {
	c, _ := newStaleTestCache()

	stale := c.GetStale("nonexistent:1")
	if stale != nil {
		t.Error("expected nil for nonexistent key")
	}
}

func TestStaleServedCounter(t *testing.T) {
	c, clock := newStaleTestCache()

	c.Set("test:1", newTestMessage(), 1)
	clock.Advance(2 * time.Second)

	// Serve stale twice
	c.GetStale("test:1")
	c.GetStale("test:1")

	count := c.StaleServed()
	if count != 2 {
		t.Errorf("StaleServed() = %d, want 2", count)
	}
}

func TestStaleStats(t *testing.T) {
	c, clock := newStaleTestCache()

	c.Set("test:1", newTestMessage(), 1)
	clock.Advance(2 * time.Second)

	c.GetStale("test:1")

	stats := c.Stats()
	if stats.StaleServed != 1 {
		t.Errorf("Stats.StaleServed = %d, want 1", stats.StaleServed)
	}
}

func TestServeStalePreservesEntry(t *testing.T) {
	c, clock := newStaleTestCache()

	c.Set("test:1", newTestMessage(), 1)
	clock.Advance(2 * time.Second)

	// Get (normal) should not delete the entry when serve-stale is on
	c.Get("test:1")

	// Entry should still be retrievable via GetStale
	stale := c.GetStale("test:1")
	if stale == nil {
		t.Error("expected stale entry to be preserved after normal Get miss")
	}
}

// Regression: RFC 8767 §4 — stale answers must be served with a short TTL
// (30s), not the TTLs the records were originally cached with. GetStale
// previously set Entry.TTL=30 metadata but left the message's RR TTLs at
// their original (potentially hours-long) values.
func TestGetStaleClampsRecordTTLs(t *testing.T) {
	c, clock := newStaleTestCache()

	msg := newTestMessage()
	for _, rr := range msg.Answers {
		rr.TTL = 3600
	}
	c.Set("test:clamp", msg, 1)

	clock.Advance(2 * time.Second)

	stale := c.GetStale("test:clamp")
	if stale == nil {
		t.Fatal("expected stale entry after expiry")
	}
	for _, section := range [][]*protocol.ResourceRecord{
		stale.Message.Answers, stale.Message.Authorities, stale.Message.Additionals,
	} {
		for _, rr := range section {
			if rr.Type == protocol.TypeOPT {
				continue
			}
			if rr.TTL > 30 {
				t.Errorf("stale RR %s TTL = %d, want <= 30 (RFC 8767 §4)", rr.Name.String(), rr.TTL)
			}
		}
	}
}
