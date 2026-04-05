package cache

import (
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func newStaleTestCache() *Cache {
	cfg := DefaultConfig()
	cfg.ServeStale = true
	cfg.StaleGrace = 1 * time.Hour
	cfg.MinTTL = 1 * time.Second
	cfg.MaxTTL = 24 * time.Hour
	return New(cfg)
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
	c := New(cfg)

	c.Set("test:1", newTestMessage(), 1)
	// Wait for expiry
	time.Sleep(2 * time.Second)

	stale := c.GetStale("test:1")
	if stale != nil {
		t.Error("expected nil when serve-stale is disabled")
	}
}

func TestGetStaleEnabled(t *testing.T) {
	c := newStaleTestCache()

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

	// Wait for expiry
	time.Sleep(2 * time.Second)

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

func TestGetStaleGracePeriodExpired(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ServeStale = true
	cfg.StaleGrace = 1 * time.Second // Very short grace
	cfg.MinTTL = 1 * time.Second
	c := New(cfg)

	c.Set("test:1", newTestMessage(), 1)

	// Wait for TTL + grace to expire
	time.Sleep(3 * time.Second)

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

func TestGetStaleNotFound(t *testing.T) {
	c := newStaleTestCache()

	stale := c.GetStale("nonexistent:1")
	if stale != nil {
		t.Error("expected nil for nonexistent key")
	}
}

func TestStaleServedCounter(t *testing.T) {
	c := newStaleTestCache()

	c.Set("test:1", newTestMessage(), 1)
	time.Sleep(2 * time.Second)

	// Serve stale twice
	c.GetStale("test:1")
	c.GetStale("test:1")

	count := c.StaleServed()
	if count != 2 {
		t.Errorf("StaleServed() = %d, want 2", count)
	}
}

func TestStaleStats(t *testing.T) {
	c := newStaleTestCache()

	c.Set("test:1", newTestMessage(), 1)
	time.Sleep(2 * time.Second)

	c.GetStale("test:1")

	stats := c.Stats()
	if stats.StaleServed != 1 {
		t.Errorf("Stats.StaleServed = %d, want 1", stats.StaleServed)
	}
}

func TestServeStalePreservesEntry(t *testing.T) {
	c := newStaleTestCache()

	c.Set("test:1", newTestMessage(), 1)
	time.Sleep(2 * time.Second)

	// Get (normal) should not delete the entry when serve-stale is on
	c.Get("test:1")

	// Entry should still be retrievable via GetStale
	stale := c.GetStale("test:1")
	if stale == nil {
		t.Error("expected stale entry to be preserved after normal Get miss")
	}
}
