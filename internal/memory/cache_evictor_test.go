package memory

import (
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
)

func TestNewCacheEvictor(t *testing.T) {
	c := cache.New(cache.Config{
		Capacity:   100,
		MinTTL:     1 * time.Second,
		MaxTTL:     1 * time.Hour,
		DefaultTTL: 5 * time.Minute,
	})
	ev := NewCacheEvictor(c)
	if ev == nil {
		t.Fatal("NewCacheEvictor returned nil")
	}
	if ev.cache != c {
		t.Error("cache reference not stored")
	}
}

func TestCacheEvictorEvict(t *testing.T) {
	c := cache.New(cache.Config{
		Capacity:   100,
		MinTTL:     1 * time.Second,
		MaxTTL:     1 * time.Hour,
		DefaultTTL: 5 * time.Minute,
	})
	ev := NewCacheEvictor(c)
	// Should not panic
	ev.Evict(50)
}

func TestCacheEvictorClear(t *testing.T) {
	c := cache.New(cache.Config{
		Capacity:   100,
		MinTTL:     1 * time.Second,
		MaxTTL:     1 * time.Hour,
		DefaultTTL: 5 * time.Minute,
	})
	ev := NewCacheEvictor(c)
	// Should not panic
	ev.Clear()
}

func TestCacheEvictorNilCache(t *testing.T) {
	ev := NewCacheEvictor(nil)
	// Should not panic on nil cache
	ev.Evict(50)
	ev.Clear()
}

func TestCacheEvictorImplementsInterface(t *testing.T) {
	c := cache.New(cache.Config{
		Capacity:   10,
		MinTTL:     1 * time.Second,
		MaxTTL:     1 * time.Hour,
		DefaultTTL: 5 * time.Minute,
	})
	var iface Evictor = NewCacheEvictor(c)
	if iface == nil {
		t.Fatal("CacheEvictor does not implement Evictor")
	}
}
