package cache

import (
	"fmt"
	"testing"
	"time"
)

func TestUpdateConfigCapacityShrinkEvictsImmediately(t *testing.T) {
	c := New(Config{Capacity: numShards * 4, MinTTL: time.Second, MaxTTL: time.Hour})
	counts := make(map[*cacheShard]int)
	for i := 0; c.Size() < numShards*4; i++ {
		key := fmt.Sprintf("capacity-shrink-%d", i)
		s := c.shardOf(key)
		if counts[s] >= 4 {
			continue
		}
		c.Set(key, nil, 300)
		counts[s]++
		if i > 100000 {
			t.Fatal("could not distribute test keys across shards")
		}
	}

	cfg := c.GetConfig()
	cfg.Capacity = numShards
	c.UpdateConfig(cfg)

	if got := c.Size(); got > numShards {
		t.Fatalf("cache size after shrink = %d, want <= %d", got, numShards)
	}
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.RLock()
		got := len(s.entries)
		capacity := s.capacity
		s.mu.RUnlock()
		if got > capacity {
			t.Fatalf("shard %d size after shrink = %d, capacity = %d", i, got, capacity)
		}
	}
}
