package cache

import "testing"

func TestCacheCapacityIsGlobalAcrossShards_F901(t *testing.T) {
	control := New(Config{Capacity: 1})
	sameShard := keysForShard(0, 2)
	control.SetNegative(sameShard[0], 3)
	control.SetNegative(sameShard[1], 3)
	if got := control.Size(); got != 1 {
		t.Fatalf("CONTROL FAILED: same-shard eviction left size %d, want 1", got)
	}
	t.Log("CONTROL OK: a shard evicts when its assigned capacity is full")

	c := New(Config{Capacity: 1})
	first := keysForShard(0, 1)[0]
	second := keysForShard(1, 1)[0]
	c.SetNegative(first, 3)
	c.SetNegative(second, 3)
	if got := c.Size(); got > 1 {
		t.Log("EXPECTED: configured global capacity 1 bounds total cache size to 1")
		t.Logf("ACTUAL: keys in two shards produced cache size %d", got)
		t.Fatal("PROBLEM CONFIRMED: rounding every shard up multiplied the configured capacity")
	}
	t.Log("PROBLEM NOT REPRODUCED: total cache size stayed within global capacity")
}

func TestCacheCapacityHotReloadIsGlobalAcrossShards_F901(t *testing.T) {
	c := New(Config{Capacity: numShards})
	for shard := range numShards {
		c.SetNegative(keysForShard(shard, 1)[0], 3)
	}
	if got := c.Size(); got != numShards {
		t.Fatalf("setup size = %d, want %d", got, numShards)
	}
	cfg := c.GetConfig()
	cfg.Capacity = 1
	c.UpdateConfig(cfg)
	if got := c.Size(); got != 1 {
		t.Fatalf("FIX NOT VERIFIED: size after capacity shrink = %d, want 1", got)
	}
	t.Log("FIX VERIFIED: hot reload redistributed and enforced the global capacity")
}
