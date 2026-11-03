package cluster

import "testing"

func TestBroadcastClusterMetricsIncludesLocalNodeInAggregate(t *testing.T) {
	self := &Node{ID: "node-a", Addr: "127.0.0.1", State: NodeStateAlive}
	gp := &GossipProtocol{
		nodeList:    NewNodeList(self),
		nodeMetrics: make(map[string]ClusterMetricsPayload),
	}

	want := ClusterMetricsPayload{
		QueriesTotal:  120,
		QueriesPerSec: 12.5,
		CacheHits:     90,
		CacheMisses:   30,
		LatencyMsAvg:  3.5,
		LatencyMsP99:  9.5,
		UptimeSeconds: 600,
	}
	if err := gp.BroadcastClusterMetrics(want); err != nil {
		t.Fatalf("BroadcastClusterMetrics: %v", err)
	}

	got := gp.GetClusterMetrics()
	if got.QueriesTotal != want.QueriesTotal || got.CacheHits != want.CacheHits ||
		got.CacheMisses != want.CacheMisses || got.QueriesPerSec != want.QueriesPerSec ||
		got.LatencyMsAvg != want.LatencyMsAvg || got.LatencyMsP99 != want.LatencyMsP99 ||
		got.UptimeSeconds != want.UptimeSeconds {
		t.Fatalf("aggregate omitted local metrics: got %+v, want %+v", got, want)
	}
}
