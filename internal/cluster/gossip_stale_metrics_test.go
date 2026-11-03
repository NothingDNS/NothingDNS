package cluster

import "testing"

func TestGetClusterMetricsExcludesDepartedNodes(t *testing.T) {
	self := &Node{ID: "node-a", State: NodeStateAlive}
	peers := NewNodeList(self)
	peers.Add(&Node{ID: "node-b", State: NodeStateAlive})
	gp := &GossipProtocol{
		nodeList: peers,
		nodeMetrics: map[string]ClusterMetricsPayload{
			"node-b": {NodeID: "node-b", QueriesTotal: 500, CacheHits: 400},
		},
	}

	if got := gp.GetClusterMetrics().QueriesTotal; got != 500 {
		t.Fatalf("control aggregate = %d, want 500", got)
	}
	peers.Remove("node-b")
	if got := gp.GetClusterMetrics().QueriesTotal; got != 0 {
		t.Fatalf("departed node remained in aggregate: got %d, want 0", got)
	}
}
