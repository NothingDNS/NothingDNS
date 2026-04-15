package api

import (
	"net/http"
)

func (s *Server) handleClusterStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.requireOperator(w, r) {
		return
	}

	if s.cluster == nil {
		s.writeJSON(w, http.StatusOK, &ClusterStatusResponse{
			NodeID:     "",
			NodeCount:  0,
			AliveCount: 0,
			Healthy:    false,
			Gossip: GossipInfo{
				MessagesSent:     0,
				MessagesReceived: 0,
				PingSent:         0,
				PingReceived:     0,
			},
		})
		return
	}

	stats := s.cluster.Stats()
	clusterMetrics := s.cluster.GetClusterMetrics()

	// Calculate cache hit rate
	var cacheHitRate float64
	if clusterMetrics.CacheHits+clusterMetrics.CacheMisses > 0 {
		cacheHitRate = float64(clusterMetrics.CacheHits) / float64(clusterMetrics.CacheHits+clusterMetrics.CacheMisses)
	}

	s.writeJSON(w, http.StatusOK, &ClusterStatusResponse{
		NodeID:     stats.NodeID,
		NodeCount:  stats.NodeCount,
		AliveCount: stats.AliveCount,
		Healthy:    stats.IsHealthy,
		Gossip: GossipInfo{
			MessagesSent:     stats.GossipStats.MessagesSent,
			MessagesReceived: stats.GossipStats.MessagesReceived,
			PingSent:         stats.GossipStats.PingSent,
			PingReceived:     stats.GossipStats.PingReceived,
		},
		Metrics: ClusterMetricsInfo{
			QueriesTotal:  clusterMetrics.QueriesTotal,
			QueriesPerSec: clusterMetrics.QueriesPerSec,
			CacheHits:     clusterMetrics.CacheHits,
			CacheMisses:   clusterMetrics.CacheMisses,
			CacheHitRate:  cacheHitRate,
			LatencyMsAvg:  clusterMetrics.LatencyMsAvg,
			LatencyMsP99:  clusterMetrics.LatencyMsP99,
		},
	})
}

// handleClusterNodes returns list of cluster nodes.
func (s *Server) handleClusterNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.requireOperator(w, r) {
		return
	}

	if s.cluster == nil {
		s.writeJSON(w, http.StatusOK, &ClusterNodesResponse{Nodes: []NodeDetail{}})
		return
	}

	nodes := s.cluster.GetNodesWithHealth()
	resp := &ClusterNodesResponse{Nodes: make([]NodeDetail, 0, len(nodes))}
	for _, node := range nodes {
		resp.Nodes = append(resp.Nodes, NodeDetail{
			ID:                node.ID,
			Addr:              node.Addr,
			Port:              node.Port,
			State:             node.State.String(),
			Region:            node.Meta.Region,
			Zone:              node.Meta.Zone,
			Weight:            node.Meta.Weight,
			HTTPAddr:          node.Meta.HTTPAddr,
			Version:           node.Version,
			HealthScore:       node.Health.HealthScore(),
			QueriesPerSecond:  node.Health.QueriesPerSecond,
			LatencyMs:         node.Health.LatencyMs,
			CPUPercent:        node.Health.CPUPercent,
			MemoryPercent:     node.Health.MemoryPercent,
			ActiveConnections: node.Health.ActiveConns,
		})
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// handleBlocklists returns blocklist stats or adds a new blocklist entry.
