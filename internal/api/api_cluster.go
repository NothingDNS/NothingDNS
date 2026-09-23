package api

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

func (s *Server) handleClusterStatus(w http.ResponseWriter, r *http.Request) {
	if s.requireMethod(w, r, http.MethodGet) {
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

	// Surface Raft consensus state when the cluster runs in Raft mode so the
	// dashboard can show leader/term/commit progress.
	var raftInfo *RaftInfo
	if string(stats.ConsensusMode) == "raft" {
		raftInfo = &RaftInfo{
			State:        stats.RaftStats.State,
			Term:         stats.RaftStats.Term,
			CommitIndex:  stats.RaftStats.CommitIndex,
			AppliedIndex: stats.RaftStats.AppliedIndex,
			IsLeader:     stats.RaftStats.IsLeader,
			LeaderID:     s.cluster.RaftLeaderID(),
		}
	}

	s.writeJSON(w, http.StatusOK, &ClusterStatusResponse{
		NodeID:     stats.NodeID,
		Consensus:  string(stats.ConsensusMode),
		NodeCount:  stats.NodeCount,
		AliveCount: stats.AliveCount,
		Healthy:    stats.IsHealthy,
		Gossip: GossipInfo{
			MessagesSent:     stats.GossipStats.MessagesSent,
			MessagesReceived: stats.GossipStats.MessagesReceived,
			PingSent:         stats.GossipStats.PingSent,
			PingReceived:     stats.GossipStats.PingReceived,
		},
		Raft: raftInfo,
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
	if s.requireMethod(w, r, http.MethodGet) {
		return
	}
	if s.requireOperator(w, r) {
		return
	}

	if s.cluster == nil {
		s.writeJSON(w, http.StatusOK, &ClusterNodesResponse{Nodes: []NodeDetail{}})
		return
	}

	nodes := s.cluster.GetTopologyMembers()
	resp := &ClusterNodesResponse{Nodes: make([]NodeDetail, 0, len(nodes))}
	for _, node := range nodes {
		resp.Nodes = append(resp.Nodes, NodeDetail{
			ID:                node.ID,
			Addr:              node.Addr,
			Port:              node.Port,
			State:             node.State.String(),
			Role:              node.Role,
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

// handleClusterJoin joins the cluster via a seed node address.
// POST /api/v1/cluster/join { "seed_address": "host:port" }
func (s *Server) handleClusterJoin(w http.ResponseWriter, r *http.Request) {
	if s.requireMethod(w, r, http.MethodPost) {
		return
	}
	// Cluster join/leave are infrastructure-level operations that change
	// cluster topology and query routing for all clients. Require admin.
	if s.requireAdmin(w, r) {
		return
	}
	if s.cluster == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Cluster not available")
		return
	}

	var req struct {
		SeedAddress string `json:"seed_address"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	if req.SeedAddress == "" {
		s.writeError(w, http.StatusBadRequest, "seed_address is required")
		return
	}
	seedAddress := strings.TrimSpace(req.SeedAddress)
	if err := validateClusterSeedAddress(seedAddress); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Dynamic node joining is only supported in SWIM (gossip) mode.
	// Raft consensus does not support runtime node addition.
	if err := s.cluster.JoinSeed(seedAddress); err != nil {
		s.writeError(w, http.StatusBadRequest, sanitizeError(err, "Failed to join cluster"))
		return
	}

	s.writeJSON(w, http.StatusOK, &MessageResponse{
		Message: "Joined cluster via " + seedAddress,
	})
}

func validateClusterSeedAddress(seed string) error {
	host, port, err := net.SplitHostPort(seed)
	if err != nil {
		return fmt.Errorf("seed_address must be host:port")
	}
	if host == "" {
		return fmt.Errorf("seed_address host is required")
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("seed_address port must be between 1 and 65535")
	}
	return nil
}

// handleClusterLeave removes the local node from the cluster gracefully.
// DELETE /api/v1/cluster/leave { "node_id": "..." }
func (s *Server) handleClusterLeave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.requireAdmin(w, r) {
		return
	}
	if s.cluster == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Cluster not available")
		return
	}

	// Drain connections before leaving so in-flight queries complete.
	if err := s.cluster.StartDraining(); err != nil {
		s.writeError(w, http.StatusInternalServerError, sanitizeError(err, "Failed to drain connections"))
		return
	}

	// CompleteDraining(true) initiates graceful departure from the cluster.
	if err := s.cluster.CompleteDraining(true); err != nil {
		s.writeError(w, http.StatusInternalServerError, sanitizeError(err, "Failed to leave cluster"))
		return
	}

	s.writeJSON(w, http.StatusOK, &MessageResponse{
		Message: "Node left cluster gracefully",
	})
}
