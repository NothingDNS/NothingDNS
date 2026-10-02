package nothingdns

import (
	"context"
)

// ClusterService handles gossip membership and Raft consensus (the
// /api/v1/cluster endpoints).
type ClusterService struct {
	t *Transport
}

// joinRequest is the JSON body of POST /api/v1/cluster/join.
type joinRequest struct {
	SeedAddress string `json:"seed_address"`
}

// Status returns cluster status: node id, consensus backend, Raft state and
// metrics. It requires the operator role or higher.
func (s *ClusterService) Status(ctx context.Context) (*ClusterStatus, error) {
	var out ClusterStatus
	if err := s.t.doJSON(ctx, "GET", "/api/v1/cluster/status", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Nodes lists every node known to the gossip layer. It requires the operator
// role or higher.
func (s *ClusterService) Nodes(ctx context.Context) ([]ClusterNode, error) {
	var out struct {
		Nodes []ClusterNode `json:"nodes"`
	}
	if err := s.t.doJSON(ctx, "GET", "/api/v1/cluster/nodes", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Nodes, nil
}

// Join joins a cluster through a seed node. It requires the admin role.
// seedAddress is the "host:port" of a node that is already a member.
//
// Joining changes this node's cluster identity. Run it once on a freshly
// provisioned node, never on a node that already serves traffic. It returns
// the server's confirmation message.
func (s *ClusterService) Join(ctx context.Context, seedAddress string) (string, error) {
	return s.t.doMessage(ctx, "POST", "/api/v1/cluster/join", nil, joinRequest{SeedAddress: seedAddress})
}

// Leave drains this node and leaves the cluster. It requires the admin role.
// It returns the server's confirmation message.
func (s *ClusterService) Leave(ctx context.Context) (string, error) {
	return s.t.doMessage(ctx, "DELETE", "/api/v1/cluster/leave", nil, nil)
}
