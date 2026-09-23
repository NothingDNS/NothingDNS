package api

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cluster"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/util"
)

func TestHandleClusterNodes_RaftTopologyShowsPeersAndRoles(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	c, err := cluster.New(cluster.Config{
		Enabled:              true,
		AllowInsecureCluster: true,
		NodeID:               "node-1",
		BindAddr:             host,
		GossipPort:           port,
		ConsensusMode:        cluster.ConsensusRaft,
		DataDir:              filepath.Join(t.TempDir(), "raft"),
		HTTPAddr:             "127.0.0.1:8080",
		Peers:                []cluster.PeerConfig{{NodeID: "node-2", Addr: "10.0.0.2:7946"}},
	}, util.DefaultLogger(), nil)
	if err != nil {
		t.Fatalf("cluster.New: %v", err)
	}
	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = c.Stop() }()

	deadline := time.Now().Add(2 * time.Second)
	for !c.IsLeader() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}

	srv := NewServer(config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}, nil, nil, nil, nil, c, nil)
	token := attachTestAuth(srv)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/cluster/nodes", nil)
	req = withTestAdminAuth(req, token)
	rec := httptest.NewRecorder()
	srv.handleClusterNodes(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}

	var resp ClusterNodesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Nodes) != 2 {
		t.Fatalf("nodes = %d, want 2: %+v", len(resp.Nodes), resp.Nodes)
	}
	byID := map[string]NodeDetail{}
	for _, n := range resp.Nodes {
		byID[n.ID] = n
	}
	if byID["node-1"].Role == "" {
		t.Fatalf("node-1 missing role: %+v", byID["node-1"])
	}
	if byID["node-2"].Role == "" {
		t.Fatalf("node-2 missing role: %+v", byID["node-2"])
	}
	if byID["node-2"].Addr != "10.0.0.2" || byID["node-2"].Port != 7946 {
		t.Fatalf("node-2 addr = %s:%d", byID["node-2"].Addr, byID["node-2"].Port)
	}

	// status counts should also reflect membership
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/cluster/status", nil)
	req2 = withTestAdminAuth(req2, token)
	rec2 := httptest.NewRecorder()
	srv.handleClusterStatus(rec2, req2)
	var st ClusterStatusResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.NodeCount != 2 {
		t.Fatalf("status node_count = %d, want 2", st.NodeCount)
	}
}
