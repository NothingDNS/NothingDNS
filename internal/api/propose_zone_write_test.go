package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/cluster"
	"github.com/nothingdns/nothingdns/internal/cluster/raft"
	"github.com/nothingdns/nothingdns/internal/util"
)

// newRaftModeCluster builds a Cluster whose IsRaftMode() is true without
// starting any consensus traffic. proposeZoneWrite takes the propose
// closure as a parameter and only consults the cluster for routing
// decisions, so a constructed-but-never-started single-node Raft cluster
// is sufficient. Port 0 (ephemeral) is safe because the Raft RPC listener
// only binds on Start, which these tests never call; DataDir points at a
// TempDir so the WAL/hard-state files never touch /var/lib.
func newRaftModeCluster(t *testing.T) *cluster.Cluster {
	t.Helper()
	c, err := cluster.New(cluster.Config{
		Enabled:              true,
		AllowInsecureCluster: true, // test: no encryption key required
		NodeID:               "test-node-1",
		BindAddr:             "127.0.0.1",
		GossipPort:           0,
		ConsensusMode:        cluster.ConsensusRaft,
		DataDir:              t.TempDir(),
		// Raft consensus refuses to initialize with zero peers; a single
		// self-entry satisfies the guard. The address is never dialed
		// because Start() is not called in these tests.
		Peers: []cluster.PeerConfig{{NodeID: "test-node-1", Addr: "127.0.0.1:0"}},
	}, util.DefaultLogger(), nil)
	if err != nil {
		t.Fatalf("cluster.New(raft): %v", err)
	}
	return c
}

// TestProposeZoneWriteNotRouted covers the standalone-server path: with no
// cluster attached, proposeZoneWrite reports (routed=false, ok=false) so
// the handler falls through to its local zone-store mutation, and nothing
// is written to the response.
func TestProposeZoneWriteNotRouted(t *testing.T) {
	s := &Server{} // cluster == nil
	rec := httptest.NewRecorder()

	routed, ok := s.proposeZoneWrite(rec, func() error {
		t.Fatal("propose must not be called when cluster is nil")
		return nil
	})
	if routed || ok {
		t.Errorf("proposeZoneWrite = (%v, %v), want (false, false)", routed, ok)
	}
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("unexpected response written: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

// TestProposeZoneWriteRaftSuccess covers the replicated-write happy path:
// Raft mode + a propose that succeeds → (routed=true, ok=true) and no
// error response; the handler continues to its success response.
func TestProposeZoneWriteRaftSuccess(t *testing.T) {
	s := &Server{cluster: newRaftModeCluster(t)}
	rec := httptest.NewRecorder()

	routed, ok := s.proposeZoneWrite(rec, func() error { return nil })
	if !routed || !ok {
		t.Errorf("proposeZoneWrite = (%v, %v), want (true, true)", routed, ok)
	}
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("unexpected response written: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

// TestProposeZoneWriteNotLeader covers the follower-redirect contract: a
// *raft.ErrNotLeader from propose must surface as 421 Misdirected Request
// naming the current leader, so API clients know where to retry. This is
// the routing signal that keeps cluster writes from silently failing on
// non-leader nodes.
func TestProposeZoneWriteNotLeader(t *testing.T) {
	s := &Server{cluster: newRaftModeCluster(t)}

	cases := []struct {
		name       string
		leaderID   raft.NodeID
		wantSubstr string
	}{
		{
			name:       "known leader is named",
			leaderID:   "node-2",
			wantSubstr: "node-2",
		},
		{
			name:       "unknown leader (election in progress)",
			leaderID:   "",
			wantSubstr: "retry the write against the current leader",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			routed, ok := s.proposeZoneWrite(rec, func() error {
				return &raft.ErrNotLeader{LeaderID: tc.leaderID}
			})
			if !routed || ok {
				t.Errorf("proposeZoneWrite = (%v, %v), want (true, false)", routed, ok)
			}
			if rec.Code != http.StatusMisdirectedRequest {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusMisdirectedRequest)
			}
			if body := rec.Body.String(); !strings.Contains(body, tc.wantSubstr) {
				t.Errorf("body %q missing %q", body, tc.wantSubstr)
			}
		})
	}
}

// TestProposeZoneWriteReplicationError covers non-leader failures: any
// other error from propose is sanitized and surfaced as 503 — the write
// did not replicate, so the client must not treat it as succeeded.
func TestProposeZoneWriteReplicationError(t *testing.T) {
	s := &Server{cluster: newRaftModeCluster(t)}

	cases := []struct {
		name       string
		err        error
		wantSubstr string
	}{
		{
			// Message without "/" or "panic" passes sanitizeError verbatim.
			name:       "simple message passes through",
			err:        errSimple("quorum not reached"),
			wantSubstr: "quorum not reached",
		},
		{
			// Message containing "/" (e.g. a file path) must be replaced by
			// the generic fallback so internal paths don't leak.
			name:       "path-like message is sanitized",
			err:        errSimple("open /var/lib/nothingdns/wal: permission denied"),
			wantSubstr: "Failed to replicate change",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			routed, ok := s.proposeZoneWrite(rec, func() error { return tc.err })
			if !routed || ok {
				t.Errorf("proposeZoneWrite = (%v, %v), want (true, false)", routed, ok)
			}
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
			}
			if body := rec.Body.String(); !strings.Contains(body, tc.wantSubstr) {
				t.Errorf("body %q missing %q", body, tc.wantSubstr)
			}
		})
	}
}

type errSimple string

func (e errSimple) Error() string { return string(e) }
