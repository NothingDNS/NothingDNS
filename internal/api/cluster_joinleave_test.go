package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/cluster"
)

// ============================================================================
// handleClusterJoin / handleClusterLeave — server-side branch coverage
//
// The dnsctl CLI side of these endpoints is at 100% (cluster_test.go);
// this suite covers the handler side. Uses newRaftModeCluster
// (propose_zone_write_test.go) because its two deterministic properties
// map exactly onto the branches under test:
//
//   - Raft mode makes JoinSeed fail with a fixed error → the 400 path,
//     without needing a live gossip peer.
//   - A started single-node Raft cluster walks StartDraining /
//     CompleteDraining(leave=true) with gossip == nil (no broadcasts) →
//     the 200 leave path.
// ============================================================================

// newStartedRaftCluster is newRaftModeCluster plus Start(). A single Raft
// node with no live peers elects itself; Stop() is deferred for cleanup.
func newStartedRaftCluster(t *testing.T) *cluster.Cluster {
	t.Helper()
	c := newRaftModeCluster(t)
	if err := c.Start(); err != nil {
		t.Fatalf("cluster.Start(raft): %v", err)
	}
	t.Cleanup(func() { _ = c.Stop() })
	return c
}

func newClusterTestServer(t *testing.T, c *cluster.Cluster) *Server {
	t.Helper()
	srv := &Server{cluster: c}
	attachTestAuth(srv)
	return srv
}

// TestHandleClusterJoinValidation table-drives the join validation funnel: method
// guard, admin guard, nil-cluster, body decode, empty seed, malformed
// seed (host:port grammar), and the JoinSeed failure surfaced as 400.
func TestHandleClusterJoinValidation(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		clusterNil bool
		body       string
		wantStatus int
		wantSubstr string
	}{
		{
			name:       "wrong method rejected",
			method:     http.MethodGet,
			body:       `{"seed_address":"10.0.0.1:7946"}`,
			wantStatus: http.StatusMethodNotAllowed,
			wantSubstr: "",
		},
		{
			name:       "cluster not configured",
			method:     http.MethodPost,
			clusterNil: true,
			body:       `{"seed_address":"10.0.0.1:7946"}`,
			wantStatus: http.StatusServiceUnavailable,
			wantSubstr: "Cluster not available",
		},
		{
			name:       "empty seed rejected",
			method:     http.MethodPost,
			body:       `{"seed_address":""}`,
			wantStatus: http.StatusBadRequest,
			wantSubstr: "seed_address is required",
		},
		{
			name:       "seed missing port rejected",
			method:     http.MethodPost,
			body:       `{"seed_address":"10.0.0.1"}`,
			wantStatus: http.StatusBadRequest,
			wantSubstr: "seed_address must be host:port",
		},
		{
			name:       "seed port out of range rejected",
			method:     http.MethodPost,
			body:       `{"seed_address":"10.0.0.1:70000"}`,
			wantStatus: http.StatusBadRequest,
			wantSubstr: "seed_address port must be between 1 and 65535",
		},
		{
			name:       "seed port zero rejected",
			method:     http.MethodPost,
			body:       `{"seed_address":"10.0.0.1:0"}`,
			wantStatus: http.StatusBadRequest,
			wantSubstr: "seed_address port must be between 1 and 65535",
		},
		{
			name:       "seed without host rejected",
			method:     http.MethodPost,
			body:       `{"seed_address":":7946"}`,
			wantStatus: http.StatusBadRequest,
			wantSubstr: "seed_address host is required",
		},
		{
			name:       "malformed body rejected",
			method:     http.MethodPost,
			body:       `{not-json`,
			wantStatus: http.StatusBadRequest,
		},
		{
			// Raft mode deterministically refuses dynamic join — this is
			// the documented contract and exactly the 400 error path.
			name:       "valid seed but raft mode refuses dynamic join",
			method:     http.MethodPost,
			body:       `{"seed_address":"10.0.0.1:7946"}`,
			wantStatus: http.StatusBadRequest,
			wantSubstr: "dynamic node joining not supported in Raft consensus mode",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newClusterTestServer(t, newRaftModeCluster(t))
			if tc.clusterNil {
				srv = &Server{}
				attachTestAuth(srv)
			}

			var req *http.Request
			if tc.body != "" {
				req = httptest.NewRequest(tc.method, "/api/v1/cluster/join", strings.NewReader(tc.body))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req = httptest.NewRequest(tc.method, "/api/v1/cluster/join", nil)
			}
			req = withTestAdminAuth(req, tokenForServer(t, srv))
			rec := httptest.NewRecorder()

			srv.handleClusterJoin(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantSubstr != "" && !strings.Contains(rec.Body.String(), tc.wantSubstr) {
				t.Errorf("body %q missing %q", rec.Body.String(), tc.wantSubstr)
			}
		})
	}
}

// TestHandleClusterJoin_Unauthorized pins the admin gate without the
// context injection: no admin in context → 403/503, never a mutation.
func TestHandleClusterJoin_Unauthorized(t *testing.T) {
	srv := newClusterTestServer(t, newRaftModeCluster(t))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/join",
		strings.NewReader(`{"seed_address":"10.0.0.1:7946"}`))
	req.Header.Set("Content-Type", "application/json")
	// No withTestAdminAuth: bearer token present but no context user.
	rec := httptest.NewRecorder()
	srv.handleClusterJoin(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (admin role required)", rec.Code)
	}
}

// TestHandleClusterLeave covers the leave funnel: method guard, admin
// guard, nil-cluster, the not-started drain failure (503 cluster not
// started → 500), and the graceful 200 on a started raft cluster.
func TestHandleClusterLeave(t *testing.T) {
	t.Run("wrong method rejected", func(t *testing.T) {
		srv := newClusterTestServer(t, newRaftModeCluster(t))
		req := withTestAdminAuth(httptest.NewRequest(http.MethodPost, "/api/v1/cluster/leave", nil), tokenForServer(t, srv))
		rec := httptest.NewRecorder()
		srv.handleClusterLeave(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405", rec.Code)
		}
	})

	t.Run("unauthenticated rejected", func(t *testing.T) {
		srv := newClusterTestServer(t, newRaftModeCluster(t))
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/cluster/leave", nil)
		rec := httptest.NewRecorder()
		srv.handleClusterLeave(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (admin role required)", rec.Code)
		}
	})

	t.Run("cluster not configured", func(t *testing.T) {
		srv := &Server{}
		attachTestAuth(srv)
		req := withTestAdminAuth(httptest.NewRequest(http.MethodDelete, "/api/v1/cluster/leave", nil), tokenForServer(t, srv))
		rec := httptest.NewRecorder()
		srv.handleClusterLeave(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	})

	t.Run("drain fails on unstarted cluster", func(t *testing.T) {
		// Constructed but never started: StartDraining returns
		// "cluster not started" → handler surfaces 500.
		srv := newClusterTestServer(t, newRaftModeCluster(t))
		req := withTestAdminAuth(httptest.NewRequest(http.MethodDelete, "/api/v1/cluster/leave", nil), tokenForServer(t, srv))
		rec := httptest.NewRecorder()
		srv.handleClusterLeave(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body.String())
		}
		// sanitizeError passes "cluster not started" through verbatim (it
		// contains neither '/' nor "panic"), so the response carries the
		// underlying error rather than the "Failed to drain" fallback.
		if !strings.Contains(rec.Body.String(), "cluster not started") {
			t.Errorf("body %q should surface the not-started error", rec.Body.String())
		}
	})

	t.Run("graceful leave on started cluster", func(t *testing.T) {
		// Started single-node raft cluster: gossip == nil so the draining
		// broadcasts are skipped and the handler reaches 200.
		srv := newClusterTestServer(t, newStartedRaftCluster(t))
		req := withTestAdminAuth(httptest.NewRequest(http.MethodDelete, "/api/v1/cluster/leave", nil), tokenForServer(t, srv))
		rec := httptest.NewRecorder()
		srv.handleClusterLeave(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "left cluster gracefully") {
			t.Errorf("body %q missing success message", rec.Body.String())
		}
	})
}

// tokenForServer returns a fresh admin token for the server's auth store.
// Each attachTestAuth call generates its own token; this keeps tests
// independent of helper call order.
func tokenForServer(t *testing.T, srv *Server) string {
	t.Helper()
	store := srv.currentAuthStore()
	if store == nil {
		t.Fatal("test server has no auth store")
	}
	tok, err := store.GenerateToken("testadmin", 0)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	return tok.Token
}
