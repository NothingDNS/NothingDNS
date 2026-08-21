package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// These tests close the coverage gap on cmdCluster (cluster.go): the
// existing tests in commands_test.go cover no-args, status success, and
// the peers rendering paths, but never exercised join, leave, the
// API-error returns on status/peers, or the non-map entry skip in the
// peers table loop.

// TestCmdCluster_JoinNoAddress covers the argument guard: join without
// a seed address must fail before any HTTP call is made.
func TestCmdCluster_JoinNoAddress(t *testing.T) {
	// Point the client at an unreachable server: if the guard leaks, the
	// test fails on the connection error rather than silently succeeding.
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected HTTP request: %s %s", r.Method, r.URL.Path)
	})
	err := cmdCluster([]string{"join"})
	if err == nil {
		t.Fatal("expected error when join has no seed address")
	}
	if !strings.Contains(err.Error(), "seed node address required") {
		t.Errorf("error = %v, want seed node address required", err)
	}
}

// TestCmdCluster_Join covers the happy path: POST /api/v1/cluster/join
// carries the seed address as JSON and the returned message is printed.
func TestCmdCluster_Join(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if r.URL.Path != "/api/v1/cluster/join" {
			t.Errorf("path = %q, want /api/v1/cluster/join", r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading body: %v", err)
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("body is not JSON: %v", err)
		}
		if payload["seed_address"] != "192.0.2.10:7946" {
			t.Errorf("seed_address = %v, want 192.0.2.10:7946", payload["seed_address"])
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "joined cluster via 192.0.2.10:7946",
		})
	})
	output := captureOutput(func() {
		if err := cmdCluster([]string{"join", "192.0.2.10:7946"}); err != nil {
			t.Fatalf("cmdCluster join: %v", err)
		}
	})
	if !strings.Contains(output, "joined cluster via 192.0.2.10:7946") {
		t.Errorf("output missing join message:\n%s", output)
	}
}

// TestCmdCluster_JoinAPIError covers the failure path: a non-2xx join
// response must surface as an error.
func TestCmdCluster_JoinAPIError(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"seed unreachable"}`, http.StatusBadGateway)
	})
	if err := cmdCluster([]string{"join", "203.0.113.1:7946"}); err == nil {
		t.Fatal("expected error when join API call fails")
	}
}

// TestCmdCluster_Leave covers the happy path: DELETE /api/v1/cluster/leave
// is issued with an empty JSON object body (the CLI deliberately sends no
// target node-id — see the comment in cluster.go) and the returned
// message is printed.
func TestCmdCluster_Leave(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %q, want DELETE", r.Method)
		}
		if r.URL.Path != "/api/v1/cluster/leave" {
			t.Errorf("path = %q, want /api/v1/cluster/leave", r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading body: %v", err)
		}
		if strings.TrimSpace(string(body)) != "{}" {
			t.Errorf("body = %q, want {}", body)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "left cluster",
		})
	})
	output := captureOutput(func() {
		if err := cmdCluster([]string{"leave"}); err != nil {
			t.Fatalf("cmdCluster leave: %v", err)
		}
	})
	if !strings.Contains(output, "left cluster") {
		t.Errorf("output missing leave message:\n%s", output)
	}
}

// TestCmdCluster_LeaveNoMessage covers the branch where the API responds
// 2xx without a "message" field: the command must succeed silently.
func TestCmdCluster_LeaveNoMessage(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{})
	})
	if err := cmdCluster([]string{"leave"}); err != nil {
		t.Fatalf("leave without message field: %v", err)
	}
}

// TestCmdCluster_LeaveAPIError covers the failure path for leave.
func TestCmdCluster_LeaveAPIError(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"not clustered"}`, http.StatusConflict)
	})
	if err := cmdCluster([]string{"leave"}); err == nil {
		t.Fatal("expected error when leave API call fails")
	}
}

// TestCmdCluster_StatusAPIError covers the failure path for status.
func TestCmdCluster_StatusAPIError(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"cluster disabled"}`, http.StatusServiceUnavailable)
	})
	if err := cmdCluster([]string{"status"}); err == nil {
		t.Fatal("expected error when status API call fails")
	}
}

// TestCmdCluster_PeersAPIError covers the failure path for peers.
func TestCmdCluster_PeersAPIError(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"gossip down"}`, http.StatusInternalServerError)
	})
	if err := cmdCluster([]string{"peers"}); err == nil {
		t.Fatal("expected error when peers API call fails")
	}
}

// TestCmdCluster_PeersSkipsNonMapEntries covers the type-assertion skip
// inside the peers table loop: a non-map entry in the nodes array must be
// dropped without breaking the loop, and valid entries still render.
func TestCmdCluster_PeersSkipsNonMapEntries(t *testing.T) {
	setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"nodes": []interface{}{
				"garbage-entry",
				map[string]interface{}{
					"id":     "node-7",
					"addr":   "192.0.2.7",
					"port":   float64(7946),
					"state":  "alive",
					"region": "eu-west",
				},
			},
		})
	})
	output := captureOutput(func() {
		if err := cmdCluster([]string{"peers"}); err != nil {
			t.Fatalf("cmdCluster peers: %v", err)
		}
	})
	if !strings.Contains(output, "node-7") {
		t.Errorf("output missing valid node row:\n%s", output)
	}
	if strings.Contains(output, "garbage-entry") {
		t.Errorf("non-map entry leaked into table:\n%s", output)
	}
}
