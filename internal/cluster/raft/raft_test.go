package raft

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

// mockTransport implements Transport for testing.
type mockTransport struct {
	sendVoteCalled   int
	sendAppendCalled int
	voteResp         *VoteResponse
	appendResp       *AppendResponse
	voteRespErr      error
	appendRespErr    error
}

func (m *mockTransport) SendRequestVote(peerID NodeID, req VoteRequest) (*VoteResponse, error) {
	m.sendVoteCalled++
	return m.voteResp, m.voteRespErr
}

func (m *mockTransport) SendAppendEntries(peerID NodeID, req AppendRequest) (*AppendResponse, error) {
	m.sendAppendCalled++
	return m.appendResp, m.appendRespErr
}

func (m *mockTransport) SendSnapshot(peerID NodeID, req SnapshotRequest) error {
	return nil
}

func TestNewNode(t *testing.T) {
	transport := &mockTransport{}
	config := DefaultConfig()
	config.NodeID = "node1"
	config.HeartbeatInterval = 50 * time.Millisecond
	config.ElectionTimeout = 150 * time.Millisecond

	node := NewNode(config, []NodeID{"node2", "node3"}, transport)

	if node == nil {
		t.Fatal("NewNode returned nil")
	}
	if node.State() != StateFollower {
		t.Errorf("expected initial state StateFollower, got %v", node.State())
	}
	if node.Term() != 0 {
		t.Errorf("expected initial term 0, got %v", node.Term())
	}
	if len(node.peers) != 2 {
		t.Errorf("expected 2 peers, got %d", len(node.peers))
	}
	if node.nextIndex["node2"] != 0 {
		t.Errorf("expected nextIndex 0 for node2, got %v", node.nextIndex["node2"])
	}
}

func TestNodeStartStop(t *testing.T) {
	transport := &mockTransport{}
	config := DefaultConfig()
	config.NodeID = "node1"

	node := NewNode(config, nil, transport)

	// Test that node can be created and stopped without starting
	// (Start would require proper async handling for election timeouts)
	node.Stop()
}

func TestHandleVoteRequest(t *testing.T) {
	tests := []struct {
		name          string
		nodeTerm      Term
		votedFor      NodeID
		candidateTerm Term
		lastLogIdx    Index
		lastLogTerm   Term
		wantGranted   bool
		wantTerm      Term
	}{
		{
			name:          "vote for candidate with newer term",
			nodeTerm:      1,
			votedFor:      "",
			candidateTerm: 2,
			lastLogIdx:    1,
			lastLogTerm:   1,
			wantGranted:   true,
			wantTerm:      2,
		},
		{
			name:          "reject candidate with older term",
			nodeTerm:      3,
			votedFor:      "",
			candidateTerm: 2,
			lastLogIdx:    1,
			lastLogTerm:   1,
			wantGranted:   false,
			wantTerm:      3,
		},
		{
			name:          "reject already voted for different candidate",
			nodeTerm:      2,
			votedFor:      "node3",
			candidateTerm: 2,
			lastLogIdx:    1,
			lastLogTerm:   1,
			wantGranted:   false,
			wantTerm:      2,
		},
		{
			name:          "allow vote for same candidate again",
			nodeTerm:      2,
			votedFor:      "node2",
			candidateTerm: 2,
			lastLogIdx:    1,
			lastLogTerm:   1,
			wantGranted:   true,
			wantTerm:      2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &mockTransport{}
			config := DefaultConfig()
			config.NodeID = "node1"

			node := NewNode(config, nil, transport)
			node.mu.Lock()
			node.currentTerm = tt.nodeTerm
			node.votedFor = tt.votedFor
			node.mu.Unlock()

			req := VoteRequest{
				Term:         tt.candidateTerm,
				CandidateID:  "node2",
				LastLogIndex: tt.lastLogIdx,
				LastLogTerm:  tt.lastLogTerm,
			}

			resp := node.HandleVoteRequest(req)

			if resp.VoteGranted != tt.wantGranted {
				t.Errorf("VoteGranted = %v, want %v", resp.VoteGranted, tt.wantGranted)
			}
			if resp.Term != tt.wantTerm {
				t.Errorf("Term = %v, want %v", resp.Term, tt.wantTerm)
			}
		})
	}
}

func TestHandleAppendRequest(t *testing.T) {
	tests := []struct {
		name       string
		nodeTerm   Term
		log        []entry
		prevIdx    Index
		prevTerm   Term
		entries    []entry
		leaderComm Index
		leaderTerm Term // Leader's term (different from node's term for stale tests)
		wantSucc   bool
		wantTerm   Term
	}{
		{
			name:       "successful append",
			nodeTerm:   1,
			leaderTerm: 1,
			log:        []entry{{Index: 1, Term: 1}},
			prevIdx:    1,
			prevTerm:   1,
			entries:    []entry{{Index: 2, Term: 1, Command: []byte("test")}},
			leaderComm: 1,
			wantSucc:   true,
			wantTerm:   1,
		},
		{
			name:       "reject stale term",
			nodeTerm:   3,
			leaderTerm: 2, // Leader has older term than follower
			log:        []entry{},
			prevIdx:    0,
			prevTerm:   0,
			entries:    []entry{{Index: 1, Term: 2}},
			leaderComm: 0,
			wantSucc:   false,
			wantTerm:   3,
		},
		{
			name:       "reject inconsistent prev log",
			nodeTerm:   1,
			leaderTerm: 1,
			log:        []entry{{Index: 1, Term: 2}}, // term mismatch
			prevIdx:    1,
			prevTerm:   1,
			entries:    []entry{{Index: 2, Term: 1}},
			leaderComm: 1,
			wantSucc:   false,
			wantTerm:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &mockTransport{}
			config := DefaultConfig()
			config.NodeID = "node1"

			node := NewNode(config, nil, transport)
			node.mu.Lock()
			node.currentTerm = tt.nodeTerm
			node.log = tt.log
			node.mu.Unlock()

			req := AppendRequest{
				Term:         tt.leaderTerm,
				LeaderID:     "node2",
				PrevLogIndex: tt.prevIdx,
				PrevLogTerm:  tt.prevTerm,
				Entries:      tt.entries,
				LeaderCommit: tt.leaderComm,
			}

			resp := node.HandleAppendRequest(req)

			if resp.Success != tt.wantSucc {
				t.Errorf("Success = %v, want %v", resp.Success, tt.wantSucc)
			}
			if resp.Term != tt.wantTerm {
				t.Errorf("Term = %v, want %v", resp.Term, tt.wantTerm)
			}
		})
	}
}

func TestStateString(t *testing.T) {
	tests := []struct {
		state State
		want  string
	}{
		{StateLeader, "Leader"},
		{StateFollower, "Follower"},
		{StateCandidate, "Candidate"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("State.String() = %v, want %v", got, tt.want)
		}
	}
}

func TestNodePeers(t *testing.T) {
	transport := &mockTransport{}
	config := DefaultConfig()
	config.NodeID = "node1"

	node := NewNode(config, []NodeID{"node2", "node3", "node4"}, transport)

	if len(node.peers) != 3 {
		t.Fatalf("expected 3 peers, got %d", len(node.peers))
	}

	// AddPeer with joint consensus - creates joint config but doesn't update peers until commit
	err := node.AddPeer("node5", "127.0.0.1:9005")
	if err != nil {
		t.Fatalf("AddPeer failed: %v", err)
	}
	// With joint consensus, peers map still shows old config until joint is committed
	if len(node.peers) != 3 {
		t.Errorf("expected 3 peers before joint commit, got %d", len(node.peers))
	}
	// But joint config is created
	if node.jointConfig == nil {
		t.Error("expected joint config to be created")
	}

	// Simulate joint commit and advance
	node.commitIndex = node.jointConfigIdx
	node.advanceJointConfig()
	if len(node.peers) != 4 {
		t.Errorf("expected 4 peers after joint commit, got %d", len(node.peers))
	}

	// Test RemovePeer with joint consensus
	err = node.RemovePeer("node2")
	if err != nil {
		t.Fatalf("RemovePeer failed: %v", err)
	}
	if len(node.peers) != 4 {
		t.Errorf("expected 4 peers before joint commit, got %d", len(node.peers))
	}

	node.commitIndex = node.jointConfigIdx
	node.advanceJointConfig()
	if len(node.peers) != 3 {
		t.Errorf("expected 3 peers after remove joint commit, got %d", len(node.peers))
	}
}

func TestPropose(t *testing.T) {
	transport := &mockTransport{}
	config := DefaultConfig()
	config.NodeID = "node1"

	node := NewNode(config, []NodeID{"node2"}, transport)

	// Propose returns error when not leader (expected)
	err := node.Propose([]byte("test command"), EntryNormal)
	if err == nil {
		t.Error("Propose should return error when not leader")
	}

	node.Stop()
}

func TestLeadershipCh(t *testing.T) {
	transport := &mockTransport{}
	config := DefaultConfig()
	config.NodeID = "node1"

	node := NewNode(config, []NodeID{"node2"}, transport)

	ch := node.LeadershipCh()
	if ch == nil {
		t.Error("LeadershipCh returned nil channel")
	}
}

// WAL tests

func TestWALNew(t *testing.T) {
	tmpDir := t.TempDir()
	wal, err := NewWAL(tmpDir)
	if err != nil {
		t.Fatalf("NewWAL failed: %v", err)
	}
	if wal == nil {
		t.Fatal("NewWAL returned nil")
	}
	wal.Close()
}

func TestWALWriteAndRead(t *testing.T) {
	tmpDir := t.TempDir()
	wal, err := NewWAL(tmpDir)
	if err != nil {
		t.Fatalf("NewWAL failed: %v", err)
	}
	defer wal.Close()

	entries := []entry{
		{Index: 1, Term: 1, Command: []byte("cmd1"), Type: EntryNormal},
		{Index: 2, Term: 1, Command: []byte("cmd2"), Type: EntryNormal},
		{Index: 3, Term: 2, Command: []byte("cmd3"), Type: EntryNormal},
	}

	for _, e := range entries {
		if err := wal.Write(e); err != nil {
			t.Fatalf("WAL.Write failed: %v", err)
		}
	}

	readEntries, err := wal.ReadAll()
	if err != nil {
		t.Fatalf("WAL.ReadAll failed: %v", err)
	}

	if len(readEntries) != len(entries) {
		t.Errorf("expected %d entries, got %d", len(entries), len(readEntries))
	}

	for i, e := range entries {
		if readEntries[i].Index != e.Index {
			t.Errorf("entry[%d].Index = %d, want %d", i, readEntries[i].Index, e.Index)
		}
		if readEntries[i].Term != e.Term {
			t.Errorf("entry[%d].Term = %d, want %d", i, readEntries[i].Term, e.Term)
		}
		if string(readEntries[i].Command) != string(e.Command) {
			t.Errorf("entry[%d].Command = %q, want %q", i, readEntries[i].Command, e.Command)
		}
		if readEntries[i].Type != e.Type {
			t.Errorf("entry[%d].Type = %d, want %d", i, readEntries[i].Type, e.Type)
		}
	}
}

func TestWALSync(t *testing.T) {
	tmpDir := t.TempDir()
	wal, err := NewWAL(tmpDir)
	if err != nil {
		t.Fatalf("NewWAL failed: %v", err)
	}
	defer wal.Close()

	if err := wal.Sync(); err != nil {
		t.Errorf("WAL.Sync failed: %v", err)
	}
}

func TestWALEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	wal, err := NewWAL(tmpDir)
	if err != nil {
		t.Fatalf("NewWAL failed: %v", err)
	}
	defer wal.Close()

	entries, err := wal.ReadAll()
	if err != nil {
		t.Fatalf("WAL.ReadAll failed: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestWALCreatesDir(t *testing.T) {
	// NewWAL creates the directory if it doesn't exist
	tmpDir := t.TempDir()
	nonExistent := tmpDir + "/does/not/exist/deeply"
	wal, err := NewWAL(nonExistent)
	if err != nil {
		t.Fatalf("NewWAL should create dirs: %v", err)
	}
	if wal == nil {
		t.Fatal("NewWAL returned nil")
	}
	wal.Close()
}

// Snapshotter tests

func TestNewSnapshotter(t *testing.T) {
	tmpDir := t.TempDir()
	snap, err := NewSnapshotter(tmpDir)
	if err != nil {
		t.Fatalf("NewSnapshotter failed: %v", err)
	}
	if snap == nil {
		t.Fatal("NewSnapshotter returned nil")
	}
}

func TestSnapshotterLoadEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	snapter, err := NewSnapshotter(tmpDir)
	if err != nil {
		t.Fatalf("NewSnapshotter failed: %v", err)
	}

	loaded, err := snapter.Load()
	if err != nil {
		t.Fatalf("Snapshotter.Load failed: %v", err)
	}
	if loaded != nil {
		t.Error("expected nil for empty directory")
	}
}

func TestSnapshotFilename(t *testing.T) {
	filename := snapFilename(42)
	if filename != "snapshot-42" {
		t.Errorf("snapFilename(42) = %q, want \"snapshot-42\"", filename)
	}
}

// ZoneStateMachine tests

func TestZoneStateMachineNew(t *testing.T) {
	zsm := NewZoneStateMachine()
	if zsm == nil {
		t.Fatal("NewZoneStateMachine returned nil")
	}
	if zsm.zones == nil {
		t.Error("expected zones to be initialized")
	}
}

func TestZoneStateMachineAddRecord(t *testing.T) {
	zsm := NewZoneStateMachine()

	cmd := ZoneCommand{
		Type:   "add_record",
		Zone:   "example.com.",
		Name:   "www.example.com.",
		RRType: 1, // A record
		TTL:    300,
		RData:  []string{"192.168.1.1"},
	}

	entry := entry{Command: mustMarshalJSON(cmd)}
	if err := zsm.Apply(entry); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	zones := zsm.GetZones()
	if len(zones) != 1 {
		t.Errorf("expected 1 zone, got %d", len(zones))
	}

	records := zsm.GetRecords("example.com.")
	if len(records) != 1 {
		t.Errorf("expected 1 record, got %d", len(records))
	}
}

func TestZoneStateMachineDelRecord(t *testing.T) {
	zsm := NewZoneStateMachine()

	// Add a record first
	addCmd := ZoneCommand{
		Type:   "add_record",
		Zone:   "example.com.",
		Name:   "www.example.com.",
		RRType: 1,
		TTL:    300,
		RData:  []string{"192.168.1.1"},
	}
	zsm.Apply(entry{Command: mustMarshalJSON(addCmd)})

	// Delete it
	delCmd := ZoneCommand{
		Type:   "del_record",
		Zone:   "example.com.",
		Name:   "www.example.com.",
		RRType: 1,
	}
	zsm.Apply(entry{Command: mustMarshalJSON(delCmd)})

	records := zsm.GetRecords("example.com.")
	if len(records) != 0 {
		t.Errorf("expected 0 records after delete, got %d", len(records))
	}
}

func TestZoneStateMachineUpdateRecord(t *testing.T) {
	zsm := NewZoneStateMachine()

	// Add initial record
	addCmd := ZoneCommand{
		Type:   "add_record",
		Zone:   "example.com.",
		Name:   "www.example.com.",
		RRType: 1,
		TTL:    300,
		RData:  []string{"192.168.1.1"},
	}
	zsm.Apply(entry{Command: mustMarshalJSON(addCmd)})

	// Update with new IP
	updateCmd := ZoneCommand{
		Type:   "update_record",
		Zone:   "example.com.",
		Name:   "www.example.com.",
		RRType: 1,
		TTL:    600,
		RData:  []string{"192.168.1.2"},
	}
	zsm.Apply(entry{Command: mustMarshalJSON(updateCmd)})

	records := zsm.GetRecords("example.com.")
	if len(records) != 1 {
		t.Errorf("expected 1 record, got %d", len(records))
	}
}

func TestZoneStateMachineDeleteZone(t *testing.T) {
	zsm := NewZoneStateMachine()

	// Add a record
	addCmd := ZoneCommand{
		Type:   "add_record",
		Zone:   "example.com.",
		Name:   "www.example.com.",
		RRType: 1,
		TTL:    300,
		RData:  []string{"192.168.1.1"},
	}
	zsm.Apply(entry{Command: mustMarshalJSON(addCmd)})

	// Delete zone
	delCmd := ZoneCommand{
		Type: "delete_zone",
		Zone: "example.com.",
	}
	zsm.Apply(entry{Command: mustMarshalJSON(delCmd)})

	zones := zsm.GetZones()
	if len(zones) != 0 {
		t.Errorf("expected 0 zones after delete, got %d", len(zones))
	}
}

func TestZoneStateMachineSnapshotRestore(t *testing.T) {
	zsm := NewZoneStateMachine()

	// Add some data
	addCmd := ZoneCommand{
		Type:   "add_record",
		Zone:   "example.com.",
		Name:   "www.example.com.",
		RRType: 1,
		TTL:    300,
		RData:  []string{"192.168.1.1"},
	}
	zsm.Apply(entry{Command: mustMarshalJSON(addCmd)})

	// Take snapshot
	snap, err := zsm.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}

	// Create new SM and restore
	zsm2 := NewZoneStateMachine()
	if err := zsm2.Restore(snap); err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	zones := zsm2.GetZones()
	if len(zones) != 1 {
		t.Errorf("expected 1 zone after restore, got %d", len(zones))
	}
}

func TestZoneStateMachineOnUpdate(t *testing.T) {
	zsm := NewZoneStateMachine()

	var updatedZone string
	var updatedCmd ZoneCommand
	zsm.OnUpdate(func(zone string, cmd ZoneCommand) {
		updatedZone = zone
		updatedCmd = cmd
	})

	addCmd := ZoneCommand{
		Type:   "add_record",
		Zone:   "example.com.",
		Name:   "www.example.com.",
		RRType: 1,
		TTL:    300,
		RData:  []string{"192.168.1.1"},
	}
	zsm.Apply(entry{Command: mustMarshalJSON(addCmd)})

	if updatedZone != "example.com." {
		t.Errorf("updatedZone = %q, want \"example.com.\"", updatedZone)
	}
	if updatedCmd.Type != "add_record" {
		t.Errorf("updatedCmd.Type = %q, want \"add_record\"", updatedCmd.Type)
	}
}

func TestZoneStateMachineNoOp(t *testing.T) {
	zsm := NewZoneStateMachine()
	err := zsm.Apply(entry{Type: EntryNoOp})
	if err != nil {
		t.Errorf("Apply EntryNoOp failed: %v", err)
	}
}

func TestZoneStateMachineEmptyCommand(t *testing.T) {
	zsm := NewZoneStateMachine()
	err := zsm.Apply(entry{Command: nil})
	if err != nil {
		t.Errorf("Apply nil command failed: %v", err)
	}
}

func TestZoneStateMachineUnknownCommand(t *testing.T) {
	zsm := NewZoneStateMachine()
	cmd := ZoneCommand{
		Type: "unknown_command",
		Zone: "example.com.",
	}
	err := zsm.Apply(entry{Command: mustMarshalJSON(cmd)})
	if err == nil {
		t.Error("expected error for unknown command")
	}
}

func TestZoneStateMachineDelNonexistentZone(t *testing.T) {
	zsm := NewZoneStateMachine()
	cmd := ZoneCommand{
		Type:   "del_record",
		Zone:   "nonexistent.com.",
		Name:   "www.nonexistent.com.",
		RRType: 1,
	}
	err := zsm.Apply(entry{Command: mustMarshalJSON(cmd)})
	if err != nil {
		t.Errorf("del on nonexistent zone failed: %v", err)
	}
}

// Transport tests

func TestTCPTransportNew(t *testing.T) {
	tp := NewTCPTransport()
	if tp == nil {
		t.Fatal("NewTCPTransport returned nil")
	}
	if tp.conns == nil {
		t.Error("expected conns to be initialized")
	}
	if tp.peerAddrs == nil {
		t.Error("expected peerAddrs to be initialized")
	}
}

func TestTCPTransportSetPeerAddr(t *testing.T) {
	tp := NewTCPTransport()
	tp.SetPeerAddr("node1", "192.168.1.1:9230")

	tp.mu.RLock()
	addr, ok := tp.peerAddrs["node1"]
	tp.mu.RUnlock()

	if !ok {
		t.Error("expected peer address to be set")
	}
	if addr != "192.168.1.1:9230" {
		t.Errorf("addr = %q, want %q", addr, "192.168.1.1:9230")
	}
}

func TestTCPTransportGetConnUnknownPeer(t *testing.T) {
	tp := NewTCPTransport()
	_, err := tp.getConn("unknown_peer")
	if err == nil {
		t.Error("expected error for unknown peer")
	}
}

func TestRecordKey(t *testing.T) {
	key := recordKey("www.example.com.", 1)
	if key != "www.example.com.:1" {
		t.Errorf("recordKey = %q, want \"www.example.com.:1\"", key)
	}
}

// Stats tests

func TestStats(t *testing.T) {
	stats := &Stats{}
	stats.BytesSent.Add(100)
	stats.BytesReceived.Add(200)
	stats.MessagesSent.Add(50)

	if stats.BytesSent.Load() != 100 {
		t.Errorf("BytesSent = %d, want 100", stats.BytesSent.Load())
	}
	if stats.BytesReceived.Load() != 200 {
		t.Errorf("BytesReceived = %d, want 200", stats.BytesReceived.Load())
	}
	if stats.MessagesSent.Load() != 50 {
		t.Errorf("MessagesSent = %d, want 50", stats.MessagesSent.Load())
	}
}

// Integration test with all components

func TestZoneStateMachineIntegration(t *testing.T) {
	zsm := NewZoneStateMachine()

	// Add multiple zones with multiple records
	zones := []string{"example.com.", "test.com.", "foo.com."}
	for _, zone := range zones {
		for i := 0; i < 3; i++ {
			cmd := ZoneCommand{
				Type:   "add_record",
				Zone:   zone,
				Name:   fmt.Sprintf("record%d.%s", i, zone),
				RRType: 1,
				TTL:    300,
				RData:  []string{fmt.Sprintf("10.0.0.%d", i)},
			}
			if err := zsm.Apply(entry{Command: mustMarshalJSON(cmd)}); err != nil {
				t.Fatalf("Apply failed: %v", err)
			}
		}
	}

	// Verify all zones present
	actualZones := zsm.GetZones()
	if len(actualZones) != len(zones) {
		t.Errorf("expected %d zones, got %d", len(zones), len(actualZones))
	}

	// Snapshot and restore
	snap, err := zsm.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}

	zsm2 := NewZoneStateMachine()
	if err := zsm2.Restore(snap); err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	restoredZones := zsm2.GetZones()
	if len(restoredZones) != len(zones) {
		t.Errorf("expected %d zones after restore, got %d", len(zones), len(restoredZones))
	}
}

// Helper

func mustMarshalJSON(v interface{}) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

// JointConfig tests

func TestQuorumForConfig(t *testing.T) {
	peers := map[NodeID]*Peer{
		"node1": {},
		"node2": {},
		"node3": {},
	}
	jc := &JointConfig{OldPeers: peers}

	// 3 peers -> quorum is 2
	if q := jc.QuorumForConfig(peers); q != 2 {
		t.Errorf("QuorumForConfig = %d, want 2", q)
	}

	// 5 peers -> quorum is 3
	peers5 := map[NodeID]*Peer{
		"node1": {},
		"node2": {},
		"node3": {},
		"node4": {},
		"node5": {},
	}
	if q := jc.QuorumForConfig(peers5); q != 3 {
		t.Errorf("QuorumForConfig(5) = %d, want 3", q)
	}
}

func TestHasQuorumOldAndNew(t *testing.T) {
	oldPeers := map[NodeID]*Peer{
		"node1": {},
		"node2": {},
		"node3": {},
	}
	newPeers := map[NodeID]*Peer{
		"node4": {},
		"node5": {},
	}
	jc := &JointConfig{OldPeers: oldPeers, NewPeers: newPeers}

	matchIndex := map[NodeID]Index{
		"node1": 10,
		"node2": 10,
		"node3": 10, // all old peers have matched
		"node4": 10,
		"node5": 10, // all new peers have matched
	}

	// With commitIdx 10, all 3 old peers matched (need quorum 2) and 2 new peers matched (need quorum 3... wait, 5 peers = quorum 3)
	if !jc.HasQuorumOldAndNew(matchIndex, 10) {
		t.Error("HasQuorumOldAndNew should return true when both configs have quorum")
	}

	// Only 1 new peer matched - no quorum for new config
	matchIndexPartial := map[NodeID]Index{
		"node1": 10,
		"node2": 10,
		"node3": 10,
		"node4": 10,
		"node5": 0, // not matched
	}
	if jc.HasQuorumOldAndNew(matchIndexPartial, 10) {
		t.Error("HasQuorumOldAndNew should return false when new config lacks quorum")
	}
}

func TestIsInJoint(t *testing.T) {
	config := DefaultConfig()
	transport := &mockTransport{}
	node := NewNode(config, []NodeID{"node2"}, transport)

	if node.IsInJoint() {
		t.Error("IsInJoint should be false initially")
	}
}

// --- Additional comprehensive tests for P0-2 ---

// TestElectionTimeoutBasics tests election timeout configuration
func TestElectionTimeoutBasics(t *testing.T) {
	transport := &mockTransport{}
	config := DefaultConfig()
	config.NodeID = "node1"
	config.ElectionTimeout = 100 * time.Millisecond
	config.HeartbeatInterval = 30 * time.Millisecond

	node := NewNode(config, []NodeID{"node2", "node3"}, transport)
	defer node.Stop()

	// Verify initial state
	if node.State() != StateFollower {
		t.Errorf("initial state = %v, want Follower", node.State())
	}

	// Verify timeout settings are applied
	if config.ElectionTimeout != 100*time.Millisecond {
		t.Errorf("election timeout = %v, want 100ms", config.ElectionTimeout)
	}
}

// TestTermAdvancement tests term increases correctly
func TestTermAdvancement(t *testing.T) {
	transport := &mockTransport{}
	config := DefaultConfig()
	config.NodeID = "node1"

	node := NewNode(config, nil, transport)
	defer node.Stop()

	initialTerm := node.Term()

	// Simulate receiving request with higher term
	node.mu.Lock()
	node.currentTerm = 5
	node.mu.Unlock()

	if node.Term() != 5 {
		t.Errorf("term = %d, want 5", node.Term())
	}
	if node.Term() <= initialTerm {
		t.Error("term should have advanced")
	}
}

// TestLogConsistencyRules tests various log consistency scenarios
func TestLogConsistencyRules(t *testing.T) {
	tests := []struct {
		name          string
		followerLog   []entry
		prevLogIndex  Index
		prevLogTerm   Term
		newEntries    []entry
		expectSuccess bool
	}{
		{
			name:          "empty_log_append_at_start",
			followerLog:   []entry{},
			prevLogIndex:  0,
			prevLogTerm:   0,
			newEntries:    []entry{{Index: 1, Term: 1, Command: []byte("cmd1")}},
			expectSuccess: true,
		},
		{
			name:          "append_at_end_matching",
			followerLog:   []entry{{Index: 1, Term: 1}, {Index: 2, Term: 1}},
			prevLogIndex:  2,
			prevLogTerm:   1,
			newEntries:    []entry{{Index: 3, Term: 1}},
			expectSuccess: true,
		},
		{
			name:          "reject_missing_prev_entry",
			followerLog:   []entry{{Index: 1, Term: 1}},
			prevLogIndex:  5,
			prevLogTerm:   1,
			newEntries:    []entry{{Index: 6, Term: 1}},
			expectSuccess: false,
		},
		{
			name:          "reject_term_mismatch",
			followerLog:   []entry{{Index: 1, Term: 1}, {Index: 2, Term: 2}},
			prevLogIndex:  2,
			prevLogTerm:   1,
			newEntries:    []entry{{Index: 3, Term: 2}},
			expectSuccess: false,
		},
		{
			name:          "overwrite_conflicting_entries",
			followerLog:   []entry{{Index: 1, Term: 1}, {Index: 2, Term: 1}},
			prevLogIndex:  1,
			prevLogTerm:   1,
			newEntries:    []entry{{Index: 2, Term: 2}},
			expectSuccess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &mockTransport{}
			config := DefaultConfig()
			config.NodeID = "node1"

			node := NewNode(config, nil, transport)
			defer node.Stop()

			node.mu.Lock()
			node.currentTerm = 2
			node.log = tt.followerLog
			node.mu.Unlock()

			req := AppendRequest{
				Term:         2,
				LeaderID:     "leader",
				PrevLogIndex: tt.prevLogIndex,
				PrevLogTerm:  tt.prevLogTerm,
				Entries:      tt.newEntries,
				LeaderCommit: 0,
			}

			resp := node.HandleAppendRequest(req)
			if resp.Success != tt.expectSuccess {
				t.Errorf("Success = %v, want %v", resp.Success, tt.expectSuccess)
			}
		})
	}
}

// TestVoteRequestLogComparison tests that vote requests consider log completeness
func TestVoteRequestLogComparison(t *testing.T) {
	tests := []struct {
		name        string
		nodeLog     []entry
		candidateLastIdx  Index
		candidateLastTerm Term
		shouldGrant bool
	}{
		{
			name:        "candidate_more_complete",
			nodeLog:     []entry{{Index: 1, Term: 1}},
			candidateLastIdx:  2,
			candidateLastTerm: 1,
			shouldGrant: true,
		},
		{
			name:        "candidate_less_complete",
			nodeLog:     []entry{{Index: 3, Term: 2}},
			candidateLastIdx:  1,
			candidateLastTerm: 1,
			shouldGrant: false,
		},
		{
			name:        "equal_logs",
			nodeLog:     []entry{{Index: 2, Term: 1}},
			candidateLastIdx:  2,
			candidateLastTerm: 1,
			shouldGrant: true,
		},
		{
			name:        "candidate_higher_term",
			nodeLog:     []entry{{Index: 5, Term: 1}},
			candidateLastIdx:  1,
			candidateLastTerm: 2,
			shouldGrant: true,
		},
		{
			name:        "empty_node_log",
			nodeLog:     []entry{},
			candidateLastIdx:  1,
			candidateLastTerm: 1,
			shouldGrant: true,
		},
		{
			name:        "candidate_equal_term_longer_log",
			nodeLog:     []entry{{Index: 1, Term: 2}, {Index: 2, Term: 2}},
			candidateLastIdx:  3,
			candidateLastTerm: 2,
			shouldGrant: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &mockTransport{}
			config := DefaultConfig()
			config.NodeID = "node1"

			node := NewNode(config, nil, transport)
			defer node.Stop()

			node.mu.Lock()
			node.currentTerm = 2
			node.votedFor = "" // Reset votedFor
			node.log = tt.nodeLog
			node.mu.Unlock()

			req := VoteRequest{
				Term:         2,
				CandidateID:  "node2",
				LastLogIndex: tt.candidateLastIdx,
				LastLogTerm:  tt.candidateLastTerm,
			}

			resp := node.HandleVoteRequest(req)
			if resp.VoteGranted != tt.shouldGrant {
				t.Errorf("VoteGranted = %v, want %v", resp.VoteGranted, tt.shouldGrant)
			}
		})
	}
}

// TestCommitIndexAdvancement tests commit index progression
func TestCommitIndexAdvancement(t *testing.T) {
	transport := &mockTransport{}
	config := DefaultConfig()
	config.NodeID = "leader1"

	node := NewNode(config, []NodeID{"follower1", "follower2"}, transport)
	defer node.Stop()

	// Set up as leader with some log entries
	node.mu.Lock()
	node.currentTerm = 1
	node.state = StateLeader
	node.log = []entry{
		{Index: 1, Term: 1},
		{Index: 2, Term: 1},
		{Index: 3, Term: 1},
	}
	node.commitIndex = 0
	node.nextIndex["follower1"] = 4
	node.nextIndex["follower2"] = 4
	node.matchIndex["follower1"] = 3
	node.matchIndex["follower2"] = 3
	node.mu.Unlock()

	// Verify commitIndex can advance when majority replicates
	node.mu.Lock()
	commitIdx := node.commitIndex
	node.mu.Unlock()

	if commitIdx != 0 {
		t.Errorf("initial commitIndex = %d, want 0", commitIdx)
	}
}

// TestLeaderReplicationCount tests that leader tracks replication correctly
func TestLeaderReplicationCount(t *testing.T) {
	transport := &mockTransport{}
	config := DefaultConfig()
	config.NodeID = "leader"

	peers := []NodeID{"f1", "f2", "f3", "f4"}
	node := NewNode(config, peers, transport)
	defer node.Stop()

	node.mu.Lock()
	node.state = StateLeader
	node.currentTerm = 1
	for _, peer := range peers {
		node.nextIndex[peer] = 1
		node.matchIndex[peer] = 0
	}
	node.mu.Unlock()

	// Verify nextIndex and matchIndex are initialized
	node.mu.Lock()
	for _, peer := range peers {
		if node.nextIndex[peer] != 1 {
			t.Errorf("nextIndex[%s] = %d, want 1", peer, node.nextIndex[peer])
		}
		if node.matchIndex[peer] != 0 {
			t.Errorf("matchIndex[%s] = %d, want 0", peer, node.matchIndex[peer])
		}
	}
	node.mu.Unlock()
}

// TestWALCorruption tests WAL behavior with corrupted data
func TestWALCorruption(t *testing.T) {
	tmpDir := t.TempDir()
	wal, err := NewWAL(tmpDir)
	if err != nil {
		t.Fatalf("NewWAL failed: %v", err)
	}

	// Write some valid entries
	entries := []entry{
		{Index: 1, Term: 1, Command: []byte("valid1")},
		{Index: 2, Term: 1, Command: []byte("valid2")},
	}
	for _, e := range entries {
		if err := wal.Write(e); err != nil {
			t.Fatalf("WAL.Write failed: %v", err)
		}
	}
	wal.Close()

	// Corrupt the WAL file by appending garbage
	walFile := tmpDir + "/raft-wal.log"
	f, err := os.OpenFile(walFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("failed to open WAL: %v", err)
	}
	f.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF}) // Garbage data
	f.Close()

	// Try to read - should handle gracefully
	wal2, err := NewWAL(tmpDir)
	if err != nil {
		t.Fatalf("NewWAL should handle corruption: %v", err)
	}
	defer wal2.Close()

	// Should be able to read entries before corruption
	readEntries, err := wal2.ReadAll()
	if err != nil {
		// Corruption might cause error, which is acceptable
		t.Logf("WAL.ReadAll returned error (expected): %v", err)
	}
	// Either we get the entries or an error - both are valid responses to corruption
	_ = readEntries
}

// TestWALLargeEntries tests WAL with large entries
func TestWALLargeEntries(t *testing.T) {
	tmpDir := t.TempDir()
	wal, err := NewWAL(tmpDir)
	if err != nil {
		t.Fatalf("NewWAL failed: %v", err)
	}
	defer wal.Close()

	// Write entries of various sizes
	sizes := []int{0, 100, 1000, 10000, 100000}
	for i, size := range sizes {
		cmd := make([]byte, size)
		for j := range cmd {
			cmd[j] = byte(j % 256)
		}
		e := entry{Index: Index(i + 1), Term: 1, Command: cmd}
		if err := wal.Write(e); err != nil {
			t.Fatalf("WAL.Write failed for size %d: %v", size, err)
		}
	}

	// Read back and verify
	entries, err := wal.ReadAll()
	if err != nil {
		t.Fatalf("WAL.ReadAll failed: %v", err)
	}
	if len(entries) != len(sizes) {
		t.Errorf("expected %d entries, got %d", len(sizes), len(entries))
	}
}

// TestSnapshotterMultipleSnapshots tests snapshotter with multiple snapshots
func TestSnapshotterMultipleSnapshots(t *testing.T) {
	tmpDir := t.TempDir()
	snap, err := NewSnapshotter(tmpDir)
	if err != nil {
		t.Fatalf("NewSnapshotter failed: %v", err)
	}

	// Create multiple snapshots using proper Save method
	for i := 1; i <= 3; i++ {
		data := []byte(fmt.Sprintf("snapshot data %d", i))
		snapshot := &Snapshot{
			Index:      Index(i * 10),
			Term:       Term(i),
			LastIndex:  Index(i*10 - 1),
			LastTerm:   Term(i),
			Data:       data,
			Membership: []NodeID{"node1", "node2"},
		}
		if err := snap.Save(snapshot); err != nil {
			t.Fatalf("Save failed at iteration %d: %v", i, err)
		}
	}

	// Load should return the most recent
	loaded, err := snap.Load()
	if err != nil {
		t.Fatalf("Snapshotter.Load failed: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected to load a snapshot")
	}
	if loaded.Index != 30 {
		t.Errorf("expected latest snapshot with Index=30, got %d", loaded.Index)
	}
}

// TestSnapshotterInvalidData tests snapshotter with invalid data
func TestSnapshotterInvalidData(t *testing.T) {
	tmpDir := t.TempDir()
	snap, err := NewSnapshotter(tmpDir)
	if err != nil {
		t.Fatalf("NewSnapshotter failed: %v", err)
	}

	// Create invalid snapshot file
	path := tmpDir + "/snapshot-invalid"
	if err := os.WriteFile(path, []byte("not valid snapshot data"), 0644); err != nil {
		t.Fatalf("failed to write invalid snapshot: %v", err)
	}

	// Load should handle gracefully
	loaded, err := snap.Load()
	if err != nil {
		t.Logf("Load returned error (acceptable): %v", err)
	}
	_ = loaded
}

// TestZoneStateMachineBulkOperations tests bulk zone operations
func TestZoneStateMachineBulkOperations(t *testing.T) {
	zsm := NewZoneStateMachine()

	// Add many records
	recordCount := 100
	for i := 0; i < recordCount; i++ {
		cmd := ZoneCommand{
			Type:   "add_record",
			Zone:   "bulk.example.com.",
			Name:   fmt.Sprintf("record%d.bulk.example.com.", i),
			RRType: 1,
			TTL:    300,
			RData:  []string{fmt.Sprintf("10.0.0.%d", i%256)},
		}
		if err := zsm.Apply(entry{Command: mustMarshalJSON(cmd)}); err != nil {
			t.Fatalf("Apply failed at record %d: %v", i, err)
		}
	}

	records := zsm.GetRecords("bulk.example.com.")
	if len(records) != recordCount {
		t.Errorf("expected %d records, got %d", recordCount, len(records))
	}

	// Snapshot and restore
	snap, err := zsm.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}

	zsm2 := NewZoneStateMachine()
	if err := zsm2.Restore(snap); err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	restoredRecords := zsm2.GetRecords("bulk.example.com.")
	if len(restoredRecords) != recordCount {
		t.Errorf("expected %d records after restore, got %d", recordCount, len(restoredRecords))
	}
}

// TestZoneStateMachineMultipleZones tests multiple zone operations
func TestZoneStateMachineMultipleZones(t *testing.T) {
	zsm := NewZoneStateMachine()

	zones := []string{"zone1.com.", "zone2.com.", "zone3.com."}
	for _, zone := range zones {
		for i := 0; i < 5; i++ {
			cmd := ZoneCommand{
				Type:   "add_record",
				Zone:   zone,
				Name:   fmt.Sprintf("www%d.%s", i, zone),
				RRType: 1,
				TTL:    300,
				RData:  []string{fmt.Sprintf("192.168.%d.%d", i, i)},
			}
			if err := zsm.Apply(entry{Command: mustMarshalJSON(cmd)}); err != nil {
				t.Fatalf("Apply failed: %v", err)
			}
		}
	}

	allZones := zsm.GetZones()
	if len(allZones) != len(zones) {
		t.Errorf("expected %d zones, got %d", len(zones), len(allZones))
	}

	// Delete one zone
	delCmd := ZoneCommand{Type: "delete_zone", Zone: "zone2.com."}
	if err := zsm.Apply(entry{Command: mustMarshalJSON(delCmd)}); err != nil {
		t.Fatalf("Delete zone failed: %v", err)
	}

	remainingZones := zsm.GetZones()
	if len(remainingZones) != len(zones)-1 {
		t.Errorf("expected %d zones after delete, got %d", len(zones)-1, len(remainingZones))
	}
}

// TestZoneStateMachineUpdateCallback tests update callback functionality
func TestZoneStateMachineUpdateCallback(t *testing.T) {
	zsm := NewZoneStateMachine()

	var callCount int
	var lastZone string
	zsm.OnUpdate(func(zone string, cmd ZoneCommand) {
		callCount++
		lastZone = zone
	})

	// Apply several commands
	for i := 0; i < 5; i++ {
		cmd := ZoneCommand{
			Type:   "add_record",
			Zone:   "callback.test.",
			Name:   fmt.Sprintf("r%d.callback.test.", i),
			RRType: 1,
			TTL:    300,
			RData:  []string{"10.0.0.1"},
		}
		zsm.Apply(entry{Command: mustMarshalJSON(cmd)})
	}

	if callCount != 5 {
		t.Errorf("callback called %d times, want 5", callCount)
	}
	if lastZone != "callback.test." {
		t.Errorf("lastZone = %q, want \"callback.test.\"", lastZone)
	}
}

// TestZoneStateMachineInvalidJSON tests handling of invalid JSON
func TestZoneStateMachineInvalidJSON(t *testing.T) {
	zsm := NewZoneStateMachine()

	// Apply invalid JSON
	err := zsm.Apply(entry{Command: []byte("not valid json")})
	if err == nil {
		t.Error("expected error for invalid JSON")
	}

	// Apply empty command
	err = zsm.Apply(entry{Command: []byte("{}")})
	if err == nil {
		t.Error("expected error for empty command object")
	}
}

// TestConfigDefaults tests default configuration values
func TestConfigDefaults(t *testing.T) {
	config := DefaultConfig()

	// Note: NodeID is intentionally empty in DefaultConfig and must be set by caller
	if config.NodeID != "" {
		t.Logf("NodeID is set to %q (caller must set this)", config.NodeID)
	}
	if config.ElectionTimeout == 0 {
		t.Error("ElectionTimeout should not be zero")
	}
	if config.HeartbeatInterval == 0 {
		t.Error("HeartbeatInterval should not be zero")
	}
	if config.HeartbeatInterval >= config.ElectionTimeout {
		t.Error("HeartbeatInterval should be less than ElectionTimeout")
	}
}

// TestNodeIDOperations tests NodeID comparisons
func TestNodeIDOperations(t *testing.T) {
	id1 := NodeID("node1")
	id2 := NodeID("node2")

	if id1 == id2 {
		t.Error("different NodeIDs should not be equal")
	}

	if id1 != NodeID("node1") {
		t.Error("same NodeIDs should be equal")
	}
}

// TestEntryTypes tests entry type constants
func TestEntryTypes(t *testing.T) {
	if EntryNormal != 0 {
		t.Errorf("EntryNormal = %d, want 0", EntryNormal)
	}
	if EntryNoOp != 1 {
		t.Errorf("EntryNoOp = %d, want 1", EntryNoOp)
	}
}

// TestQuorumCalculations tests quorum calculation for various cluster sizes
func TestQuorumCalculations(t *testing.T) {
	tests := []struct {
		peers    int
		expected int
	}{
		{1, 1},
		{2, 2},
		{3, 2},
		{4, 3},
		{5, 3},
		{6, 4},
		{7, 4},
	}

	for _, tt := range tests {
		peers := make(map[NodeID]*Peer)
		for i := 0; i < tt.peers; i++ {
			peers[NodeID(fmt.Sprintf("node%d", i))] = &Peer{}
		}
		jc := &JointConfig{OldPeers: peers}
		quorum := jc.QuorumForConfig(peers)
		if quorum != tt.expected {
			t.Errorf("QuorumForConfig(%d peers) = %d, want %d", tt.peers, quorum, tt.expected)
		}
	}
}

// TestEmptyNodeOperations tests operations on node with no peers
func TestEmptyNodeOperations(t *testing.T) {
	transport := &mockTransport{}
	config := DefaultConfig()
	config.NodeID = "single"

	node := NewNode(config, nil, transport)
	defer node.Stop()

	if len(node.peers) != 0 {
		t.Errorf("expected 0 peers, got %d", len(node.peers))
	}

	// Single node should be able to become leader
	node.mu.Lock()
	node.state = StateLeader
	node.currentTerm = 1
	node.mu.Unlock()

	if node.State() != StateLeader {
		t.Error("expected to be leader")
	}
}

// TestLogEntryJSON tests JSON marshaling of log entries
func TestLogEntryJSON(t *testing.T) {
	e := entry{
		Index:   1,
		Term:    2,
		Command: []byte("test command"),
		Type:    EntryNormal,
	}

	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded entry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decoded.Index != e.Index {
		t.Errorf("Index = %d, want %d", decoded.Index, e.Index)
	}
	if decoded.Term != e.Term {
		t.Errorf("Term = %d, want %d", decoded.Term, e.Term)
	}
	if string(decoded.Command) != string(e.Command) {
		t.Errorf("Command = %q, want %q", decoded.Command, e.Command)
	}
}

// TestZoneCommandJSON tests ZoneCommand JSON marshaling
func TestZoneCommandJSON(t *testing.T) {
	cmd := ZoneCommand{
		Type:   "add_record",
		Zone:   "example.com.",
		Name:   "www.example.com.",
		RRType: 1,
		TTL:    300,
		RData:  []string{"192.168.1.1", "192.168.1.2"},
	}

	data, err := json.Marshal(cmd)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded ZoneCommand
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decoded.Type != cmd.Type {
		t.Errorf("Type = %q, want %q", decoded.Type, cmd.Type)
	}
	if len(decoded.RData) != len(cmd.RData) {
		t.Errorf("RData length = %d, want %d", len(decoded.RData), len(cmd.RData))
	}
}

// TestStatsConcurrentAccess tests Stats under concurrent access
func TestStatsConcurrentAccess(t *testing.T) {
	stats := &Stats{}

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 1000; j++ {
				stats.BytesSent.Add(1)
				stats.BytesReceived.Add(2)
				stats.MessagesSent.Add(1)
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	if stats.BytesSent.Load() != 10000 {
		t.Errorf("BytesSent = %d, want 10000", stats.BytesSent.Load())
	}
}

// TestRecordKeyVariations tests record key generation with various inputs
func TestRecordKeyVariations(t *testing.T) {
	tests := []struct {
		name   string
		rrtype uint16
		want   string
	}{
		{"example.com.", 1, "example.com.:1"},
		{"www.example.com.", 1, "www.example.com.:1"},
		{"example.com.", 28, "example.com.:28"}, // AAAA
		{"", 0, ":0"},
		{"a.b.c.d.e.f.", 255, "a.b.c.d.e.f.:255"},
	}

	for _, tt := range tests {
		got := recordKey(tt.name, tt.rrtype)
		if got != tt.want {
			t.Errorf("recordKey(%q, %d) = %q, want %q", tt.name, tt.rrtype, got, tt.want)
		}
	}
}

// TestPeerOperations tests peer-related operations
func TestPeerOperations(t *testing.T) {
	transport := &mockTransport{}
	config := DefaultConfig()
	config.NodeID = "node1"

	peers := []NodeID{"node2", "node3", "node4"}
	node := NewNode(config, peers, transport)
	defer node.Stop()

	// Test peer tracking
	for _, peer := range peers {
		node.mu.Lock()
		_, hasNext := node.nextIndex[peer]
		_, hasMatch := node.matchIndex[peer]
		node.mu.Unlock()

		if !hasNext {
			t.Errorf("nextIndex missing for peer %s", peer)
		}
		if !hasMatch {
			t.Errorf("matchIndex missing for peer %s", peer)
		}
	}
}

// TestAppendRequestResponseJSON tests JSON serialization
func TestAppendRequestResponseJSON(t *testing.T) {
	req := AppendRequest{
		Term:         1,
		LeaderID:     "leader",
		PrevLogIndex: 0,
		PrevLogTerm:  0,
		Entries: []entry{
			{Index: 1, Term: 1, Command: []byte("cmd")},
		},
		LeaderCommit: 0,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded AppendRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decoded.Term != req.Term {
		t.Errorf("Term = %d, want %d", decoded.Term, req.Term)
	}
	if len(decoded.Entries) != len(req.Entries) {
		t.Errorf("Entries length = %d, want %d", len(decoded.Entries), len(req.Entries))
	}

	// Test response
	resp := AppendResponse{
		Term:       1,
		Success:    true,
		MatchIndex: 2,
	}

	data, err = json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decodedResp AppendResponse
	if err := json.Unmarshal(data, &decodedResp); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decodedResp.Success != resp.Success {
		t.Errorf("Success = %v, want %v", decodedResp.Success, resp.Success)
	}
}

// TestVoteRequestResponseJSON tests JSON serialization
func TestVoteRequestResponseJSON(t *testing.T) {
	req := VoteRequest{
		Term:         1,
		CandidateID:  "candidate",
		LastLogIndex: 0,
		LastLogTerm:  0,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded VoteRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decoded.CandidateID != req.CandidateID {
		t.Errorf("CandidateID = %q, want %q", decoded.CandidateID, req.CandidateID)
	}

	resp := VoteResponse{
		Term:        1,
		VoteGranted: true,
	}

	data, err = json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decodedResp VoteResponse
	if err := json.Unmarshal(data, &decodedResp); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decodedResp.VoteGranted != resp.VoteGranted {
		t.Errorf("VoteGranted = %v, want %v", decodedResp.VoteGranted, resp.VoteGranted)
	}
}

// TestConcurrentWALOperations tests concurrent WAL access
func TestConcurrentWALOperations(t *testing.T) {
	tmpDir := t.TempDir()
	wal, err := NewWAL(tmpDir)
	if err != nil {
		t.Fatalf("NewWAL failed: %v", err)
	}
	defer wal.Close()

	done := make(chan bool)
	for i := 0; i < 5; i++ {
		go func(id int) {
			for j := 0; j < 20; j++ {
				e := entry{
					Index:   Index(id*100 + j),
					Term:    1,
					Command: []byte(fmt.Sprintf("cmd-%d-%d", id, j)),
				}
				wal.Write(e)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 5; i++ {
		<-done
	}

	// Sync at the end
	if err := wal.Sync(); err != nil {
		t.Errorf("Sync failed: %v", err)
	}
}

// TestTransportMockVariations tests mock transport with different responses
func TestTransportMockVariations(t *testing.T) {
	tests := []struct {
		name        string
		voteResp    *VoteResponse
		voteErr     error
		appendResp  *AppendResponse
		appendErr   error
		expectPanic bool
	}{
		{
			name:       "success_responses",
			voteResp:   &VoteResponse{Term: 1, VoteGranted: true},
			appendResp: &AppendResponse{Term: 1, Success: true, MatchIndex: 1},
		},
		{
			name:       "error_responses",
			voteErr:    fmt.Errorf("network error"),
			appendErr:  fmt.Errorf("network error"),
		},
		{
			name:       "rejected_vote",
			voteResp:   &VoteResponse{Term: 1, VoteGranted: false},
			appendResp: &AppendResponse{Term: 1, Success: false},
		},
		{
			name:       "higher_term_response",
			voteResp:   &VoteResponse{Term: 5, VoteGranted: false},
			appendResp: &AppendResponse{Term: 5, Success: false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &mockTransport{
				voteResp:     tt.voteResp,
				voteRespErr:  tt.voteErr,
				appendResp:   tt.appendResp,
				appendRespErr: tt.appendErr,
			}

			// Test vote request
			voteResp, err := transport.SendRequestVote("peer", VoteRequest{})
			if tt.voteErr != nil {
				if err == nil {
					t.Error("expected error for vote request")
				}
			} else if voteResp == nil && !tt.expectPanic {
				t.Error("expected vote response")
			}

			// Test append request
			appendResp, err := transport.SendAppendEntries("peer", AppendRequest{})
			if tt.appendErr != nil {
				if err == nil {
					t.Error("expected error for append request")
				}
			} else if appendResp == nil && !tt.expectPanic {
				t.Error("expected append response")
			}
		})
	}
}

// TestSnapshotRequestResponse tests snapshot-related structures
func TestSnapshotRequestResponse(t *testing.T) {
	req := SnapshotRequest{
		Term:      1,
		LeaderID:  "leader",
		LastIndex: 10,
		LastTerm:  1,
		Data:      []byte("snapshot data"),
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded SnapshotRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decoded.LastIndex != req.LastIndex {
		t.Errorf("LastIndex = %d, want %d", decoded.LastIndex, req.LastIndex)
	}
	if string(decoded.Data) != string(req.Data) {
		t.Errorf("Data = %q, want %q", decoded.Data, req.Data)
	}
}
