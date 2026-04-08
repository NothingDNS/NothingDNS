package raft

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// mockTransport implements Transport for testing.
type mockTransport struct {
	sendVoteCalled     int
	sendAppendCalled  int
	voteResp          *VoteResponse
	appendResp        *AppendResponse
	voteRespErr       error
	appendRespErr     error
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
		name        string
		nodeTerm    Term
		votedFor    NodeID
		candidateTerm Term
		lastLogIdx  Index
		lastLogTerm Term
		wantGranted bool
		wantTerm    Term
	}{
		{
			name:        "vote for candidate with newer term",
			nodeTerm:    1,
			votedFor:    "",
			candidateTerm: 2,
			lastLogIdx:  1,
			lastLogTerm: 1,
			wantGranted: true,
			wantTerm:    2,
		},
		{
			name:        "reject candidate with older term",
			nodeTerm:    3,
			votedFor:    "",
			candidateTerm: 2,
			lastLogIdx:  1,
			lastLogTerm: 1,
			wantGranted: false,
			wantTerm:    3,
		},
		{
			name:        "reject already voted for different candidate",
			nodeTerm:    2,
			votedFor:    "node3",
			candidateTerm: 2,
			lastLogIdx:  1,
			lastLogTerm: 1,
			wantGranted: false,
			wantTerm:    2,
		},
		{
			name:        "allow vote for same candidate again",
			nodeTerm:    2,
			votedFor:    "node2",
			candidateTerm: 2,
			lastLogIdx:  1,
			lastLogTerm: 1,
			wantGranted: true,
			wantTerm:    2,
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
			entries:     []entry{{Index: 2, Term: 1, Command: []byte("test")}},
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
			entries:     []entry{{Index: 1, Term: 2}},
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
			entries:     []entry{{Index: 2, Term: 1}},
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
		Type: "del_record",
		Zone: "nonexistent.com.",
		Name: "www.nonexistent.com.",
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
