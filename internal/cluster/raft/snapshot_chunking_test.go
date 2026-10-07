package raft

// F173 regression: an InstallSnapshot whose state-machine payload exceeds the
// 16 MiB RPC frame cap was refused by writeFramed on every attempt, so a
// follower that needed a snapshot never caught up. Snapshots larger than
// snapshotChunkBytes are now sent in chunks. The transport below pushes every
// InstallSnapshot (and its response) through the REAL wire framing.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"runtime"
	"testing"
)

type chunkSnapCall struct {
	n   int
	err error
}

type chunkSnapTransport struct {
	follower *Node
	aead     cipher.AEAD
	calls    chan chunkSnapCall
}

func (t *chunkSnapTransport) SendRequestVote(context.Context, NodeID, VoteRequest) (*VoteResponse, error) {
	return nil, context.Canceled
}
func (t *chunkSnapTransport) SendAppendEntries(context.Context, NodeID, AppendRequest) (*AppendResponse, error) {
	return nil, context.Canceled
}
func (t *chunkSnapTransport) SendSnapshot(_ context.Context, _ NodeID, req SnapshotRequest) (*SnapshotResponse, error) {
	var buf bytes.Buffer
	if err := newFrameWriter(&buf, t.aead).writeFramed(msgTypeSnapshot, req); err != nil {
		t.calls <- chunkSnapCall{n: len(req.Data), err: err}
		return nil, err
	}
	var got SnapshotRequest
	if _, err := newFrameReader(&buf, t.aead).readFramed(&got); err != nil {
		t.calls <- chunkSnapCall{n: len(req.Data), err: err}
		return nil, err
	}
	resp := t.follower.HandleSnapshotRequest(got)
	var rbuf bytes.Buffer
	if err := newFrameWriter(&rbuf, t.aead).writeFramed(msgTypeSnapshotResponse, resp); err != nil {
		t.calls <- chunkSnapCall{n: len(req.Data), err: err}
		return nil, err
	}
	var out SnapshotResponse
	if _, err := newFrameReader(&rbuf, t.aead).readFramed(&out); err != nil {
		t.calls <- chunkSnapCall{n: len(req.Data), err: err}
		return nil, err
	}
	t.calls <- chunkSnapCall{n: len(req.Data)}
	return &out, nil
}

func chunkSnapGCM(t *testing.T) cipher.AEAD {
	block, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return gcm
}

type chunkRestored struct {
	sum   [32]byte
	n     int
	count int
}

func (r *chunkRestored) Apply(entry) error         { return nil }
func (r *chunkRestored) Snapshot() ([]byte, error) { return nil, nil }
func (r *chunkRestored) Restore(b []byte) error {
	r.sum = sha256.Sum256(b)
	r.n = len(b)
	r.count++
	return nil
}

// chunkSnapRun: leader L holds a snapshot of `size` bytes at index 10 (term 1)
// and an empty log; follower F is empty. One replicateTo; returns whether F
// installed the exact snapshot and L recorded matchIndex=10.
func chunkSnapRun(t *testing.T, aead cipher.AEAD, size int) (installed bool, match Index, calls int, lastErr error) {
	fcfg := DefaultConfig()
	fcfg.NodeID = "F"
	follower, err := NewNode(fcfg, []NodeID{"L"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sm := &chunkRestored{}
	follower.SetStateMachine(sm)
	tr := &chunkSnapTransport{follower: follower, aead: aead, calls: make(chan chunkSnapCall, 1024)}
	lcfg := DefaultConfig()
	lcfg.NodeID = "L"
	leader, err := NewNode(lcfg, []NodeID{"F"}, tr)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i * 7)
	}
	want := sha256.Sum256(data)
	leader.mu.Lock()
	leader.currentTerm = 1
	leader.state = StateLeader
	leader.leaderID = "L"
	leader.lastSnapshot = 10
	leader.lastSnapshotTerm = 1
	leader.snapshotBytes = data
	leader.nextIndex["F"] = 1
	leader.matchIndex["F"] = 0
	leader.mu.Unlock()

	leader.replicateTo("F", 1)
	// Gate on the send goroutine finishing (in-flight flag cleared after
	// every chunk/response was processed) — no sleeps.
	for {
		leader.mu.Lock()
		inFlight := leader.snapshotInFlight["F"]
		leader.mu.Unlock()
		if !inFlight {
			break
		}
		runtime.Gosched()
	}
	close(tr.calls)
	for c := range tr.calls {
		calls++
		if c.err != nil {
			lastErr = c.err
		}
	}
	follower.mu.Lock()
	installed = follower.lastSnapshot == 10 && sm.count == 1 && sm.n == size && sm.sum == want
	follower.mu.Unlock()
	leader.mu.Lock()
	match = leader.matchIndex["F"]
	leader.mu.Unlock()
	return
}

func TestInstallSnapshot_ChunkedBeyondFrameCap(t *testing.T) {
	for _, tc := range []struct {
		name      string
		aead      bool
		size      int
		wantSends int
	}{
		{"plaintext 17MiB", false, 17 << 20, 5},
		{"aead 17MiB", true, 17 << 20, 5},
		{"aead 40MiB", true, 40 << 20, 10},
		{"exactly one chunk (legacy single frame)", false, snapshotChunkBytes, 1},
		{"one chunk plus one byte", true, snapshotChunkBytes + 1, 2},
		{"small", false, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var aead cipher.AEAD
			if tc.aead {
				aead = chunkSnapGCM(t)
			}
			ok, m, sends, err := chunkSnapRun(t, aead, tc.size)
			if !ok || m != 10 || err != nil || sends != tc.wantSends {
				t.Fatalf("installed=%v match=%d err=%v sends=%d (want true, 10, nil, %d)", ok, m, err, sends, tc.wantSends)
			}
		})
	}
}

func chunkFollower(t *testing.T) (*Node, *chunkRestored) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.NodeID = "F"
	f, err := NewNode(cfg, []NodeID{"L"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sm := &chunkRestored{}
	f.SetStateMachine(sm)
	return f, sm
}

func chunkReq(off, total uint64, data string) SnapshotRequest {
	return SnapshotRequest{Term: 1, LeaderID: "L", LastIndex: 10, LastTerm: 1, Data: []byte(data), Offset: off, Total: total}
}

func TestInstallSnapshot_ChunkSequenceValidation(t *testing.T) {
	t.Run("out of order chunk refused and partial dropped", func(t *testing.T) {
		f, sm := chunkFollower(t)
		if r := f.HandleSnapshotRequest(chunkReq(0, 6, "ab")); !r.Success {
			t.Fatal("first chunk refused")
		}
		if r := f.HandleSnapshotRequest(chunkReq(4, 6, "ef")); r.Success {
			t.Fatal("gap chunk accepted")
		}
		if r := f.HandleSnapshotRequest(chunkReq(2, 6, "cd")); r.Success {
			t.Fatal("chunk accepted after the partial transfer was dropped")
		}
		if sm.count != 0 || f.lastSnapshot != 0 {
			t.Fatalf("partial snapshot installed: restores=%d lastSnapshot=%d", sm.count, f.lastSnapshot)
		}
	})
	t.Run("offset zero restarts transfer", func(t *testing.T) {
		f, sm := chunkFollower(t)
		f.HandleSnapshotRequest(chunkReq(0, 4, "xx"))
		for _, c := range []SnapshotRequest{chunkReq(0, 4, "ab"), chunkReq(2, 4, "cd")} {
			if r := f.HandleSnapshotRequest(c); !r.Success {
				t.Fatalf("chunk at %d refused", c.Offset)
			}
		}
		if sm.count != 1 || sm.sum != sha256.Sum256([]byte("abcd")) || f.lastSnapshot != 10 {
			t.Fatalf("restores=%d lastSnapshot=%d, want 1 restore of \"abcd\" at 10", sm.count, f.lastSnapshot)
		}
	})
	t.Run("mismatched snapshot identity refused", func(t *testing.T) {
		f, sm := chunkFollower(t)
		f.HandleSnapshotRequest(chunkReq(0, 4, "ab"))
		other := chunkReq(2, 4, "cd")
		other.LastIndex = 11
		if r := f.HandleSnapshotRequest(other); r.Success || sm.count != 0 {
			t.Fatalf("chunk of a different snapshot accepted (success=%v restores=%d)", r.Success, sm.count)
		}
	})
	t.Run("oversized total and overrun refused", func(t *testing.T) {
		f, sm := chunkFollower(t)
		if r := f.HandleSnapshotRequest(chunkReq(0, maxSnapshotDataBytes+1, "ab")); r.Success {
			t.Fatal("total above maxSnapshotDataBytes accepted")
		}
		if r := f.HandleSnapshotRequest(chunkReq(0, 1, "ab")); r.Success {
			t.Fatal("chunk overrunning total accepted")
		}
		if sm.count != 0 {
			t.Fatal("state machine restored")
		}
	})
}

func TestSnapshotRequest_ChunkFieldsWireRoundTrip(t *testing.T) {
	legacy := SnapshotRequest{Term: 3, LeaderID: "L", Data: []byte("abc"), LastIndex: 9, LastTerm: 2}
	b, err := encodeSnapshotRequest(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if want := 8 + 4 + 1 + 8 + 3 + 8 + 8; len(b) != want {
		t.Fatalf("unchunked request encoding changed: %d bytes, want %d", len(b), want)
	}
	chunk := legacy
	chunk.Offset, chunk.Total = 5, 8
	b, err = encodeSnapshotRequest(chunk)
	if err != nil {
		t.Fatal(err)
	}
	var got SnapshotRequest
	if err := decodeSnapshotRequest(&got, b); err != nil {
		t.Fatal(err)
	}
	if got.Offset != 5 || got.Total != 8 || string(got.Data) != "abc" || got.LastIndex != 9 || got.LastTerm != 2 {
		t.Fatalf("chunk round-trip mismatch: %+v", got)
	}
}
