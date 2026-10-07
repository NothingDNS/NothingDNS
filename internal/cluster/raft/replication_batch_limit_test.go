package raft

// Regression tests for F167/F168: AppendEntries batches must fit the RPC frame
// (and honour Config.MaxLogEntries), and ProposeEntry must refuse commands that
// could never be framed. Every request goes through the real frameWriter /
// frameReader so the 16 MiB cap (and the AEAD expansion) applies exactly as on
// a TCPTransport. Sends are gated on a channel — no sleeps.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

type batchCall struct {
	entries int
	err     error
}

type batchFramedTransport struct {
	follower *Node
	aead     cipher.AEAD
	calls    chan batchCall
}

func (t *batchFramedTransport) SendRequestVote(context.Context, NodeID, VoteRequest) (*VoteResponse, error) {
	return nil, context.Canceled
}

func (t *batchFramedTransport) SendSnapshot(context.Context, NodeID, SnapshotRequest) (*SnapshotResponse, error) {
	return nil, context.Canceled
}

func (t *batchFramedTransport) SendAppendEntries(_ context.Context, _ NodeID, req AppendRequest) (*AppendResponse, error) {
	var buf bytes.Buffer
	if err := newFrameWriter(&buf, t.aead).writeFramed(msgTypeAppendRequest, req); err != nil {
		t.calls <- batchCall{entries: len(req.Entries), err: err}
		return nil, err
	}
	var got AppendRequest
	if _, err := newFrameReader(&buf, t.aead).readFramed(&got); err != nil {
		t.calls <- batchCall{entries: len(req.Entries), err: err}
		return nil, err
	}
	resp := t.follower.HandleAppendRequest(got)
	t.calls <- batchCall{entries: len(req.Entries)}
	return &resp, nil
}

func batchTestGCM(t *testing.T) cipher.AEAD {
	t.Helper()
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

// newBatchLeader returns a term-1 leader "L" with one empty follower "F"
// (nextIndex 1) and a log of entries whose commands have the given sizes.
func newBatchLeader(t *testing.T, aead cipher.AEAD, maxLogEntries int, sizes []int) (*Node, *Node, *batchFramedTransport) {
	t.Helper()
	fcfg := DefaultConfig()
	fcfg.NodeID = "F"
	follower, err := NewNode(fcfg, []NodeID{"L"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr := &batchFramedTransport{follower: follower, aead: aead, calls: make(chan batchCall, 1)}
	lcfg := DefaultConfig()
	lcfg.NodeID = "L"
	if maxLogEntries > 0 {
		lcfg.MaxLogEntries = maxLogEntries
	}
	leader, err := NewNode(lcfg, []NodeID{"F"}, tr)
	if err != nil {
		t.Fatal(err)
	}
	leader.mu.Lock()
	leader.currentTerm = 1
	leader.state = StateLeader
	leader.leaderID = "L"
	for i, sz := range sizes {
		leader.log = append(leader.log, entry{Index: Index(i + 1), Term: 1, Type: EntryNormal, Command: make([]byte, sz)})
	}
	leader.nextIndex["F"] = 1
	leader.matchIndex["F"] = 0
	leader.mu.Unlock()
	return leader, follower, tr
}

func batchRound(leader *Node, tr *batchFramedTransport) batchCall {
	leader.replicateTo("F", 1)
	call := <-tr.calls
	if call.err == nil {
		leader.handleAppendResponse(<-leader.appendRespCh)
	}
	return call
}

func batchMatch(leader *Node) Index {
	leader.mu.Lock()
	defer leader.mu.Unlock()
	return leader.matchIndex["F"]
}

func repeatSize(n, size int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = size
	}
	return out
}

// TestReplication_LaggingFollowerBeyondFrameCatchesUp is the F167 regression:
// a follower more than 16 MiB behind must be caught up in frame-sized batches.
func TestReplication_LaggingFollowerBeyondFrameCatchesUp(t *testing.T) {
	const mib = 1 << 20
	for _, tc := range []struct {
		name  string
		aead  bool
		sizes []int
	}{
		{"plaintext_17x1MiB", false, repeatSize(17, mib)},
		{"aead_17x1MiB", true, repeatSize(17, mib)},
		{"aead_mixed_sizes", true, append(repeatSize(5, 7*mib), repeatSize(40, 1000)...)},
		{"plaintext_two_near_max", false, repeatSize(2, 16*mib-4096)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var aead cipher.AEAD
			if tc.aead {
				aead = batchTestGCM(t)
			}
			leader, _, tr := newBatchLeader(t, aead, 0, tc.sizes)
			want := Index(len(tc.sizes))
			for round := 0; batchMatch(leader) < want; round++ {
				if round > len(tc.sizes) {
					t.Fatalf("follower stuck at match=%d of %d", batchMatch(leader), want)
				}
				before := batchMatch(leader)
				if call := batchRound(leader, tr); call.err != nil {
					t.Fatalf("round %d: send refused: %v", round, call.err)
				}
				if batchMatch(leader) <= before {
					t.Fatalf("round %d: no progress (match=%d)", round, before)
				}
			}
			// Once caught up, a heartbeat carries no entries and still succeeds.
			if call := batchRound(leader, tr); call.err != nil || call.entries != 0 {
				t.Fatalf("heartbeat after catch-up: entries=%d err=%v", call.entries, call.err)
			}
		})
	}
}

// TestReplication_MaxLogEntriesCapsBatch: Config.MaxLogEntries is the
// documented per-AppendEntries entry cap (F167).
func TestReplication_MaxLogEntriesCapsBatch(t *testing.T) {
	for _, maxN := range []int{1, 128} {
		leader, _, tr := newBatchLeader(t, nil, maxN, repeatSize(300, 10))
		rounds := 0
		for batchMatch(leader) < 300 {
			call := batchRound(leader, tr)
			if call.err != nil || call.entries > maxN || call.entries == 0 {
				t.Fatalf("max=%d round %d: entries=%d err=%v", maxN, rounds, call.entries, call.err)
			}
			rounds++
		}
		if wantRounds := (300 + maxN - 1) / maxN; rounds != wantRounds {
			t.Fatalf("max=%d: rounds=%d, want %d", maxN, rounds, wantRounds)
		}
	}
}

// TestProposeEntry_RejectsUnframeableCommand is the F168 regression: a
// command that cannot fit in one AppendEntries frame is refused (and not
// appended), while one exactly at the limit is accepted and replicated even
// on an AEAD cluster.
func TestProposeEntry_RejectsUnframeableCommand(t *testing.T) {
	limit := appendEntriesBudget("L") - appendEntryWireOverhead
	for _, aeadOn := range []bool{false, true} {
		var aead cipher.AEAD
		if aeadOn {
			aead = batchTestGCM(t)
		}

		leader, _, tr := newBatchLeader(t, aead, 0, nil)
		if _, err := leader.ProposeEntry(make([]byte, limit+1), EntryNormal); err == nil {
			t.Fatalf("aead=%v: command of %d bytes accepted", aeadOn, limit+1)
		}
		if li := leader.lastIndexUnderLock(); li != 0 {
			t.Fatalf("aead=%v: rejected command was appended (lastIndex=%d)", aeadOn, li)
		}
		if call := batchRound(leader, tr); call.err != nil {
			t.Fatalf("aead=%v: heartbeat after rejected propose failed: %v", aeadOn, call.err)
		}

		idx, err := leader.ProposeEntry(make([]byte, limit), EntryNormal)
		if err != nil {
			t.Fatalf("aead=%v: command at limit rejected: %v", aeadOn, err)
		}
		if call := <-tr.calls; call.err != nil { // async replicateToFollowers
			t.Fatalf("aead=%v: command at limit not deliverable: %v", aeadOn, call.err)
		}
		leader.handleAppendResponse(<-leader.appendRespCh)
		if batchMatch(leader) != idx {
			t.Fatalf("aead=%v: match=%d, want %d", aeadOn, batchMatch(leader), idx)
		}
	}
}
