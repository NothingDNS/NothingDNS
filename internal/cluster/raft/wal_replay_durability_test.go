package raft

// Regression tests for WAL replay / persistence-failure defects (audit round
// R23, findings F162–F164). Failures are injected at the logPersister seam by
// wrapping a real on-disk WAL; no network, no timing.

import (
	"errors"
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/nothingdns/nothingdns/internal/util"
)

// faultyPersister wraps a real WAL and fails the next failWrites Write calls
// (after allowWrites successful ones), the next failSyncs Sync calls and the
// next failTruncates TruncateAfter calls.
type faultyPersister struct {
	*WAL
	allowWrites   int
	failWrites    int
	failSyncs     int
	failTruncates int
}

func (p *faultyPersister) Write(e entry) error {
	if p.allowWrites > 0 {
		p.allowWrites--
		return p.WAL.Write(e)
	}
	if p.failWrites > 0 {
		p.failWrites--
		return errors.New("injected write failure")
	}
	return p.WAL.Write(e)
}

func (p *faultyPersister) Sync() error {
	if p.failSyncs > 0 {
		p.failSyncs--
		return errors.New("injected fsync failure")
	}
	return p.WAL.Sync()
}

func (p *faultyPersister) TruncateAfter(k Index) error {
	if p.failTruncates > 0 {
		p.failTruncates--
		return errors.New("injected truncate failure")
	}
	return p.WAL.TruncateAfter(k)
}

func walIndexTerms(t *testing.T, w *WAL) string {
	t.Helper()
	got, err := w.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	s := ""
	for _, e := range got {
		s += fmt.Sprintf("%d/%d:%s ", e.Index, e.Term, e.Command)
	}
	return s
}

// F162: Start must refuse to boot over a mid-file-corrupt WAL instead of
// logging a warning and booting with an empty log.
func TestClusterIntegration_StartRefusesCorruptWAL(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(fmt.Sprintf("corrupt=%v", corrupt), func(t *testing.T) {
			dir := t.TempDir()
			w, err := NewWAL(path.Join(dir, "raft-wal"))
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range walTestEntries() {
				if err := w.Write(e); err != nil {
					t.Fatal(err)
				}
			}
			_ = w.Close()
			if corrupt {
				p := path.Join(dir, "raft-wal", "raft-wal.log")
				data, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				rec1 := walRecordHeaderSize + len("cmd-one") + 1
				data[len(walMagic)+rec1+walRecordHeaderSize+1] ^= 0x01
				if err := os.WriteFile(p, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			ci, err := NewClusterIntegration("n1", nil, nil, freeTCPAddr(t), dir, "", "", nil, util.DefaultLogger())
			if err != nil {
				t.Fatalf("NewClusterIntegration: %v", err)
			}
			defer ci.Stop()
			err = ci.Start()
			if corrupt {
				if !errors.Is(err, ErrWALCorrupt) {
					t.Fatalf("Start over corrupt WAL: err = %v, want ErrWALCorrupt", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Start over intact WAL: %v", err)
			}
			ci.node.mu.Lock()
			li := ci.node.lastIndex()
			ci.node.mu.Unlock()
			if li < 3 {
				t.Fatalf("intact WAL replay: lastIndex = %d, want >= 3", li)
			}
		})
	}
}

// F163: a follower whose WAL write fails must not keep the entries in its
// in-memory log; otherwise the leader's retry is ACKed without persisting.
func TestAppendEntries_PersistFailureDoesNotAckOnRetry(t *testing.T) {
	batch := []entry{
		{Index: 1, Term: 1, Command: []byte("x1")},
		{Index: 2, Term: 1, Command: []byte("x2")},
	}
	cases := []struct {
		name        string
		allowWrites int // successful writes before the injected failure
	}{
		{"first write fails", 0},
		{"second write fails (partial batch)", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wal := openTestWAL(t)
			n, _ := NewNode(Config{NodeID: "follower"}, nil, &mockTransport{})
			defer n.Stop()
			n.SetLogPersister(&faultyPersister{WAL: wal, allowWrites: tc.allowWrites, failWrites: 1})
			n.mu.Lock()
			n.currentTerm = 1
			n.mu.Unlock()
			req := AppendRequest{Term: 1, LeaderID: "l", Entries: batch}
			if n.HandleAppendRequest(req).Success {
				t.Fatal("append with failed WAL write must not ACK")
			}
			if !n.HandleAppendRequest(req).Success {
				t.Fatal("retry after the disk recovered should ACK")
			}
			if got := walIndexTerms(t, wal); got != "1/1:x1 2/1:x2 " {
				t.Fatalf("ACKed but WAL holds %q, want both entries", got)
			}
		})
	}

	// Conflict path: TruncateAfter fails; the retry must still persist the
	// new entry, and replay must yield the new suffix, not the stale one.
	t.Run("conflict truncate fails", func(t *testing.T) {
		wal := openTestWAL(t)
		n, _ := NewNode(Config{NodeID: "follower"}, nil, &mockTransport{})
		defer n.Stop()
		fp := &faultyPersister{WAL: wal}
		n.SetLogPersister(fp)
		n.mu.Lock()
		n.currentTerm = 1
		n.mu.Unlock()
		if !n.HandleAppendRequest(AppendRequest{Term: 1, LeaderID: "l", Entries: append(batch, entry{Index: 3, Term: 1, Command: []byte("x3")})}).Success {
			t.Fatal("initial append should ACK")
		}
		fp.failTruncates = 1
		req := AppendRequest{Term: 2, LeaderID: "l2", PrevLogIndex: 1, PrevLogTerm: 1,
			Entries: []entry{{Index: 2, Term: 2, Command: []byte("y2")}}}
		if n.HandleAppendRequest(req).Success {
			t.Fatal("append whose truncation failed must not ACK")
		}
		if !n.HandleAppendRequest(req).Success {
			t.Fatal("retry should ACK")
		}
		if got := walIndexTerms(t, wal); got != "1/1:x1 2/2:y2 " {
			t.Fatalf("WAL replay = %q, want %q", got, "1/1:x1 2/2:y2 ")
		}
	})
}

// F164: a later WAL record for an already-seen index supersedes it and every
// entry after it (etcd semantics); replay must not keep both copies.
func TestWAL_ReplayLaterRecordSupersedesIndex(t *testing.T) {
	t.Run("propose sync failure then retry", func(t *testing.T) {
		dir := t.TempDir()
		wal, err := NewWAL(path.Join(dir, "raft-wal"))
		if err != nil {
			t.Fatal(err)
		}
		n, _ := NewNode(Config{NodeID: "leader"}, nil, &mockTransport{})
		n.SetLogPersister(&faultyPersister{WAL: wal, failSyncs: 1})
		n.mu.Lock()
		n.state = StateLeader
		n.currentTerm = 1
		n.mu.Unlock()
		if err := n.Propose([]byte("a"), EntryNormal); err == nil {
			t.Fatal("propose with failed fsync must be refused")
		}
		if err := n.Propose([]byte("b"), EntryNormal); err != nil {
			t.Fatalf("second propose: %v", err)
		}
		n.Stop()
		_ = wal.Close()

		ci, err := NewClusterIntegration("leader", nil, nil, freeTCPAddr(t), dir, "", "", nil, util.DefaultLogger())
		if err != nil {
			t.Fatal(err)
		}
		defer ci.Stop()
		if err := ci.bootstrapState(); err != nil {
			t.Fatalf("bootstrapState: %v", err)
		}
		ci.node.mu.Lock()
		defer ci.node.mu.Unlock()
		if ci.node.lastIndex() != 1 || len(ci.node.log) != 1 || string(ci.node.log[0].Command) != "b" {
			t.Fatalf("after restart lastIndex=%d log=%+v, want only index 1 = \"b\"", ci.node.lastIndex(), ci.node.log)
		}
	})

	t.Run("stale suffix then new suffix, then compaction", func(t *testing.T) {
		w := openTestWAL(t)
		for _, e := range []entry{
			{Index: 1, Term: 1, Command: []byte("a")},
			{Index: 2, Term: 1, Command: []byte("b")},
			{Index: 3, Term: 1, Command: []byte("c")},
			{Index: 2, Term: 2, Command: []byte("B")}, // supersedes 2 and 3
			{Index: 3, Term: 2, Command: []byte("C")},
		} {
			if err := w.Write(e); err != nil {
				t.Fatal(err)
			}
		}
		if got, want := walIndexTerms(t, w), "1/1:a 2/2:B 3/2:C "; got != want {
			t.Fatalf("replay = %q, want %q", got, want)
		}
		if err := w.CompactBefore(1); err != nil {
			t.Fatal(err)
		}
		if got, want := walIndexTerms(t, w), "2/2:B 3/2:C "; got != want {
			t.Fatalf("after compaction = %q, want %q", got, want)
		}
	})
}
