package raft

// F562 (P2-G1): the leader advertises its DNS address in AppendEntries (an
// optional, additive trailing wire field) so followers can forward RFC 2136
// UPDATEs to it.

import (
	"bytes"
	"strings"
	"testing"
)

func TestAppendRequest_LeaderDNSAddrWire_F562(t *testing.T) {
	base := AppendRequest{Term: 7, LeaderID: "n1", PrevLogIndex: 3, PrevLogTerm: 6,
		Entries: []entry{{Index: 4, Term: 7, Command: []byte("x")}}, LeaderCommit: 3}

	// Without an address the encoding is byte-identical to the pre-F562
	// format, so older peers decode it unchanged.
	old, err := encodeAppendRequest(base)
	if err != nil {
		t.Fatal(err)
	}
	var got AppendRequest
	if err := decodeAppendRequest(&got, old); err != nil || got.LeaderDNSAddr != "" || got.LeaderCommit != 3 {
		t.Fatalf("no-trailer decode = (%+v, %v)", got, err)
	}

	withAddr := base
	withAddr.LeaderDNSAddr = "192.0.2.53:53"
	b, err := encodeAppendRequest(withAddr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b[:len(old)], old) || len(b) != len(old)+2+len(withAddr.LeaderDNSAddr) {
		t.Fatalf("trailer is not a pure suffix of the old encoding")
	}
	got = AppendRequest{LeaderDNSAddr: "stale"}
	if err := decodeAppendRequest(&got, b); err != nil || got.LeaderDNSAddr != "192.0.2.53:53" || got.LeaderCommit != 3 || len(got.Entries) != 1 {
		t.Fatalf("trailer decode = (%+v, %v)", got, err)
	}
	// Reusing a struct must not keep a previous address.
	if err := decodeAppendRequest(&got, old); err != nil || got.LeaderDNSAddr != "" {
		t.Fatalf("re-decode kept stale address %q (%v)", got.LeaderDNSAddr, err)
	}

	// Malformed trailers are rejected, not read out of bounds.
	for name, bad := range map[string][]byte{
		"one byte":       append(append([]byte(nil), old...), 0),
		"length overrun": append(append([]byte(nil), old...), 0, 9, 'a'),
		"length > max":   append(append([]byte(nil), old...), 0x01, 0x00),
	} {
		if err := decodeAppendRequest(&AppendRequest{}, bad); err == nil {
			t.Errorf("%s: decoded without error", name)
		}
	}
	long := base
	long.LeaderDNSAddr = strings.Repeat("a", maxLeaderDNSAddrLen+1)
	if _, err := encodeAppendRequest(long); err == nil {
		t.Errorf("over-long address encoded")
	}
}

func TestNode_LeaderDNSAddr_F562(t *testing.T) {
	n, err := NewNode(Config{NodeID: "f"}, []NodeID{"l1", "l2"}, &mockTransport{})
	if err != nil {
		t.Fatal(err)
	}
	if id, addr := n.LeaderDNSAddr(); id != "" || addr != "" {
		t.Fatalf("fresh node = (%q, %q)", id, addr)
	}
	if resp := n.HandleAppendRequest(AppendRequest{Term: 1, LeaderID: "l1", LeaderDNSAddr: "192.0.2.1:53"}); !resp.Success {
		t.Fatalf("append from l1 rejected")
	}
	if id, addr := n.LeaderDNSAddr(); id != "l1" || addr != "192.0.2.1:53" {
		t.Fatalf("after l1 = (%q, %q)", id, addr)
	}
	// A new leader that advertises nothing must not inherit l1's address.
	n.HandleAppendRequest(AppendRequest{Term: 2, LeaderID: "l2"})
	if id, addr := n.LeaderDNSAddr(); id != "l2" || addr != "" {
		t.Fatalf("after l2 = (%q, %q), want (l2, \"\")", id, addr)
	}
	// A stale-term append is rejected and does not change the address.
	n.HandleAppendRequest(AppendRequest{Term: 1, LeaderID: "l1", LeaderDNSAddr: "192.0.2.1:53"})
	if id, addr := n.LeaderDNSAddr(); id != "l2" || addr != "" {
		t.Fatalf("after stale l1 = (%q, %q)", id, addr)
	}
	// Leader learned via a snapshot only: address unknown for that leader.
	n.HandleAppendRequest(AppendRequest{Term: 3, LeaderID: "l1", LeaderDNSAddr: "192.0.2.1:53"})
	n.mu.Lock()
	n.leaderID = "l2"
	n.mu.Unlock()
	if _, addr := n.LeaderDNSAddr(); addr != "" {
		t.Fatalf("address of l1 reported for leader l2: %q", addr)
	}

	// A leader reports and sends its own address.
	ld, err := NewNode(Config{NodeID: "l"}, []NodeID{"f"}, &mockTransport{})
	if err != nil {
		t.Fatal(err)
	}
	ld.SetDNSAddr("198.51.100.1:53")
	ld.mu.Lock()
	ld.state, ld.leaderID = StateLeader, "l"
	ld.nextIndex["f"] = 1
	req, ok := ld.buildAppendRequestLocked("f", ld.currentTerm)
	ld.mu.Unlock()
	if !ok || req.LeaderDNSAddr != "198.51.100.1:53" {
		t.Fatalf("leader AppendRequest LeaderDNSAddr = %q (ok=%v)", req.LeaderDNSAddr, ok)
	}
	if id, addr := ld.LeaderDNSAddr(); id != "l" || addr != "198.51.100.1:53" {
		t.Fatalf("leader self = (%q, %q)", id, addr)
	}
}
