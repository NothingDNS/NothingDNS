package raft

import "testing"

func TestDecodeSnapshotRequestRejectsMalformedTrailer(t *testing.T) {
	req := SnapshotRequest{
		Term: 3, LeaderID: "leader", Data: []byte("snapshot"),
		LastIndex: 9, LastTerm: 2,
	}
	encoded, err := encodeSnapshotRequest(req)
	if err != nil {
		t.Fatal(err)
	}

	for _, extra := range []int{1, 15, 17} {
		wire := append(append([]byte(nil), encoded...), make([]byte, extra)...)
		var got SnapshotRequest
		if err := decodeSnapshotRequest(&got, wire); err == nil {
			t.Errorf("accepted malformed trailer with %d bytes", extra)
		}
	}
}
