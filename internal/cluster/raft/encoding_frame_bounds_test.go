package raft

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"
)

func testGCM(t *testing.T) cipher.AEAD {
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

// F147: a response frame with a zero-length payload is truncated input and
// must not be reported as a successfully decoded (zero-valued) response.
func TestReadFramed_EmptyPayloadRejected(t *testing.T) {
	gcm := testGCM(t)
	resps := map[uint8]func() any{
		msgTypeVoteResponse:     func() any { return &VoteResponse{} },
		msgTypeAppendResponse:   func() any { return &AppendResponse{} },
		msgTypeSnapshotResponse: func() any { return &SnapshotResponse{} },
		msgTypeVoteRequest:      func() any { return &VoteRequest{} },
		msgTypeAppendRequest:    func() any { return &AppendRequest{} },
		msgTypeSnapshot:         func() any { return &SnapshotRequest{} },
	}
	for mt, mk := range resps {
		for _, aead := range []cipher.AEAD{nil, gcm} {
			var buf bytes.Buffer
			if aead == nil {
				buf.Write([]byte{mt, 0, 0, 0, 0})
			} else {
				nonce := make([]byte, aead.NonceSize())
				ct := aead.Seal(append([]byte(nil), nonce...), nonce, nil, []byte{mt})
				var hdr [frameHeaderSize]byte
				hdr[0] = mt
				binary.BigEndian.PutUint32(hdr[1:], uint32(len(ct)))
				buf.Write(hdr[:])
				buf.Write(ct)
			}
			if _, err := newFrameReader(&buf, aead).readFramed(mk()); err == nil {
				t.Errorf("type %d aead=%v: empty payload decoded without error", mt, aead != nil)
			}
		}
	}

	// Well-formed minimal messages still round-trip (repeated on one stream).
	var buf bytes.Buffer
	fw := newFrameWriter(&buf, gcm)
	for i := 0; i < 2; i++ {
		if err := fw.writeFramed(msgTypeSnapshotResponse, SnapshotResponse{}); err != nil {
			t.Fatal(err)
		}
	}
	fr := newFrameReader(&buf, gcm)
	for i := 0; i < 2; i++ {
		var got SnapshotResponse
		if _, err := fr.readFramed(&got); err != nil {
			t.Fatalf("zero-valued SnapshotResponse #%d: %v", i, err)
		}
	}
}

// F148: every frame the AEAD writer accepts must be accepted by the reader;
// payloads whose sealed size exceeds maxRPCMessageBytes are refused up front
// without writing anything to the stream.
func TestWriteFramed_AEADCapMatchesReader(t *testing.T) {
	gcm := testGCM(t)
	maxPlain := maxRPCMessageBytes - gcm.NonceSize() - gcm.Overhead()
	const fixed = 8 + 4 + 1 + 8 + 8 + 8 // SnapshotRequest framing with LeaderID "L"
	mk := func(n int) SnapshotRequest {
		return SnapshotRequest{Term: 1, LeaderID: "L", Data: make([]byte, n-fixed), LastIndex: 3, LastTerm: 1}
	}
	for _, n := range []int{maxPlain - 1, maxPlain, maxPlain + 1, maxRPCMessageBytes} {
		var buf bytes.Buffer
		werr := newFrameWriter(&buf, gcm).writeFramed(msgTypeSnapshot, mk(n))
		if n > maxPlain {
			if werr == nil {
				t.Errorf("payload %d: writer accepted a frame larger than the reader's cap", n)
			}
			if buf.Len() != 0 {
				t.Errorf("payload %d: rejected write left %d bytes on the stream", n, buf.Len())
			}
			continue
		}
		if werr != nil {
			t.Fatalf("payload %d: unexpected write error %v", n, werr)
		}
		var got SnapshotRequest
		if _, err := newFrameReader(&buf, gcm).readFramed(&got); err != nil {
			t.Fatalf("payload %d: reader rejected writer-accepted frame: %v", n, err)
		}
		if len(got.Data) != n-fixed || got.LastIndex != 3 {
			t.Fatalf("payload %d: round-trip mismatch", n)
		}
	}
}
