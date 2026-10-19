package transfer

// Regression test for the 2026-10-19 proof-driven round: the IXFR client discards the master's AXFR-fallback
// answer when the client's serial is AHEAD of the master's.
//
// The in-repo server answers that case with a full AXFR-style stream
// (ixfr.go:247-252, pinned by proof_round011_ixfr_stale_serial_test:
// "server behind client must force AXFR" so the stale zone does not persist
// silently). The client's stream tracker instead marks the transfer DONE at
// the first record whenever the opening SOA is not strictly newer than the
// client serial (ixfrStreamTracker.feed, idx==0), so every record after the
// leading SOA is dropped and a one-record "up to date" answer is reported
// for what is a full-zone transfer.

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestIXFRClientConsumesAXFRFallbackWhenClientAhead(t *testing.T) {
	// The exact wire shape HandleIXFRWithKey produces for client serial 200
	// vs master serial 100: SOA(100) + zone records + SOA(100).
	stream := []*protocol.ResourceRecord{
		mkSOARR(t, 100),
		mkARR(t, "www.example.com.", 192, 0, 2, 1),
		mkSOARR(t, 100),
	}
	recs, err := runIXFRStream(t, ixfrStreamFrames(t, 0x4242, onePerMessage(stream, nil)), nil, 200)
	if err != nil {
		t.Fatalf("FAIL: AXFR-fallback stream for a client-ahead secondary errored: %v", err)
	}
	if len(recs) != len(stream) {
		t.Fatalf("FAIL: client consumed %d of %d records of the master's AXFR-fallback stream "+
			"(first SOA serial %d): the round-011 contract says this answer is a full zone, "+
			"not an up-to-date single SOA", len(recs), len(stream), stream[0].Data.(*protocol.RDataSOA).Serial)
	}
}

// Controls that must keep passing before AND after the fix.
func TestIXFRClientFallbackWireShapes(t *testing.T) {
	t.Run("up-to-date single SOA (equal serial) still accepted", func(t *testing.T) {
		stream := []*protocol.ResourceRecord{mkSOARR(t, 200)}
		recs, err := runIXFRStream(t, ixfrStreamFrames(t, 0x4242, onePerMessage(stream, nil)), nil, 200)
		if err != nil || len(recs) != 1 {
			t.Fatalf("FAIL control: single-SOA up-to-date answer: recs=%d err=%v, want 1/nil", len(recs), err)
		}
	})

	t.Run("incremental diff still read to end", func(t *testing.T) {
		stream := ixfrDiffStream(t)
		recs, err := runIXFRStream(t, ixfrStreamFrames(t, 0x4242, onePerMessage(stream, nil)), nil, 2)
		if err != nil || len(recs) != len(stream) {
			t.Fatalf("FAIL control: incremental stream: recs=%d err=%v, want %d/nil", len(recs), err, len(stream))
		}
	})

	t.Run("truncated AXFR stream still errors (F199)", func(t *testing.T) {
		stream := []*protocol.ResourceRecord{
			mkSOARR(t, 6),
			mkARR(t, "www.example.com.", 192, 0, 2, 1),
		}
		if _, err := runIXFRStream(t, ixfrStreamFrames(t, 0x4242, onePerMessage(stream, nil)), nil, 5); err == nil {
			t.Fatalf("FAIL control: truncated AXFR stream accepted without its closing SOA")
		}
	})
}
