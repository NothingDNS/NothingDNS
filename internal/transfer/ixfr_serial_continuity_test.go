package transfer

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// RFC 1995 section 4 orders difference sequences oldest first through the
// client's version to the server's current version. The old SOA opening each
// later sequence must equal the new SOA that closed the preceding sequence.
func TestIXFRClientRejectsDiscontinuousDiffSequence_F902(t *testing.T) {
	continuous := []*protocol.ResourceRecord{
		mkSOARR(t, 4),
		mkSOARR(t, 2), mkSOARR(t, 3), mkARR(t, "v3.example.com.", 192, 0, 2, 3),
		mkSOARR(t, 3), mkSOARR(t, 4), mkARR(t, "v4.example.com.", 192, 0, 2, 4),
		mkSOARR(t, 4),
	}
	if records, err := runIXFRStream(t, ixfrStreamFrames(t, 0x4242, onePerMessage(continuous, nil)), nil, 2); err != nil || len(records) != len(continuous) {
		t.Fatalf("CONTROL FAILED: continuous IXFR returned %d records, err=%v", len(records), err)
	}
	t.Log("CONTROL OK: a continuous 2 -> 3 -> 4 IXFR sequence was accepted")

	discontinuous := append([]*protocol.ResourceRecord(nil), continuous...)
	discontinuous[4] = mkSOARR(t, 99)
	if records, err := runIXFRStream(t, ixfrStreamFrames(t, 0x4242, onePerMessage(discontinuous, nil)), nil, 2); err == nil {
		t.Log("EXPECTED: second difference sequence starts at serial 3 or is rejected")
		t.Logf("ACTUAL: discontinuous 2 -> 3, 99 -> 4 stream returned %d records without error", len(records))
		t.Fatal("PROBLEM CONFIRMED: IXFR client accepted a gap between difference sequences")
	}
	t.Log("PROBLEM NOT REPRODUCED: discontinuous IXFR sequence was rejected")
}

func TestIXFRClientRejectsWrongInitialDiffSerial_F902(t *testing.T) {
	stream := []*protocol.ResourceRecord{
		mkSOARR(t, 4), mkSOARR(t, 99), mkSOARR(t, 4), mkSOARR(t, 4),
	}
	if records, err := runIXFRStream(t, ixfrStreamFrames(t, 0x4242, onePerMessage(stream, nil)), nil, 2); err == nil {
		t.Fatalf("FIX NOT VERIFIED: wrong-base IXFR returned %d records", len(records))
	}
	t.Log("FIX VERIFIED: first difference sequence must start at the requested client serial")
}
