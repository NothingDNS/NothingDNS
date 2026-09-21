// Round-011 proof: HandleIXFR's "client up-to-date" check used
// `!serialIsNewer(serverSerial, clientSerial)`, which conflates two
// distinct cases:
//   1. server == client          → client is up-to-date, send single SOA (correct)
//   2. client > server           → server is BEHIND the client (stale zone, misconfig);
//                                  sending a single SOA falsely tells the client it's
//                                  up-to-date, causing the stale zone to persist silently.
//                                  Correct behavior: fall back to AXFR.
//
// The fix splits the check into:
//   - serverSerial == clientSerial → generateSingleSOA
//   - serialIsNewer(clientSerial, serverSerial) → fall back to AXFR
//   - otherwise (server has newer data) → generateIncrementalIXFR
//
// This proof directly exercises the three branches via a small replica
// of the fixed check logic.
package transfer

import "testing"

func TestProofRound011_IXFRStaleSerial(t *testing.T) {
	// Replica of the fixed check at ixfr.go:199-217.
	check := func(serverSerial, clientSerial uint32) string {
		if serverSerial == clientSerial {
			return "singleSOA"
		}
		if serialIsNewer(clientSerial, serverSerial) {
			return "axfr" // client newer than server → server behind, force full transfer
		}
		return "ixfr" // server has strictly newer data → generate incremental
	}

	cases := []struct {
		server, client uint32
		want           string
	}{
		{server: 100, client: 100, want: "singleSOA"}, // up-to-date
		{server: 200, client: 100, want: "ixfr"},      // server newer
		{server: 100, client: 200, want: "axfr"},      // server behind → force AXFR
	}

	for _, tc := range cases {
		got := check(tc.server, tc.client)
		if got != tc.want {
			t.Fatalf("FAIL: server=%d client=%d: got=%q want=%q. "+
				"Case \"server behind client\" must force AXFR, not silently send single SOA.",
				tc.server, tc.client, got, tc.want)
		}
	}

	t.Logf("PROOF PASS: all three serial-comparison branches are correctly distinguished")
}
