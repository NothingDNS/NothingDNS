package upstream

// Tests for the shared liveness classification.
//
// This file has NO build tag on purpose. classifyRecv is the part of the
// probe that decides reusable-or-not, and it is byte-for-byte the same code
// the Windows WSARecv wrapper feeds. Running it on every platform means the
// Windows decision logic is genuinely covered even though the Windows wrapper
// itself can only be compile-checked on a Linux host.
//
// Sentinels are reached through currentLivenessSentinels() rather than a
// platform-specific variable, so these assertions test the constants the
// running binary actually uses — on unix, on Windows, and on the fallback.

import (
	"errors"
	"fmt"
	"testing"
)

func TestClassifyRecv_Verdicts(t *testing.T) {
	// Synthetic sentinels stand in for the real per-platform values so the
	// table is byte-identical everywhere. The real sets are asserted
	// separately by TestCurrentLivenessSentinels below.
	s := livenessSentinels{
		wouldBlock:   []error{errWouldBlock},
		interrupted:  []error{errInterrupted},
		notSupported: []error{errNotSocket},
	}

	tests := []struct {
		name     string
		n        int
		err      error
		want     recvVerdict
		reusable bool
	}{
		{"no data available is alive", 0, errWouldBlock, recvVerdictAlive, true},
		{"interrupted is inconclusive-alive", 0, errInterrupted, recvVerdictAlive, true},
		{"zero bytes no error is peer closed", 0, nil, recvVerdictPeerClosed, false},
		{"one byte no error is unsolicited data", 1, nil, recvVerdictUnusable, false},
		{"wrapped would-block is still alive", 0, fmt.Errorf("peek: %w", errWouldBlock), recvVerdictAlive, true},
		{"not a socket is inconclusive", 0, errNotSocket, recvVerdictInconclusive, true},
		{"hard error is unusable", 0, errReset, recvVerdictUnusable, false},
		{"unknown error is unusable", 5, errors.New("boom"), recvVerdictUnusable, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyRecv(tc.n, tc.err, s)
			if got != tc.want {
				t.Errorf("classifyRecv(%d, %v) = %v, want %v", tc.n, tc.err, got, tc.want)
			}
			if got := verdictReusable(got); got != tc.reusable {
				t.Errorf("verdictReusable(%v) = %v, want %v", got, got, tc.reusable)
			}
		})
	}
}

// Sentinels used only by the table above; the real per-platform values are
// checked by TestCurrentLivenessSentinels.
var (
	errWouldBlock  = errors.New("would block")
	errInterrupted = errors.New("interrupted")
	errNotSocket   = errors.New("not a socket")
	errReset       = errors.New("connection reset")
)

// TestCurrentLivenessSentinels checks the sentinel set the running binary
// actually uses. A typo in a platform constant (EAGAIN, WSAEWOULDBLOCK, …)
// would silently turn a closed peer into a reusable connection — the original
// bug — so the sets must be non-empty and must steer an unrecognised hard
// error to "unusable".
func TestCurrentLivenessSentinels(t *testing.T) {
	s := currentLivenessSentinels()

	if len(s.wouldBlock) == 0 {
		t.Error("wouldBlock sentinel set is empty: an alive connection could never be recognised")
	}
	if len(s.interrupted) == 0 {
		t.Error("interrupted sentinel set is empty")
	}

	// A hard error matching no sentinel must be discarded, not reused.
	if got := classifyRecv(0, errReset, s); got != recvVerdictUnusable {
		t.Errorf("unrecognised hard error = %v, want unusable", got)
	}
	// Each declared sentinel must land in its intended verdict.
	for _, e := range s.wouldBlock {
		if got := classifyRecv(0, e, s); got != recvVerdictAlive {
			t.Errorf("wouldBlock sentinel %v = %v, want alive", e, got)
		}
	}
	for _, e := range s.interrupted {
		if got := classifyRecv(0, e, s); got != recvVerdictAlive {
			t.Errorf("interrupted sentinel %v = %v, want alive", e, got)
		}
	}
	for _, e := range s.notSupported {
		if got := classifyRecv(0, e, s); got != recvVerdictInconclusive {
			t.Errorf("notSupported sentinel %v = %v, want inconclusive", e, got)
		}
	}
}

// TestVerdictReusable keeps the two "safe to hand out" verdicts distinct from
// the two discard verdicts, since conflating them is the original bug.
func TestVerdictReusable(t *testing.T) {
	for _, v := range []recvVerdict{recvVerdictAlive, recvVerdictInconclusive} {
		if !verdictReusable(v) {
			t.Errorf("verdictReusable(%v) = false, want true", v)
		}
	}
	for _, v := range []recvVerdict{recvVerdictPeerClosed, recvVerdictUnusable} {
		if verdictReusable(v) {
			t.Errorf("verdictReusable(%v) = true, want false", v)
		}
	}
}
