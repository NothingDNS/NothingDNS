//go:build windows

package upstream

// Windows-specific tests for the WSARecv MSG_PEEK liveness probe.
//
// NOTE ON VERIFICATION: on a Linux host this file can only be compile-checked
// (GOOS=windows go vet / go test -c), not executed — there is no Windows
// runtime available in this project's CI. What IS executed on every platform
// is the decision logic in tcppool_liveness_classify_test.go, which is the
// same classifyRecv this wrapper feeds, and the end-to-end pool behaviour in
// tcppool_liveness_test.go, which carries no build tag and therefore already
// runs on Windows. These tests close the remaining gap: that the Windows
// wrapper feeds classifyRecv correctly and uses the right Winsock constants.

import (
	"testing"
	"time"
)

// TestWindowsLivenessSentinels pins the Winsock error classification. A typo
// in a WSAE* value would silently turn a dead connection into a reusable one,
// which is the original bug.
func TestWindowsLivenessSentinels(t *testing.T) {
	s := windowsLivenessSentinels

	tests := []struct {
		name string
		err  error
		want recvVerdict
	}{
		{"WSAEWOULDBLOCK means alive", wsaewouldblock, recvVerdictAlive},
		{"WSAEINTR means alive", wsaeintr, recvVerdictAlive},
		{"WSAENOTSOCK is inconclusive", wsaenotsock, recvVerdictInconclusive},
		{"WSAEOPNOTSUPP is inconclusive", wsaeopnotsupp, recvVerdictInconclusive},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyRecv(0, tc.err, s); got != tc.want {
				t.Errorf("classifyRecv(0, %v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestWindowsLivenessConstants pins the Winsock constant values, which Go's
// syscall package for Windows does not provide.
func TestWindowsLivenessConstants(t *testing.T) {
	if msgPeek != 0x2 {
		t.Errorf("msgPeek = %#x, want 0x2", msgPeek)
	}
	for _, c := range []struct {
		name string
		got  int
		want int
	}{
		{"WSAEINTR", int(wsaeintr), 10004},
		{"WSAEWOULDBLOCK", int(wsaewouldblock), 10035},
		{"WSAENOTSOCK", int(wsaenotsock), 10038},
		{"WSAEOPNOTSUPP", int(wsaeopnotsupp), 10045},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

// TestWindowsWSARecv_StalePooledConnNotReused exercises the real WSARecv probe
// end to end against a live loopback listener. Named distinctly from the
// untagged equivalent in tcppool_liveness_test.go so both coexist in a Windows
// build, where the untagged one runs the same scenario.
func TestWindowsWSARecv_StalePooledConnNotReused(t *testing.T) {
	ln, accepted := newLivenessTestListener(t)
	defer ln.Close()

	pool := newTCPConnPool(ln.Addr().String(), 2, 4, time.Minute, 2*time.Second)

	first, err := pool.get()
	if err != nil {
		t.Fatalf("first get(): %v", err)
	}
	serverSide := <-accepted
	if err := pool.put(first); err != nil {
		t.Fatalf("put(): %v", err)
	}

	serverSide.Close()
	waitForPeerClose(t, first.conn)

	second, err := pool.get()
	if err != nil {
		t.Fatalf("second get(): %v", err)
	}
	defer second.close()

	if second == first {
		t.Fatalf("WSARecv probe handed back a connection the upstream had closed")
	}
}
