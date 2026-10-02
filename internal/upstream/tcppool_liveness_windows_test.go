//go:build windows

package upstream

// Windows-specific tests for the deadline-bounded liveness probe.
//
// NOTE ON VERIFICATION: on a Linux host this file can only be compile-checked
// (GOOS=windows go vet / go test -c), not executed — there is no Windows
// runtime available in this project's CI. What IS executed on every platform
// is the decision logic in tcppool_liveness_classify_test.go, which is the
// same classifyRecv this wrapper feeds, and the end-to-end pool behaviour in
// tcppool_liveness_test.go, which carries no build tag and therefore already
// runs on Windows. These tests close the remaining gap: that the Windows
// wrapper returns PROMPTLY on an idle connection (the first WSARecv-based
// implementation hung there and blew the 10-minute test timeout), feeds
// classifyRecv correctly, and keeps the Winsock constant contract pinned.

import (
	"net"
	"os"
	"testing"
	"time"
)

// TestWindowsLivenessSentinels pins the Winsock error classification. A typo
// in a WSAE* value would silently turn a dead connection into a reusable one,
// which is the original bug. The deadline sentinel (os.ErrDeadlineExceeded,
// the would-block category of the Read-based probe) is asserted alongside.
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
		{"deadline exceeded means alive", os.ErrDeadlineExceeded, recvVerdictAlive},
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

// TestWindowsProbe_StalePooledConnNotReused exercises the probe end to end
// against a live loopback listener: once the upstream closes the connection,
// the EOF path must judge it not reusable.
func TestWindowsProbe_StalePooledConnNotReused(t *testing.T) {
	ln, accepted := newLivenessTestListener(t)
	defer ln.Close()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	serverSide := <-accepted

	serverSide.Close()
	waitForPeerClose(t, client)

	if tcpConnReusable(client) {
		t.Fatal("probe handed back a connection the upstream had closed")
	}
}

// TestWindowsProbe_IdleConnIsReusableAndPrompt is the regression guard for
// the original CI failure: probing an idle-but-live connection must return
// quickly with an alive verdict. The WSARecv implementation parked in
// syscall.WSARecv for minutes here and blew the 10-minute test timeout.
func TestWindowsProbe_IdleConnIsReusableAndPrompt(t *testing.T) {
	ln, accepted := newLivenessTestListener(t)
	defer ln.Close()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	serverSide := <-accepted
	defer serverSide.Close()

	done := make(chan bool, 1)
	go func() { done <- tcpConnReusable(client) }()

	select {
	case reusable := <-done:
		if !reusable {
			t.Fatal("idle live connection judged not reusable")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tcpConnReusable did not return within 5s on an idle connection — probe hang regression")
	}
}
