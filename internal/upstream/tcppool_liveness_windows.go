//go:build windows

package upstream

// Liveness probe for pooled DNS-over-TCP connections (Windows).
//
// HISTORY: the first implementation peeked with WSARecv(MSG_PEEK) inside
// syscall.RawConn.Read, assuming the handle was in non-blocking mode there so
// an empty peek would return WSAEWOULDBLOCK immediately. On the Windows runner
// that assumption is false: a synchronous nil-overlapped WSARecv on Go's
// overlapped-mode socket is a blocking receive, and the probe parked in
// syscall.WSARecv for the entire test timeout on an idle connection
// ("panic: test timed out after 10m0s", goroutine stuck at
// tcppool_liveness_windows.go:75). Windows offers no non-blocking peek
// through the raw handle, so the Winsock receive path is gone entirely.
//
// The probe now uses the public net API instead: a 1-byte Read bounded twice
// — an advisory SetReadDeadline the poller enforces, plus a hard wall-clock
// bound in case a conn ignores deadlines (a probe abandoned at that bound
// retires the connection) — and the outcome is classified by the shared
// classifyRecv table:
//
//	os.ErrDeadlineExceeded → nothing arrived → idle and open → alive
//	                         (the read is canceled before any byte is
//	                         consumed, so the stream is untouched)
//	io.EOF (0 bytes)       → peer closed → discard
//	n > 0, no error        → data queued outside a query → desynced → discard
//	anything else          → hard error (ECONNRESET, …) → discard
//
// This mirrors the unix probe's classifyRecv table (EAGAIN ≡ deadline
// exceeded, 0-byte peek ≡ EOF, readable data ≡ unusable), with one documented
// divergence: the deadline case is the alive signal, so probing an idle
// connection always costs the window. Keep livenessProbeWindow small — the
// probe runs under tcpConnPool.mu, so the window is a serialized stall for
// concurrent callers (the unix probe, by contrast, never waits).

import (
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"time"
)

const (
	// livenessProbeWindow bounds one probe. A peer FIN queued before the
	// probe is observed almost immediately; only a genuinely idle connection
	// pays the full window, which is the alive signal. Keep it small: the
	// probe runs under tcpConnPool.mu (get probes candidates while holding
	// the pool lock), so the window is a serialized stall for concurrent
	// callers. A FIN missed because the window was too short is caught on
	// the next checkout — the probe runs every time a pooled connection is
	// handed out.
	livenessProbeWindow = 10 * time.Millisecond

	// livenessProbeHardBound caps the whole probe regardless of whether the
	// connection honours its deadline: a net.Conn may ignore SetReadDeadline
	// (test stubs do; nothing in the net.Conn contract forbids it), and a
	// read on such a conn would park get() forever. The bound converts that
	// into an inconclusive verdict instead of a stall.
	livenessProbeHardBound = 50 * time.Millisecond

	// wsaewouldblock and the other WSAE* values below remain part of the
	// classification contract for raw Winsock errors (see classifyRecv).
	wsaewouldblock syscall.Errno = 10035
	wsaeintr       syscall.Errno = 10004
	wsaenotsock    syscall.Errno = 10038
	wsaeopnotsupp  syscall.Errno = 10045
)

var windowsLivenessSentinels = livenessSentinels{
	// A read that outlives livenessProbeWindow means nothing was queued: the
	// connection is idle and open. Go reports that as a deadline error, so it
	// takes the wouldBlock (alive) category.
	wouldBlock:   []error{wsaewouldblock, os.ErrDeadlineExceeded},
	interrupted:  []error{wsaeintr},
	notSupported: []error{wsaenotsock, wsaeopnotsupp},
}

// currentLivenessSentinels exposes the running platform's sentinel set so the
// untagged classification tests can assert against the real constants.
func currentLivenessSentinels() livenessSentinels {
	return windowsLivenessSentinels
}

// tcpConnReusable reports whether a pooled connection is safe to hand out for
// another DNS-over-TCP exchange. The outcome mapping mirrors the unix probe's
// classifyRecv table; see probeVerdict.
func tcpConnReusable(conn net.Conn) bool {
	if conn == nil {
		return false
	}
	return verdictReusable(probeVerdict(conn))
}

// probeVerdict bounds one 1-byte read and maps the result through the shared
// classifier.
//
// The SetReadDeadline is advisory: a net.Conn is free to ignore it (test
// stubs do), and a read on such a conn would otherwise park forever inside
// get() — under the pool lock. So the read runs in a goroutine and the probe
// gives up after a hard wall-clock bound, keeping the connection. A goroutine
// still parked in Read unblocks when the connection is eventually closed
// (the pool closes discarded and evicted connections).
func probeVerdict(conn net.Conn) recvVerdict {
	if err := conn.SetReadDeadline(time.Now().Add(livenessProbeWindow)); err != nil {
		// Deadlines refused: the probe cannot even ask to be bounded, so it
		// must not run. Reuse the connection — never discard one on a guess.
		return recvVerdictInconclusive
	}
	defer conn.SetReadDeadline(time.Time{}) // restore the no-deadline default

	type readResult struct {
		n   int
		err error
	}
	ch := make(chan readResult, 1)
	go func() {
		var b [1]byte
		n, err := conn.Read(b[:])
		ch <- readResult{n, err}
	}()

	select {
	case r := <-ch:
		if errors.Is(r.err, io.EOF) {
			// net.Conn reports a closed peer as (0, io.EOF); classifyRecv's
			// table expects that as a successful 0-byte receive.
			r.n, r.err = 0, nil
		}
		// os.ErrDeadlineExceeded is registered as a wouldBlock sentinel, so
		// an idle window classifies as alive; queued data classifies as
		// unusable; a reset or anything hard falls through to unusable.
		return classifyRecv(r.n, r.err, windowsLivenessSentinels)
	case <-time.After(livenessProbeHardBound):
		// The conn ignored its deadline and the read did not complete. Retire
		// the connection: a read still parked on it could complete later and
		// steal the first byte of the next exchange, desynchronising the
		// stream — unusable, not inconclusive, on purpose. The goroutine
		// unblocks when get() closes the discarded connection, and the
		// buffered channel absorbs its result, so nothing leaks.
		return recvVerdictUnusable
	}
}
