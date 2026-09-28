//go:build unix

package upstream

// Liveness probe for pooled DNS-over-TCP connections (unix).
//
// An upstream routinely closes idle TCP connections. A pooled connection that
// was closed while sitting idle must not be handed back out: the query on it
// fails, and Client.queryTCPBuf's deferred markFailure() then records a
// failure against an upstream that is in fact perfectly healthy. Enough
// consecutive stale connections flip Server.IsHealthy() to false and pull a
// working upstream out of rotation.
//
// Setting a read deadline does NOT detect this. SetReadDeadline only arms a
// deadline; it performs no I/O. (Nor would a read under an already-expired
// deadline help: net.Conn checks the deadline in prepareRead and returns
// os.ErrDeadlineExceeded without ever polling, so a pending FIN is never
// surfaced. Both facts are why the previous "zero-read deadline" check was a
// silent no-op.)
//
// So this uses recv(2) with MSG_PEEK|MSG_DONTWAIT: it never blocks, never
// consumes a byte, and reports precisely what the socket has to offer. The
// decision itself lives in the platform-independent classifyRecv.

import (
	"net"
	"syscall"
)

var unixLivenessSentinels = livenessSentinels{
	wouldBlock:   []error{syscall.EAGAIN, syscall.EWOULDBLOCK},
	interrupted:  []error{syscall.EINTR},
	notSupported: []error{syscall.ENOTSOCK, syscall.EOPNOTSUPP},
}

// currentLivenessSentinels exposes the running platform's sentinel set so the
// untagged classification tests can assert against the real constants.
func currentLivenessSentinels() livenessSentinels {
	return unixLivenessSentinels
}

// tcpConnReusable reports whether a pooled connection is safe to hand out for
// another DNS-over-TCP exchange.
//
// A non-blocking MSG_PEEK probe distinguishes every state that matters:
// EAGAIN (alive), 0 bytes (orderly close), ECONNRESET (abortive close), and
// readable (unsolicited data). Anything inconclusive — not a socket, SyscallConn
// refused, the RawConn callback could not run — is reported as reusable,
// preserving the previous behaviour rather than discarding a possibly-good
// connection on a guess.
func tcpConnReusable(conn net.Conn) bool {
	if conn == nil {
		return false
	}

	sc, ok := conn.(syscall.Conn)
	if !ok {
		// Not a syscall-backed connection (e.g. net.Pipe in tests).
		return true
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return true
	}

	verdict := recvVerdictInconclusive
	if err := raw.Read(func(fd uintptr) bool {
		var b [1]byte
		// MSG_PEEK leaves the bytes queued; MSG_DONTWAIT guarantees this
		// returns immediately instead of parking the caller in the poller.
		n, _, recvErr := syscall.Recvfrom(int(fd), b[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		verdict = classifyRecv(int(n), recvErr, unixLivenessSentinels)
		return true // the syscall completed; it cannot block under MSG_DONTWAIT
	}); err != nil {
		// The callback never ran (would block, or the fd is gone mid-flight).
		// Inconclusive: do not discard a possibly-good connection.
		return true
	}

	return verdictReusable(verdict)
}
