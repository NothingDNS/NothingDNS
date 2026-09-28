package upstream

// Shared classification for the pooled-connection liveness probe.
//
// The probe itself is platform-specific (recv(2) on unix, WSARecv on Windows),
// but the decision it feeds is not: given how many bytes a non-blocking,
// non-consuming peek returned and what error it produced, the same rule applies
// everywhere. Keeping that rule here — with no build tag — means it is unit
// testable on every platform, including ones whose probe we cannot execute in
// CI. Only the thin syscall wrapper remains platform-specific.

import "errors"

// recvVerdict is the outcome of one non-blocking peek.
type recvVerdict uint8

const (
	// recvVerdictAlive: nothing readable and no fatal error. Reusable.
	recvVerdictAlive recvVerdict = iota
	// recvVerdictPeerClosed: the peer shut the connection down. Not reusable.
	recvVerdictPeerClosed
	// recvVerdictUnusable: unsolicited data, or a hard error such as
	// ECONNRESET. Not reusable.
	recvVerdictUnusable
	// recvVerdictInconclusive: the probe could not decide (not a socket, the
	// RawConn callback never ran). Treated as reusable so a possibly-good
	// connection is never discarded on a guess.
	recvVerdictInconclusive
)

// livenessSentinels holds the platform-specific error values that steer
// classification. The values differ per platform (EAGAIN/EWOULDBLOCK on unix
// versus WSAEWOULDBLOCK on Windows) but the meaning of each category does not.
type livenessSentinels struct {
	// wouldBlock: no data available right now — the connection is alive.
	wouldBlock []error
	// interrupted: the call was interrupted before deciding anything.
	interrupted []error
	// notSupported: the handle is not a socket, so the probe is meaningless.
	notSupported []error
}

// classifyRecv maps one non-blocking peek result to a verdict.
//
//	n == 0 with no error  → peer closed (EOF). Winsock and BSD both report an
//	                       orderly shutdown as a successful 0-byte receive.
//	n > 0 with no error   → unsolicited data. MSG_PEEK/WSARecv left the bytes
//	                       queued so the stream is intact, but the next
//	                       exchange would misread them, so discard.
//	anything else         → decided by the sentinel categories.
func classifyRecv(n int, recvErr error, s livenessSentinels) recvVerdict {
	if recvErr == nil {
		if n == 0 {
			return recvVerdictPeerClosed
		}
		return recvVerdictUnusable
	}
	for _, e := range s.wouldBlock {
		if errors.Is(recvErr, e) {
			return recvVerdictAlive
		}
	}
	for _, e := range s.interrupted {
		if errors.Is(recvErr, e) {
			return recvVerdictAlive
		}
	}
	for _, e := range s.notSupported {
		if errors.Is(recvErr, e) {
			return recvVerdictInconclusive
		}
	}
	// ECONNRESET, ECONNABORTED, EBADF, and anything else hard.
	return recvVerdictUnusable
}

// verdictReusable reports whether a verdict permits handing the connection out.
func verdictReusable(v recvVerdict) bool {
	return v == recvVerdictAlive || v == recvVerdictInconclusive
}
