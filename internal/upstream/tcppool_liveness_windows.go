//go:build windows

package upstream

// Liveness probe for pooled DNS-over-TCP connections (Windows).
//
// The Windows equivalent of the unix recv(2) MSG_PEEK|MSG_DONTWAIT probe is
// WSARecv with MSG_PEEK. Inside syscall.RawConn.Read the handle is already in
// non-blocking mode, so a peek with nothing queued returns WSAEWOULDBLOCK
// immediately rather than parking the caller — the same guarantee MSG_DONTWAIT
// gives on unix.
//
// MSG_PEEK leaves any bytes queued, so the stream is never disturbed. The
// decision logic is shared with the unix path via classifyRecv, so it is unit
// tested on every platform even though this wrapper only runs on Windows.

import (
	"net"
	"syscall"
)

const (
	// msgPeek is Winsock's MSG_PEEK. Go's syscall package for Windows does
	// not define the MSG_* constants, so they are spelled out here; 0x2 is
	// the stable Winsock value.
	msgPeek = 0x2

	// Winsock error codes. Go's syscall for Windows likewise does not define
	// the WSAE* constants, and these values are fixed by the Winsock
	// specification. They arrive from WSARecv as syscall.Errno, which is why
	// classifyRecv's errors.Is comparison works.
	wsaeintr       syscall.Errno = 10004
	wsaewouldblock syscall.Errno = 10035
	wsaenotsock    syscall.Errno = 10038
	wsaeopnotsupp  syscall.Errno = 10045
)

var windowsLivenessSentinels = livenessSentinels{
	wouldBlock:   []error{wsaewouldblock},
	interrupted:  []error{wsaeintr},
	notSupported: []error{wsaenotsock, wsaeopnotsupp},
}

// currentLivenessSentinels exposes the running platform's sentinel set so the
// untagged classification tests can assert against the real constants.
func currentLivenessSentinels() livenessSentinels {
	return windowsLivenessSentinels
}

// tcpConnReusable reports whether a pooled connection is safe to hand out for
// another DNS-over-TCP exchange. Semantics are identical to the unix probe.
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
		buf := syscall.WSABuf{Len: 1, Buf: &b[0]}
		var recvd uint32
		flags := uint32(msgPeek)
		// overlapped and croutine are nil: the handle is in non-blocking
		// mode inside this callback, so this is the synchronous form.
		recvErr := syscall.WSARecv(syscall.Handle(fd), &buf, 1, &recvd, &flags, nil, nil)
		verdict = classifyRecv(int(recvd), recvErr, windowsLivenessSentinels)
		return true
	}); err != nil {
		// The callback never ran. Inconclusive: keep the connection.
		return true
	}

	return verdictReusable(verdict)
}
