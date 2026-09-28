//go:build !unix && !windows

package upstream

// Fallback liveness probe for platforms that have neither the unix recv(2)
// path nor the Windows WSARecv path.
//
// The MSG_PEEK probe needs a non-blocking, non-consuming peek: recv(2) on
// unix, WSARecv on Windows. Platforms outside both sets (plan9, js/wasm,
// wasip1) expose no portable equivalent, so there is nothing real to probe
// with and this reports every connection as reusable — the behaviour that
// predates the fix.
//
// On these platforms a connection closed by the upstream while idle is still
// handed back out, and the failed query still marks the upstream unhealthy.
// See tcppool_liveness_unix.go for the full rationale and impact.

import "net"

func tcpConnReusable(conn net.Conn) bool {
	return conn != nil
}

// currentLivenessSentinels exposes the running platform's sentinel set. There
// is no probe on these platforms, so the set is empty and the untagged
// classification tests' non-empty assertions are expected to fail here — they
// guard the real probe platforms, not this fallback.
func currentLivenessSentinels() livenessSentinels {
	return livenessSentinels{}
}
