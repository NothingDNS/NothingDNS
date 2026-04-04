package server

import "net"

// listenUDPWithReusePort creates a *net.UDPConn, preferring SO_REUSEPORT
// on platforms that support it.
func listenUDPWithReusePort(network, addr string) (*net.UDPConn, error) {
	return listenUDPWithReusePortImpl(network, addr)
}

// listenTCPWithReusePort creates a net.Listener, preferring SO_REUSEPORT
// on platforms that support it.
func listenTCPWithReusePort(addr string) (net.Listener, error) {
	return listenTCPWithReusePortImpl(addr)
}
