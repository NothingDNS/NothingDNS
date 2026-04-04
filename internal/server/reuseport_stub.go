//go:build !linux && !darwin && !freebsd

package server

import (
	"fmt"
	"net"
)

// listenUDPWithReusePortImpl creates a *net.UDPConn without SO_REUSEPORT
// on platforms that do not support it.
func listenUDPWithReusePortImpl(network, addr string) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return nil, fmt.Errorf("resolve udp addr: %w", err)
	}
	return net.ListenUDP(network, udpAddr)
}

// listenTCPWithReusePortImpl creates a TCP listener without SO_REUSEPORT
// on platforms that do not support it.
func listenTCPWithReusePortImpl(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}
