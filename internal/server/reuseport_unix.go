//go:build linux || darwin || freebsd

package server

import (
	"context"
	"fmt"
	"net"
	"syscall"
)

// listenUDPWithReusePortImpl creates a *net.UDPConn with SO_REUSEPORT set.
// Falls back to a standard listener if reuseport is unavailable.
func listenUDPWithReusePortImpl(network, addr string) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return nil, fmt.Errorf("resolve udp addr: %w", err)
	}

	lc := net.ListenConfig{
		Control: reusePortControl(),
	}

	conn, err := lc.ListenPacket(context.Background(), network, addr)
	if err != nil {
		// Fallback: try without reuseport
		fbConn, fbErr := net.ListenUDP(network, udpAddr)
		if fbErr != nil {
			return nil, fbErr
		}
		return fbConn, nil
	}

	// ListenPacket returns a *net.UDPConn for udp networks
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		// Should not happen, but handle gracefully
		conn.Close()
		return net.ListenUDP(network, udpAddr)
	}
	return udpConn, nil
}

// reusePortControl returns a net.ListenConfig.Control function that sets SO_REUSEPORT.
func reusePortControl() func(string, string, syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var opErr error
		err := c.Control(func(fd uintptr) {
			opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
		})
		if err != nil {
			return err
		}
		return opErr
	}
}

// listenTCPWithReusePortImpl creates a TCP listener with SO_REUSEPORT set.
// Falls back to a standard listener if reuseport is unavailable.
func listenTCPWithReusePortImpl(addr string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: reusePortControl(),
	}

	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		// Fallback: try without reuseport
		fbLn, fbErr := net.Listen("tcp", addr)
		if fbErr != nil {
			return nil, fbErr
		}
		return fbLn, nil
	}
	return ln, nil
}
