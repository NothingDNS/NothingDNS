//go:build !linux

package server

import "net"

func wrapUDPPacketInfoImpl(conn *net.UDPConn) UDPConn {
	return conn
}
