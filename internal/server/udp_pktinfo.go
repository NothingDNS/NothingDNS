package server

import (
	"net"
)

// udpPacketInfoConn optionally carries the local destination address of an
// inbound UDP datagram so replies can use the same source IP (secondary /
// alias addresses on a wildcard bind). Mocks need not implement this.
type udpPacketInfoConn interface {
	ReadFromUDPWithDst(buf []byte) (n int, addr *net.UDPAddr, dst net.IP, err error)
	WriteToUDPWithSrc(buf []byte, addr *net.UDPAddr, src net.IP) (n int, err error)
}

// wrapUDPPacketInfo enables platform support for sticky UDP reply source
// addresses. Non-Linux platforms return the conn unchanged.
func wrapUDPPacketInfo(conn *net.UDPConn) UDPConn {
	return wrapUDPPacketInfoImpl(conn)
}
