package server

import (
	"net"
)

// udpLocalAddr carries the local IP (and Linux ifindex) a UDP query arrived
// on, so the reply can use the same source address on multi-homed hosts.
type udpLocalAddr struct {
	IP      net.IP
	IfIndex int
}

// udpPacketInfoConn optionally carries the local destination address of an
// inbound UDP datagram so replies can use the same source IP (secondary /
// alias addresses on a wildcard bind). Mocks need not implement this.
type udpPacketInfoConn interface {
	ReadFromUDPWithDst(buf []byte) (n int, addr *net.UDPAddr, local udpLocalAddr, err error)
	WriteToUDPWithSrc(buf []byte, addr *net.UDPAddr, local udpLocalAddr) (n int, err error)
}

// wrapUDPPacketInfo enables platform support for sticky UDP reply source
// addresses. Non-Linux platforms return the conn unchanged.
func wrapUDPPacketInfo(conn *net.UDPConn) UDPConn {
	return wrapUDPPacketInfoImpl(conn)
}
