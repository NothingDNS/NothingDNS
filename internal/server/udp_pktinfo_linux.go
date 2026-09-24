//go:build linux

package server

import (
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// pktinfoUDPConn wraps *net.UDPConn with IP_PKTINFO / IPV6_RECVPKTINFO so
// replies to a wildcard bind use the same local IP the query arrived on
// (secondary /32 aliases, additional host addresses).
type pktinfoUDPConn struct {
	*net.UDPConn
}

func wrapUDPPacketInfoImpl(conn *net.UDPConn) UDPConn {
	if conn == nil {
		return conn
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return conn
	}
	_ = raw.Control(func(fd uintptr) {
		// Best-effort: IPv4-only or IPv6-only sockets reject the other family.
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
	})
	return &pktinfoUDPConn{UDPConn: conn}
}

func (c *pktinfoUDPConn) ReadFromUDPWithDst(buf []byte) (int, *net.UDPAddr, udpLocalAddr, error) {
	oob := make([]byte, unix.CmsgSpace(unix.SizeofInet4Pktinfo)+unix.CmsgSpace(unix.SizeofInet6Pktinfo))
	n, oobn, _, addr, err := c.UDPConn.ReadMsgUDP(buf, oob)
	if err != nil {
		return n, addr, udpLocalAddr{}, err
	}
	return n, addr, parseUDPPktinfo(oob[:oobn]), nil
}

func (c *pktinfoUDPConn) WriteToUDPWithSrc(buf []byte, addr *net.UDPAddr, local udpLocalAddr) (int, error) {
	if len(local.IP) == 0 || addr == nil {
		return c.UDPConn.WriteToUDP(buf, addr)
	}
	oob := packUDPPktinfo(local)
	if len(oob) == 0 {
		return c.UDPConn.WriteToUDP(buf, addr)
	}
	n, _, err := c.UDPConn.WriteMsgUDP(buf, oob, addr)
	if err != nil {
		// Some kernels reject a mismatched ifindex; retry with IP only.
		if local.IfIndex != 0 {
			oob = packUDPPktinfo(udpLocalAddr{IP: local.IP})
			if len(oob) > 0 {
				if n2, _, err2 := c.UDPConn.WriteMsgUDP(buf, oob, addr); err2 == nil {
					return n2, nil
				}
			}
		}
		// Last resort: unsticky write (may fail for secondary IPs).
		return c.UDPConn.WriteToUDP(buf, addr)
	}
	return n, nil
}

func parseUDPPktinfo(oob []byte) udpLocalAddr {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return udpLocalAddr{}
	}
	for _, m := range msgs {
		switch {
		case m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_PKTINFO:
			if len(m.Data) < unix.SizeofInet4Pktinfo {
				continue
			}
			info := *(*unix.Inet4Pktinfo)(unsafe.Pointer(&m.Data[0]))
			// Spec_dst is the local address the datagram was delivered to.
			ip := net.IP(info.Spec_dst[:]).To4()
			if ip == nil || ip.IsUnspecified() {
				ip = net.IP(info.Addr[:]).To4()
			}
			if ip != nil && !ip.IsUnspecified() {
				return udpLocalAddr{IP: append(net.IP(nil), ip...), IfIndex: int(info.Ifindex)}
			}
		case m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_PKTINFO:
			if len(m.Data) < unix.SizeofInet6Pktinfo {
				continue
			}
			info := *(*unix.Inet6Pktinfo)(unsafe.Pointer(&m.Data[0]))
			ip := append(net.IP(nil), info.Addr[:]...)
			if !ip.IsUnspecified() {
				return udpLocalAddr{IP: ip, IfIndex: int(info.Ifindex)}
			}
		}
	}
	return udpLocalAddr{}
}

func packUDPPktinfo(local udpLocalAddr) []byte {
	if ip4 := local.IP.To4(); ip4 != nil {
		var info unix.Inet4Pktinfo
		info.Ifindex = int32(local.IfIndex)
		copy(info.Spec_dst[:], ip4)
		copy(info.Addr[:], ip4)
		return unix.PktInfo4(&info)
	}
	if ip16 := local.IP.To16(); ip16 != nil {
		var info unix.Inet6Pktinfo
		info.Ifindex = uint32(local.IfIndex)
		copy(info.Addr[:], ip16)
		return unix.PktInfo6(&info)
	}
	return nil
}
