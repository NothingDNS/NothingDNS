package util

import "net"

// IPLimitKey maps a client address to the key per-source limits are counted
// under: IPv4 addresses (and IPv4-mapped IPv6) as is, IPv6 addresses as their
// /64. One IPv6 line holds 2^64 addresses, so a per-address count never
// limits it (F709).
func IPLimitKey(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	if v6 := ip.To16(); v6 != nil {
		return v6.Mask(net.CIDRMask(64, 128)).String() + "/64"
	}
	return ip.String()
}
