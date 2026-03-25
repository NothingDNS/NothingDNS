package util

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// IsIPv4 returns true if the IP address is an IPv4 address.
func IsIPv4(ip net.IP) bool {
	return ip.To4() != nil
}

// IsIPv6 returns true if the IP address is an IPv6 address.
func IsIPv6(ip net.IP) bool {
	return ip.To4() == nil && ip.To16() != nil
}

// ParseIP parses a string as an IP address.
// Returns nil if the string is not a valid IP address.
func ParseIP(s string) net.IP {
	return net.ParseIP(s)
}

// IPToBytes converts an IP address to a byte slice.
// For IPv4, returns 4 bytes. For IPv6, returns 16 bytes.
func IPToBytes(ip net.IP) []byte {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}

// IPToUint32 converts an IPv4 address to a uint32.
// Returns 0 if the IP is not IPv4.
func IPToUint32(ip net.IP) uint32 {
	if v4 := ip.To4(); v4 != nil {
		return binary.BigEndian.Uint32(v4)
	}
	return 0
}

// Uint32ToIP converts a uint32 to an IPv4 address.
func Uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

// IPToString returns the string representation of an IP address.
// Returns empty string if ip is nil.
func IPToString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// IPRange represents a range of IP addresses.
type IPRange struct {
	Start net.IP
	End   net.IP
}

// Contains returns true if the IP is within the range.
func (r *IPRange) Contains(ip net.IP) bool {
	if IsIPv4(r.Start) != IsIPv4(ip) {
		return false
	}
	return bytesCompare(ip, r.Start) >= 0 && bytesCompare(ip, r.End) <= 0
}

// bytesCompare compares two byte slices.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func bytesCompare(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}

// CIDR represents an IP network (CIDR notation).
type CIDR struct {
	IP   net.IP
	Mask net.IPMask
}

// ParseCIDR parses a CIDR string (e.g., "192.168.1.0/24").
func ParseCIDR(s string) (*CIDR, error) {
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	return &CIDR{
		IP:   ip,
		Mask: ipnet.Mask,
	}, nil
}

// Contains returns true if the IP is within the CIDR.
func (c *CIDR) Contains(ip net.IP) bool {
	return ip.Mask(c.Mask).Equal(c.IP.Mask(c.Mask))
}

// String returns the CIDR in string format.
func (c *CIDR) String() string {
	ones, _ := c.Mask.Size()
	return fmt.Sprintf("%s/%d", c.IP.String(), ones)
}

// CIDRList is a list of CIDRs for matching.
type CIDRList []*CIDR

// ParseCIDRList parses a list of CIDR strings.
func ParseCIDRList(cidrs []string) (CIDRList, error) {
	list := make(CIDRList, 0, len(cidrs))
	for _, cidr := range cidrs {
		c, err := ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		list = append(list, c)
	}
	return list, nil
}

// Contains returns true if any CIDR in the list contains the IP.
func (l CIDRList) Contains(ip net.IP) bool {
	for _, c := range l {
		if c.Contains(ip) {
			return true
		}
	}
	return false
}

// IsPrivateIP returns true if the IP is in a private RFC 1918 range.
func IsPrivateIP(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		// RFC 1918 private ranges
		// 10.0.0.0/8
		if v4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if v4[0] == 192 && v4[1] == 168 {
			return true
		}
		// 127.0.0.0/8 (loopback)
		if v4[0] == 127 {
			return true
		}
		// 169.254.0.0/16 (link-local)
		if v4[0] == 169 && v4[1] == 254 {
			return true
		}
	}
	// IPv6 private ranges
	if IsIPv6(ip) {
		// fc00::/7 (unique local)
		if ip[0]&0xfe == 0xfc {
			return true
		}
		// fe80::/10 (link-local)
		if ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
			return true
		}
		// ::1 (loopback)
		if ip.Equal(net.ParseIP("::1")) {
			return true
		}
	}
	return false
}

// IsLoopback returns true if the IP is a loopback address.
func IsLoopback(ip net.IP) bool {
	return ip.IsLoopback()
}

// IsMulticast returns true if the IP is a multicast address.
func IsMulticast(ip net.IP) bool {
	return ip.IsMulticast()
}

// NormalizeIP returns a normalized form of the IP address.
// IPv4-mapped IPv6 addresses are converted to IPv4.
func NormalizeIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	// Try to convert to IPv4
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}

// IPFamily represents the IP address family.
type IPFamily int

const (
	IPv4 IPFamily = iota
	IPv6
)

// Family returns the IP family (IPv4 or IPv6).
func (f IPFamily) String() string {
	switch f {
	case IPv4:
		return "IPv4"
	case IPv6:
		return "IPv6"
	default:
		return "Unknown"
	}
}

// GetIPFamily returns the IP family of the given IP address.
func GetIPFamily(ip net.IP) IPFamily {
	if IsIPv4(ip) {
		return IPv4
	}
	return IPv6
}

// ReverseDNS returns the reverse DNS lookup name for an IP address.
// For IPv4: octets reversed with .in-addr.arpa suffix
// For IPv6: nibbles reversed with .ip6.arpa suffix
func ReverseDNS(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa",
			v4[3], v4[2], v4[1], v4[0])
	}
	v6 := ip.To16()
	if v6 == nil {
		return ""
	}
	// IPv6: each byte becomes 2 hex nibbles
	var parts []string
	for i := len(v6) - 1; i >= 0; i-- {
		parts = append(parts, fmt.Sprintf("%x", v6[i]&0x0f))
		parts = append(parts, fmt.Sprintf("%x", v6[i]>>4))
	}
	return strings.Join(parts, ".") + ".ip6.arpa"
}

// MaskIP masks an IP address with the given prefix length.
func MaskIP(ip net.IP, prefixLen int) net.IP {
	// Determine the bit length based on IP version
	bits := 128
	if IsIPv4(ip) {
		bits = 32
	}
	mask := net.CIDRMask(prefixLen, bits)
	masked := ip.Mask(mask)
	return NormalizeIP(masked)
}
