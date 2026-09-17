package util

import "strings"

// RedactIP masks the last octet (IPv4) or group (IPv6) of an address so logs
// and non-admin views do not expose full client addresses. Anything that is
// not recognisably an address is masked entirely.
func RedactIP(ip string) string {
	if idx := strings.LastIndex(ip, "."); idx != -1 {
		return ip[:idx+1] + "xxx"
	}
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		return ip[:idx+1] + "xxxx"
	}
	return "xxx.xxx.xxx.xxx"
}
