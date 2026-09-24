//go:build linux

package server

import (
	"net"
	"testing"
)

func TestPackParseUDPPktinfoIPv4(t *testing.T) {
	src := net.ParseIP("37.247.108.2").To4()
	oob := packUDPPktinfo(udpLocalAddr{IP: src, IfIndex: 2})
	if len(oob) == 0 {
		t.Fatal("packUDPPktinfo returned empty oob")
	}
	got := parseUDPPktinfo(oob)
	if !got.IP.Equal(src) {
		t.Fatalf("parseUDPPktinfo IP = %v, want %v", got.IP, src)
	}
	if got.IfIndex != 2 {
		t.Fatalf("parseUDPPktinfo IfIndex = %d, want 2", got.IfIndex)
	}
}
