//go:build linux

package server

import (
	"net"
	"testing"
)

func TestPackParseUDPPktinfoIPv4(t *testing.T) {
	src := net.ParseIP("37.247.108.2").To4()
	oob := packUDPPktinfo(src)
	if len(oob) == 0 {
		t.Fatal("packUDPPktinfo returned empty oob")
	}
	got := parseUDPPktinfo(oob)
	if !got.Equal(src) {
		t.Fatalf("parseUDPPktinfo = %v, want %v", got, src)
	}
}
