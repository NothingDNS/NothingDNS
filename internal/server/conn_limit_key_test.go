package server

import (
	"net"
	"testing"
)

// F709: the per-source-IP connection cap keyed on the full address, so a
// client holding an IPv6 /64 opened 64 connections per address — in effect
// unlimited (only the global cap applied).
func TestPerIPConnectionKeyAggregatesIPv6Prefix(t *testing.T) {
	a := getIP(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2::1"), Port: 1})
	b := getIP(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2:dead:beef::9"), Port: 2})
	c := getIP(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:3::1"), Port: 3})
	if a != b {
		t.Errorf("one /64 got two keys: %q %q", a, b)
	}
	if a == c {
		t.Errorf("two /64s share a key: %q", a)
	}
	if x, y := getIP(&net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1}), getIP(&net.TCPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 1}); x == y || x != "192.0.2.1" {
		t.Errorf("IPv4 keys wrong: %q %q", x, y)
	}
	if getIP(nil) != "" {
		t.Error("nil addr")
	}
}
