package server

import (
	"net"
	"testing"
)

type zonedStrAddr string

func (a zonedStrAddr) Network() string { return "custom" }
func (a zonedStrAddr) String() string  { return string(a) }

// F428: a client address whose string form carries an IPv6 zone
// ("[fe80::1%eth0]:443", or a *net.IPAddr with Zone) must yield the IP, not
// nil — a nil IP made every client-IP-keyed pipeline stage see "no client".
func TestClientInfoIP_ZonedStringFallback(t *testing.T) {
	tests := []struct {
		addr net.Addr
		want string
	}{
		{zonedStrAddr("[fe80::1%eth0]:443"), "fe80::1"},
		{zonedStrAddr("fe80::1%eth0"), "fe80::1"},
		{&net.IPAddr{IP: net.ParseIP("fe80::3"), Zone: "en0"}, "fe80::3"},
		{zonedStrAddr("192.0.2.1:53"), "192.0.2.1"},
		{zonedStrAddr("bogus"), "<nil>"},
		{zonedStrAddr("%eth0"), "<nil>"},
	}
	for _, tt := range tests {
		if got := (&ClientInfo{Addr: tt.addr}).IP(); got.String() != tt.want {
			t.Errorf("IP() for %q = %v, want %s", tt.addr.String(), got, tt.want)
		}
	}
}
