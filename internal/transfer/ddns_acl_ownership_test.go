package transfer

import (
	"net"
	"testing"
)

func TestDynamicDNSHandlerCopiesACLNetworks(t *testing.T) {
	h := NewDynamicDNSHandler(nil)
	_, network, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	h.AddACL("example.com.", network)

	network.IP = net.IPv4zero
	network.Mask = net.CIDRMask(0, 32)
	if h.IsAllowed("example.com.", net.ParseIP("203.0.113.10")) {
		t.Fatal("caller mutation widened the stored DDNS ACL")
	}
}

func TestDynamicDNSHandlerAddACLNilIsIgnored(t *testing.T) {
	h := NewDynamicDNSHandler(nil)
	h.AddACL("example.com.", nil)
	if len(h.acl["example.com."]) != 0 {
		t.Fatal("nil network was stored")
	}
}
