package main

import (
	"net"
	"testing"
)

// The @server argument of `dnsctl dig` must default to port 53 whether it is
// an IPv4 address, a hostname, or an IPv6 literal. Detecting the port with a
// naive colon check made every bare IPv6 literal look like it already had a
// port, so `dig @2001:db8::1` handed an unbracketed literal to net.Dial and
// failed with "too many colons in address" — IPv6 resolvers were unreachable
// unless the operator spelled out an explicit port.
func TestDigServerAddrDefaultsToPort53(t *testing.T) {
	tests := []struct {
		name   string
		server string
		want   string
	}{
		// Regression: a bare IPv6 literal must be bracketed and defaulted.
		{"bare-ipv6", "2001:db8::1", "[2001:db8::1]:53"},
		{"bare-ipv6-loopback", "::1", "[::1]:53"},
		{"bare-ipv6-expanded", "fe80:0:0:0:0:0:0:1", "[fe80:0:0:0:0:0:0:1]:53"},

		// IPv4 and hostnames keep defaulting to 53.
		{"ipv4", "127.0.0.1", "127.0.0.1:53"},
		{"ipv4-public", "192.0.2.1", "192.0.2.1:53"},
		{"hostname", "dns.example.com", "dns.example.com:53"},

		// An explicit port is always preserved verbatim.
		{"ipv4-with-port", "127.0.0.1:5353", "127.0.0.1:5353"},
		{"hostname-with-port", "dns.example.com:5353", "dns.example.com:5353"},
		{"ipv6-with-port", "[2001:db8::1]:5353", "[2001:db8::1]:5353"},
		{"bracketed-ipv6-no-port", "[2001:db8::1]", "[2001:db8::1]:53"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := digServerAddr(tc.server); got != tc.want {
				t.Errorf("digServerAddr(%q) = %q, want %q", tc.server, got, tc.want)
			}
		})
	}
}

// Whatever the input, the result must be a host:port net.Dial can parse.
// This is the property that actually broke: the address string itself was
// rejected by the dialer before a single packet was sent.
func TestDigServerAddrAlwaysProducesDialableAddress(t *testing.T) {
	for _, server := range []string{
		"2001:db8::1", "::1", "[::1]", "[2001:db8::1]", "2001:db8::1:5353",
		"127.0.0.1", "127.0.0.1:5353", "dns.example.com", "dns.example.com:5353",
	} {
		addr := digServerAddr(server)
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			t.Errorf("digServerAddr(%q) = %q, which net.SplitHostPort rejects: %v", server, addr, err)
			continue
		}
		if host == "" {
			t.Errorf("digServerAddr(%q) = %q has an empty host", server, addr)
		}
		if port == "" {
			t.Errorf("digServerAddr(%q) = %q has an empty port", server, addr)
		}
	}
}
