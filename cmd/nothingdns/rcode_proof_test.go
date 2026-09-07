package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// TestRcodeToString_YXDOMAIN verifies that rcodeToString (helpers.go) correctly
// maps DNS RCODE 6 (YXDOMAIN, RFC 2136) to "YXDOMAIN".
//
// The protocol package defines protocol.RcodeYXDomain = 6 with string "YXDOMAIN".
// The helpers.go version must match — YXDOMAIN is returned by primary nameservers
// during DDNS (RFC 2136) when a name exists but a condition requires it to not
// exist (e.g. prerequisite check fails).
func TestRcodeToString_YXDOMAIN(t *testing.T) {
	want := "YXDOMAIN"
	got := rcodeToString(protocol.RcodeYXDomain)
	if got != want {
		t.Errorf("rcodeToString(%d) = %q; want %q", protocol.RcodeYXDomain, got, want)
	}
}

// TestRcodeToString_AllDefined checks every defined RCODE so that future
// additions are caught at the test level rather than silently returning
// "RCODE<n>" in observability traces and audit logs.
func TestRcodeToString_AllDefined(t *testing.T) {
	cases := []struct {
		rcode uint8
		want  string
	}{
		{0, "NOERROR"},
		{1, "FORMERR"},
		{2, "SERVFAIL"},
		{3, "NXDOMAIN"},
		{4, "NOTIMP"},
		{5, "REFUSED"},
		{6, "YXDOMAIN"}, // RFC 2136 — returned by primary nameservers during DDNS
	}
	for _, c := range cases {
		got := rcodeToString(c.rcode)
		if got != c.want {
			t.Errorf("rcodeToString(%d) = %q; want %q", c.rcode, got, c.want)
		}
	}
}
