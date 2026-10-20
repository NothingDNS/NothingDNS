package protocol

import "testing"

// RFC 1035 §3.4.1 / RFC 3596 §2.4: an A record's text is a dotted quad and an
// AAAA record's text is IPv6. net.ParseIP accepts both families for either, so
// `AAAA 192.0.2.1` was served as ::ffff:192.0.2.1 and `A ::ffff:192.0.2.1` as
// 192.0.2.1 instead of being rejected as the typo it is.
func TestParseRDataTextRejectsWrongAddressFamily(t *testing.T) {
	for _, tc := range []struct {
		rtype, text string
		valid       bool
	}{
		{"A", "192.0.2.1", true},
		{"AAAA", "2001:db8::1", true},
		{"AAAA", "::ffff:192.0.2.1", true}, // an explicit IPv4-mapped address is IPv6 text
		{"AAAA", "192.0.2.1", false},
		{"A", "2001:db8::1", false},
		{"A", "::ffff:192.0.2.1", false},
	} {
		got := ParseRDataText(tc.rtype, tc.text)
		if tc.valid && got == nil {
			t.Errorf("%s %q rejected", tc.rtype, tc.text)
		}
		if !tc.valid && got != nil {
			t.Errorf("FAIL: %s %q accepted as %s", tc.rtype, tc.text, got.String())
		}
	}
}
