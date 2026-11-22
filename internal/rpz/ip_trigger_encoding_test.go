package rpz

import (
	"net"
	"testing"
)

// draft-vixie-dnsop-dns-rpz-00 §4.1.1 encodes IPv6 triggers as the address's
// 16-bit words reversed, "zz" for "::" (F877), and §4.1 names the client IP
// trigger "rpz-client-ip" (F878). The pre-F877 nibble form and the
// "rpz-clientip" spelling are still read.
func TestRPZIPTriggerEncoding(t *testing.T) {
	e := NewEngine(Config{Enabled: true})
	for _, tc := range []struct {
		owner   string
		trigger TriggerType
		want    string
	}{
		{"128.3.zz.db8.2001.rpz-ip", TriggerResponseIP, "2001:db8::3/128"},
		{"48.zz.101.db8.2001.rpz-ip", TriggerResponseIP, "2001:db8:101::/48"},
		{"128.1.zz.rpz-nsip", TriggerNSIP, "::1/128"},
		{"128.8.7.6.5.4.3.2.1.rpz-ip", TriggerResponseIP, "1:2:3:4:5:6:7:8/128"},
		{"24.0.2.0.192.rpz-client-ip", TriggerClientIP, "192.0.2.0/24"},
		{"24.0.2.0.192.rpz-clientip", TriggerClientIP, "192.0.2.0/24"},
		{"48.8.b.d.0.1.0.0.2.rpz-ip", TriggerResponseIP, "2001:db8::/48"},
		{"32.10.2.0.192.rpz-ip", TriggerResponseIP, "192.0.2.10/32"},
	} {
		trig, pattern := e.parseOwnerName(tc.owner)
		_, cidr, err := net.ParseCIDR(pattern)
		if trig != tc.trigger || err != nil || cidr.String() != tc.want {
			t.Errorf("%s: trigger %v pattern %q (%v), want %v %s", tc.owner, trig, pattern, err, tc.trigger, tc.want)
		}
	}
}
