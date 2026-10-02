// Round-033 proof: RPZ IPv6 triggers must load and match.
//
// Contract basis: loadFile documents the rpz-ip trigger generally ("Response
// IP: 32.1.0.168.192.rpz-ip. -> matches 192.168.0.1/32") and TriggerResponseIP
// is documented as "matches IP addresses in the response" — IP addresses, not
// IPv4-only. DNS-RPZ encodes IPv6 triggers as reversed nibble labels, e.g.
//
//	32.4.3.3.7.0.7.3.0.8.e.f.f.3.0.6.8.d.0.a.0.2.0.0.0.8.b.d.0.1.0.0.2.rpz-ip.
//	= 2001:0db8:0002:0a0d:8603:ffe8:0370:7334/32
//
// Pre-fix: reverseRPZToCIDR only reversed/padded IPv4 octets, so nibble
// encodings produced a 32-label dotted string that net.ParseCIDR rejected in
// addRule; the rule was silently dropped (no warning, no parseErrors tick)
// and response-/client-IP policy was a silent no-op for IPv6.
//
// The fix decodes 5+ single-hex-digit labels as IPv6 nibbles (dotted-quad can
// never exceed 4 labels, so every IPv4 form that already parsed keeps its
// exact legacy interpretation — pinned below byte-for-byte).
package rpz

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func writeRound033Zone(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "probe.rpz")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("writing probe zone: %v", err)
	}
	return path
}

// PROOF (was red before the fix): a standard full-length IPv6 nibble rpz-ip
// trigger loads into the engine and matches an address inside its /32.
func TestRound033RPZIPv6ResponseIPTriggerLoadsAndMatches(t *testing.T) {
	path := writeRound033Zone(t,
		"32.4.3.3.7.0.7.3.0.8.e.f.f.3.0.6.8.d.0.a.0.2.0.0.0.8.b.d.0.1.0.0.2.rpz-ip. 60 IN CNAME .\n")

	e := NewEngine(Config{Enabled: true, Files: []string{path}})
	if err := e.Load(); err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if got := e.Stats().RespIPRules; got != 1 {
		t.Fatalf("IPv6 rpz-ip trigger silently dropped: RespIPRules=%d, want 1 (parseErrors=%d)",
			got, e.Stats().ParseErrors)
	}
	rule := e.ResponseIPPolicy([]net.IP{net.ParseIP("2001:db8:2::1")})
	if rule == nil {
		t.Fatalf("ResponseIPPolicy(2001:db8:2::1) returned nil; IPv6 response-IP policy never fires")
	}
	if rule.Action != ActionNXDOMAIN {
		t.Fatalf("matched rule action = %v, want NXDOMAIN", rule.Action)
	}
}

// Truncated nibble form (trailing zero nibbles omitted): 48.8.b.d.0.1.0.0.2 =
// 2001:0db8::/48. Matches inside the /48, not outside it.
func TestRound033RPZIPv6TruncatedNibbleTrigger(t *testing.T) {
	path := writeRound033Zone(t, "48.8.b.d.0.1.0.0.2.rpz-ip. 60 IN CNAME .\n")

	e := NewEngine(Config{Enabled: true, Files: []string{path}})
	if err := e.Load(); err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if got := e.Stats().RespIPRules; got != 1 {
		t.Fatalf("truncated IPv6 rpz-ip trigger dropped: RespIPRules=%d, want 1", got)
	}
	if rule := e.ResponseIPPolicy([]net.IP{net.ParseIP("2001:db8::1")}); rule == nil {
		t.Fatalf("ResponseIPPolicy(2001:db8::1) returned nil, want match inside /48")
	}
	if rule := e.ResponseIPPolicy([]net.IP{net.ParseIP("2001:db8:1::1")}); rule != nil {
		t.Fatalf("ResponseIPPolicy(2001:db8:1::1) matched, want no match outside /48")
	}
}

// rpz-clientip uses the same encoding: 128 + 32 nibbles = ::1/128.
func TestRound033RPZIPv6ClientIPTrigger(t *testing.T) {
	path := writeRound033Zone(t,
		"128.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.rpz-clientip. 60 IN CNAME .\n")

	e := NewEngine(Config{Enabled: true, Files: []string{path}})
	if err := e.Load(); err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if got := e.Stats().ClientIPRules; got != 1 {
		t.Fatalf("IPv6 rpz-clientip trigger dropped: ClientIPRules=%d, want 1", got)
	}
	if rule := e.ClientIPPolicy(net.ParseIP("::1")); rule == nil {
		t.Fatalf("ClientIPPolicy(::1) returned nil, want match for ::1/128")
	}
	if rule := e.ClientIPPolicy(net.ParseIP("127.0.0.1")); rule != nil {
		t.Fatalf("ClientIPPolicy(127.0.0.1) matched, want no match outside ::1/128")
	}
}

// Legacy encodings must stay byte-identical: every IPv4 form that parsed
// before the fix decodes to exactly the same CIDR string, and the historical
// "ip6.arpa"-suffixed input keeps its pinned legacy (dotted) output.
func TestRound033RPZLegacyEncodingsUnchanged(t *testing.T) {
	cases := []struct{ in, want string }{
		{"32.1.0.168.192", "192.168.0.1/32"},
		{"24.0.168.192", "192.168.0.0/24"},
		{"8.0.0.10", "10.0.0.0/8"},
		{"32.1.2.3.10", "10.3.2.1/32"},
		// Pinned by rpz_test.go TestParseOwnerName ("actual output depends on
		// implementation"): the ip6.arpa form is not valid DNS-RPZ and keeps
		// the legacy dotted interpretation.
		{"128.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0.ip6.arpa",
			"arpa.ip6.0.0.0.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1/128"},
	}
	for _, tc := range cases {
		if got := reverseRPZToCIDR(tc.in); got != tc.want {
			t.Errorf("reverseRPZToCIDR(%q) = %q, want legacy %q", tc.in, got, tc.want)
		}
	}
}
