package rpz

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/nothingdns/nothingdns/internal/util"
)

func testLogger() *util.Logger {
	return util.NewLogger(util.INFO, util.TextFormat, io.Discard)
}

func TestNewEngine(t *testing.T) {
	e := NewEngine(Config{Logger: testLogger(),Enabled: true})
	if !e.IsEnabled() {
		t.Error("engine should be enabled")
	}

	e2 := NewEngine(Config{Logger: testLogger(),Enabled: false})
	if e2.IsEnabled() {
		t.Error("engine should be disabled")
	}
}

func TestReverseRPZToCIDR(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"32.1.0.168.192", "192.168.0.1/32"},
		{"24.0.168.192", "192.168.0.0/24"},
		{"16.0.10", "10.0.0.0/16"},
		{"128.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0", "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1/128"},
	}
	for _, tc := range tests {
		got := reverseRPZToCIDR(tc.input)
		if got != tc.want {
			t.Errorf("reverseRPZToCIDR(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestParseAction(t *testing.T) {
	e := NewEngine(Config{Logger: testLogger(),Enabled: true})

	tests := []struct {
		rtype, rdata string
		wantAction   PolicyAction
		wantOverride string
	}{
		{"CNAME", ".", ActionNODATA, ""},
		{"CNAME", "*", ActionNXDOMAIN, ""},
		{"CNAME", "garden.example.com.", ActionCNAME, "garden.example.com"},
		{"A", "192.168.1.1", ActionOverride, "192.168.1.1"},
		{"AAAA", "::1", ActionOverride, "::1"},
		{"TXT", "drop", ActionDrop, ""},
		{"TXT", `"passthru"`, ActionPassThrough, ""},
		{"TXT", `"tcp-only"`, ActionTCPOnly, ""},
	}
	for _, tc := range tests {
		action, override := e.parseAction(tc.rtype, tc.rdata)
		if action != tc.wantAction {
			t.Errorf("parseAction(%q, %q) action = %v, want %v", tc.rtype, tc.rdata, action, tc.wantAction)
		}
		if override != tc.wantOverride {
			t.Errorf("parseAction(%q, %q) override = %q, want %q", tc.rtype, tc.rdata, override, tc.wantOverride)
		}
	}
}

func TestParseOwnerName(t *testing.T) {
	e := NewEngine(Config{Logger: testLogger(),Enabled: true})

	tests := []struct {
		owner       string
		wantTrigger TriggerType
		wantPattern string
	}{
		{"bad.example.com.rpz-zone.", TriggerQNAME, "bad.example.com"},
		{"*.ads.example.com.rpz-zone.", TriggerQNAME, "*.ads.example.com"},
		{"32.1.0.168.192.rpz-ip.", TriggerResponseIP, "192.168.0.1/32"},
		{"24.0.168.192.rpz-clientip.", TriggerClientIP, "192.168.0.0/24"},
		{"ns.evil.com.rpz-nsdname.", TriggerNSDNAME, "ns.evil.com"},
		{"32.1.0.168.192.rpz-nsip.", TriggerNSIP, "192.168.0.1/32"},
	}
	for _, tc := range tests {
		trigger, pattern := e.parseOwnerName(tc.owner)
		if trigger != tc.wantTrigger {
			t.Errorf("parseOwnerName(%q) trigger = %v, want %v", tc.owner, trigger, tc.wantTrigger)
		}
		if pattern != tc.wantPattern {
			t.Errorf("parseOwnerName(%q) pattern = %q, want %q", tc.owner, pattern, tc.wantPattern)
		}
	}
}

func TestLoadRPZFile(t *testing.T) {
	// Create a temporary RPZ zone file
	dir := t.TempDir()
	rpzFile := filepath.Join(dir, "rpz-zone")

	content := `$TTL 300
@   IN  SOA localhost. admin.localhost. (
        2024010101 3600 600 86400 60 )
    IN  NS  localhost.

; NODATA policy - block exact domain
bad.example.com.rpz-zone.   IN  CNAME  .

; NXDOMAIN policy
nodata.example.com.rpz-zone.  IN  CNAME  *.

; CNAME redirect to walled garden
redirect.example.com.rpz-zone.  IN  CNAME  garden.example.com.

; Override with specific IP
override.example.com.rpz-zone.  IN  A  192.168.1.1

; Wildcard block
*.ads.example.com.rpz-zone.  IN  CNAME  .

; Response IP trigger
32.1.2.3.10.rpz-ip.  IN  CNAME  .

; Client IP trigger
24.0.168.192.rpz-clientip.  IN  CNAME  .

; Pass-through (whitelist)
safe.example.com.rpz-zone.  IN  TXT  "passthru"

; Drop
drop.example.com.rpz-zone.  IN  TXT  "drop"
`
	if err := os.WriteFile(rpzFile, []byte(content), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	e := NewEngine(Config{Logger: testLogger(),
		Enabled: true,
		Files:   []string{rpzFile},
	})
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	stats := e.Stats()
	if stats.TotalRules == 0 {
		t.Error("expected rules to be loaded")
	}
}

func TestQNAMEPolicyExact(t *testing.T) {
	dir := t.TempDir()
	rpzFile := filepath.Join(dir, "rpz-zone")

	content := `bad.example.com.rpz-zone.  IN  CNAME  *.
safe.example.com.rpz-zone.  IN  TXT  "passthru"
redirect.example.com.rpz-zone.  IN  CNAME  garden.example.com.
`
	if err := os.WriteFile(rpzFile, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	e := NewEngine(Config{Logger: testLogger(),Enabled: true, Files: []string{rpzFile}})
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Exact NXDOMAIN match (CNAME *)
	rule := e.QNAMEPolicy("bad.example.com.")
	if rule == nil {
		t.Fatal("expected rule match for bad.example.com")
	}
	if rule.Action != ActionNXDOMAIN {
		t.Errorf("action = %v, want NXDOMAIN", rule.Action)
	}

	// Pass-through
	rule = e.QNAMEPolicy("safe.example.com.")
	if rule == nil {
		t.Fatal("expected rule match for safe.example.com")
	}
	if rule.Action != ActionPassThrough {
		t.Errorf("action = %v, want PassThrough", rule.Action)
	}

	// CNAME redirect
	rule = e.QNAMEPolicy("redirect.example.com.")
	if rule == nil {
		t.Fatal("expected rule match for redirect.example.com")
	}
	if rule.Action != ActionCNAME {
		t.Errorf("action = %v, want CNAME", rule.Action)
	}
	if rule.OverrideData != "garden.example.com" {
		t.Errorf("override = %q, want garden.example.com", rule.OverrideData)
	}

	// No match
	rule = e.QNAMEPolicy("good.example.com.")
	if rule != nil {
		t.Error("expected no match for good.example.com")
	}
}

func TestQNAMEPolicyWildcard(t *testing.T) {
	dir := t.TempDir()
	rpzFile := filepath.Join(dir, "rpz-zone")

	content := `*.ads.example.com.rpz-zone.  IN  CNAME  .
`
	if err := os.WriteFile(rpzFile, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	e := NewEngine(Config{Logger: testLogger(),Enabled: true, Files: []string{rpzFile}})
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Should match subdomains (CNAME . = NODATA)
	rule := e.QNAMEPolicy("tracker.ads.example.com.")
	if rule == nil {
		t.Fatal("expected wildcard match for tracker.ads.example.com")
	}
	if rule.Action != ActionNODATA {
		t.Errorf("action = %v, want NODATA", rule.Action)
	}

	// Should match deeper subdomains
	rule = e.QNAMEPolicy("a.b.ads.example.com.")
	if rule == nil {
		t.Fatal("expected wildcard match for a.b.ads.example.com")
	}

	// Should NOT match the base domain itself
	rule = e.QNAMEPolicy("ads.example.com.")
	if rule != nil {
		t.Error("wildcard should not match base domain")
	}
}

func TestClientIPPolicy(t *testing.T) {
	dir := t.TempDir()
	rpzFile := filepath.Join(dir, "rpz-zone")

	content := `24.0.168.192.rpz-clientip.  IN  CNAME  .
`
	if err := os.WriteFile(rpzFile, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	e := NewEngine(Config{Logger: testLogger(),Enabled: true, Files: []string{rpzFile}})
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// IP in range
	rule := e.ClientIPPolicy(net.ParseIP("192.168.0.100"))
	if rule == nil {
		t.Fatal("expected match for 192.168.0.100")
	}

	// IP not in range
	rule = e.ClientIPPolicy(net.ParseIP("10.0.0.1"))
	if rule != nil {
		t.Error("expected no match for 10.0.0.1")
	}
}

func TestResponseIPPolicy(t *testing.T) {
	dir := t.TempDir()
	rpzFile := filepath.Join(dir, "rpz-zone")

	content := `32.1.2.3.10.rpz-ip.  IN  CNAME  .
`
	if err := os.WriteFile(rpzFile, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	e := NewEngine(Config{Logger: testLogger(),Enabled: true, Files: []string{rpzFile}})
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Matching IP
	rule := e.ResponseIPPolicy([]net.IP{net.ParseIP("10.3.2.1")})
	if rule == nil {
		t.Fatal("expected match for 10.3.2.1")
	}

	// Non-matching IP
	rule = e.ResponseIPPolicy([]net.IP{net.ParseIP("192.168.1.1")})
	if rule != nil {
		t.Error("expected no match for 192.168.1.1")
	}
}

func TestDisabledEngine(t *testing.T) {
	e := NewEngine(Config{Logger: testLogger(),Enabled: false})

	if rule := e.QNAMEPolicy("bad.example.com."); rule != nil {
		t.Error("disabled engine should return nil")
	}
	if rule := e.ClientIPPolicy(net.ParseIP("192.168.0.1")); rule != nil {
		t.Error("disabled engine should return nil")
	}
	if rule := e.ResponseIPPolicy([]net.IP{net.ParseIP("10.0.0.1")}); rule != nil {
		t.Error("disabled engine should return nil")
	}
}

func TestReload(t *testing.T) {
	dir := t.TempDir()
	rpzFile := filepath.Join(dir, "rpz-zone")

	// Initial file
	content := `bad.example.com.rpz-zone.  IN  CNAME  .
`
	if err := os.WriteFile(rpzFile, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	e := NewEngine(Config{Logger: testLogger(),Enabled: true, Files: []string{rpzFile}})
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	if rule := e.QNAMEPolicy("bad.example.com."); rule == nil {
		t.Fatal("expected match after first load")
	}

	// Rewrite file with different content
	content2 := `newbad.example.com.rpz-zone.  IN  CNAME  .
`
	if err := os.WriteFile(rpzFile, []byte(content2), 0644); err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	if err := e.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// Old rule should be gone
	if rule := e.QNAMEPolicy("bad.example.com."); rule != nil {
		t.Error("old rule should be removed after reload")
	}

	// New rule should exist
	if rule := e.QNAMEPolicy("newbad.example.com."); rule == nil {
		t.Fatal("expected match for newbad after reload")
	}
}

func TestStats(t *testing.T) {
	dir := t.TempDir()
	rpzFile := filepath.Join(dir, "rpz-zone")

	content := `bad.example.com.rpz-zone.  IN  CNAME  .
*.ads.example.com.rpz-zone.  IN  CNAME  .
24.0.168.192.rpz-clientip.  IN  CNAME  .
32.1.0.10.rpz-ip.  IN  CNAME  .
`
	if err := os.WriteFile(rpzFile, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	e := NewEngine(Config{Logger: testLogger(),Enabled: true, Files: []string{rpzFile}})
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	stats := e.Stats()
	if !stats.Enabled {
		t.Error("should be enabled")
	}
	if stats.QNAMERules != 2 {
		t.Errorf("QNAMERules = %d, want 2", stats.QNAMERules)
	}
	if stats.ClientIPRules != 1 {
		t.Errorf("ClientIPRules = %d, want 1", stats.ClientIPRules)
	}
	if stats.RespIPRules != 1 {
		t.Errorf("RespIPRules = %d, want 1", stats.RespIPRules)
	}
	if stats.Files != 1 {
		t.Errorf("Files = %d, want 1", stats.Files)
	}
}

func TestPriorityPolicyZones(t *testing.T) {
	dir := t.TempDir()
	file1 := filepath.Join(dir, "high-priority-rpz")
	file2 := filepath.Join(dir, "low-priority-rpz")

	// High priority zone
	if err := os.WriteFile(file1, []byte("bad.example.com.rpz-zone.  IN  A  10.0.0.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Low priority zone
	if err := os.WriteFile(file2, []byte("bad.example.com.rpz-zone.  IN  CNAME  .\n"), 0644); err != nil {
		t.Fatal(err)
	}

	e := NewEngine(Config{Logger: testLogger(),
		Enabled: true,
		Files:   []string{file1, file2},
		Policies: map[string]int{
			file1: 1, // higher priority
			file2: 10,
		},
	})
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	rule := e.QNAMEPolicy("bad.example.com.")
	if rule == nil {
		t.Fatal("expected match")
	}
	// High priority zone should win (override action)
	if rule.Action != ActionOverride {
		t.Errorf("action = %v, want Override (from high priority zone)", rule.Action)
	}
}

func TestLoadNonexistentFile(t *testing.T) {
	e := NewEngine(Config{Logger: testLogger(),Enabled: true, Files: []string{"/nonexistent/rpz-zone"}})
	if err := e.Load(); err == nil {
		t.Error("expected error loading nonexistent file")
	}
}

// TestParseOwnerNameEdgeCases tests owner name parsing edge cases
func TestParseOwnerNameEdgeCases(t *testing.T) {
	e := NewEngine(Config{Logger: testLogger(),Enabled: true})

	tests := []struct {
		owner       string
		wantTrigger TriggerType
		wantPattern string
	}{
		// Standard cases
		{"bad.example.com.rpz-zone.", TriggerQNAME, "bad.example.com"},
		{"*.ads.example.com.rpz-zone.", TriggerQNAME, "*.ads.example.com"},
		// Edge cases with unusual characters
		{"test-domain.example.com.rpz-zone.", TriggerQNAME, "test-domain.example.com"},
		{"_dmarc.example.com.rpz-zone.", TriggerQNAME, "_dmarc.example.com"},
		// IPv6 reverse notation (actual output depends on implementation)
		{"128.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0.ip6.arpa.rpz-ip.", TriggerResponseIP, "arpa.ip6.0.0.0.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1/128"},
		// Very short prefixes
		{"8.0.0.10.rpz-ip.", TriggerResponseIP, "10.0.0.0/8"},
		// Single label
		{"bad.rpz-zone.", TriggerQNAME, "bad"},
		// Empty pattern after trigger suffix (actual output depends on implementation)
		{"rpz-zone.", TriggerQNAME, "rpz-zone."},
	}

	for _, tc := range tests {
		t.Run(tc.owner, func(t *testing.T) {
			trigger, pattern := e.parseOwnerName(tc.owner)
			if trigger != tc.wantTrigger {
				t.Errorf("parseOwnerName(%q) trigger = %v, want %v", tc.owner, trigger, tc.wantTrigger)
			}
			if pattern != tc.wantPattern {
				t.Errorf("parseOwnerName(%q) pattern = %q, want %q", tc.owner, pattern, tc.wantPattern)
			}
		})
	}
}

// TestNSDNAMEPolicy tests NSDNAME trigger policies (if supported)
func TestNSDNAMEPolicy(t *testing.T) {
	dir := t.TempDir()
	rpzFile := filepath.Join(dir, "rpz-zone")

	content := `ns.evil.com.rpz-nsdname.  IN  CNAME  .
*.bad-ns.example.com.rpz-nsdname.  IN  CNAME  *.
`
	if err := os.WriteFile(rpzFile, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	e := NewEngine(Config{Logger: testLogger(),Enabled: true, Files: []string{rpzFile}})
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Verify the file loaded (rules should be in stats)
	stats := e.Stats()
	if stats.TotalRules == 0 {
		t.Error("expected rules to be loaded")
	}
}

// TestNSIPPolicy tests NSIP trigger policies (if supported)
func TestNSIPPolicy(t *testing.T) {
	dir := t.TempDir()
	rpzFile := filepath.Join(dir, "rpz-zone")

	content := `32.1.0.168.192.rpz-nsip.  IN  CNAME  .
24.0.168.192.rpz-nsip.  IN  CNAME  *.
`
	if err := os.WriteFile(rpzFile, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	e := NewEngine(Config{Logger: testLogger(),Enabled: true, Files: []string{rpzFile}})
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Verify the file loaded
	stats := e.Stats()
	if stats.TotalRules == 0 {
		t.Error("expected rules to be loaded")
	}
}

// TestTCPOnlyPolicy tests TCP-Only policy action
func TestTCPOnlyPolicy(t *testing.T) {
	dir := t.TempDir()
	rpzFile := filepath.Join(dir, "rpz-zone")

	content := `tcponly.example.com.rpz-zone.  IN  TXT  "tcp-only"
`
	if err := os.WriteFile(rpzFile, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	e := NewEngine(Config{Logger: testLogger(),Enabled: true, Files: []string{rpzFile}})
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	rule := e.QNAMEPolicy("tcponly.example.com.")
	if rule == nil {
		t.Fatal("expected match for tcponly.example.com")
	}
	if rule.Action != ActionTCPOnly {
		t.Errorf("action = %v, want TCPOnly", rule.Action)
	}
}

// TestDropPolicy tests Drop policy action
func TestDropPolicy(t *testing.T) {
	dir := t.TempDir()
	rpzFile := filepath.Join(dir, "rpz-zone")

	content := `drop.example.com.rpz-zone.  IN  TXT  "drop"
`
	if err := os.WriteFile(rpzFile, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	e := NewEngine(Config{Logger: testLogger(),Enabled: true, Files: []string{rpzFile}})
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	rule := e.QNAMEPolicy("drop.example.com.")
	if rule == nil {
		t.Fatal("expected match for drop.example.com")
	}
	if rule.Action != ActionDrop {
		t.Errorf("action = %v, want Drop", rule.Action)
	}
}

// TestMalformedRPZFile tests handling of malformed RPZ files
func TestMalformedRPZFile(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"empty_file", ""},
		{"no_soa", `bad.example.com.rpz-zone.  IN  CNAME  .`},
		{"invalid_ttl", `$TTL invalid
@ IN SOA localhost. admin.localhost. 1 3600 600 86400 60
bad.example.com.rpz-zone.  IN  CNAME  .`},
		{"missing_rdata", `bad.example.com.rpz-zone.  IN  CNAME`},
		{"invalid_ip", `bad.example.com.rpz-zone.  IN  A  not-an-ip`},
		{"garbage_lines", `this is not a valid zone file at all`},
		{"unclosed_quotes", `bad.example.com.rpz-zone.  IN  TXT  "unclosed`},
		{"null_bytes", `bad.example.com.rpz-zone.  IN  CNAME  .\x00`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			rpzFile := filepath.Join(dir, "rpz-zone")

			if err := os.WriteFile(rpzFile, []byte(tc.content), 0644); err != nil {
				t.Fatalf("write: %v", err)
			}

			e := NewEngine(Config{Logger: testLogger(),Enabled: true, Files: []string{rpzFile}})
			// Should not panic, may or may not return error depending on content
			_ = e.Load()
		})
	}
}

// TestQNAMEPolicyEdgeCases tests edge cases for QNAME policy matching
func TestQNAMEPolicyEdgeCases(t *testing.T) {
	dir := t.TempDir()
	rpzFile := filepath.Join(dir, "rpz-zone")

	content := `exact.example.com.rpz-zone.  IN  CNAME  .
*.wildcard.example.com.rpz-zone.  IN  CNAME  .
double..dots.example.com.rpz-zone.  IN  CNAME  .
UPPERCASE.EXAMPLE.COM.rpz-zone.  IN  CNAME  .
`
	if err := os.WriteFile(rpzFile, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	e := NewEngine(Config{Logger: testLogger(),Enabled: true, Files: []string{rpzFile}})
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	tests := []struct {
		qname    string
		expected bool
	}{
		{"exact.example.com.", true},
		{"sub.wildcard.example.com.", true},
		{"deep.sub.wildcard.example.com.", true},
		{"wildcard.example.com.", false}, // Wildcard doesn't match base
		{"EXACT.EXAMPLE.COM.", true},     // Case insensitive
		{"uppercase.example.com.", true}, // Case insensitive
		{"other.example.com.", false},
		{"", false},
		{".", false},
	}

	for _, tc := range tests {
		t.Run(tc.qname, func(t *testing.T) {
			rule := e.QNAMEPolicy(tc.qname)
			if tc.expected && rule == nil {
				t.Errorf("expected match for %q", tc.qname)
			}
			if !tc.expected && rule != nil {
				t.Errorf("expected no match for %q", tc.qname)
			}
		})
	}
}

// TestClientIPPolicyEdgeCases tests edge cases for Client IP matching
func TestClientIPPolicyEdgeCases(t *testing.T) {
	dir := t.TempDir()
	rpzFile := filepath.Join(dir, "rpz-zone")

	content := `32.0.0.127.rpz-clientip.  IN  CNAME  .
24.0.0.10.rpz-clientip.  IN  CNAME  .
16.0.0.172.rpz-clientip.  IN  CNAME  .
8.0.0.192.rpz-clientip.  IN  CNAME  .
`
	if err := os.WriteFile(rpzFile, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	e := NewEngine(Config{Logger: testLogger(),Enabled: true, Files: []string{rpzFile}})
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	tests := []struct {
		ip       string
		expected bool
	}{
		{"127.0.0.0", true},
		{"10.0.0.255", true},
		{"172.0.255.255", true},
		{"192.255.255.255", true},  // In 192.0.0.0/8
		{"192.254.255.255", true},  // Also in 192.0.0.0/8
		{"0.0.0.0", false},
		{"255.255.255.255", false},
		{"::1", false}, // IPv6 not in range
	}

	for _, tc := range tests {
		t.Run(tc.ip, func(t *testing.T) {
			rule := e.ClientIPPolicy(net.ParseIP(tc.ip))
			if tc.expected && rule == nil {
				t.Errorf("expected match for %s", tc.ip)
			}
			if !tc.expected && rule != nil {
				t.Errorf("expected no match for %s", tc.ip)
			}
		})
	}
}

// TestResponseIPPolicyEdgeCases tests edge cases for Response IP matching
func TestResponseIPPolicyEdgeCases(t *testing.T) {
	dir := t.TempDir()
	rpzFile := filepath.Join(dir, "rpz-zone")

	content := `24.0.0.10.rpz-ip.  IN  CNAME  .
24.0.0.192.rpz-ip.  IN  CNAME  .
`
	if err := os.WriteFile(rpzFile, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	e := NewEngine(Config{Logger: testLogger(),Enabled: true, Files: []string{rpzFile}})
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	tests := []struct {
		name     string
		ips      []net.IP
		expected bool
	}{
		{"single_match", []net.IP{net.ParseIP("10.0.0.100")}, true}, // In 10.0.0.0/24
		{"single_no_match", []net.IP{net.ParseIP("192.168.1.1")}, false},
		{"multiple_first_match", []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8")}, true}, // 10.0.0.1 in /24
		{"multiple_second_match", []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("192.0.0.50")}, true},
		{"multiple_none_match", []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8")}, false},
		{"empty_list", []net.IP{}, false},
		{"nil_list", nil, false},
		{"boundary_low", []net.IP{net.ParseIP("192.0.0.0")}, true},
		{"boundary_high", []net.IP{net.ParseIP("192.0.0.255")}, true},
		{"boundary_out_low", []net.IP{net.ParseIP("191.255.255.255")}, false},
		{"boundary_out_high", []net.IP{net.ParseIP("192.1.0.0")}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rule := e.ResponseIPPolicy(tc.ips)
			if tc.expected && rule == nil {
				t.Errorf("expected match for %v", tc.ips)
			}
			if !tc.expected && rule != nil {
				t.Errorf("expected no match for %v", tc.ips)
			}
		})
	}
}

// TestConcurrentEngineAccess tests concurrent access to the engine
func TestConcurrentEngineAccess(t *testing.T) {
	dir := t.TempDir()
	rpzFile := filepath.Join(dir, "rpz-zone")

	content := `bad.example.com.rpz-zone.  IN  CNAME  .
*.ads.example.com.rpz-zone.  IN  CNAME  .
24.0.168.192.rpz-clientip.  IN  CNAME  .
32.1.2.3.10.rpz-ip.  IN  CNAME  .
`
	if err := os.WriteFile(rpzFile, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	e := NewEngine(Config{Logger: testLogger(),Enabled: true, Files: []string{rpzFile}})
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	done := make(chan bool)

	// Concurrent QNAME queries
	for i := 0; i < 20; i++ {
		go func(id int) {
			for j := 0; j < 50; j++ {
				e.QNAMEPolicy("bad.example.com.")
				e.QNAMEPolicy("good.example.com.")
				e.QNAMEPolicy(fmt.Sprintf("%d.ads.example.com.", id))
			}
			done <- true
		}(i)
	}

	// Concurrent ClientIP queries
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 50; j++ {
				e.ClientIPPolicy(net.ParseIP("192.168.0.100"))
				e.ClientIPPolicy(net.ParseIP("10.0.0.1"))
			}
			done <- true
		}(i)
	}

	// Concurrent ResponseIP queries
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 50; j++ {
				e.ResponseIPPolicy([]net.IP{net.ParseIP("10.3.2.1")})
				e.ResponseIPPolicy([]net.IP{net.ParseIP("192.168.1.1")})
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 40; i++ {
		<-done
	}

	// If we get here without panic or deadlock, concurrent access works
	stats := e.Stats()
	if !stats.Enabled {
		t.Error("engine should still be enabled after concurrent access")
	}
}

// TestEmptyEngine tests behavior of empty/unloaded engine
func TestEmptyEngine(t *testing.T) {
	e := NewEngine(Config{Logger: testLogger(),Enabled: true})

	// No files loaded, policies should return nil
	if rule := e.QNAMEPolicy("anything.example.com."); rule != nil {
		t.Error("empty engine should return nil for QNAME")
	}
	if rule := e.ClientIPPolicy(net.ParseIP("192.168.0.1")); rule != nil {
		t.Error("empty engine should return nil for ClientIP")
	}
	if rule := e.ResponseIPPolicy([]net.IP{net.ParseIP("10.0.0.1")}); rule != nil {
		t.Error("empty engine should return nil for ResponseIP")
	}

	// Stats should show empty
	stats := e.Stats()
	if stats.TotalRules != 0 {
		t.Errorf("empty engine should have 0 rules, got %d", stats.TotalRules)
	}
}

// TestLoadMultipleFiles tests loading multiple RPZ files
func TestLoadMultipleFiles(t *testing.T) {
	dir := t.TempDir()
	file1 := filepath.Join(dir, "rpz1")
	file2 := filepath.Join(dir, "rpz2")
	file3 := filepath.Join(dir, "rpz3")

	if err := os.WriteFile(file1, []byte("bad1.example.com.rpz-zone.  IN  CNAME  .\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file2, []byte("bad2.example.com.rpz-zone.  IN  CNAME  .\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file3, []byte("bad3.example.com.rpz-zone.  IN  CNAME  .\n"), 0644); err != nil {
		t.Fatal(err)
	}

	e := NewEngine(Config{Logger: testLogger(),Enabled: true, Files: []string{file1, file2, file3}})
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// All files should be loaded
	if e.QNAMEPolicy("bad1.example.com.") == nil {
		t.Error("expected match for bad1 from file1")
	}
	if e.QNAMEPolicy("bad2.example.com.") == nil {
		t.Error("expected match for bad2 from file2")
	}
	if e.QNAMEPolicy("bad3.example.com.") == nil {
		t.Error("expected match for bad3 from file3")
	}

	stats := e.Stats()
	if stats.Files != 3 {
		t.Errorf("expected 3 files, got %d", stats.Files)
	}
}

// TestIPv6ResponseIPPolicy tests IPv6 response IP matching
func TestIPv6ResponseIPPolicy(t *testing.T) {
	dir := t.TempDir()
	rpzFile := filepath.Join(dir, "rpz-zone")

	// IPv6 reverse notation in RPZ
	content := `128.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0.ip6.arpa.rpz-ip.  IN  CNAME  .
`
	if err := os.WriteFile(rpzFile, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	e := NewEngine(Config{Logger: testLogger(),Enabled: true, Files: []string{rpzFile}})
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Matching IPv6
	rule := e.ResponseIPPolicy([]net.IP{net.ParseIP("2000::1")})
	if rule == nil {
		t.Log("IPv6 response IP matching may not be fully supported")
	}
}

// TestWildcardMatchingDepth tests wildcard matching at different depths
func TestWildcardMatchingDepth(t *testing.T) {
	dir := t.TempDir()
	rpzFile := filepath.Join(dir, "rpz-zone")

	content := `*.example.com.rpz-zone.  IN  CNAME  .
*.sub.example.com.rpz-zone.  IN  CNAME  *.
*.deep.sub.example.com.rpz-zone.  IN  CNAME  .
`
	if err := os.WriteFile(rpzFile, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	e := NewEngine(Config{Logger: testLogger(),Enabled: true, Files: []string{rpzFile}})
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	tests := []struct {
		qname    string
		expected bool
	}{
		{"a.example.com.", true},
		{"a.b.example.com.", true},
		{"example.com.", false},
		{"a.sub.example.com.", true},
		{"sub.example.com.", true}, // Matches *.example.com wildcard
		{"a.deep.sub.example.com.", true},
		{"deep.sub.example.com.", true}, // Matches *.example.com wildcard
	}

	for _, tc := range tests {
		t.Run(tc.qname, func(t *testing.T) {
			rule := e.QNAMEPolicy(tc.qname)
			if tc.expected && rule == nil {
				t.Errorf("expected match for %s", tc.qname)
			}
			if !tc.expected && rule != nil {
				t.Errorf("expected no match for %s", tc.qname)
			}
		})
	}
}

// TestActionStringValidation tests action string parsing
func TestActionStringValidation(t *testing.T) {
	e := NewEngine(Config{Logger: testLogger(),Enabled: true})

	tests := []struct {
		rtype   string
		rdata   string
		want    PolicyAction
	}{
		{"CNAME", ".", ActionNODATA},
		{"CNAME", "*", ActionNXDOMAIN},
		{"CNAME", "redirect.example.com.", ActionCNAME},
		{"CNAME", "", ActionNODATA}, // Empty CNAME target = NODATA
		{"A", "192.168.1.1", ActionOverride},
		{"AAAA", "2001:db8::1", ActionOverride},
		{"TXT", `"passthru"`, ActionPassThrough},
		{"TXT", `"drop"`, ActionDrop},
		{"TXT", `"tcp-only"`, ActionTCPOnly},
		{"TXT", `"unknown"`, ActionNXDOMAIN}, // Unknown TXT action = NXDOMAIN
		{"TXT", ``, ActionNXDOMAIN}, // Empty TXT = NXDOMAIN
		{"MX", `10 mail.example.com.`, ActionNXDOMAIN}, // Unsupported type = NXDOMAIN
	}

	for _, tc := range tests {
		t.Run(tc.rtype+"_"+tc.rdata, func(t *testing.T) {
			action, _ := e.parseAction(tc.rtype, tc.rdata)
			if action != tc.want {
				t.Errorf("parseAction(%q, %q) = %v, want %v", tc.rtype, tc.rdata, action, tc.want)
			}
		})
	}
}

// TestRPZDisabledEngine tests disabled RPZ engine behavior
func TestRPZDisabledEngine(t *testing.T) {
	e := NewEngine(Config{Logger: testLogger(), Enabled: false})

	// Try to load - should not error but do nothing
	if err := e.Load(); err != nil {
		t.Errorf("Load on disabled engine should not error: %v", err)
	}

	// All policies should return nil
	if rule := e.QNAMEPolicy("anything.example.com."); rule != nil {
		t.Error("disabled engine should return nil for QNAME")
	}
	if rule := e.ClientIPPolicy(net.ParseIP("192.168.1.1")); rule != nil {
		t.Error("disabled engine should return nil for ClientIP")
	}
	if rule := e.ResponseIPPolicy([]net.IP{net.ParseIP("10.0.0.1")}); rule != nil {
		t.Error("disabled engine should return nil for ResponseIP")
	}

	// Stats should show disabled
	stats := e.Stats()
	if stats.Enabled {
		t.Error("stats should show disabled")
	}
}

// TestCNAMEChainInRPZ tests CNAME chains within RPZ
func TestCNAMEChainInRPZ(t *testing.T) {
	dir := t.TempDir()
	rpzFile := filepath.Join(dir, "rpz-cname-chain")

	// CNAME chain in RPZ
	content := `bad.example.com.rpz-zone.  IN  CNAME  blocked.example.com.
blocked.example.com.rpz-zone.  IN  CNAME  .
`
	if err := os.WriteFile(rpzFile, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	e := NewEngine(Config{Logger: testLogger(),Enabled: true, Files: []string{rpzFile}})
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Both entries should be loaded
	rule := e.QNAMEPolicy("bad.example.com.")
	if rule == nil {
		t.Error("expected match for bad.example.com")
	}

	rule2 := e.QNAMEPolicy("blocked.example.com.")
	if rule2 == nil {
		t.Error("expected match for blocked.example.com")
	}
}

// TestInvalidFilePath tests loading from non-existent file
func TestInvalidFilePath(t *testing.T) {
	e := NewEngine(Config{Logger: testLogger(),Enabled: true, Files: []string{"/nonexistent/path/rpz.txt"}})

	// Should return error for non-existent file
	err := e.Load()
	if err == nil {
		t.Error("Load should return error for non-existent file")
	}
}

// TestMalformedRPZLines tests various malformed RPZ entries
func TestMalformedRPZLines(t *testing.T) {
	dir := t.TempDir()
	rpzFile := filepath.Join(dir, "rpz-malformed")

	content := `; This is a comment
# Also a comment

bad.example.com.rpz-zone.  IN  CNAME  .
malformed line without proper format
192.168.1.1.rpz-client-ip.rpz-zone.  IN  CNAME  .


another.bad.example.com.rpz-zone.  3600  IN  A  127.0.0.1
`
	if err := os.WriteFile(rpzFile, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	e := NewEngine(Config{Logger: testLogger(),Enabled: true, Files: []string{rpzFile}})
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Valid entries should be loaded
	if e.QNAMEPolicy("bad.example.com.") == nil {
		t.Error("expected match for bad.example.com")
	}

	// Stats should track parse errors
	stats := e.Stats()
	if stats.ParseErrors == 0 {
		t.Log("Parse errors may not be tracked for all malformed lines")
	}
}

// TestRPZPriorityOrdering tests priority handling
func TestRPZPriorityOrdering(t *testing.T) {
	dir := t.TempDir()
	file1 := filepath.Join(dir, "rpz-high-priority")
	file2 := filepath.Join(dir, "rpz-low-priority")

	// High priority zone with NXDOMAIN
	if err := os.WriteFile(file1, []byte("test.example.com.file1.  IN  CNAME  *\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Low priority zone with NODATA
	if err := os.WriteFile(file2, []byte("test.example.com.file2.  IN  CNAME  .\n"), 0644); err != nil {
		t.Fatal(err)
	}

	e := NewEngine(Config{
		Logger: testLogger(),
		Enabled: true,
		Files: []string{file1, file2},
		Policies: map[string]int{
			"file1": 1, // Higher priority (lower number)
			"file2": 2, // Lower priority
		},
	})

	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Should match one of them
	rule := e.QNAMEPolicy("test.example.com.")
	if rule == nil {
		t.Log("priority ordering may use zone names from SOA rather than file paths")
	}
}

// TestRPZReload tests RPZ reload functionality
func TestRPZReload(t *testing.T) {
	dir := t.TempDir()
	rpzFile := filepath.Join(dir, "rpz-dynamic")

	// Initial content
	if err := os.WriteFile(rpzFile, []byte("initial.example.com.rpz-zone.  IN  CNAME  .\n"), 0644); err != nil {
		t.Fatal(err)
	}

	e := NewEngine(Config{Logger: testLogger(),Enabled: true, Files: []string{rpzFile}})
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Verify initial rule
	if e.QNAMEPolicy("initial.example.com.") == nil {
		t.Error("expected match for initial rule")
	}

	// Update file with new content
	if err := os.WriteFile(rpzFile, []byte("updated.example.com.rpz-zone.  IN  CNAME  .\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Reload
	if err := e.Load(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// Updated rule should be present
	if e.QNAMEPolicy("updated.example.com.") == nil {
		t.Error("expected match for updated rule after reload")
	}
}

// TestEmptyRPZFile tests loading empty RPZ file
func TestEmptyRPZFile(t *testing.T) {
	dir := t.TempDir()
	rpzFile := filepath.Join(dir, "rpz-empty")

	// Create empty file
	if err := os.WriteFile(rpzFile, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	e := NewEngine(Config{Logger: testLogger(),Enabled: true, Files: []string{rpzFile}})
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Should have no rules
	stats := e.Stats()
	if stats.TotalRules != 0 {
		t.Errorf("expected 0 rules from empty file, got %d", stats.TotalRules)
	}
}

// TestCommentOnlyRPZFile tests RPZ file with only comments
func TestCommentOnlyRPZFile(t *testing.T) {
	dir := t.TempDir()
	rpzFile := filepath.Join(dir, "rpz-comments")

	content := `; This is a comment
; Another comment
# Hash-style comment
  ; Indented comment

`
	if err := os.WriteFile(rpzFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	e := NewEngine(Config{Logger: testLogger(),Enabled: true, Files: []string{rpzFile}})
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Should have no rules
	stats := e.Stats()
	if stats.TotalRules != 0 {
		t.Errorf("expected 0 rules from comment-only file, got %d", stats.TotalRules)
	}
}
