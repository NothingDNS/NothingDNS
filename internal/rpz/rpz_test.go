package rpz

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestNewEngine(t *testing.T) {
	e := NewEngine(Config{Enabled: true})
	if !e.IsEnabled() {
		t.Error("engine should be enabled")
	}

	e2 := NewEngine(Config{Enabled: false})
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
	e := NewEngine(Config{Enabled: true})

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
	e := NewEngine(Config{Enabled: true})

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

	e := NewEngine(Config{
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

	e := NewEngine(Config{Enabled: true, Files: []string{rpzFile}})
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

	e := NewEngine(Config{Enabled: true, Files: []string{rpzFile}})
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

	e := NewEngine(Config{Enabled: true, Files: []string{rpzFile}})
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

	e := NewEngine(Config{Enabled: true, Files: []string{rpzFile}})
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
	e := NewEngine(Config{Enabled: false})

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

	e := NewEngine(Config{Enabled: true, Files: []string{rpzFile}})
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

	e := NewEngine(Config{Enabled: true, Files: []string{rpzFile}})
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

	e := NewEngine(Config{
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
	e := NewEngine(Config{Enabled: true, Files: []string{"/nonexistent/rpz-zone"}})
	if err := e.Load(); err == nil {
		t.Error("expected error loading nonexistent file")
	}
}
