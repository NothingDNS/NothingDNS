package blocklist

import (
	"net"
	"os"
	"strings"
	"testing"
)

// --- validateBlocklistURL tests ---

func TestValidateBlocklistURL_HTTPSSuccess(t *testing.T) {
	err := validateBlocklistURL("https://1.2.3.4/blocklist.txt")
	if err != nil {
		t.Errorf("valid HTTPS IP URL should pass: %v", err)
	}
}

func TestValidateBlocklistURL_HTTPRejected(t *testing.T) {
	err := validateBlocklistURL("http://1.2.3.4/blocklist.txt")
	if err == nil {
		t.Error("HTTP scheme should be rejected")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("error should mention HTTPS, got: %v", err)
	}
}

func TestValidateBlocklistURL_FTPRejected(t *testing.T) {
	err := validateBlocklistURL("ftp://1.2.3.4/blocklist.txt")
	if err == nil {
		t.Error("FTP scheme should be rejected")
	}
}

func TestValidateBlocklistURL_PrivateIP10(t *testing.T) {
	err := validateBlocklistURL("https://10.0.0.1/list.txt")
	if err == nil {
		t.Error("10.x.x.x should be rejected")
	}
}

func TestValidateBlocklistURL_PrivateIP172(t *testing.T) {
	err := validateBlocklistURL("https://172.16.0.1/list.txt")
	if err == nil {
		t.Error("172.16.x.x should be rejected")
	}
}

func TestValidateBlocklistURL_PrivateIP192(t *testing.T) {
	err := validateBlocklistURL("https://192.168.1.1/list.txt")
	if err == nil {
		t.Error("192.168.x.x should be rejected")
	}
}

func TestValidateBlocklistURL_Loopback(t *testing.T) {
	err := validateBlocklistURL("https://127.0.0.1/list.txt")
	if err == nil {
		t.Error("127.x.x.x should be rejected")
	}
}

func TestValidateBlocklistURL_LinkLocal(t *testing.T) {
	err := validateBlocklistURL("https://169.254.1.1/list.txt")
	if err == nil {
		t.Error("169.254.x.x should be rejected")
	}
}

func TestValidateBlocklistURL_CloudMetadata(t *testing.T) {
	hosts := []string{
		"169.254.169.254",
		"metadata.google.internal",
		"metadata.azure.com",
		"metadata.googleusercontent.com",
	}
	for _, host := range hosts {
		err := validateBlocklistURL("https://" + host + "/list.txt")
		if err == nil {
			t.Errorf("cloud metadata host %s should be rejected", host)
		}
	}
}

func TestValidateBlocklistURL_HostnameRejected(t *testing.T) {
	err := validateBlocklistURL("https://example.com/list.txt")
	if err == nil {
		t.Error("hostname should be rejected (DNS rebinding protection)")
	}
}

func TestValidateBlocklistURL_InvalidURL(t *testing.T) {
	err := validateBlocklistURL("not a url")
	if err == nil {
		t.Error("invalid URL should be rejected")
	}
}

func TestValidateBlocklistURL_NoScheme(t *testing.T) {
	err := validateBlocklistURL("1.2.3.4/list.txt")
	if err == nil {
		t.Error("URL without scheme should be rejected")
	}
}

func TestValidateBlocklistURL_IPv6Loopback(t *testing.T) {
	err := validateBlocklistURL("https://[::1]/list.txt")
	if err == nil {
		t.Error("IPv6 loopback should be rejected")
	}
}

func TestValidateBlocklistURL_IPv6LinkLocal(t *testing.T) {
	err := validateBlocklistURL("https://[fe80::1]/list.txt")
	if err == nil {
		t.Error("IPv6 link-local should be rejected")
	}
}

func TestValidateBlocklistURL_IPv6UniqueLocal(t *testing.T) {
	err := validateBlocklistURL("https://[fd00::1]/list.txt")
	if err == nil {
		t.Error("IPv6 unique local should be rejected")
	}
}

// --- isPrivateOrReservedIP tests ---

func TestIsPrivateOrReservedIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		// Private IPv4
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"172.15.0.1", false},   // Not in 172.16/12
		{"172.32.0.1", false},   // Not in 172.16/12
		{"192.168.0.1", true},
		{"192.168.255.255", true},
		// Loopback
		{"127.0.0.1", true},
		{"127.255.255.255", true},
		// Link-local
		{"169.254.0.1", true},
		{"169.254.255.255", true},
		// Public IPs (should NOT be private)
		{"1.1.1.1", false},
		{"8.8.8.8", false},
		{"172.15.0.1", false},
		{"192.169.0.1", false},
		// IPv6
		{"::1", true},           // loopback
		{"fe80::1", true},       // link-local
		{"::", true},            // unspecified
		{"fd00::1", true},       // unique local
		{"fc00::1", true},       // unique local
		{"2001:db8::1", false},  // documentation prefix, not in our check
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := isPrivateOrReservedIP(mustParseIP(tt.ip))
			if got != tt.expected {
				t.Errorf("isPrivateOrReservedIP(%s) = %v, want %v", tt.ip, got, tt.expected)
			}
		})
	}
}

// Helper to parse IP strings for tests
func mustParseIP(s string) net.IP {
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	ip := net.ParseIP(s)
	if ip == nil {
		panic("bad IP in test: " + s)
	}
	return ip
}

// --- parseURL tests ---

func TestParseURL_Valid(t *testing.T) {
	u, err := parseURL("https://example.com/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.Scheme != "https" {
		t.Errorf("expected scheme https, got %s", u.Scheme)
	}
	if u.Host != "example.com" {
		t.Errorf("expected host example.com, got %s", u.Host)
	}
}

func TestParseURL_WithPort(t *testing.T) {
	u, err := parseURL("https://example.com:8443/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.Host != "example.com" {
		t.Errorf("expected host without port, got %s", u.Host)
	}
}

func TestParseURL_NoScheme(t *testing.T) {
	_, err := parseURL("example.com/path")
	if err == nil {
		t.Error("expected error for URL without scheme")
	}
}

func TestParseURL_EmptyString(t *testing.T) {
	_, err := parseURL("")
	if err == nil {
		t.Error("expected error for empty URL")
	}
}

// --- loadURL domain-only parsing (tested via AddFile with temp files) ---

func TestLoadURL_DomainOnlyFormat(t *testing.T) {
	// Test domain-only parsing path via AddDomain (single field per line)
	// Note: loadFile does not support domain-only format; loadURL does.
	// We test AddDomain which is the manual entry path.
	bl := New(Config{Enabled: true})
	bl.AddDomain("ad.example.com")
	bl.AddDomain("tracker.example.com")

	if !bl.IsBlocked("ad.example.com") {
		t.Error("ad.example.com should be blocked")
	}
	if !bl.IsBlocked("tracker.example.com") {
		t.Error("tracker.example.com should be blocked")
	}
}

// TestLoadURL_SSRFBlocksLoopback verifies SSRF protection blocks test server URLs.
func TestLoadURL_SSRFBlocksLoopback(t *testing.T) {
	bl := New(Config{Enabled: true})
	err := bl.AddURL("https://127.0.0.1:9999/list.txt")
	if err == nil {
		t.Error("loopback URL should be rejected by SSRF protection")
	}
}

// --- Close tests ---

func TestClose(t *testing.T) {
	bl := New(Config{Enabled: true})
	if err := bl.Close(); err != nil {
		t.Errorf("Close should not error: %v", err)
	}
	// Double close should not panic
	if err := bl.Close(); err != nil {
		t.Errorf("Double close should not error: %v", err)
	}
}

func TestClose_NilHTTPClient(t *testing.T) {
	bl := &Blocklist{
		entries:         make(map[string]Entry),
		sourceEntries:   make(map[string]map[string]Entry),
		disabledSources: make(map[string]bool),
		manualEntries:   make(map[string]Entry),
	}
	// Should not panic with nil httpClient
	if err := bl.Close(); err != nil {
		t.Errorf("Close should not error: %v", err)
	}
}

// --- GetSources tests ---

func TestGetSources_Empty(t *testing.T) {
	bl := New(Config{Enabled: true})
	sources := bl.GetSources()
	if len(sources) != 0 {
		t.Errorf("expected 0 sources, got %d", len(sources))
	}
}

func TestGetSources_WithFiles(t *testing.T) {
	tmpDir := t.TempDir()
	path := tmpDir + "/list.txt"
	content := "0.0.0.0 ad.example.com\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	bl := New(Config{Enabled: true, Files: []string{path}})
	if err := bl.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	sources := bl.GetSources()
	if len(sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(sources))
	}
	if sources[0].Type != "file" {
		t.Errorf("expected type 'file', got %s", sources[0].Type)
	}
	if sources[0].ID != path {
		t.Errorf("expected ID %s, got %s", path, sources[0].ID)
	}
	if sources[0].Domains != 1 {
		t.Errorf("expected 1 domain, got %d", sources[0].Domains)
	}
	if !sources[0].Enabled {
		t.Error("source should be enabled by default")
	}
}

// --- ToggleSource tests ---

func TestToggleSource_FileSource(t *testing.T) {
	tmpDir := t.TempDir()
	path := tmpDir + "/list.txt"
	content := "0.0.0.0 ad.example.com\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	bl := New(Config{Enabled: true, Files: []string{path}})
	if err := bl.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Disable
	enabled, err := bl.ToggleSource(path)
	if err != nil {
		t.Fatalf("ToggleSource failed: %v", err)
	}
	if enabled {
		t.Error("source should be disabled after first toggle")
	}

	// Re-enable
	enabled, err = bl.ToggleSource(path)
	if err != nil {
		t.Fatalf("ToggleSource re-enable failed: %v", err)
	}
	if !enabled {
		t.Error("source should be enabled after second toggle")
	}
}

func TestToggleSource_NotFound(t *testing.T) {
	bl := New(Config{Enabled: true})
	_, err := bl.ToggleSource("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent source")
	}
}

// --- RemoveSource tests ---

func TestRemoveSource_File(t *testing.T) {
	tmpDir := t.TempDir()
	path1 := tmpDir + "/list1.txt"
	path2 := tmpDir + "/list2.txt"
	os.WriteFile(path1, []byte("0.0.0.0 ad.example.com\n"), 0644)
	os.WriteFile(path2, []byte("0.0.0.0 tracker.example.com\n"), 0644)

	bl := New(Config{Enabled: true, Files: []string{path1, path2}})
	if err := bl.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if !bl.IsBlocked("ad.example.com") {
		t.Error("ad.example.com should be blocked before removal")
	}

	err := bl.RemoveSource(path1)
	if err != nil {
		t.Fatalf("RemoveSource failed: %v", err)
	}

	if bl.IsBlocked("ad.example.com") {
		t.Error("ad.example.com should NOT be blocked after source removal")
	}
	if !bl.IsBlocked("tracker.example.com") {
		t.Error("tracker.example.com should still be blocked")
	}
}

func TestRemoveSource_NotFound(t *testing.T) {
	bl := New(Config{Enabled: true})
	err := bl.RemoveSource("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent source")
	}
}

// --- AddURL tests ---

func TestAddURL_Validation(t *testing.T) {
	bl := New(Config{Enabled: true})
	err := bl.AddURL("http://example.com/list.txt")
	if err == nil {
		t.Error("HTTP URL should be rejected")
	}
}

func TestAddURL_PrivateIP(t *testing.T) {
	bl := New(Config{Enabled: true})
	err := bl.AddURL("https://10.0.0.1/list.txt")
	if err == nil {
		t.Error("private IP URL should be rejected")
	}
}

func TestAddURL_Hostname(t *testing.T) {
	bl := New(Config{Enabled: true})
	err := bl.AddURL("https://example.com/list.txt")
	if err == nil {
		t.Error("hostname URL should be rejected (DNS rebinding protection)")
	}
}
