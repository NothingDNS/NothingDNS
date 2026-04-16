package zone

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIncludeBasic(t *testing.T) {
	// Create a temp directory with an included file
	dir := t.TempDir()

	includedContent := `
www  3600 IN A 192.168.1.1
mail 3600 IN A 192.168.1.2
`
	if err := os.WriteFile(filepath.Join(dir, "included.zone"), []byte(includedContent), 0644); err != nil {
		t.Fatal(err)
	}

	mainContent := `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. hostmaster.example.com. 2024010101 3600 900 604800 86400
@ IN NS ns1.example.com.
$INCLUDE included.zone
api 3600 IN A 10.0.0.1
`

	z, err := ParseFile(filepath.Join(dir, "test.zone"), strings.NewReader(mainContent))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	// Records from the included file should be present
	wwwRecs := z.Lookup("www.example.com.", "A")
	if len(wwwRecs) != 1 {
		t.Fatalf("expected 1 www A record, got %d", len(wwwRecs))
	}
	if wwwRecs[0].RData != "192.168.1.1" {
		t.Errorf("www A = %q, want %q", wwwRecs[0].RData, "192.168.1.1")
	}

	mailRecs := z.Lookup("mail.example.com.", "A")
	if len(mailRecs) != 1 {
		t.Fatalf("expected 1 mail A record, got %d", len(mailRecs))
	}
	if mailRecs[0].RData != "192.168.1.2" {
		t.Errorf("mail A = %q, want %q", mailRecs[0].RData, "192.168.1.2")
	}

	// Record after the $INCLUDE should also be present
	apiRecs := z.Lookup("api.example.com.", "A")
	if len(apiRecs) != 1 {
		t.Fatalf("expected 1 api A record, got %d", len(apiRecs))
	}
	if apiRecs[0].RData != "10.0.0.1" {
		t.Errorf("api A = %q, want %q", apiRecs[0].RData, "10.0.0.1")
	}
}

func TestIncludeWithOriginOverride(t *testing.T) {
	dir := t.TempDir()

	// The included file uses names relative to the overridden origin
	includedContent := `
www 3600 IN A 10.0.0.1
`
	if err := os.WriteFile(filepath.Join(dir, "sub.zone"), []byte(includedContent), 0644); err != nil {
		t.Fatal(err)
	}

	mainContent := `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. hostmaster.example.com. 2024010101 3600 900 604800 86400
@ IN NS ns1.example.com.
$INCLUDE sub.zone sub.example.com.
api 3600 IN A 10.0.0.2
`

	z, err := ParseFile(filepath.Join(dir, "test.zone"), strings.NewReader(mainContent))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	// The included record "www" should be relative to "sub.example.com."
	subRecs := z.Lookup("www.sub.example.com.", "A")
	if len(subRecs) != 1 {
		t.Fatalf("expected 1 www.sub.example.com. A record, got %d", len(subRecs))
	}
	if subRecs[0].RData != "10.0.0.1" {
		t.Errorf("www.sub A = %q, want %q", subRecs[0].RData, "10.0.0.1")
	}

	// After the include, origin should revert to example.com.
	// so "api" should be api.example.com., NOT api.sub.example.com.
	apiRecs := z.Lookup("api.example.com.", "A")
	if len(apiRecs) != 1 {
		t.Fatalf("expected 1 api.example.com. A record, got %d", len(apiRecs))
	}
	if apiRecs[0].RData != "10.0.0.2" {
		t.Errorf("api A = %q, want %q", apiRecs[0].RData, "10.0.0.2")
	}

	// Verify the record is NOT under the overridden origin
	wrongRecs := z.Lookup("api.sub.example.com.", "A")
	if len(wrongRecs) != 0 {
		t.Errorf("expected no api.sub.example.com. records, got %d", len(wrongRecs))
	}
}

func TestIncludeDepthLimitExceeded(t *testing.T) {
	dir := t.TempDir()

	// Create a file that includes itself, causing infinite recursion
	selfContent := "$INCLUDE self.zone\n"
	if err := os.WriteFile(filepath.Join(dir, "self.zone"), []byte(selfContent), 0644); err != nil {
		t.Fatal(err)
	}

	mainContent := `$ORIGIN example.com.
$TTL 3600
$INCLUDE self.zone
`

	_, err := ParseFile(filepath.Join(dir, "test.zone"), strings.NewReader(mainContent))
	if err == nil {
		t.Fatal("expected error for recursive $INCLUDE, got nil")
	}

	if !strings.Contains(err.Error(), "depth limit exceeded") {
		t.Errorf("expected 'depth limit exceeded' in error, got: %v", err)
	}
}

func TestIncludeNonexistentFile(t *testing.T) {
	mainContent := `$ORIGIN example.com.
$TTL 3600
$INCLUDE /nonexistent/path/nofile.zone
`

	_, err := ParseFile("test.zone", strings.NewReader(mainContent))
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}

	// The error should mention the file path
	if !strings.Contains(err.Error(), "nofile.zone") {
		t.Errorf("expected error to mention filename, got: %v", err)
	}
}

func TestIncludeNested(t *testing.T) {
	dir := t.TempDir()

	// Create a chain: main -> level1.zone -> level2.zone
	level2Content := `
deep 3600 IN A 172.16.0.1
`
	if err := os.WriteFile(filepath.Join(dir, "level2.zone"), []byte(level2Content), 0644); err != nil {
		t.Fatal(err)
	}

	level1Content := `
mid 3600 IN A 172.16.0.2
$INCLUDE level2.zone
`
	if err := os.WriteFile(filepath.Join(dir, "level1.zone"), []byte(level1Content), 0644); err != nil {
		t.Fatal(err)
	}

	mainContent := `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. hostmaster.example.com. 2024010101 3600 900 604800 86400
@ IN NS ns1.example.com.
top 3600 IN A 172.16.0.3
$INCLUDE level1.zone
`

	z, err := ParseFile(filepath.Join(dir, "test.zone"), strings.NewReader(mainContent))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	// Verify all three levels of records are present
	tests := []struct {
		name  string
		rdata string
	}{
		{"top.example.com.", "172.16.0.3"},
		{"mid.example.com.", "172.16.0.2"},
		{"deep.example.com.", "172.16.0.1"},
	}

	for _, tt := range tests {
		recs := z.Lookup(tt.name, "A")
		if len(recs) != 1 {
			t.Errorf("%s: expected 1 A record, got %d", tt.name, len(recs))
			continue
		}
		if recs[0].RData != tt.rdata {
			t.Errorf("%s: A = %q, want %q", tt.name, recs[0].RData, tt.rdata)
		}
	}
}

func TestIncludeRelativePath(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "includes")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	includedContent := `
cdn 3600 IN A 203.0.113.1
`
	includedPath := filepath.Join(subdir, "cdn.zone")
	if err := os.WriteFile(includedPath, []byte(includedContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Main zone file is in dir; include uses a relative path from dir
	mainContent := `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. hostmaster.example.com. 2024010101 3600 900 604800 86400
@ IN NS ns1.example.com.
$INCLUDE includes/cdn.zone
`
	mainPath := filepath.Join(dir, "example.zone")

	z, err := ParseFile(mainPath, strings.NewReader(mainContent))
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	recs := z.Lookup("cdn.example.com.", "A")
	if len(recs) != 1 {
		t.Fatalf("expected 1 cdn A record, got %d", len(recs))
	}
	if recs[0].RData != "203.0.113.1" {
		t.Errorf("cdn A = %q, want %q", recs[0].RData, "203.0.113.1")
	}
}

func TestIncludeMissingFilename(t *testing.T) {
	mainContent := `$ORIGIN example.com.
$TTL 3600
$INCLUDE
`

	_, err := ParseFile("test.zone", strings.NewReader(mainContent))
	if err == nil {
		t.Fatal("expected error for $INCLUDE without filename, got nil")
	}

	if !strings.Contains(err.Error(), "$INCLUDE requires a filename") {
		t.Errorf("expected '$INCLUDE requires a filename' in error, got: %v", err)
	}
}

// TestIncludeAbsolutePathRejected locks in the VULN-006 fix: $INCLUDE must
// never accept an absolute path, because an absolute path bypassed the
// zone-directory filepath.Rel confinement check in the pre-fix code.
func TestIncludeAbsolutePathRejected(t *testing.T) {
	var target string
	if filepath.Separator == '\\' {
		target = `C:\Windows\System32\drivers\etc\hosts`
	} else {
		target = "/etc/shadow"
	}

	mainContent := `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. hostmaster.example.com. 2024010101 3600 900 604800 86400
@ IN NS ns1.example.com.
$INCLUDE ` + target + `
`

	_, err := ParseFile("test.zone", strings.NewReader(mainContent))
	if err == nil {
		t.Fatal("expected $INCLUDE absolute path to be rejected, got nil error")
	}
	if !strings.Contains(err.Error(), "absolute path not allowed") {
		t.Errorf("expected 'absolute path not allowed' in error, got: %v", err)
	}
}
