package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ============================================================================
// validateRPZ — table-driven branch coverage
//
// validateRPZ gates every RPZ file/zone path at config-load time
// (--validate-config and startup). Branches: disabled early-return,
// per-entry empty-path and nonexistent-path errors for both the flat
// rpz.files list and the named rpz.zones list, and error accumulation
// across entries.
// ============================================================================

func TestValidateRPZ(t *testing.T) {
	// Existing file and directory inside a temp dir: the existing file is
	// the "valid" fixture; both path kinds are needed to pin the contract.
	dir := t.TempDir()
	existing := filepath.Join(dir, "policy.rpz")
	if err := os.WriteFile(existing, []byte("$TTL 60\n"), 0o600); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	asDir := filepath.Join(dir, "as-dir")
	if err := os.Mkdir(asDir, 0o750); err != nil {
		t.Fatalf("fixture dir: %v", err)
	}

	tests := []struct {
		name       string
		rpz        RPZConfig
		wantSubstr []string // every entry must appear in the joined errors
		wantErrs   int
	}{
		{
			name: "disabled skips validation entirely",
			rpz: RPZConfig{
				Enabled: false,
				Files:   []string{"/definitely/does/not/exist.rpz", ""},
				Zones:   []RPZPolicyZone{{Name: "z", File: "/nope.rpz"}},
			},
			wantErrs: 0,
		},
		{
			name: "enabled with no paths is clean",
			rpz:  RPZConfig{Enabled: true},
		},
		{
			name: "enabled with existing file is clean",
			rpz: RPZConfig{
				Enabled: true,
				Files:   []string{existing},
				Zones:   []RPZPolicyZone{{Name: "rpz.local", File: existing}},
			},
			wantErrs: 0,
		},
		{
			name: "empty file path rejected",
			rpz: RPZConfig{
				Enabled: true,
				Files:   []string{""},
			},
			wantSubstr: []string{"rpz: file path cannot be empty"},
			wantErrs:   1,
		},
		{
			name: "nonexistent file rejected with path in message",
			rpz: RPZConfig{
				Enabled: true,
				Files:   []string{filepath.Join(dir, "missing.rpz")},
			},
			wantSubstr: []string{"rpz: file '" + filepath.Join(dir, "missing.rpz") + "' does not exist"},
			wantErrs:   1,
		},
		{
			name: "empty zone file path rejected",
			rpz: RPZConfig{
				Enabled: true,
				Zones:   []RPZPolicyZone{{Name: "rpz.local", File: ""}},
			},
			wantSubstr: []string{"rpz: zone file path cannot be empty"},
			wantErrs:   1,
		},
		{
			name: "nonexistent zone file rejected with path in message",
			rpz: RPZConfig{
				Enabled: true,
				Zones:   []RPZPolicyZone{{Name: "rpz.local", File: filepath.Join(dir, "zone-missing.rpz")}},
			},
			wantSubstr: []string{"rpz: zone file '" + filepath.Join(dir, "zone-missing.rpz") + "' does not exist"},
			wantErrs:   1,
		},
		{
			name: "errors accumulate across all four kinds",
			rpz: RPZConfig{
				Enabled: true,
				Files:   []string{"", filepath.Join(dir, "m1.rpz")},
				Zones: []RPZPolicyZone{
					{Name: "a", File: ""},
					{Name: "b", File: filepath.Join(dir, "m2.rpz")},
				},
			},
			wantSubstr: []string{
				"rpz: file path cannot be empty",
				"rpz: file '" + filepath.Join(dir, "m1.rpz") + "' does not exist",
				"rpz: zone file path cannot be empty",
				"rpz: zone file '" + filepath.Join(dir, "m2.rpz") + "' does not exist",
			},
			wantErrs: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{RPZ: tt.rpz}
			errs := c.validateRPZ()

			if len(errs) != tt.wantErrs {
				t.Fatalf("validateRPZ returned %d errors, want %d: %v", len(errs), tt.wantErrs, errs)
			}
			joined := strings.Join(errs, "\n")
			for _, want := range tt.wantSubstr {
				if !strings.Contains(joined, want) {
					t.Errorf("errors missing %q:\n%s", want, joined)
				}
			}
		})
	}
}

// TestValidateRPZ_DirectoryPathPasses pins the CURRENT contract (recorded as
// an observation, not a desired behavior): validateRPZ only rejects paths
// whose os.Stat reports IsNotExist, so a directory path passes validation
// and fails later at load time. Contrast validateGeoDNS, which rejects
// directories explicitly. If this behavior is ever tightened, update this
// test to expect the rejection.
func TestValidateRPZ_DirectoryPathPasses(t *testing.T) {
	dir := t.TempDir()
	c := &Config{RPZ: RPZConfig{
		Enabled: true,
		Files:   []string{dir},
	}}
	if errs := c.validateRPZ(); len(errs) != 0 {
		t.Fatalf("directory path unexpectedly rejected: %v", errs)
	}
}
