package util

import "testing"

// TestNormalizeVersion pins the canonical version format: bare semver
// without a leading "v"/"V". Exactly one prefix character is stripped —
// "vv1.1.4" becomes "v1.1.4", not "1.1.4" — because over-stripping would
// corrupt versions that legitimately begin with "v".
func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "bare semver unchanged", in: "1.1.4", want: "1.1.4"},
		{name: "lowercase v prefix stripped", in: "v1.1.4", want: "1.1.4"},
		{name: "uppercase V prefix stripped", in: "V1.1.4", want: "1.1.4"},
		{name: "only one v stripped", in: "vv1.1.4", want: "v1.1.4"},
		{name: "empty string", in: "", want: ""},
		{name: "lone v", in: "v", want: ""},
		{name: "non-version string unchanged", in: "dev", want: "dev"},
		{name: "v not at start unchanged", in: "1.1.4-v2", want: "1.1.4-v2"},
		{name: "prerelease tag", in: "v1.2.0-rc1", want: "1.2.0-rc1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeVersion(tt.in); got != tt.want {
				t.Errorf("normalizeVersion(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestVersionIsBareSemver guards the package-level invariant after the
// init() normalization: whatever the compile-time fallback or -X
// injection provided, the exported Version must not carry a "v" prefix.
// Regression: release binaries built via build-release.sh with a
// git-describe tag reported "v1.1.4" while images built via the
// Dockerfile VERSION-file path reported "1.1.4" (startup log:
// "vv1.1.4"). Both paths must now agree.
func TestVersionIsBareSemver(t *testing.T) {
	if Version == "" {
		t.Fatal("Version must not be empty")
	}
	if Version[0] == 'v' || Version[0] == 'V' {
		t.Errorf("Version = %q, want bare semver without v prefix", Version)
	}
}
