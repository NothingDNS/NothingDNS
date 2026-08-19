package util

import "strings"

// Version is the current version of NothingDNS.
// This is the single source of truth; all packages and binaries should reference this.
//
// Build tooling can override at link time with
//
//	-ldflags "-X github.com/nothingdns/nothingdns/internal/util.Version=<release-tag>"
//
// so release artifacts get the precise git tag baked in. Tracks the
// most recently released line in docs/CHANGELOG.md; bump this together
// with the matching changelog entry when cutting a new release.
//
// The canonical format is bare semver WITHOUT the "v" prefix ("1.1.4"):
// the VERSION file, this fallback, and the Dockerfile build-arg all use
// it, and the consumers that print "v%s" (startup log) or "%s version
// %s" (-version flag) render it correctly either way. init() strips a
// leading "v" so a git-describe tag passed via -X ("v1.1.4") cannot
// reintroduce the mixed-format reporting where release binaries printed
// "v1.1.4" while images printed "1.1.4" (and the startup log "vv1.1.4").
var Version = "1.1.4"

func init() {
	Version = normalizeVersion(Version)
}

// normalizeVersion strips a single leading "v"/"V" from a version
// string, yielding the canonical bare-semver form. Anything that does
// not start with v/V is returned unchanged.
func normalizeVersion(v string) string {
	return strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")
}
