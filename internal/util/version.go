package util

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
var Version = "1.1.1"
