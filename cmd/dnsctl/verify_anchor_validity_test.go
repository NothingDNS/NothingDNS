package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func writeValidityAnchor(t *testing.T, validFrom, validUntil string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "anchor.xml")
	body := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor id="test" source="test">
  <Zone>.</Zone>
  <KeyDigest id="1" validFrom="%s" validUntil="%s">
    <KeyTag>12345</KeyTag><Algorithm>13</Algorithm><DigestType>2</DigestType>
    <Digest>abababababababababababababababababababababababababababababababab</Digest>
  </KeyDigest>
</TrustAnchor>`, validFrom, validUntil)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVerifyAnchorRejectsExpiredAndFutureAnchors(t *testing.T) {
	tests := map[string][2]string{
		"expired": {"2000-01-01T00:00:00Z", "2001-01-01T00:00:00Z"},
		"future":  {"2098-01-01T00:00:00Z", "2099-01-01T00:00:00Z"},
	}
	for name, dates := range tests {
		t.Run(name, func(t *testing.T) {
			if err := cmdDNSSECVerifyAnchor([]string{writeValidityAnchor(t, dates[0], dates[1])}); err == nil {
				t.Fatal("currently invalid anchor reported as verified")
			}
		})
	}
}

func TestVerifyAnchorAcceptsCurrentAnchor(t *testing.T) {
	path := writeValidityAnchor(t, "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z")
	if err := cmdDNSSECVerifyAnchor([]string{path}); err != nil {
		t.Fatalf("current anchor rejected: %v", err)
	}
}
