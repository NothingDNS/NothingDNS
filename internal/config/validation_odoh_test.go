package config

import (
	"strings"
	"testing"
)

// The odoh runtime (internal/odoh) implements exactly one suite —
// DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM, KEM ID 0x0020 —
// and parseConfigContents rejects every other KEM ("odoh: unsupported
// suite"). The published ObliviousDoHConfigs carry the configured ODoHKEM,
// so config validation must accept KEM 0x0020 (32): the only value that
// can actually function end to end.
func TestODoHValidationAcceptsRuntimeImplementedKEM(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ODoH.Enabled = true
	cfg.ODoH.KEM = 32  // hpkeKEMX25519HKDFSHA256 (0x0020)
	cfg.ODoH.KDF = 1   // HKDF-SHA256
	cfg.ODoH.AEAD = 1  // AES-128-GCM

	var odohErrors []string
	for _, err := range cfg.Validate() {
		if strings.Contains(err, "odoh") {
			odohErrors = append(odohErrors, err)
		}
	}
	if len(odohErrors) > 0 {
		t.Fatalf("FAIL: the runtime-implemented ODoH suite (KEM 0x0020) is rejected by config validation: %v", odohErrors)
	}
}

// An unknown KEM must still be rejected.
func TestODoHValidationRejectsUnknownKEM(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ODoH.Enabled = true
	cfg.ODoH.KEM = 999

	for _, err := range cfg.Validate() {
		if strings.Contains(err, "unsupported kem") {
			return // correctly rejected
		}
	}
	t.Fatal("FAIL: an unknown ODoH KEM was not rejected by config validation")
}

// The suite validation must run whenever ODoH is enabled, regardless of
// whether a TargetURL is configured — a garbage KEM behind a valid URL
// publishes an unusable ObliviousDoHConfigs.
func TestODoHValidationRejectsBadSuiteWithTargetURL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ODoH.Enabled = true
	cfg.ODoH.TargetURL = "https://odoh.example.com/dns-query"
	cfg.ODoH.KEM = 999
	cfg.ODoH.KDF = 1
	cfg.ODoH.AEAD = 1

	for _, err := range cfg.Validate() {
		if strings.Contains(err, "unsupported kem") {
			return // correctly rejected
		}
	}
	t.Fatal("FAIL: an unsupported ODoH KEM behind a configured TargetURL was not rejected by config validation")
}
