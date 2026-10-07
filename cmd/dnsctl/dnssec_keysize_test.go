package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/dnssec"
)

// TestRSAKeySizeCappedAt4096_F460: dnsctl must not generate RSA DNSKEYs the
// validator rejects (RFC 5702 §2: at most 4096 bits; F227).
func TestRSAKeySizeCappedAt4096_F460(t *testing.T) {
	for _, tc := range []struct {
		alg  uint8
		bits int
	}{{8, 4104}, {10, 8192}, {8, 1023}} {
		if _, err := generateKeyPair(tc.alg, true, tc.bits); err == nil || !strings.Contains(err.Error(), "1024-4096") {
			t.Errorf("alg %d keysize %d: err = %v, want RSA key size range error", tc.alg, tc.bits, err)
		}
	}

	key, err := generateKeyPair(8, false, 2048)
	if err != nil {
		t.Fatalf("2048-bit key: %v", err)
	}
	if _, err := dnssec.ParseDNSKEYPublicKey(key.DNSKEY.Algorithm, key.DNSKEY.PublicKey); err != nil {
		t.Fatalf("validator rejects generated 2048-bit key: %v", err)
	}

	dir := t.TempDir()
	err = cmdDNSSECGenerateKey([]string{"--algorithm", "8", "--type", "KSK", "--zone", "example.com", "--keysize", "8192", "--output", dir})
	if err == nil || !strings.Contains(err.Error(), "RSA key size") {
		t.Fatalf("generate-key -keysize 8192: err = %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("generate-key wrote files despite the error: %v", entries)
	}

	err = cmdDNSSECSignZone([]string{"--zone", "example.com", "--input", filepath.Join(dir, "missing.zone"), "--algorithm", "8", "--keysize", "5000"})
	if err == nil || !strings.Contains(err.Error(), "RSA key size") {
		t.Fatalf("sign-zone -keysize 5000: err = %v", err)
	}
}
