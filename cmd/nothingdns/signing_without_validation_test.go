package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
)

// dnssec.signing works without dnssec.enabled (validation): an authoritative
// server that resolves nothing turns validation off and must still sign (F755).

func signersWithValidation(t *testing.T, validation bool) bool {
	dir, keys := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "auth.example.zone"), []byte("$ORIGIN auth.example.\n$TTL 300\n@ IN SOA ns1 h 1 1 1 1 1\n@ IN NS ns1\nns1 IN A 192.0.2.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.ZoneDir = dir
	cfg.Zones = nil
	cfg.DNSSEC.Enabled = validation
	cfg.DNSSEC.Signing = config.SigningConfig{Enabled: true, Keys: []config.KeyConfig{
		{PrivateKey: signingTestKeyFile(t, keys, "ksk.pem"), Algorithm: protocol.AlgorithmECDSAP256SHA256, Type: "ksk"},
		{PrivateKey: signingTestKeyFile(t, keys, "zsk.pem"), Algorithm: protocol.AlgorithmECDSAP256SHA256, Type: "zsk"},
	}}
	if errs := cfg.Validate(); len(errs) != 0 {
		t.Fatalf("config refused: %v", errs)
	}
	mgr, err := NewZoneManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatal(err)
	}
	return mgr.Signers()["auth.example."] != nil
}

func TestSigningWithoutValidation(t *testing.T) {
	if !signersWithValidation(t, false) {
		t.Fatal("zone not signed with dnssec.enabled false and signing enabled")
	}
	if !signersWithValidation(t, true) {
		t.Fatal("zone not signed with validation on")
	}
}
