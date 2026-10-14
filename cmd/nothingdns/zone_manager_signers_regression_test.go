package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/storage"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func signingTestKeyFile(t *testing.T, dir, name string) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNewZoneManagerSignsKVLoadedZones(t *testing.T) {
	dir := t.TempDir()
	keys := t.TempDir()

	// a zone only the persistent database knows (API-created before the restart)
	seed := zone.NewManager()
	soa := &zone.SOARecord{MName: "ns1.kv.example.", RName: "h.kv.example.", Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 300}
	if err := seed.CreateZone("kv.example.", 300, soa, []zone.NSRecord{{NSDName: "ns1.kv.example."}}); err != nil {
		t.Fatal(err)
	}
	kv, err := storage.OpenKVStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	kvp := zone.NewKVPersistence(seed, kv)
	kvp.Enable()
	if err := kvp.PersistAll(); err != nil {
		t.Fatal(err)
	}
	if err := kv.Close(); err != nil {
		t.Fatal(err)
	}

	// a file-backed zone for the control
	if err := os.WriteFile(filepath.Join(dir, "file.example.zone"), []byte("$ORIGIN file.example.\n$TTL 300\n@ IN SOA ns1 h 1 1 1 1 1\n@ IN NS ns1\nns1 IN A 192.0.2.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.ZoneDir = dir
	cfg.Zones = nil
	cfg.DNSSEC.Enabled = true
	cfg.DNSSEC.Signing = config.SigningConfig{Enabled: true, Keys: []config.KeyConfig{
		{PrivateKey: signingTestKeyFile(t, keys, "ksk.pem"), Algorithm: protocol.AlgorithmECDSAP256SHA256, Type: "ksk"},
		{PrivateKey: signingTestKeyFile(t, keys, "zsk.pem"), Algorithm: protocol.AlgorithmECDSAP256SHA256, Type: "zsk"},
	}}
	mgr, err := NewZoneManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatal(err)
	}
	if mgr.Signers()["file.example."] == nil {
		t.Fatal("CONTROL FAILED: file-backed zone has no signer")
	}
	if mgr.Zones()["kv.example."] == nil {
		t.Fatal("KV zone not loaded")
	}
	got := mgr.Signers()["kv.example."] != nil
	fmt.Printf("EXPECTED: signer for the KV-loaded zone = true | ACTUAL: %v\n", got)
	if !got {
		fmt.Println("PROBLEM CONFIRMED")
		t.Fatal("KV-loaded zone is served unsigned")
	}
	fmt.Println("PROBLEM NOT REPRODUCED")
}
