package main

import (
	"fmt"
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func signerSyncHandler(t *testing.T) *integratedHandler {
	t.Helper()
	dir := t.TempDir()
	h := newTestHandler()
	h.config.DNSSEC.Enabled = true
	h.config.DNSSEC.Signing = config.SigningConfig{Enabled: true, Keys: []config.KeyConfig{
		{PrivateKey: signingTestKeyFile(t, dir, "ksk.pem"), Algorithm: protocol.AlgorithmECDSAP256SHA256, Type: "ksk"},
		{PrivateKey: signingTestKeyFile(t, dir, "zsk.pem"), Algorithm: protocol.AlgorithmECDSAP256SHA256, Type: "zsk"},
	}}
	h.zoneManager = zone.NewManager()
	h.zoneSigners = map[string]*dnssec.Signer{}
	return h
}

func signerSyncCreate(t *testing.T, h *integratedHandler, origin string) {
	t.Helper()
	soa := &zone.SOARecord{MName: "ns1." + origin, RName: "h." + origin, Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 300}
	if err := h.zoneManager.CreateZone(origin, 300, soa, []zone.NSRecord{{NSDName: "ns1." + origin}}); err != nil {
		t.Fatal(err)
	}
}

func signerSyncSigner(h *integratedHandler, origin string) *dnssec.Signer {
	h.zoneSignersMu.RLock()
	defer h.zoneSignersMu.RUnlock()
	return h.zoneSigners[origin]
}

func TestRuntimeZonesGetSigners(t *testing.T) {
	h := signerSyncHandler(t)
	signerSyncCreate(t, h, "created.test.")
	h.RebuildZoneTree() // what the zone mutation hook and a reload run
	got := signerSyncSigner(h, "created.test.") != nil
	fmt.Printf("EXPECTED: signer for a zone created at runtime = true | ACTUAL: %v\n", got)
	if !got {
		fmt.Println("PROBLEM CONFIRMED")
		t.Fatal("runtime-created zone is served unsigned")
	}
	fmt.Println("PROBLEM NOT REPRODUCED")
}

func TestRuntimeZoneSignerLifecycle(t *testing.T) {
	h := signerSyncHandler(t)
	var published int
	h.zoneSignersChanged = func(map[string]*dnssec.Signer) { published++ }

	signerSyncCreate(t, h, "one.test.")
	h.RebuildZoneTree()
	first := signerSyncSigner(h, "one.test.")
	if first == nil || published != 1 {
		t.Fatalf("signer=%v published=%d", first, published)
	}

	// an existing zone keeps its signer object; a second zone is added alongside
	signerSyncCreate(t, h, "two.test.")
	h.RebuildZoneTree()
	if signerSyncSigner(h, "one.test.") != first || signerSyncSigner(h, "two.test.") == nil {
		t.Fatal("existing signer replaced or new zone unsigned")
	}
	// nothing to do: no republish
	before := published
	h.RebuildZoneTree()
	if published != before {
		t.Fatal("republished without a change")
	}

	// a deleted zone drops its signer
	if err := h.zoneManager.DeleteZone("one.test."); err != nil {
		t.Fatal(err)
	}
	h.RebuildZoneTree()
	if signerSyncSigner(h, "one.test.") != nil || signerSyncSigner(h, "two.test.") == nil {
		t.Fatal("stale signer kept or live signer dropped")
	}

	// a key that cannot be loaded leaves the zone unsigned without panicking
	bad := signerSyncHandler(t)
	bad.config.DNSSEC.Signing.Keys[0].PrivateKey = "/nonexistent/key.pem"
	signerSyncCreate(t, bad, "bad.test.")
	bad.RebuildZoneTree()
	if signerSyncSigner(bad, "bad.test.") != nil {
		t.Fatal("signer built from a missing key")
	}

	// signing disabled: nothing is built
	off := signerSyncHandler(t)
	off.config.DNSSEC.Signing.Enabled = false
	signerSyncCreate(t, off, "off.test.")
	off.RebuildZoneTree()
	if signerSyncSigner(off, "off.test.") != nil {
		t.Fatal("signer built with signing disabled")
	}
}
