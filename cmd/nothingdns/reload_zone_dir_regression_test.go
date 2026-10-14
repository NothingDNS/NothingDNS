package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestReloadKeepsZoneDirZones(t *testing.T) {
	zoneDir := t.TempDir()
	zoneText := "$ORIGIN scanned.test.\n$TTL 300\n@ IN SOA ns1 h 1 1 1 1 1\n@ IN NS ns1\nns1 IN A 192.0.2.1\n"
	if err := os.WriteFile(filepath.Join(zoneDir, "scanned.test.zone"), []byte(zoneText), 0o600); err != nil {
		t.Fatal(err)
	}
	body := "zone_dir: \"" + zoneDir + "\"\n"
	env := reloadRTStart(t, body)
	if _, ok := env.h.zoneManager.Get("scanned.test."); !ok {
		t.Fatal("CONTROL FAILED: zone_dir zone not loaded at start")
	}
	env.mustReload(t, body) // SIGHUP / POST /config/reload with an unchanged config
	_, inMgr := env.h.zoneManager.Get("scanned.test.")
	env.h.zonesMu.RLock()
	_, inHandler := env.h.zones["scanned.test."]
	env.h.zonesMu.RUnlock()
	fmt.Printf("EXPECTED: zone still served after an unchanged reload | ACTUAL: manager=%v handler=%v\n", inMgr, inHandler)
	if !inMgr || !inHandler {
		fmt.Println("PROBLEM CONFIRMED")
		t.Fatal("reload dropped a zone_dir zone")
	}
	fmt.Println("PROBLEM NOT REPRODUCED")
}

func reloadZoneDirText(origin, serial string) string {
	return "$ORIGIN " + origin + "\n$TTL 300\n@ IN SOA ns1 h " + serial + " 1 1 1 1\n@ IN NS ns1\nns1 IN A 192.0.2.1\n"
}

func TestReloadZoneDirAddRemoveAndDuplicates(t *testing.T) {
	zoneDir := t.TempDir()
	write := func(name, text string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(zoneDir, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("a.test.zone", reloadZoneDirText("a.test.", "1"))
	body := "zone_dir: \"" + zoneDir + "\"\n"
	env := reloadRTStart(t, body)
	has := func(origin string) bool {
		_, ok := env.h.zoneManager.Get(origin)
		return ok
	}

	// a new file is picked up, a deleted one is dropped
	write("b.test.zone", reloadZoneDirText("b.test.", "1"))
	if err := os.Remove(filepath.Join(zoneDir, "a.test.zone")); err != nil {
		t.Fatal(err)
	}
	env.mustReload(t, body)
	if has("a.test.") || !has("b.test.") {
		t.Fatalf("after reload a=%v b=%v, want false/true", has("a.test."), has("b.test."))
	}

	// a stray second file for the same origin does not replace the first
	write("b.test.zone", reloadZoneDirText("b.test.", "5"))
	write("b.test.zone.bak.zone", reloadZoneDirText("b.test.", "9"))
	env.mustReload(t, body)
	z, _ := env.h.zoneManager.Get("b.test.")
	if z == nil || z.SOA == nil || z.SOA.Serial != 5 {
		t.Fatalf("serial after duplicate-origin reload = %v, want 5 (first file wins)", z)
	}

	// an unreadable zone_dir aborts the reload and leaves the running zones alone
	bad := "zone_dir: \"" + filepath.Join(zoneDir, "missing") + "\"\n"
	if err := env.reload(t, bad); err == nil {
		t.Fatal("reload with an unreadable zone_dir succeeded")
	}
	if !has("b.test.") {
		t.Fatal("failed reload dropped a running zone")
	}
}
