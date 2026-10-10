package main

// F673: POST /api/v1/zones/reload (zone.Manager.Reload) swapped in a new Zone
// object without firing the mutation hook, so query routing kept serving, and
// AXFR kept transferring, the old object until some unrelated mutation.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestZoneManagerReload_NewZoneServedAndTransferred(t *testing.T) {
	h, zm := zoneDelBoot(t)
	path := filepath.Join(filepath.Dir(t.TempDir()), "001", "example.com.zone")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("zone file: %v", err)
	}
	var fired atomic.Int32
	prev := zm.MutationHook()
	zm.SetMutationHook(func(n string, d bool) { fired.Add(1); prev(n, d) })

	// 1. proof scenario
	if err := os.WriteFile(path, []byte(fmt.Sprintf(zoneDelZone, "example.com.", 2, "192.0.2.99")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := zm.Reload("example.com."); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := zoneDelQuery(h, "www.example.com."); !strings.Contains(got, "192.0.2.99") {
		t.Fatalf("query after Reload = %q", got)
	}
	// 2. transfers hand out the same data
	if got := zoneDelAXFR(h, "example.com."); !strings.Contains(got, "192.0.2.99") {
		t.Fatalf("AXFR after Reload = %q", got)
	}
	if fired.Load() != 1 {
		t.Fatalf("hook fired %d times, want 1", fired.Load())
	}
	// 3. unknown zone: error, hook silent
	if err := zm.Reload("nope.test."); err == nil {
		t.Fatal("Reload of unknown zone succeeded")
	}
	// 4. broken file: error, old data keeps serving, hook silent
	if err := os.WriteFile(path, []byte("this is not a zone file ((("), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := zm.Reload("example.com."); err == nil {
		t.Fatal("Reload of a broken file succeeded")
	}
	if got := zoneDelQuery(h, "www.example.com."); !strings.Contains(got, "192.0.2.99") {
		t.Fatalf("after failed Reload query = %q", got)
	}
	if fired.Load() != 1 {
		t.Fatalf("hook fired %d times after failures, want 1", fired.Load())
	}
	// 5. repeated reload picks up each change
	for i, ip := range []string{"192.0.2.101", "192.0.2.102"} {
		if err := os.WriteFile(path, []byte(fmt.Sprintf(zoneDelZone, "example.com.", 3+i, ip)), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := zm.Reload("example.com."); err != nil {
			t.Fatalf("Reload: %v", err)
		}
		if got := zoneDelQuery(h, "www.example.com."); !strings.Contains(got, ip) {
			t.Fatalf("reload %d query = %q, want %s", i, got, ip)
		}
	}
	// 6. the other zone is untouched
	if got := zoneDelQuery(h, "www.keep.test."); !strings.Contains(got, "192.0.2.7") {
		t.Fatalf("keep.test = %q", got)
	}
}
