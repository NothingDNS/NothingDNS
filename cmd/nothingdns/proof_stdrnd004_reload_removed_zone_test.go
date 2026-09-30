// Regression: a zone removed from the config must stop being served after a
// hot reload.
//
// CONTRACT. applyConfiguredZoneFiles exists to remove "stale file-backed zones"
// so a zone deleted from the config cannot survive a reload. RebuildZoneTree
// builds the served zone set from THREE sources — handler.zones,
// kvPersistence.Manager().List() and zoneManager.List() — and hands the merged
// map to NewMultiZoneProvider, which the query pipeline consults via
// h.zoneProvider.FindZones. So a removed zone must be pruned from every one of
// those sources, not just one.
//
// DEFECT. applyConfiguredZoneFiles pruned only zoneManager, and never removed
// the stale origin from handler.zones (nor from the zoneFiles tracking map).
// Because RebuildZoneTree merges handler.zones as its first source, the removed
// zone was still in the merged map, still built into the radix tree, and still
// returned by the provider. The operator deleted the zone from the config, the
// reload reported success, and the zone kept answering queries with its stale
// records. The code comment proves the leak-through-rebuild mechanism was
// understood; only the zoneManager source was fixed.
//
// FIX. Every tracked stale origin is now deleted from handler.zones and from
// the zoneFiles tracking map alongside zoneManager.RemoveZones.
//
// The controls below pin the other direction: a zone still present in the
// config must keep being served, and KV/API-created zones (never tracked in
// zoneFiles) must survive a reload untouched.
package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func reloadTestLogger() *util.Logger {
	return util.NewLogger(util.ERROR, util.TextFormat, nil)
}

// TestReloadRemovesZoneDeletedFromConfig is the defect case: the zone manager
// was pruned, but the handler's own map — the source the provider reads — kept
// the removed zone, so it stayed resolvable.
func TestReloadRemovesZoneDeletedFromConfig(t *testing.T) {
	h := newTestHandler()
	h.zoneManager = zone.NewManager()
	zoneFiles := map[string]string{}

	// Reload #1: the config contains one zone.
	if _, err := reloadConfiguredZoneFiles(
		h, h.zoneManager, zoneFiles,
		[]string{"a.zone"},
		func(string) (*zone.Zone, error) { return zone.NewZone("a.example."), nil },
		reloadTestLogger(),
	); err != nil {
		t.Fatalf("first reload: %v", err)
	}
	// Control: the zone must actually be served, or the removal assertion
	// below would pass vacuously.
	if _, ok := h.zoneProvider.GetZone("a.example."); !ok {
		t.Fatal("setup: a.example. was not served after the first reload, so the " +
			"removal assertion below would be meaningless")
	}

	// Reload #2: the operator removed that zone from the config.
	if _, err := reloadConfiguredZoneFiles(
		h, h.zoneManager, zoneFiles,
		nil,
		func(string) (*zone.Zone, error) {
			t.Fatal("setup: no zone file should be loaded on the second reload")
			return nil, nil
		},
		reloadTestLogger(),
	); err != nil {
		t.Fatalf("second reload: %v", err)
	}

	if _, ok := h.zoneManager.Get("a.example."); ok {
		t.Error("setup: zone manager still holds a.example., so the test would not be " +
			"exercising the handler.zones leak")
	}
	if _, ok := h.zoneProvider.GetZone("a.example."); ok {
		t.Errorf("zone a.example. was removed from the config and reloaded, but the zone " +
			"provider still returns it — the removed zone keeps being served with stale records")
	}
	if _, stale := zoneFiles["a.example."]; stale {
		t.Errorf("zoneFiles still tracks the removed origin a.example.; it must be pruned " +
			"so the tracking map does not accumulate stale origins")
	}
}

// TestReloadKeepsConfiguredZoneServed pins the other direction: a zone still in
// the config must remain served after the reload, so the fix cannot over-prune.
func TestReloadKeepsConfiguredZoneServed(t *testing.T) {
	h := newTestHandler()
	h.zoneManager = zone.NewManager()
	zoneFiles := map[string]string{}

	if _, err := reloadConfiguredZoneFiles(
		h, h.zoneManager, zoneFiles,
		[]string{"a.zone", "b.zone"},
		func(p string) (*zone.Zone, error) {
			if p == "a.zone" {
				return zone.NewZone("a.example."), nil
			}
			return zone.NewZone("b.example."), nil
		},
		reloadTestLogger(),
	); err != nil {
		t.Fatalf("first reload: %v", err)
	}

	// Reload keeping only b.zone.
	if _, err := reloadConfiguredZoneFiles(
		h, h.zoneManager, zoneFiles,
		[]string{"b.zone"},
		func(string) (*zone.Zone, error) { return zone.NewZone("b.example."), nil },
		reloadTestLogger(),
	); err != nil {
		t.Fatalf("second reload: %v", err)
	}

	if _, ok := h.zoneProvider.GetZone("b.example."); !ok {
		t.Error("b.example. is still in the config and must remain served; the fix " +
			"must not drop zones that are still configured")
	}
	if _, ok := h.zoneProvider.GetZone("a.example."); ok {
		t.Error("a.example. was removed and must not be served")
	}
}

// TestReloadPreservesUntrackedZones pins the boundary the fix must respect:
// a zone that exists only in the handler map (created via the API/KV store, and
// therefore never tracked in zoneFiles) is not stale and must survive a reload.
func TestReloadPreservesUntrackedZones(t *testing.T) {
	h := newTestHandler()
	h.zoneManager = zone.NewManager()
	zoneFiles := map[string]string{}

	// An API-created zone: present in handler.zones but never in zoneFiles.
	apiZone := zone.NewZone("api.example.")
	h.zones["api.example."] = apiZone

	// A file-backed zone, so the reload has a real stale origin to prune.
	if _, err := reloadConfiguredZoneFiles(
		h, h.zoneManager, zoneFiles,
		[]string{"a.zone"},
		func(string) (*zone.Zone, error) { return zone.NewZone("a.example."), nil },
		reloadTestLogger(),
	); err != nil {
		t.Fatalf("first reload: %v", err)
	}

	// Reload with the file-backed zone gone from config.
	if _, err := reloadConfiguredZoneFiles(
		h, h.zoneManager, zoneFiles,
		nil,
		func(string) (*zone.Zone, error) {
			t.Fatal("setup: no zone file should be loaded on the second reload")
			return nil, nil
		},
		reloadTestLogger(),
	); err != nil {
		t.Fatalf("second reload: %v", err)
	}

	if _, ok := h.zoneProvider.GetZone("api.example."); !ok {
		t.Error("api.example. was created via the API and is not tracked in zoneFiles; " +
			"a config reload must not remove it")
	}
	if _, ok := h.zoneProvider.GetZone("a.example."); ok {
		t.Error("a.example. was file-backed and removed from config, so it must be gone")
	}
}
