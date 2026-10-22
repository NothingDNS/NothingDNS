package main

// Round 026 (2026-10-22): synchronizeKVZones installs every zone the
// persistent database holds with no content gate. Every other loader
// validates (loadZoneFile → z.Validate, Manager.Load → z.Validate) and the
// slave loader refuses an origin mismatch (slave_persist.go). A KV record
// set without a parseable SOA — legacy data, an interrupted old writer —
// restores as a zone with z.SOA == nil: no negative-answer SOA, no DDNS
// serial checks, no AXFR source, silently. The guard skips such entries
// with a warning, exactly like the slave loader, and leaves the KV entry
// untouched (repairable), while well-formed zones load unchanged.

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/storage"
	"github.com/nothingdns/nothingdns/internal/util"
)

func TestSynchronizeKVZones_SkipsSOALessZone(t *testing.T) {
	dir := t.TempDir()
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	cfg := &config.Config{Storage: config.StorageConfig{DataDir: dir}}

	mgr, err := NewZoneManager(cfg, logger)
	if err != nil {
		t.Fatalf("NewZoneManager: %v", err)
	}
	if mgr.result.KVStore == nil || mgr.result.KVPersistence == nil {
		t.Fatal("KV persistence not wired (storage.data_dir unset?)")
	}
	zm := mgr.result.Manager

	// Persist one SOA-less zone (legacy/buggy-writer simulation) and one
	// well-formed control zone through the public storage API — the seam a
	// real writer uses, so this exercises the restore path end to end.
	zs := storage.NewZoneStore(mgr.result.KVStore)
	orphan := "orphan.example.com."
	orphanRecords := map[string][]storage.StoredRecord{
		orphan: {{Name: orphan, TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.1"}},
	}
	if err := zs.SaveZone(orphan, storage.ZoneMeta{Origin: orphan, DefaultTTL: 300}, orphanRecords); err != nil {
		t.Fatalf("SaveZone orphan: %v", err)
	}
	sound := "sound.example.com."
	soundRecords := map[string][]storage.StoredRecord{
		sound: {
			{Name: sound, TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.sound.example.com. hostmaster.sound.example.com. 1 3600 900 604800 60"},
			{Name: sound, TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.sound.example.com."},
		},
	}
	if err := zs.SaveZone(sound, storage.ZoneMeta{Origin: sound, DefaultTTL: 3600}, soundRecords); err != nil {
		t.Fatalf("SaveZone sound: %v", err)
	}

	synchronizeKVZones(mgr, zm, mgr.result.KVPersistence, logger)

	// Control: the well-formed zone must still load, SOA intact.
	z, installed := zm.Get(sound)
	if !installed || z == nil || z.SOA == nil {
		t.Fatalf("control broken: sound zone not installed with an SOA (installed=%v)", installed)
	}
	// The defect: the SOA-less entry must be skipped, not installed.
	if z, ok := zm.Get(orphan); ok && z != nil {
		t.Fatalf("PROBLEM CONFIRMED: SOA-less KV zone installed (SOA=%v); negative answers, DDNS serial checks and AXFR for %s have no SOA", z.SOA, orphan)
	}
}
