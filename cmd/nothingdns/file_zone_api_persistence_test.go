package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/storage"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// A zone listed under `zones:` (no zone_dir) whose records change through the
// API: the change must survive a restart, and the zone must not come back
// from the persistent database once its file leaves the config.

const fileZoneContent = `$ORIGIN filezone.example.
$TTL 300
@ IN SOA ns1 hostmaster %s 3600 900 604800 300
@ IN NS ns1
ns1 IN A 192.0.2.53
www IN A %s
`

type fileZoneEnv struct {
	file  string
	dbDir string
}

func newFileZoneEnv(t *testing.T, serial, www string) *fileZoneEnv {
	t.Helper()
	env := &fileZoneEnv{file: filepath.Join(t.TempDir(), "filezone.example.zone"), dbDir: t.TempDir()}
	env.writeFile(t, serial, www)
	return env
}

func (env *fileZoneEnv) writeFile(t *testing.T, serial, www string) {
	t.Helper()
	content := strings.Replace(strings.Replace(fileZoneContent, "%s", serial, 1), "%s", www, 1)
	if err := os.WriteFile(env.file, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
}

// boot runs the startup path with the zone file configured (or not) and
// returns the manager; the persistent database is closed at test cleanup.
func (env *fileZoneEnv) boot(t *testing.T, configured bool) *ZoneManager {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Storage.DataDir = env.dbDir
	cfg.Zones = nil
	if configured {
		cfg.Zones = []string{env.file}
	}
	mgr, err := NewZoneManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatalf("NewZoneManager: %v", err)
	}
	return mgr
}

func closeZoneDB(t *testing.T, mgr *ZoneManager) {
	t.Helper()
	if mgr.result.KVStore != nil {
		if err := mgr.result.KVStore.Close(); err != nil {
			t.Fatalf("close persistent database: %v", err)
		}
	}
}

func wwwAddress(t *testing.T, mgr *ZoneManager) string {
	t.Helper()
	z, ok := mgr.Manager().Get("filezone.example.")
	if !ok {
		t.Fatal("filezone.example. is not loaded")
	}
	recs := z.Lookup("www.filezone.example.", "A")
	if len(recs) != 1 {
		t.Fatalf("www A records = %v, want one", recs)
	}
	return recs[0].RData
}

func TestFileZone_APIChangeSurvivesRestart(t *testing.T) {
	env := newFileZoneEnv(t, "2026102601", "192.0.2.1")

	mgr := env.boot(t, true)
	if err := mgr.Manager().UpdateRecord("filezone.example.", "www", "A", "192.0.2.1",
		zone.Record{Name: "www", Type: "A", TTL: 300, Class: "IN", RData: "192.0.2.2"}); err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}
	closeZoneDB(t, mgr)

	data, err := os.ReadFile(env.file)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "192.0.2.2") {
		t.Errorf("zone file was not updated:\n%s", data)
	}
	if info, err := os.Stat(env.file); err != nil || info.Mode().Perm() != 0o640 {
		t.Errorf("zone file mode = %v (err %v), want 0640 kept", info.Mode().Perm(), err)
	}

	mgr = env.boot(t, true)
	defer closeZoneDB(t, mgr)
	if got := wwwAddress(t, mgr); got != "192.0.2.2" {
		t.Errorf("after restart www = %s, want 192.0.2.2", got)
	}
}

func TestFileZone_BackupNotRestoredAfterRemovalFromConfig(t *testing.T) {
	env := newFileZoneEnv(t, "2026102601", "192.0.2.1")

	mgr := env.boot(t, true)
	if err := mgr.Manager().UpdateRecord("filezone.example.", "www", "A", "192.0.2.1",
		zone.Record{Name: "www", Type: "A", TTL: 300, Class: "IN", RData: "192.0.2.2"}); err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}
	closeZoneDB(t, mgr)

	mgr = env.boot(t, false)
	defer closeZoneDB(t, mgr)
	if _, ok := mgr.Manager().Get("filezone.example."); ok {
		t.Error("zone removed from the config came back from the persistent database")
	}
}

// seedLegacyKVCopy stores a copy of the zone the way versions that never
// wrote API changes to the file did: without the FileBacked flag.
func seedLegacyKVCopy(t *testing.T, env *fileZoneEnv, serial, www string) {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "seed.zone")
	content := strings.Replace(strings.Replace(fileZoneContent, "%s", serial, 1), "%s", www, 1)
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	z, err := loadZoneFile(tmp)
	if err != nil {
		t.Fatal(err)
	}
	seed := zone.NewManager()
	seed.LoadZone(z, "")
	kv, err := storage.OpenKVStore(env.dbDir)
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
}

// Upgrade path: a change made before API writes reached the file lives only
// in the database, with a newer serial. It is restored and written to the file.
func TestFileZone_RestoresNewerDatabaseCopy(t *testing.T) {
	env := newFileZoneEnv(t, "2026102601", "192.0.2.1")
	seedLegacyKVCopy(t, env, "2026102602", "192.0.2.2")

	mgr := env.boot(t, true)
	if got := wwwAddress(t, mgr); got != "192.0.2.2" {
		t.Errorf("www = %s, want the database copy's 192.0.2.2", got)
	}
	if data, err := os.ReadFile(env.file); err != nil || !strings.Contains(string(data), "192.0.2.2") {
		t.Errorf("restored zone was not written to the file (err %v):\n%s", err, data)
	}
	_, fileBacked, found, err := mgr.KVPersistence().LoadStoredZone("filezone.example.")
	if err != nil || !found || !fileBacked {
		t.Errorf("database copy: found=%v fileBacked=%v err=%v, want a FileBacked copy", found, fileBacked, err)
	}
	closeZoneDB(t, mgr)

	// The re-flagged copy no longer resurrects the zone once it is removed.
	mgr = env.boot(t, false)
	defer closeZoneDB(t, mgr)
	if _, ok := mgr.Manager().Get("filezone.example."); ok {
		t.Error("legacy database copy resurrected a zone removed from the config")
	}
}

// An operator edit to the file with a higher serial wins over an older
// database copy.
func TestFileZone_NewerFileWinsOverDatabaseCopy(t *testing.T) {
	env := newFileZoneEnv(t, "2026102605", "192.0.2.5")
	seedLegacyKVCopy(t, env, "2026102602", "192.0.2.2")

	mgr := env.boot(t, true)
	defer closeZoneDB(t, mgr)
	if got := wwwAddress(t, mgr); got != "192.0.2.5" {
		t.Errorf("www = %s, want the file's 192.0.2.5", got)
	}
	if data, err := os.ReadFile(env.file); err != nil || strings.Contains(string(data), "192.0.2.2") {
		t.Errorf("file was overwritten with the older database copy (err %v)", err)
	}
}
