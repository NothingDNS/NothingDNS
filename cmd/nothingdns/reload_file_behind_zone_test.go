package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/nothingdns/nothingdns/internal/zone"
)

func f726Env(t *testing.T) (*reloadRTEnv, string, string, string) {
	t.Helper()
	dir := t.TempDir()
	zdir := filepath.Join(dir, "zones")
	if err := os.Mkdir(zdir, 0o755); err != nil {
		t.Fatal(err)
	}
	zoneFile := filepath.Join(zdir, "f726.test.zone")
	writeF726(t, zoneFile, 1, "")
	body := "zones:\n  - \"" + zoneFile + "\"\n"
	env, _ := reloadRTStartIn(t, dir, body)
	return env, zdir, zoneFile, body
}

func writeF726(t *testing.T, path string, serial int, extra string) {
	t.Helper()
	text := fmt.Sprintf("$ORIGIN f726.test.\n$TTL 300\n@ IN SOA ns1 h %d 3600 600 604800 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\n%s", serial, extra)
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func f726Has(env *reloadRTEnv, name string) bool {
	z, ok := env.h.zoneManager.Get("f726.test.")
	return ok && len(z.Lookup(name+".f726.test.", "A")) == 1
}

// F726: an API change whose write-back to the zone file failed is held only
// in memory and the persistent database. A config reload used to serve the
// older file instead, and the next mutation overwrote the database copy,
// losing the change. The reload now keeps such a zone (Manager.FileBehind)
// and retries the write; in every other case the file wins.
func TestReloadKeepsZoneAheadOfItsFile(t *testing.T) {
	t.Run("failed write-back: reload keeps the change, the file gets it once writable", func(t *testing.T) {
		env, zdir, file, body := f726Env(t)
		_ = os.Chmod(zdir, 0o555)
		defer os.Chmod(zdir, 0o755)
		if err := env.s.zoneMgr.AddRecord("f726.test.", zone.Record{Name: "api", Type: "A", TTL: 300, RData: "192.0.2.77"}); err != nil {
			t.Fatal(err)
		}
		env.mustReload(t, body) // write still fails: served from the database copy
		if !f726Has(env, "api") {
			t.Fatal("reload reverted the change")
		}
		_ = os.Chmod(zdir, 0o755)
		env.mustReload(t, body) // now the restored zone is written to the file
		b, _ := os.ReadFile(file)
		if !f726Has(env, "api") || !containsLine(string(b), "api") {
			t.Fatalf("change not written to the file after a writable reload:\n%s", b)
		}
		if err := env.s.zoneMgr.AddRecord("f726.test.", zone.Record{Name: "other", Type: "A", TTL: 300, RData: "192.0.2.78"}); err != nil {
			t.Fatal(err)
		}
		if !f726Has(env, "api") || !f726Has(env, "other") {
			t.Fatal("change lost after the next mutation")
		}
	})
	t.Run("no failed write: an operator edit wins", func(t *testing.T) {
		env, _, file, body := f726Env(t)
		if err := env.s.zoneMgr.AddRecord("f726.test.", zone.Record{Name: "api", Type: "A", TTL: 300, RData: "192.0.2.77"}); err != nil {
			t.Fatal(err)
		}
		z, _ := env.h.zoneManager.Get("f726.test.")
		writeF726(t, file, int(z.SOA.Serial)+10, "edited IN A 192.0.2.99\n")
		env.mustReload(t, body)
		if !f726Has(env, "edited") || f726Has(env, "api") {
			t.Fatal("the operator's newer file did not win")
		}
	})
	t.Run("no failed write, equal serial: the file wins", func(t *testing.T) {
		env, _, file, body := f726Env(t)
		if err := env.s.zoneMgr.AddRecord("f726.test.", zone.Record{Name: "api", Type: "A", TTL: 300, RData: "192.0.2.77"}); err != nil {
			t.Fatal(err)
		}
		z, _ := env.h.zoneManager.Get("f726.test.")
		writeF726(t, file, int(z.SOA.Serial), "edited IN A 192.0.2.99\n")
		env.mustReload(t, body)
		if !f726Has(env, "edited") || f726Has(env, "api") {
			t.Fatal("equal serial: database copy replaced the file")
		}
	})
	t.Run("no database copy: the file is loaded", func(t *testing.T) {
		env, _, file, body := f726Env(t)
		writeF726(t, file, 5, "edited IN A 192.0.2.99\n")
		env.mustReload(t, body)
		if !f726Has(env, "edited") {
			t.Fatal("file edit not loaded")
		}
	})
}

func containsLine(s, owner string) bool {
	for _, l := range splitLines(s) {
		if len(l) > len(owner) && l[:len(owner)] == owner && (l[len(owner)] == '\t' || l[len(owner)] == ' ') {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// F733: a reload reads the zone files long before it applies them. A record
// change made in between was written to the file but missing from the copy
// the reload installed, and the next write-back removed it from the file too.
// A file that changed since it was read is now read again at apply time.
func TestReloadKeepsChangesMadeWhileItRuns(t *testing.T) {
	setup := func(t *testing.T) (*reloadRTEnv, string, []loadedZoneFile) {
		env, _, file, _ := f726Env(t)
		plan, err := prepareConfiguredZoneFiles([]string{file}, loadZoneFile)
		if err != nil {
			t.Fatal(err)
		}
		if err := env.s.zoneMgr.AddRecord("f726.test.", zone.Record{Name: "api", Type: "A", TTL: 300, RData: "192.0.2.77"}); err != nil {
			t.Fatal(err)
		}
		return env, file, plan
	}
	apply := func(env *reloadRTEnv, plan []loadedZoneFile) {
		applyConfiguredZoneFiles(env.h, env.s.zoneMgr, *env.s.zoneFiles, plan, env.s.logger)
	}
	t.Run("change made during the reload is kept", func(t *testing.T) {
		env, file, plan := setup(t)
		apply(env, plan)
		if err := env.s.zoneMgr.AddRecord("f726.test.", zone.Record{Name: "later", Type: "A", TTL: 300, RData: "192.0.2.78"}); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(file)
		if !f726Has(env, "api") || !containsLine(string(b), "api") {
			t.Fatalf("change lost:\n%s", b)
		}
	})
	t.Run("operator edit after it still wins", func(t *testing.T) {
		env, file, plan := setup(t)
		z, _ := env.h.zoneManager.Get("f726.test.")
		writeF726(t, file, int(z.SOA.Serial)+10, "edited IN A 192.0.2.99\n")
		apply(env, plan)
		if !f726Has(env, "edited") || f726Has(env, "api") {
			t.Fatal("the operator's edit did not win")
		}
	})
	t.Run("file broken meanwhile: the running zone is kept", func(t *testing.T) {
		env, file, plan := setup(t)
		if err := os.WriteFile(file, []byte("$ORIGIN f726.test.\n@ IN SOA broken\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		apply(env, plan)
		if !f726Has(env, "api") {
			t.Fatal("running zone not kept")
		}
	})
}
