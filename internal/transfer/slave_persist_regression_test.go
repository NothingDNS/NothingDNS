package transfer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/zone"
)

const persistZoneText = "$ORIGIN p.test.\n$TTL 300\n@ IN SOA ns1 h 7 60 30 3600 60\n@ IN NS ns1\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.10\n"

func persistTestManager(t *testing.T, dir string, now time.Time) *SlaveManager {
	t.Helper()
	sm := NewSlaveManager(NewKeyStore())
	sm.SetPersistDir(dir)
	sm.SetClock(func() time.Time { return now }, func(time.Duration, func()) func() bool { return func() bool { return true } })
	t.Cleanup(sm.Stop)
	return sm
}

func persistTestZone(t *testing.T) *zone.Zone {
	t.Helper()
	z, err := zone.ParseFile("p", strings.NewReader(persistZoneText))
	if err != nil {
		t.Fatal(err)
	}
	return z
}

// F725: a slave keeps its zone on disk, so a restart while the master is
// unreachable still serves it until the EXPIRE counted from the last refresh.
func TestSlaveZoneSurvivesRestartUntilExpire(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Now().Truncate(time.Second)

	sm1 := persistTestManager(t, dir, t0)
	sz, err := NewSlaveZone(SlaveZoneConfig{ZoneName: "p.test.", Masters: []string{"127.0.0.1:1"}})
	if err != nil {
		t.Fatal(err)
	}
	sz.UpdateZone(persistTestZone(t), 7)
	sm1.persistSlaveZone("p.test.", sz)
	file := filepath.Join(dir, "p.test.zone")
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("zone not persisted: %v", err)
	}

	cfg := SlaveZoneConfig{ZoneName: "p.test.", Masters: []string{"127.0.0.1:1"}, Timeout: time.Second, RetryInterval: time.Minute}

	// restart 10 minutes later, master unreachable: served from the file
	sm2 := persistTestManager(t, dir, t0.Add(10*time.Minute))
	if err := sm2.AddSlaveZone(cfg); err != nil {
		t.Fatal(err)
	}
	got := sm2.GetSlaveZone("p.test.")
	if got == nil || !got.IsServable() || got.GetLastSerial() != 7 {
		t.Fatalf("restarted slave: servable=%v serial=%d", got != nil && got.IsServable(), got.GetLastSerial())
	}
	if want := t0.Add(time.Hour); !got.ExpiresAt().Equal(want) {
		t.Fatalf("ExpiresAt = %v, want %v (refresh time + SOA expire)", got.ExpiresAt(), want)
	}
	if z := got.GetZone(); z == nil || len(z.Records["www.p.test."]) != 1 {
		t.Fatal("persisted records not loaded")
	}

	// restart after the EXPIRE window: not loaded, nothing served
	sm3 := persistTestManager(t, dir, t0.Add(2*time.Hour))
	if err := sm3.AddSlaveZone(cfg); err != nil {
		t.Fatal(err)
	}
	if got := sm3.GetSlaveZone("p.test."); got.IsServable() || got.GetLastSerial() != 0 {
		t.Fatal("an expired persisted zone was loaded")
	}

	// persistence off: nothing is read or written
	off := persistTestManager(t, "", t0)
	if err := off.AddSlaveZone(cfg); err != nil {
		t.Fatal(err)
	}
	if off.GetSlaveZone("p.test.").IsServable() {
		t.Fatal("zone loaded with persistence disabled")
	}
}

// An unchanged serial only renews the refresh time, it does not rewrite the file.
func TestSlavePersistRenewsRefreshTimeWithoutRewrite(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Now().Truncate(time.Second).Add(-time.Hour)
	sm := persistTestManager(t, dir, t0)
	sz, _ := NewSlaveZone(SlaveZoneConfig{ZoneName: "p.test.", Masters: []string{"127.0.0.1:1"}})
	sz.UpdateZone(persistTestZone(t), 7)
	sm.persistSlaveZone("p.test.", sz)
	file := filepath.Join(dir, "p.test.zone")
	before, _ := os.ReadFile(file)

	t1 := t0.Add(30 * time.Minute)
	sm.SetClock(func() time.Time { return t1 }, func(time.Duration, func()) func() bool { return func() bool { return true } })
	sm.persistSlaveZone("p.test.", sz)
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(file)
	if !info.ModTime().Equal(t1) || string(before) != string(after) {
		t.Fatalf("modtime=%v want %v, content changed=%v", info.ModTime(), t1, string(before) != string(after))
	}
}
