package transfer

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// Slave zone persistence (RFC 1034 §4.3.5): a secondary keeps its zone data on
// disk so that restarting it while the master is unreachable does not drop the
// zone. The file's modification time is the last successful refresh, so the
// EXPIRE window survives the restart too (F725).

// SetPersistDir enables persistence of transferred zones under dir (one
// "<zone>.zone" file each). An empty dir disables it. Call before AddSlaveZone.
func (sm *SlaveManager) SetPersistDir(dir string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.persistDir = dir
}

func (sm *SlaveManager) persistFile(zoneName string) string {
	if sm.persistDir == "" {
		return ""
	}
	name := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		}
		return '_'
	}, strings.TrimSuffix(strings.ToLower(zoneName), "."))
	return filepath.Join(sm.persistDir, name+".zone")
}

// persistSlaveZone records a successful refresh of sz: the zone is written when
// its serial changed since the last write, otherwise only the file's refresh
// time is renewed. Failures are logged; the zone stays served from memory.
func (sm *SlaveManager) persistSlaveZone(zoneName string, sz *SlaveZone) {
	sm.mu.RLock()
	path := sm.persistFile(zoneName)
	now := sm.now
	sm.mu.RUnlock()
	if path == "" {
		return
	}
	z := sz.GetZone()
	if z == nil {
		return
	}
	z.RLock()
	soa := z.SOA
	var serial uint32
	if soa != nil {
		serial = soa.Serial
	}
	z.RUnlock()
	if soa == nil {
		return
	}

	sz.mu.Lock()
	unchanged := sz.persisted && sz.persistedSerial == serial
	sz.mu.Unlock()
	if unchanged {
		if err := os.Chtimes(path, now(), now()); err == nil {
			return
		}
	}
	text, err := zone.WriteZone(z)
	if err != nil {
		util.Warnf("slave: cannot serialize %s for persistence: %v", zoneName, err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		util.Warnf("slave: cannot create %s: %v", filepath.Dir(path), err)
		return
	}
	if err := util.AtomicWriteFile(path, []byte(text), 0o600); err != nil {
		util.Warnf("slave: cannot persist %s: %v", zoneName, err)
		return
	}
	if err := os.Chtimes(path, now(), now()); err != nil {
		util.Warnf("slave: cannot stamp %s: %v", path, err)
	}
	sz.mu.Lock()
	sz.persisted, sz.persistedSerial = true, serial
	sz.mu.Unlock()
}

// loadPersistedZone preloads sz from its persisted file so the zone is served
// at once and the first transfer is incremental from the held serial. A zone
// whose EXPIRE window (counted from the file's refresh time) has already
// elapsed is not loaded: it must not be served until a transfer succeeds.
// Caller holds sm.mu.
func (sm *SlaveManager) loadPersistedZone(zoneName string, sz *SlaveZone) {
	path := sm.persistFile(zoneName)
	if path == "" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	// The file holds what this server received by transfer, so a record the
	// zone-file parser would refuse is skipped rather than discarding the zone.
	z, err := zone.ParseStored(path, f)
	if err != nil || z == nil || z.SOA == nil || !strings.EqualFold(z.Origin, zoneName) {
		util.Warnf("slave: ignoring unusable persisted zone file %s", path)
		return
	}
	for _, w := range z.Warnings {
		util.Warnf("slave: persisted zone %s: %s", zoneName, w)
	}
	timers, ok := zoneSOATimers(z)
	if !ok {
		return
	}
	refreshed := info.ModTime()
	expireAt := refreshed.Add(timers.expire)
	if !sm.now().Before(expireAt) {
		util.Warnf("slave: persisted zone %s expired at %s; waiting for a transfer", zoneName, expireAt.Format("2006-01-02T15:04:05Z07:00"))
		return
	}
	sz.mu.Lock()
	sz.Zone = z
	sz.LastSerial = z.SOA.Serial
	sz.LastTransfer = refreshed
	sz.expireAt = expireAt
	sz.persisted, sz.persistedSerial = true, z.SOA.Serial
	sz.mu.Unlock()
	util.Infof("slave: loaded persisted zone %s (serial %d, expires %s)", zoneName, z.SOA.Serial, expireAt.Format("2006-01-02T15:04:05Z07:00"))
}
