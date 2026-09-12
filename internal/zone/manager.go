package zone

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// RFC 1982 serial number arithmetic constants
const (
	// SerialHalfRange is half of the serial number space (2^31).
	// Serial numbers more than this apart are considered to have rolled over.
	SerialHalfRange = uint32(1 << 31)
)

// reservedZoneNames cannot be created via the API.
//
// Why: allowing an operator to create a zone at a real IANA TLD would shadow
// the global DNS for every downstream client that resolves through this
// server, and is almost never intended. The list covers common gTLDs and
// ccTLDs rather than aiming for exhaustiveness.
//
// Deliberately NOT on this list:
//   - arpa. / in-addr.arpa. / ip6.arpa. — operators routinely serve reverse
//     DNS for their own networks at these names.
//   - example.* / test. / invalid. / localhost. — RFC 6761 designates these
//     for testing and local use; blocking them breaks common workflows.
//
// Normalized form is lowercase + trailing dot, matching normalizeZoneName.
var reservedZoneNames = map[string]bool{
	// Root — already blocked by origin == "." guard; kept for clarity.
	".": true,
	// Common IANA gTLDs / ccTLDs. Split-horizon authority over a real TLD
	// requires removing entries here or adding a config override.
	"com.": true, "net.": true, "org.": true, "edu.": true, "gov.": true,
	"mil.": true, "int.": true, "info.": true, "biz.": true, "name.": true,
	"io.": true, "co.": true, "uk.": true, "us.": true, "de.": true,
	"fr.": true, "jp.": true, "cn.": true, "ru.": true, "br.": true,
	"au.": true, "ca.": true, "it.": true, "es.": true, "nl.": true,
	"tr.": true,
}

// SerialIsNewer returns true if s1 is considered newer than s2 per RFC 1982 §3.2.
//
// Serial numbers are 32-bit unsigned integers with wrap-around semantics:
//
//	s1 is newer than s2 iff
//	  (s1 > s2 AND s1 - s2 < 2^31)   // direct ordering within half-range
//	  OR
//	  (s1 < s2 AND s2 - s1 > 2^31)   // wrap-around: s1 is past the top
//
// Equal serials and the s2-s1 == 2^31 boundary case are defined as "not newer"
// (RFC 1982 leaves the exact-half-range case undefined; we return false).
func SerialIsNewer(s1, s2 uint32) bool {
	if s1 == s2 {
		return false
	}
	if s1 > s2 {
		return s1-s2 < SerialHalfRange
	}
	// s1 < s2
	return s2-s1 > SerialHalfRange
}

// SerialIncrement returns s + 1 with RFC 1982 §3.1 wrap-around semantics.
// The serial space is the full 32-bit unsigned range; arithmetic is mod 2^32,
// which Go's uint32 provides natively. Only the true 2^32-1 → 0 boundary wraps.
func SerialIncrement(s uint32) uint32 {
	return s + 1
}

// Manager manages DNS zones.
type Manager struct {
	mu           sync.RWMutex
	zones        map[string]*Zone
	files        map[string]string // zone name -> file path
	zoneDir      string            // directory for zone file storage
	logger       Logger            // optional logger for errors
	onemdEnabled bool              // enable ZONEMD computation (RFC 8976)

	// mutationHook, when set, is invoked after every successful zone
	// mutation (CreateZone, AddRecord, DeleteRecord, UpdateRecord with
	// deleted=false; DeleteZone with deleted=true). It centralizes
	// durability concerns (KV persistence) at the manager layer so that
	// EVERY mutation path — REST API, Raft apply, gossip —
	// is covered without each caller persisting explicitly.
	//
	// The hook is deliberately NOT fired by Load/LoadZone/Reload/Remove:
	// those (re)load file-backed zones into memory and must not push
	// config zones into the KV store (KV is durability for API-created
	// zones only; persisting config zones would resurrect them after
	// config removal).
	mutationHook func(zoneName string, deleted bool)
}

// Logger interface for logging errors.
type Logger interface {
	Warnf(format string, args ...any)
}

// NewManager creates a new zone manager.
func NewManager() *Manager {
	return &Manager{
		zones: make(map[string]*Zone),
		files: make(map[string]string),
	}
}

// SetLogger sets the logger for the manager.
func (m *Manager) SetLogger(logger Logger) {
	m.logger = logger
}

// SetMutationHook registers a callback invoked after every successful zone
// mutation (see the field doc on Manager.mutationHook).
//
// LOCKING CONTRACT: the hook is always called WITHOUT m.mu held, because hook
// implementations read zone state back through manager methods that take the
// lock (e.g. KV persistence calls Get). Mutation methods therefore release
// the mutex before notifying.
func (m *Manager) SetMutationHook(hook func(zoneName string, deleted bool)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mutationHook = hook
}

// NotifyMutated fires the mutation hook for a zone that was mutated OUTSIDE
// the manager's mutation methods — e.g. DDNS (transfer.ApplyUpdate) mutates
// the *Zone object directly. Such paths must call this once after applying
// their changes so hook consumers (KV persistence) observe the new state.
func (m *Manager) NotifyMutated(zoneName string) {
	m.notifyMutation(normalizeZoneName(zoneName), false)
}

// notifyMutation invokes the mutation hook, if set. Must be called without
// m.mu held — see SetMutationHook.
func (m *Manager) notifyMutation(zoneName string, deleted bool) {
	m.mu.RLock()
	hook := m.mutationHook
	m.mu.RUnlock()
	if hook != nil {
		hook(zoneName, deleted)
	}
}

// warnf logs via the configured logger, if any.
func (m *Manager) warnf(format string, args ...any) {
	if m.logger != nil {
		m.logger.Warnf(format, args...)
	}
}

// SetZONEMDEnabled enables or disables ZONEMD computation for zones.
func (m *Manager) SetZONEMDEnabled(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onemdEnabled = enabled
}

// SetZoneDir sets the directory where zone files are stored.
func (m *Manager) SetZoneDir(dir string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.zoneDir = dir
}

// Load loads a zone from a file.
func (m *Manager) Load(name, path string) error {
	cleanPath := filepath.Clean(path)
	if m.zoneDir != "" {
		absPath, err := filepath.Abs(cleanPath)
		if err != nil {
			return fmt.Errorf("zone path: %w", err)
		}
		absDir, err := filepath.Abs(m.zoneDir)
		if err != nil {
			return fmt.Errorf("zone dir: %w", err)
		}
		rel, err := filepath.Rel(absDir, absPath)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("zone path %q is outside zone_dir %q", path, m.zoneDir)
		}
	}

	// Check for symlinks to prevent path disclosure attacks
	info, err := os.Lstat(cleanPath)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("zone file %s is a symlink: symlinks are not allowed", path)
	}

	f, err := os.Open(cleanPath)
	if err != nil {
		return err
	}
	defer f.Close()

	z, err := ParseFile(path, f)
	if err != nil {
		return err
	}

	if err := z.Validate(); err != nil {
		return fmt.Errorf("zone validation: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.zones[z.Origin] = z
	m.files[z.Origin] = path

	// Compute ZONEMD if enabled
	if m.onemdEnabled {
		zonemd, err := ComputeZoneMD(z, ZONEMDSHA256)
		if err != nil {
			m.warnf("zone: failed to compute ZONEMD for %s: %v", z.Origin, err)
		} else {
			z.ZONEMD = zonemd
		}
	}

	return nil
}

// LoadZone loads a zone directly without validation.
// Prefer Load() for new zones, which validates before loading.
func (m *Manager) LoadZone(z *Zone, path string) {
	if z == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	m.zones[z.Origin] = z
	m.files[z.Origin] = path
}

// Get returns a zone by name.
func (m *Manager) Get(name string) (*Zone, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	z, ok := m.zones[name]
	return z, ok
}

// List returns all loaded zones.
func (m *Manager) List() map[string]*Zone {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy
	result := make(map[string]*Zone, len(m.zones))
	for k, v := range m.zones {
		result[k] = v
	}
	return result
}

// ListShared returns the internal zones map for read-only access.
// Caller must NOT modify the returned map.
// This enables single-source-of-truth zone access without map copying.
func (m *Manager) ListShared() map[string]*Zone {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.zones
}

// Reload reloads a zone from its file.
func (m *Manager) Reload(name string) error {
	m.mu.RLock()
	path, ok := m.files[name]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("zone %s not found", name)
	}

	return m.Load(name, path)
}

// Remove removes a zone.
func (m *Manager) Remove(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.zones, name)
	delete(m.files, name)
}

// Count returns the number of loaded zones.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.zones)
}

// CreateZone creates a new zone with SOA and NS records.
func (m *Manager) CreateZone(origin string, defaultTTL uint32, soa *SOARecord, nsRecords []NSRecord) error {
	origin = normalizeZoneName(origin)
	if origin == "" || origin == "." {
		return fmt.Errorf("invalid zone origin")
	}

	if reservedZoneNames[origin] {
		return fmt.Errorf("zone origin %q is reserved and cannot be created", origin)
	}

	if soa == nil {
		return fmt.Errorf("SOA record is required")
	}
	if len(nsRecords) == 0 {
		return fmt.Errorf("at least one NS record is required")
	}

	m.mu.Lock()

	if _, exists := m.zones[origin]; exists {
		m.mu.Unlock()
		return fmt.Errorf("zone %s already exists", origin)
	}

	z := &Zone{
		Origin:     origin,
		DefaultTTL: defaultTTL,
		SOA:        soa,
		NS:         nsRecords,
		Records:    make(map[string][]Record),
	}

	// Store SOA and NS in the Records map too for consistency
	if soa.TTL == 0 {
		soa.TTL = defaultTTL
	}
	z.Records[origin] = append(z.Records[origin], Record{
		Name:  origin,
		TTL:   soa.TTL,
		Class: "IN",
		Type:  "SOA",
		RData: fmt.Sprintf("%s %s %d %d %d %d %d",
			soa.MName, soa.RName, soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minimum),
	})

	for _, ns := range nsRecords {
		if ns.TTL == 0 {
			ns.TTL = defaultTTL
		}
		z.Records[origin] = append(z.Records[origin], Record{
			Name:  origin,
			TTL:   ns.TTL,
			Class: "IN",
			Type:  "NS",
			RData: ns.NSDName,
		})
	}

	m.zones[origin] = z

	// Write zone file if zoneDir is set
	if m.zoneDir != "" {
		path := filepath.Join(m.zoneDir, sanitizeZoneFileName(origin)+".zone")
		if err := m.writeZoneFile(z, path); err != nil {
			// Zone is loaded in memory; log the error but don't fail the operation
			m.warnf("zone: failed to persist zone %s to %s: %v", origin, path, err)
		}
		m.files[origin] = path
	}
	m.mu.Unlock()

	m.notifyMutation(origin, false)
	return nil
}

// DeleteZone removes a zone entirely.
func (m *Manager) DeleteZone(name string) error {
	name = normalizeZoneName(name)

	m.mu.Lock()

	if _, exists := m.zones[name]; !exists {
		m.mu.Unlock()
		return fmt.Errorf("zone %s not found", name)
	}

	path := m.files[name]
	if path != "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			m.mu.Unlock()
			return fmt.Errorf("delete zone file %s: %w", path, err)
		}
	}

	delete(m.zones, name)
	delete(m.files, name)
	m.mu.Unlock()

	m.notifyMutation(name, true)
	return nil
}

// AddRecord adds a record to an existing zone.
func (m *Manager) AddRecord(zoneName string, record Record) error {
	zoneName = normalizeZoneName(zoneName)
	if err := ValidateRecordData(record.Name, record.RData); err != nil {
		return err
	}
	if record.Class == "" {
		record.Class = "IN"
	}

	m.mu.RLock()
	z, exists := m.zones[zoneName]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("zone %s not found", zoneName)
	}

	z.Lock()

	// Key by the absolute owner name (relative to the zone origin), matching
	// the parser — so a relative "api" resolves as "api.<origin>".
	record.Name = qualifyName(record.Name, z.Origin)
	z.Records[record.Name] = append(z.Records[record.Name], record)
	IncrementSerial(z)
	z.Unlock()

	if m.zoneDir != "" {
		m.mu.RLock()
		path := m.files[zoneName]
		m.mu.RUnlock()
		if path != "" {
			if err := m.writeZoneFile(z, path); err != nil {
				m.warnf("zone: failed to persist zone %s to %s: %v", zoneName, path, err)
			}
		}
	}

	m.notifyMutation(zoneName, false)
	return nil
}

// DeleteRecord deletes records matching name+type from a zone.
func (m *Manager) DeleteRecord(zoneName, name, rtype string) error {
	zoneName = normalizeZoneName(zoneName)
	rtype = strings.ToUpper(rtype)

	m.mu.RLock()
	z, exists := m.zones[zoneName]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("zone %s not found", zoneName)
	}

	z.Lock()

	name = qualifyName(name, z.Origin)
	records, ok := z.Records[name]
	if !ok {
		z.Unlock()
		return fmt.Errorf("no records found for %s", name)
	}

	var filtered []Record
	found := false
	for _, r := range records {
		if strings.ToUpper(r.Type) == rtype {
			found = true
			continue
		}
		filtered = append(filtered, r)
	}

	if !found {
		z.Unlock()
		return fmt.Errorf("no %s record found for %s", rtype, name)
	}

	if len(filtered) == 0 {
		delete(z.Records, name)
	} else {
		z.Records[name] = filtered
	}

	IncrementSerial(z)
	z.Unlock()

	if m.zoneDir != "" {
		m.mu.RLock()
		path := m.files[zoneName]
		m.mu.RUnlock()
		if path != "" {
			if err := m.writeZoneFile(z, path); err != nil {
				m.warnf("zone: failed to persist zone %s to %s: %v", zoneName, path, err)
			}
		}
	}

	m.notifyMutation(zoneName, false)
	return nil
}

// UpdateRecord replaces a record identified by name+type+oldData with a new record.
func (m *Manager) UpdateRecord(zoneName string, name, rtype, oldData string, newRecord Record) error {
	zoneName = normalizeZoneName(zoneName)
	rtype = strings.ToUpper(rtype)
	// Parity with AddRecord: reject injection-shaped RDATA (embedded newlines,
	// NULs) before it reaches the zone file writer — otherwise an update could
	// inject a live record into the authoritative zone on the next persist.
	if err := ValidateRecordData(newRecord.Name, newRecord.RData); err != nil {
		return err
	}
	if newRecord.Class == "" {
		newRecord.Class = "IN"
	}

	m.mu.RLock()
	z, exists := m.zones[zoneName]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("zone %s not found", zoneName)
	}

	z.Lock()

	name = qualifyName(name, z.Origin)
	newRecord.Name = qualifyName(newRecord.Name, z.Origin)
	records, ok := z.Records[name]
	if !ok {
		z.Unlock()
		return fmt.Errorf("no records found for %s", name)
	}

	found := false
	for i, r := range records {
		if strings.ToUpper(r.Type) == rtype && strings.EqualFold(r.RData, oldData) {
			records[i] = newRecord
			found = true
			break
		}
	}

	if !found {
		z.Unlock()
		return fmt.Errorf("record not found: %s %s %s", name, rtype, oldData)
	}

	IncrementSerial(z)
	z.Unlock()

	if m.zoneDir != "" {
		m.mu.RLock()
		path := m.files[zoneName]
		m.mu.RUnlock()
		if path != "" {
			if err := m.writeZoneFile(z, path); err != nil {
				m.warnf("zone: failed to persist zone %s to %s: %v", zoneName, path, err)
			}
		}
	}

	m.notifyMutation(zoneName, false)
	return nil
}

// GetRecords returns all records for a zone, optionally filtered by name.
func (m *Manager) GetRecords(zoneName, name string) ([]Record, error) {
	zoneName = normalizeZoneName(zoneName)

	m.mu.RLock()
	z, exists := m.zones[zoneName]
	m.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("zone %s not found", zoneName)
	}

	z.RLock()
	defer z.RUnlock()

	if name != "" {
		name = qualifyName(name, z.Origin)
		return cloneRecords(z.Records[name]), nil
	}

	// Return all records
	var all []Record
	for _, records := range z.Records {
		all = append(all, records...)
	}
	return all, nil
}

func cloneRecords(records []Record) []Record {
	if len(records) == 0 {
		return nil
	}
	cloned := make([]Record, len(records))
	copy(cloned, records)
	return cloned
}

// ExportZone returns the BIND format representation of a zone.
func (m *Manager) ExportZone(name string) (string, error) {
	name = normalizeZoneName(name)

	m.mu.RLock()
	z, exists := m.zones[name]
	m.mu.RUnlock()

	if !exists {
		return "", fmt.Errorf("zone %s not found", name)
	}

	return WriteZone(z)
}

// sanitizeZoneFileName removes path traversal characters from a zone name
// to ensure it is safe to use as a file name.
func sanitizeZoneFileName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".")
	// Remove any path separators or parent-directory references
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")
	name = strings.ReplaceAll(name, "..", "_")
	return name
}

// qualifyName converts a record owner name to the absolute, lowercased key
// used in z.Records — matching the zone-file parser, which stores owners as
// absolute names (makeAbsolute). normalizeZoneName must NOT be used for record
// names: it only appends a trailing dot, so a relative "api" became the ROOT
// name "api." instead of "api.<origin>", and every API/dashboard-added record
// with a relative name silently failed to resolve. FQDN inputs are unchanged.
func qualifyName(name, origin string) string {
	return makeAbsolute(strings.ToLower(strings.TrimSpace(name)), origin)
}

// normalizeZoneName ensures a zone name is lowercase with a trailing dot.
func normalizeZoneName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ToLower(name)
	if name == "" {
		return ""
	}
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

// IncrementSerial bumps the SOA serial using YYYYMMDDNN format.
// Exported so that DDNS and other mutation paths can bump the serial.
func IncrementSerial(z *Zone) {
	if z.SOA == nil {
		return
	}

	now := time.Now().UTC()
	datePrefix := uint32(now.Year()*10000+int(now.Month())*100+now.Day()) * 100

	// Use RFC 1982 serial arithmetic for proper wrap-around handling
	if SerialIsNewer(datePrefix, z.SOA.Serial) {
		z.SOA.Serial = datePrefix + 1
	} else {
		z.SOA.Serial = SerialIncrement(z.SOA.Serial)
	}

	// Update the SOA record in the Records map too
	if records, ok := z.Records[z.Origin]; ok {
		for i, r := range records {
			if r.Type == "SOA" {
				records[i].RData = fmt.Sprintf("%s %s %d %d %d %d %d",
					z.SOA.MName, z.SOA.RName, z.SOA.Serial,
					z.SOA.Refresh, z.SOA.Retry, z.SOA.Expire, z.SOA.Minimum)
				break
			}
		}
	}
}

// writeZoneFile writes a zone to a file in BIND format using the
// standard temp + fsync + rename atomic-replace pattern. A crash
// mid-write to a zone file used to leave a partial BIND text on
// disk; on the next start, the parser would either error out
// ("zone has no origin", "unexpected token") and refuse to load
// the zone, or silently drop trailing records. PersistZone is
// invoked from API mutations (zone add/remove/update) and from the
// catalog/IXFR paths, so this fronts every write that ever lands
// in `zoneDir`.
func (m *Manager) writeZoneFile(z *Zone, path string) (err error) {
	content, err := WriteZone(z)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".zone-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			if removeErr := os.Remove(tmpName); removeErr != nil && !os.IsNotExist(removeErr) && err == nil {
				err = fmt.Errorf("remove temp: %w", removeErr)
			}
		}
	}()
	if err := os.Chmod(tmpName, 0644); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	cleanup = false
	if err := syncDir(dir); err != nil {
		return err
	}
	return nil
}

func syncDir(dir string) (err error) {
	dirFd, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open dir: %w", err)
	}
	defer func() {
		if closeErr := dirFd.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close dir: %w", closeErr)
		}
	}()

	if err := dirFd.Sync(); err != nil {
		return fmt.Errorf("fsync dir: %w", err)
	}
	return nil
}

// PersistZone writes a zone file to disk if zoneDir is configured.
// The caller must NOT hold the zone lock.
func (m *Manager) PersistZone(zoneName string) error {
	m.mu.RLock()
	z, ok := m.zones[zoneName]
	path := m.files[zoneName]
	dir := m.zoneDir
	m.mu.RUnlock()

	if !ok || dir == "" {
		return nil
	}

	// If no existing file path, construct one from zoneDir
	if path == "" {
		path = filepath.Join(dir, sanitizeZoneFileName(zoneName)+".zone")
		m.mu.Lock()
		m.files[zoneName] = path
		m.mu.Unlock()
	}

	return m.writeZoneFile(z, path)
}
