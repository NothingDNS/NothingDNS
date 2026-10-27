package zone

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// RFC 1982 serial number arithmetic constants
const (
	// SerialHalfRange is half of the serial number space (2^31).
	// Serial numbers more than this apart are considered to have rolled over.
	SerialHalfRange = uint32(1 << 31)
)

// ErrRecordExists is returned by AddRecord when the RRset already holds an RR
// with the same RDATA (RFC 2181 §5: an RRset has no duplicate RRs).
var ErrRecordExists = errors.New("record already exists")

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
	mu    sync.RWMutex
	zones map[string]*Zone
	files map[string]string // zone name -> file path
	// fileBehind holds the zones whose last write to their file failed, so
	// the file lacks changes the zone has (F726). Kept across RemoveZones,
	// which a config reload calls before it decides which version to load.
	fileBehind map[string]bool
	// fileWriteMu serialises zone file writes, snapshot through rename: two
	// mutations writing back concurrently could otherwise rename an older
	// snapshot over a newer one and leave the file without a change (F727).
	fileWriteMu  sync.Mutex
	zoneDir      string // directory for zone file storage
	logger       Logger // optional logger for errors
	onemdEnabled bool   // enable ZONEMD computation (RFC 8976)

	// deterministicSerials makes the manager's own mutations bump the SOA
	// serial by plain RFC 1982 increment instead of the date-style
	// IncrementSerial, which reads the local wall clock. A Raft cluster sets
	// it: every replica applies the same log, so the serial must depend only
	// on the zone and the log.
	deterministicSerials atomic.Bool

	// mutationHook, when set, is invoked after every successful zone
	// mutation (CreateZone, AddRecord, DeleteRecord, UpdateRecord with
	// deleted=false; DeleteZone with deleted=true). It centralizes
	// durability concerns (KV persistence) at the manager layer so that
	// EVERY mutation path — REST API, Raft apply, gossip —
	// is covered without each caller persisting explicitly.
	//
	// The hook is deliberately NOT fired by Load/LoadZone/Reload/Remove:
	// those (re)load file-backed zones into memory, and an unchanged config
	// zone needs no KV copy. A file-backed zone the API changes is written
	// back to its file and its KV copy is flagged FileBacked, so it is never
	// restored once the file is removed from the config.
	mutationHook func(zoneName string, deleted bool)
}

// Logger interface for logging errors.
type Logger interface {
	Warnf(format string, args ...any)
}

// NewManager creates a new zone manager.
func NewManager() *Manager {
	return &Manager{
		zones:      make(map[string]*Zone),
		files:      make(map[string]string),
		fileBehind: make(map[string]bool),
	}
}

// SetDeterministicSerials selects how the manager bumps a zone's SOA serial on
// AddRecord, UpdateRecord, DeleteRecord and DeleteRecordData: plain increment
// when enabled (identical on every Raft replica), YYYYMMDDNN otherwise.
func (m *Manager) SetDeterministicSerials(enabled bool) {
	m.deterministicSerials.Store(enabled)
}

// bumpSerial advances z's SOA serial per SetDeterministicSerials. The caller
// holds z.Lock().
func (m *Manager) bumpSerial(z *Zone) {
	if m.deterministicSerials.Load() {
		incrementSerialPlain(z)
		return
	}
	IncrementSerial(z)
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

// MutationHook returns the currently registered mutation hook, or nil if
// none is set. Used to compose hooks (e.g. layering the query-routing
// rebuild on top of the KV-persistence hook) without losing the earlier
// registration.
func (m *Manager) MutationHook() func(zoneName string, deleted bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.mutationHook
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

// IsZONEMDEnabled reports whether ZONEMD computation is enabled.
func (m *Manager) IsZONEMDEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.onemdEnabled
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
	for _, w := range z.Warnings {
		m.warnf("zone: %s", w)
	}

	if err := z.Validate(); err != nil {
		return fmt.Errorf("zone validation: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.zones[z.Origin] = z
	m.files[z.Origin] = path

	m.attachZONEMD(z)

	return nil
}

// attachZONEMD marks z as carrying a ZONEMD (RFC 8976) when digests are
// enabled: z.ZONEMD is what makes AXFR/XoT stream one, re-digested per transfer
// (F713). Every way a zone enters the manager needs it — Load, LoadZone (start,
// reload, Raft snapshot, gossip) and CreateZone — not only Load, which the
// server's own start-up path never calls (F720). A zone whose file already
// holds its own apex ZONEMD RR keeps that one: a second RR with the same
// scheme/algorithm is invalid (RFC 8976 §2.2) and the file's may be signed.
// Caller holds m.mu and z is not yet shared.
func (m *Manager) attachZONEMD(z *Zone) {
	if !m.onemdEnabled || z == nil {
		return
	}
	for _, r := range z.Records[z.Origin] {
		if strings.EqualFold(r.Type, "ZONEMD") {
			return
		}
	}
	zonemd, err := ComputeZoneMD(z, ZONEMDSHA384)
	if err != nil {
		m.warnf("zone: failed to compute ZONEMD for %s: %v", z.Origin, err)
		return
	}
	z.ZONEMD = zonemd
}

// LoadZone loads a zone directly without validation.
// Prefer Load() for new zones, which validates before loading.
// RemoveZones removes the named origins from the manager. It is safe to call
// with an empty or partially-overlapping list; only origins that exist are removed.
// Panics are recovered and logged so a failure here does not abort a reload.
func (m *Manager) RemoveZones(origins ...string) {
	if len(origins) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, origin := range origins {
		delete(m.zones, origin)
		delete(m.files, origin)
	}
}

func (m *Manager) LoadZone(z *Zone, path string) {
	if z == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	m.attachZONEMD(z)
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

// Range calls fn for every loaded zone under the manager's read lock, without
// copying the zone map (List copies it on every call). fn must be quick and
// must not call back into the Manager; returning false stops the iteration.
func (m *Manager) Range(fn func(name string, z *Zone) bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for name, z := range m.zones {
		if !fn(name, z) {
			return
		}
	}
}

// ListShared returns the internal zones map for read-only access.
// Caller must NOT modify the returned map.
// This enables single-source-of-truth zone access without map copying.
func (m *Manager) ListShared() map[string]*Zone {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.zones
}

// Reload reloads a zone from its file. The name may be given in any spelling
// the manager's other methods accept (case, with or without the trailing dot).
func (m *Manager) Reload(name string) error {
	name = normalizeZoneName(name)
	m.mu.RLock()
	path, ok := m.files[name]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("zone %s not found", name)
	}

	if err := m.Load(name, path); err != nil {
		return err
	}
	// Load swapped in a new Zone object: tell the hook (query routing, KV
	// persistence) like every other mutation, or the old object keeps serving.
	m.notifyMutation(name, false)
	return nil
}

// Remove removes a zone.
func (m *Manager) Remove(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.zones, name)
	delete(m.files, name)
	delete(m.fileBehind, name)
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
	// Normalize the SOA and NS names before they are rendered into RDATA. An
	// empty RNAME left the SOA with six fields, which the persistence layer
	// could not parse back, so the zone came back without its SOA after a
	// restart; names without a trailing dot were re-qualified with the origin
	// when the written zone file was loaded again.
	soa.MName = absoluteDomainName(soa.MName, origin)
	rname, err := SOAMailbox(soa.RName, origin)
	if err != nil {
		return err
	}
	soa.RName = rname
	if soa.MName == "" {
		return fmt.Errorf("SOA primary nameserver is required")
	}
	for i := range nsRecords {
		nsRecords[i].NSDName = absoluteDomainName(nsRecords[i].NSDName, origin)
		if nsRecords[i].NSDName == "" {
			return fmt.Errorf("NS record %d has an empty nameserver", i)
		}
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

	m.attachZONEMD(z)
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

// pathWithinDir reports whether path lies inside dir (dir must be non-empty).
func pathWithinDir(path, dir string) bool {
	if strings.TrimSpace(dir) == "" {
		return false
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(absDir, absPath)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "."
}

// absoluteDomainName returns name as an absolute domain name. Names with a
// trailing dot are kept; dotted names (ns1.example.com) are taken as fully
// qualified; single labels (ns1) are relative to origin.
func absoluteDomainName(name, origin string) string {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return ""
	case name == "@":
		return origin
	case strings.HasSuffix(name, "."):
		return name
	case strings.Contains(name, "."):
		return name + "."
	default:
		return name + "." + origin
	}
}

// SOAMailbox converts an administrator address to the SOA RNAME form
// (RFC 1035 §3.3.13): "hostmaster@example.com" becomes
// "hostmaster.example.com.", and an address already in that form is made
// absolute. An empty address defaults to hostmaster.<origin>. A local part
// containing dots would need a "\." escape, which the DNS name codec does
// not support, so such addresses are rejected.
func SOAMailbox(email, origin string) (string, error) {
	origin = normalizeZoneName(origin)
	email = strings.TrimSpace(email)
	if email == "" {
		return "hostmaster." + origin, nil
	}
	if at := strings.LastIndex(email, "@"); at >= 0 {
		local, domain := email[:at], strings.TrimSuffix(email[at+1:], ".")
		if local == "" || domain == "" || strings.ContainsAny(local, ". @") {
			return "", fmt.Errorf("invalid admin email %q: use user@domain with no dots in the user part", email)
		}
		return local + "." + domain + ".", nil
	}
	if strings.ContainsAny(email, " @") {
		return "", fmt.Errorf("invalid admin email %q", email)
	}
	return absoluteDomainName(email, origin), nil
}

// DeleteZone removes a zone entirely.
func (m *Manager) DeleteZone(name string) error {
	name = normalizeZoneName(name)

	m.mu.Lock()

	if _, exists := m.zones[name]; !exists {
		m.mu.Unlock()
		return fmt.Errorf("zone %s not found", name)
	}

	// Only remove zone files this manager owns — those inside zone_dir,
	// where API-created zones are written. Files listed under `zones:` in the
	// config belong to the operator: deleting one through the API used to
	// destroy it on disk. Such a zone is removed from memory and the
	// persistent store, and comes back from its file on the next restart
	// unless it is also removed from the config.
	path := m.files[name]
	if path != "" && pathWithinDir(path, m.zoneDir) {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			m.mu.Unlock()
			return fmt.Errorf("delete zone file %s: %w", path, err)
		}
	} else if path != "" {
		m.warnf("zone: %s deleted; its file %s is outside zone_dir and was kept (remove it from the config to keep the zone deleted)", name, path)
	}

	delete(m.zones, name)
	delete(m.files, name)
	delete(m.fileBehind, name)
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
	// An absolute name from outside the zone passes through qualifyName
	// unchanged (makeAbsolute returns any dotted name as-is), and storing it
	// would put out-of-zone data into the zone's data set — which is written to
	// the zone file, shipped by AXFR/IXFR and signed into the NSEC/NSEC3 denial
	// chain. nameInZone is the package's own predicate and is label-boundary
	// aware, so "notexample.com." is correctly outside "example.com.".
	if !nameInZone(record.Name, z.Origin) {
		z.Unlock()
		return fmt.Errorf("record owner %s is outside zone %s", record.Name, z.Origin)
	}
	// Callers pre-check for a duplicate, but only here, under the zone lock, is
	// the check atomic: a replayed gossip add or a racing API request would
	// otherwise store the same RR twice (F718).
	for _, existing := range z.Records[record.Name] {
		if strings.EqualFold(existing.Type, record.Type) && RDataEqual(record.Type, existing.RData, record.RData) {
			z.Unlock()
			return fmt.Errorf("%w: %s %s %s", ErrRecordExists, record.Name, record.Type, record.RData)
		}
	}
	setRRsetTTL(z.Records[record.Name], record.Type, record.TTL)
	z.Records[record.Name] = append(z.Records[record.Name], record)
	m.bumpSerial(z)
	z.Unlock()

	m.writeBackZoneFile(zoneName, z)

	m.notifyMutation(zoneName, false)
	return nil
}

// setRRsetTTL gives every record of rtype in records the same TTL: all RRs of
// an RRset share one TTL (RFC 2181 §5.2), so a change to one member's TTL is a
// change to the set's, as for a DDNS add (F716).
func setRRsetTTL(records []Record, rtype string, ttl uint32) {
	for i := range records {
		if strings.EqualFold(records[i].Type, rtype) {
			records[i].TTL = ttl
		}
	}
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

	m.bumpSerial(z)
	z.Unlock()

	m.writeBackZoneFile(zoneName, z)

	m.notifyMutation(zoneName, false)
	return nil
}

// DeleteRecordData deletes the single resource record name+type+rdata from a
// zone, leaving the other records of the RRset in place (F417). The owner
// name is matched case-insensitively (qualified against the zone origin) and
// RDATA is compared in canonical form via RDataEqual. Exact duplicates of the
// RR are one RR (RFC 2181 §5), so every stored copy equal to rdata is removed.
// It bumps the SOA serial, persists the zone file and fires the mutation hook
// exactly like DeleteRecord. An empty rdata is rejected: use DeleteRecord to
// remove a whole RRset.
func (m *Manager) DeleteRecordData(zoneName, name, rtype, rdata string) error {
	zoneName = normalizeZoneName(zoneName)
	rtype = strings.ToUpper(strings.TrimSpace(rtype))
	if strings.TrimSpace(rdata) == "" {
		return fmt.Errorf("record data is required to delete a single record")
	}

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

	filtered := make([]Record, 0, len(records))
	found := false
	for _, r := range records {
		if strings.ToUpper(r.Type) == rtype && RDataEqual(rtype, r.RData, rdata) {
			found = true
			continue
		}
		filtered = append(filtered, r)
	}

	if !found {
		z.Unlock()
		return fmt.Errorf("record not found: %s %s %s", name, rtype, rdata)
	}

	if len(filtered) == 0 {
		delete(z.Records, name)
	} else {
		z.Records[name] = filtered
	}

	m.bumpSerial(z)
	z.Unlock()

	m.writeBackZoneFile(zoneName, z)

	m.notifyMutation(zoneName, false)
	return nil
}

// nameOnlyRDataTypes are the types whose presentation RDATA holds only
// numbers and domain names, so it can be lowercased before encoding: their
// names compare case-insensitively (RFC 4034 §6.2) and nothing else in the
// RDATA carries case.
var nameOnlyRDataTypes = map[string]bool{
	"NS": true, "CNAME": true, "PTR": true, "DNAME": true, "MX": true,
	"SRV": true, "KX": true, "AFSDB": true, "RT": true, "PX": true, "MD": true,
	"MF": true, "MB": true, "MG": true, "MR": true, "MINFO": true, "RP": true,
	"SOA": true,
}

// RDataEqual reports whether two presentation-form RDATA strings of type
// rtype denote the same RDATA. Both sides are compared in canonical wire form
// (so "2001:DB8::1" equals "2001:db8::0:1" and TXT quoting is normalized), with
// domain names compared case-insensitively. Text that cannot be encoded falls
// back to an exact comparison (case-insensitive for name-only types).
// The comparison is a pure function of its inputs, so every Raft replica
// selects the same record.
func RDataEqual(rtype, a, b string) bool {
	rtype = strings.ToUpper(strings.TrimSpace(rtype))
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == b {
		return true
	}
	nameOnly := nameOnlyRDataTypes[rtype]
	if nameOnly {
		a, b = strings.ToLower(a), strings.ToLower(b)
		if a == b {
			return true
		}
	}
	wa := serializeRecordData(Record{Type: rtype, RData: a})
	wb := serializeRecordData(Record{Type: rtype, RData: b})
	if wa != nil && wb != nil && protocol.RecordTypeFromText(rtype) != 0 {
		return bytes.Equal(wa, wb)
	}
	return false
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
	// Same in-zone requirement as AddRecord: the replacement record's owner is
	// what gets stored (and later written, transferred and signed), so an
	// update must not be the way a foreign name enters the zone's data set.
	if !nameInZone(name, z.Origin) || !nameInZone(newRecord.Name, z.Origin) {
		z.Unlock()
		return fmt.Errorf("record owner %s is outside zone %s", newRecord.Name, z.Origin)
	}
	records, ok := z.Records[name]
	if !ok {
		z.Unlock()
		return fmt.Errorf("no records found for %s", name)
	}

	found := false
	for i, r := range records {
		// RDataEqual, not a case-insensitive text match: TXT and other data are
		// case-sensitive, so records differing only in case are different RRs.
		if strings.ToUpper(r.Type) == rtype && RDataEqual(rtype, r.RData, oldData) {
			records[i] = newRecord
			found = true
			break
		}
	}

	if !found {
		z.Unlock()
		return fmt.Errorf("record not found: %s %s %s", name, rtype, oldData)
	}
	// The updated TTL applies to the whole RRset (see setRRsetTTL), unless the
	// record moved to another owner name.
	if newRecord.Name == name {
		setRRsetTTL(records, rtype, newRecord.TTL)
	}

	m.bumpSerial(z)
	z.Unlock()

	m.writeBackZoneFile(zoneName, z)

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
	syncSOARecord(z)
}

// incrementSerialPlain bumps the SOA serial by one (RFC 1982), with no
// dependence on the clock.
func incrementSerialPlain(z *Zone) {
	if z.SOA == nil {
		return
	}
	z.SOA.Serial = SerialIncrement(z.SOA.Serial)
	syncSOARecord(z)
}

// syncSOARecord rewrites the SOA record in the Records map from z.SOA.
func syncSOARecord(z *Zone) {
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
	m.fileWriteMu.Lock()
	defer m.fileWriteMu.Unlock()
	content, err := WriteZone(z)
	if err != nil {
		return err
	}
	if zoneFileSnapshotHook != nil {
		zoneFileSnapshotHook(path)
	}

	// Keep an existing zone file's permissions (an operator's 0640 file must
	// not become world-readable). A symlink is not followed: the rename below
	// replaces the link itself.
	mode := os.FileMode(0644)
	if info, statErr := os.Lstat(path); statErr == nil && info.Mode().IsRegular() {
		mode = info.Mode().Perm()
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
	if err := os.Chmod(tmpName, mode); err != nil {
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

// PersistZone writes a zone to its file: the file it was loaded from (a
// `zones:` entry or zone_dir), or, for a zone without one, a new file in
// zone_dir when that is configured. The caller must NOT hold the zone lock.
func (m *Manager) PersistZone(zoneName string) error {
	m.mu.RLock()
	z, ok := m.zones[zoneName]
	path := m.files[zoneName]
	dir := m.zoneDir
	m.mu.RUnlock()

	if !ok || (path == "" && dir == "") {
		return nil
	}

	// If no existing file path, construct one from zoneDir
	if path == "" {
		path = filepath.Join(dir, sanitizeZoneFileName(zoneName)+".zone")
		m.mu.Lock()
		m.files[zoneName] = path
		m.mu.Unlock()
	}

	err := m.writeZoneFile(z, path)
	m.setFileBehind(zoneName, err != nil)
	return err
}

// writeBackZoneFile writes a mutated zone to the file it was loaded from, so
// a record change made through the API survives a restart. Zones listed
// under `zones:` are written back like zone_dir zones: the file is their
// source of truth at start. Zones without a file (API-created without
// zone_dir, KV-restored) are left to the KV store. A failure is logged and
// does not fail the mutation; the KV copy (see KVPersistence) keeps the
// change and is restored over the older file at the next start.
func (m *Manager) writeBackZoneFile(zoneName string, z *Zone) {
	m.mu.RLock()
	path := m.files[zoneName]
	m.mu.RUnlock()
	if path == "" {
		return
	}
	err := m.writeZoneFile(z, path)
	m.setFileBehind(zoneName, err != nil)
	if err != nil {
		m.warnf("zone: failed to persist zone %s to %s: %v", zoneName, path, err)
	}
}

// zoneFileSnapshotHook, when set by a test, runs after writeZoneFile has
// taken its snapshot of the zone and before the file is replaced.
var zoneFileSnapshotHook func(path string)

func (m *Manager) setFileBehind(zoneName string, behind bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if behind {
		m.fileBehind[zoneName] = true
	} else {
		delete(m.fileBehind, zoneName)
	}
}

// FileBehind returns zoneName's current zone when the last write of it to
// its file failed and the zone's SOA serial is newer than fileSerial: the
// file lacks changes made through the API, which a config reload must keep
// instead of reloading the older file (F726). Otherwise it returns nil, and
// the file wins (an operator who edits the file bumps its serial).
func (m *Manager) FileBehind(zoneName string, fileSerial uint32) *Zone {
	zoneName = normalizeZoneName(zoneName)
	m.mu.RLock()
	behind := m.fileBehind[zoneName]
	z := m.zones[zoneName]
	m.mu.RUnlock()
	if !behind || z == nil {
		return nil
	}
	z.RLock()
	newer := z.SOA != nil && SerialIsNewer(z.SOA.Serial, fileSerial)
	z.RUnlock()
	if !newer {
		return nil
	}
	return z
}

// ZoneFile returns the file zoneName was loaded from or is written to, or ""
// when the zone has none.
func (m *Manager) ZoneFile(zoneName string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.files[normalizeZoneName(zoneName)]
}

// QualifyRDataNames returns data with every domain-name field made absolute
// the way the API treats names (absoluteDomainName: a trailing dot is kept,
// dotted names are fully qualified, single labels and "@" are relative to
// origin). Stored RDATA is read two ways: protocol.ParseRDataText, which
// serves it, has no origin and reads "target.example.org" as absolute, while
// the zone file, an export and a Raft snapshot are read with $ORIGIN, which
// makes it "target.example.org.<origin>". An API record stored without its
// trailing dot therefore changed meaning after a restart; stored absolute, it
// reads the same both ways. Only the name fields change; the rest of the
// text, quoted strings included, is kept as is.
func QualifyRDataNames(rtype, data, origin string) string {
	origin = normalizeZoneName(origin)
	rtype = strings.ToUpper(strings.TrimSpace(rtype))
	spans := rdataFieldSpans(data)
	fields := make([]string, len(spans))
	for i, sp := range spans {
		fields[i] = data[sp[0]:sp[1]]
	}
	var b strings.Builder
	last := 0
	for _, idx := range rdataNameIndices(rtype, fields) {
		f := fields[idx]
		if strings.HasSuffix(f, ".") || strings.ContainsAny(f, "\"\\") {
			continue
		}
		b.WriteString(data[last:spans[idx][0]])
		b.WriteString(absoluteDomainName(f, origin))
		last = spans[idx][1]
	}
	if last == 0 {
		return data
	}
	b.WriteString(data[last:])
	return b.String()
}

// rdataFieldSpans returns the byte ranges of the whitespace-separated fields
// of data; a quoted string (with backslash escapes) is one field.
func rdataFieldSpans(data string) [][2]int {
	var spans [][2]int
	for i := 0; i < len(data); {
		if data[i] == ' ' || data[i] == '\t' {
			i++
			continue
		}
		start := i
		inQuotes := false
		for ; i < len(data); i++ {
			c := data[i]
			if c == '\\' {
				i++
				continue
			}
			if c == '"' {
				inQuotes = !inQuotes
				continue
			}
			if !inQuotes && (c == ' ' || c == '\t') {
				break
			}
		}
		if i > len(data) {
			i = len(data)
		}
		spans = append(spans, [2]int{start, i})
	}
	return spans
}
