package zone

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Manager manages DNS zones.
type Manager struct {
	mu      sync.RWMutex
	zones   map[string]*Zone
	files   map[string]string // zone name -> file path
	zoneDir string            // directory for zone file storage
}

// NewManager creates a new zone manager.
func NewManager() *Manager {
	return &Manager{
		zones: make(map[string]*Zone),
		files: make(map[string]string),
	}
}

// SetZoneDir sets the directory where zone files are stored.
func (m *Manager) SetZoneDir(dir string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.zoneDir = dir
}

// Load loads a zone from a file.
func (m *Manager) Load(name, path string) error {
	f, err := os.Open(path)
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

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.zones[origin]; exists {
		return fmt.Errorf("zone %s already exists", origin)
	}

	if soa == nil {
		return fmt.Errorf("SOA record is required")
	}
	if len(nsRecords) == 0 {
		return fmt.Errorf("at least one NS record is required")
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
		path := filepath.Join(m.zoneDir, strings.TrimSuffix(origin, ".")+".zone")
		if err := m.writeZoneFile(z, path); err != nil {
			// Zone is loaded in memory; log but don't fail
			_ = err
		}
		m.files[origin] = path
	}

	return nil
}

// DeleteZone removes a zone entirely.
func (m *Manager) DeleteZone(name string) error {
	name = normalizeZoneName(name)

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.zones[name]; !exists {
		return fmt.Errorf("zone %s not found", name)
	}

	delete(m.zones, name)
	delete(m.files, name)
	return nil
}

// AddRecord adds a record to an existing zone.
func (m *Manager) AddRecord(zoneName string, record Record) error {
	zoneName = normalizeZoneName(zoneName)
	record.Name = normalizeZoneName(record.Name)
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
	defer z.Unlock()

	z.Records[record.Name] = append(z.Records[record.Name], record)
	IncrementSerial(z)

	if m.zoneDir != "" {
		m.mu.RLock()
		path := m.files[zoneName]
		m.mu.RUnlock()
		if path != "" {
			_ = m.writeZoneFile(z, path)
		}
	}

	return nil
}

// DeleteRecord deletes records matching name+type from a zone.
func (m *Manager) DeleteRecord(zoneName, name, rtype string) error {
	zoneName = normalizeZoneName(zoneName)
	name = normalizeZoneName(name)
	rtype = strings.ToUpper(rtype)

	m.mu.RLock()
	z, exists := m.zones[zoneName]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("zone %s not found", zoneName)
	}

	z.Lock()
	defer z.Unlock()

	records, ok := z.Records[name]
	if !ok {
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
		return fmt.Errorf("no %s record found for %s", rtype, name)
	}

	if len(filtered) == 0 {
		delete(z.Records, name)
	} else {
		z.Records[name] = filtered
	}

	IncrementSerial(z)

	if m.zoneDir != "" {
		m.mu.RLock()
		path := m.files[zoneName]
		m.mu.RUnlock()
		if path != "" {
			_ = m.writeZoneFile(z, path)
		}
	}

	return nil
}

// UpdateRecord replaces a record identified by name+type+oldData with a new record.
func (m *Manager) UpdateRecord(zoneName string, name, rtype, oldData string, newRecord Record) error {
	zoneName = normalizeZoneName(zoneName)
	name = normalizeZoneName(name)
	rtype = strings.ToUpper(rtype)
	newRecord.Name = normalizeZoneName(newRecord.Name)
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
	defer z.Unlock()

	records, ok := z.Records[name]
	if !ok {
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
		return fmt.Errorf("record not found: %s %s %s", name, rtype, oldData)
	}

	IncrementSerial(z)

	if m.zoneDir != "" {
		m.mu.RLock()
		path := m.files[zoneName]
		m.mu.RUnlock()
		if path != "" {
			_ = m.writeZoneFile(z, path)
		}
	}

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
		name = normalizeZoneName(name)
		return z.Records[name], nil
	}

	// Return all records
	var all []Record
	for _, records := range z.Records {
		all = append(all, records...)
	}
	return all, nil
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
	datePrefix := uint32(now.Year()*10000 + int(now.Month())*100 + now.Day()) * 100

	if z.SOA.Serial < datePrefix {
		z.SOA.Serial = datePrefix + 1
	} else {
		z.SOA.Serial++
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

// writeZoneFile writes a zone to a file in BIND format.
func (m *Manager) writeZoneFile(z *Zone, path string) error {
	content, err := WriteZone(z)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(path, []byte(content), 0644)
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
		path = filepath.Join(dir, zoneName+".zone")
		m.mu.Lock()
		m.files[zoneName] = path
		m.mu.Unlock()
	}

	return m.writeZoneFile(z, path)
}
