package zone

import (
	"fmt"
	"os"
	"sync"
)

// Manager manages DNS zones.
type Manager struct {
	mu    sync.RWMutex
	zones map[string]*Zone
	files map[string]string // zone name -> file path
}

// NewManager creates a new zone manager.
func NewManager() *Manager {
	return &Manager{
		zones: make(map[string]*Zone),
		files: make(map[string]string),
	}
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

// LoadZone loads a zone directly
func (m *Manager) LoadZone(z *Zone, path string) {
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
