// Package blocklist provides domain blocking functionality for NothingDNS.
package blocklist

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
)

// Entry represents a blocked domain entry.
type Entry struct {
	Domain  string
	Comment string
}

// Blocklist manages blocked domains.
type Blocklist struct {
	mu       sync.RWMutex
	entries  map[string]Entry
	suffixes map[string]struct{} // Pre-computed suffixes for O(1) longest-match lookup
	files    []string
	enabled  bool
}

// Config holds blocklist configuration.
type Config struct {
	Enabled bool
	Files   []string
}

// New creates a new blocklist manager.
func New(cfg Config) *Blocklist {
	bl := &Blocklist{
		entries: make(map[string]Entry),
		files:   cfg.Files,
		enabled: cfg.Enabled,
	}
	return bl
}

// Load loads all configured blocklist files.
func (bl *Blocklist) Load() error {
	if !bl.enabled {
		return nil
	}

	bl.mu.Lock()
	defer bl.mu.Unlock()

	bl.entries = make(map[string]Entry)

	for _, file := range bl.files {
		if err := bl.loadFile(file); err != nil {
			return fmt.Errorf("loading blocklist %s: %w", file, err)
		}
	}

	return nil
}

// loadFile loads a single blocklist file.
func (bl *Blocklist) loadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse hosts file format: IP domain [comment]
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		// fields[0] is IP (127.0.0.1, 0.0.0.0, etc.)
		// fields[1] is the domain to block
		domain := strings.ToLower(fields[1])

		// Extract comment if present
		comment := ""
		if idx := strings.Index(line, "#"); idx != -1 {
			comment = strings.TrimSpace(line[idx+1:])
		}

		bl.entries[domain] = Entry{
			Domain:  domain,
			Comment: comment,
		}
	}

	return scanner.Err()
}

// IsBlocked checks if a domain is blocked.
// Uses efficient suffix matching without repeated string allocations.
func (bl *Blocklist) IsBlocked(domain string) bool {
	if !bl.enabled {
		return false
	}

	bl.mu.RLock()
	defer bl.mu.RUnlock()

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	// Check exact match
	if _, blocked := bl.entries[domain]; blocked {
		return true
	}

	// Check parent domains by finding dots and checking substrings
	// For "sub.ads.example.com", check "ads.example.com", then "example.com"
	// This avoids O(n²) string split+join operations
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' && i < len(domain)-1 {
			parent := domain[i+1:] // Everything after this dot
			if _, blocked := bl.entries[parent]; blocked {
				return true
			}
		}
	}

	return false
}

// Reload reloads all blocklist files.
func (bl *Blocklist) Reload() error {
	return bl.Load()
}

// Stats returns blocklist statistics.
func (bl *Blocklist) Stats() Stats {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	return Stats{
		Enabled:     bl.enabled,
		TotalBlocks: len(bl.entries),
		Files:       len(bl.files),
	}
}

// Stats holds blocklist statistics.
type Stats struct {
	Enabled     bool
	TotalBlocks int
	Files       int
}

// GetEntries returns all blocked domains (for debugging/monitoring).
func (bl *Blocklist) GetEntries() []Entry {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	entries := make([]Entry, 0, len(bl.entries))
	for _, entry := range bl.entries {
		entries = append(entries, entry)
	}
	return entries
}

// AddFile loads a new blocklist file and merges its entries.
func (bl *Blocklist) AddFile(path string) error {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	if err := bl.loadFile(path); err != nil {
		return err
	}
	bl.files = append(bl.files, path)
	return nil
}

// RemoveFile removes all entries that originated from a given file path.
func (bl *Blocklist) RemoveFile(path string) error {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	// Reload without the target file
	newFiles := make([]string, 0, len(bl.files))
	for _, f := range bl.files {
		if f != path {
			newFiles = append(newFiles, f)
		}
	}
	bl.files = newFiles

	// Rebuild entries from remaining files
	bl.entries = make(map[string]Entry)
	for _, f := range bl.files {
		if err := bl.loadFile(f); err != nil {
			return err
		}
	}
	return nil
}

// SetEnabled enables or disables the blocklist.
func (bl *Blocklist) SetEnabled(enabled bool) {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	bl.enabled = enabled
}

// AddDomain adds a single domain to the blocklist in-memory.
func (bl *Blocklist) AddDomain(domain string) {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	bl.entries[d] = Entry{Domain: d}
}

// RemoveDomain removes a single domain from the blocklist in-memory.
func (bl *Blocklist) RemoveDomain(domain string) {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	delete(bl.entries, d)
}

// ListFiles returns the list of configured blocklist file paths.
func (bl *Blocklist) ListFiles() []string {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	files := make([]string, len(bl.files))
	copy(files, bl.files)
	return files
}
