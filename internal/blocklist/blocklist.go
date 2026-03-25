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

	// Check subdomains (e.g., ads.example.com matches example.com)
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if _, blocked := bl.entries[parent]; blocked {
			return true
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
